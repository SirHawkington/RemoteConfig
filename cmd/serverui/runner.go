package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	maxLines    = 3000
	stopTimeout = 8 * time.Second
)

// runner owns the server process: start, stop, and the output it printed.
type runner struct {
	exe string

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	stopping  bool
	startedAt time.Time
	exitMsg   string
	lines     []string
	gen       int // bumped whenever lines change
	scan      scanState
}

type snapshot struct {
	Running   bool
	StartedAt time.Time
	ExitMsg   string // why the last run ended, "" while running or never started
	Gen       int
	Scan      scanState
}

func (r *runner) snapshot() snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return snapshot{Running: r.cmd != nil, StartedAt: r.startedAt, ExitMsg: r.exitMsg, Gen: r.gen, Scan: r.scan}
}

func (r *runner) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\r\n")
}

func (r *runner) add(l string) {
	r.lines = append(r.lines, l)
	if len(r.lines) > maxLines {
		r.lines = r.lines[len(r.lines)-maxLines:]
	}
	r.gen++
}

// start runs the server with args; env is added to this process's environment (secrets go
// there rather than on the command line, where other users could list them).
func (r *runner) start(args, env []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return fmt.Errorf("the server is already running")
	}
	cmd := exec.Command(r.exe, args...)
	cmd.Env = append(os.Environ(), env...)
	prepare(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return err
	}
	adopt(cmd.Process)
	done := make(chan struct{})
	r.cmd, r.done, r.stopping, r.exitMsg, r.startedAt = cmd, done, false, "", time.Now()
	r.scan.Listening = false
	r.add("--- " + r.startedAt.Format("15:04:05") + " starting: server " + strings.Join(args, " "))

	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			l := strings.TrimRight(sc.Text(), "\r")
			r.mu.Lock()
			r.scan.line(l)
			r.add(l)
			r.mu.Unlock()
		}
	}()
	go func() {
		err := cmd.Wait()
		pw.Close()
		time.Sleep(50 * time.Millisecond) // let the reader drain the last lines
		r.mu.Lock()
		switch {
		case r.stopping:
			r.exitMsg = "stopped"
		case err != nil:
			r.exitMsg = "exited unexpectedly (" + err.Error() + ")"
			if n := len(r.lines); n > 0 {
				r.exitMsg += ": " + r.lines[n-1]
			}
		default:
			r.exitMsg = "exited"
		}
		r.add("--- server " + r.exitMsg)
		r.cmd = nil
		r.mu.Unlock()
		close(done)
	}()
	return nil
}

// stop kills the server and waits for it to be gone. The database is SQLite in WAL mode, so
// an abrupt end loses nothing that was committed.
func (r *runner) stop() {
	r.mu.Lock()
	cmd, done := r.cmd, r.done
	if cmd == nil {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	r.mu.Unlock()
	cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(stopTimeout):
	}
}
