package agent

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

var testappExe string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rc-testapp")
	if err != nil {
		panic(err)
	}
	testappExe = filepath.Join(dir, "testapp.exe")
	if out, err := exec.Command("go", "build", "-o", testappExe, "remoteconfig/cmd/testapp").CombinedOutput(); err != nil {
		panic("building testapp: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startAgent runs an agent with cached config containing the given supervisor block, a
// local API (so the app can heartbeat and poll for quit requests) and a supervisor loop.
// Calling the returned stop function stops the agent and waits for the supervisor to
// finish what it does on exit (which, with StopAppOnAgentExit, includes stopping the app).
func startAgent(t *testing.T, sc proto.SupervisorConfig, state, addr string, tweak ...func(*Agent)) (*Agent, func()) {
	t.Helper()
	a := New(Options{StateDir: state, Listen: addr, Version: "test"})
	a.localToken = "tok"
	a.cfg = &proto.EffectiveConfig{Revision: 1, Etag: "e1", Data: map[string]any{}, Supervisor: &sc}
	a.sup.tick, a.sup.backoffBase = 25*time.Millisecond, 25*time.Millisecond
	for _, f := range tweak {
		f(a) // before the supervisor starts, so tests can adjust its timings race-free
	}

	ctx, cancel := context.WithCancel(context.Background())
	go a.serveLocal(ctx)
	go a.sup.run(ctx)
	return a, func() {
		cancel()
		select {
		case <-a.sup.done:
		case <-time.After(30 * time.Second): // a shutdown may wait out a 20 s grace period
			t.Error("supervisor did not stop")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// newSupervised is startAgent with a fresh state dir, configured to stop the app when the
// agent stops so a test never leaves a process behind.
func newSupervised(t *testing.T, sc proto.SupervisorConfig, tweak ...func(*Agent)) (*Agent, func()) {
	t.Helper()
	sc.StopAppOnAgentExit = true
	return startAgent(t, sc, t.TempDir(), freeAddr(t), tweak...)
}

// killPIDQuietly makes sure a process started by a test is gone.
func killPIDQuietly(pid int) {
	if pid != 0 {
		killProcess(pid)
	}
}

func readFile(path string) string { b, _ := os.ReadFile(path); return string(b) }

func eventTypes(a *Agent) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.events {
		out = append(out, e.Type)
	}
	return out
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func count(types []string, want string) (n int) {
	for _, t := range types {
		if t == want {
			n++
		}
	}
	return
}

func TestSupervisorRestartsCrashingApp(t *testing.T) {
	runLog := filepath.Join(t.TempDir(), "run.log")
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-crash-after", "300ms", "-log", runLog},
		MaxRestarts: 100, HeartbeatTimeoutS: 30,
	})
	defer stop()

	waitUntil(t, "3 restarts after crashes", func() bool { return a.sup.Snapshot().Restarts >= 3 })
	if n := count(eventTypes(a), "app.crash"); n < 3 {
		t.Fatalf("want >=3 app.crash events, got %d (%v)", n, eventTypes(a))
	}
	// The newest process may not have written its log line yet; wait for it.
	waitUntil(t, "4 launches recorded by the app itself", func() bool {
		b, _ := os.ReadFile(runLog)
		return strings.Count(string(b), "start pid=") >= 4
	})
}

func TestSupervisorStopsOnCrashLoopAndRecoversOnRequest(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-crash-after", "1ms"},
		MaxRestarts: 3, RestartWindowS: 60, HeartbeatTimeoutS: 30,
	})
	defer stop()

	waitUntil(t, "crash loop", func() bool { return a.sup.Snapshot().CrashLoop })
	restarts := a.sup.Snapshot().Restarts
	time.Sleep(400 * time.Millisecond)
	if got := a.sup.Snapshot().Restarts; got != restarts {
		t.Fatalf("supervisor kept restarting in crash loop: %d -> %d", restarts, got)
	}
	if count(eventTypes(a), "app.crashloop") != 1 {
		t.Fatalf("want exactly one app.crashloop event: %v", eventTypes(a))
	}

	a.sup.RequestRestart("operator")
	waitUntil(t, "restart after explicit request", func() bool { return a.sup.Snapshot().Restarts > restarts })
}

func TestSupervisorKillsHungApp(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-hang-after", "500ms"},
		HeartbeatTimeoutS: 1, MaxRestarts: 100, QuitTimeoutS: 1,
	})
	defer stop()

	waitUntil(t, "app.hung then a relaunch", func() bool {
		return count(eventTypes(a), "app.hung") >= 1 && a.sup.Snapshot().Restarts >= 1
	})
}

func TestSupervisorRestartRequestAndConfigDisable(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{Exe: testappExe, HeartbeatTimeoutS: 30})
	defer stop()

	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	pid1 := a.sup.Snapshot().PID
	a.sup.RequestRestart("test")
	waitUntil(t, "new pid after restart request", func() bool {
		s := a.sup.Snapshot()
		return s.Running && s.PID != pid1
	})
	if a.sup.Snapshot().CrashLoop || count(eventTypes(a), "app.crash") != 0 {
		t.Fatalf("a requested restart must not count as a crash: %v", eventTypes(a))
	}

	// Switching to monitor mode (old script owns the app again) stops our copy.
	a.mu.Lock()
	a.cfg = &proto.EffectiveConfig{Revision: 2, Etag: "e2", Data: map[string]any{}, Supervisor: &proto.SupervisorConfig{Exe: testappExe, Mode: "monitor"}}
	a.mu.Unlock()
	waitUntil(t, "stopped in monitor mode", func() bool {
		s := a.sup.Snapshot()
		return !s.Running && s.State == "monitor"
	})
}

func TestSupervisorTriggerFallsBackToRestartWithoutAck(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{Exe: testappExe, HeartbeatTimeoutS: 30})
	defer stop()
	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	pid1 := a.sup.Snapshot().PID

	// trigger mode with no reload_url: nothing to call, so it must restart.
	a.sup.onConfigApplied(proto.EffectiveConfig{Revision: 5, ReloadMode: "trigger", Supervisor: &proto.SupervisorConfig{Exe: testappExe}})
	waitUntil(t, "restart fallback", func() bool {
		s := a.sup.Snapshot()
		return s.Running && s.PID != pid1
	})
}

func TestScheduledDue(t *testing.T) {
	loc := time.UTC
	at := func(h, m int) time.Time { return time.Date(2026, 10, 26, h, m, 0, 0, loc) }
	last := ""

	if scheduledDue(at(5, 0), "04:00", &last) { // first sight, already past: no surprise restart
		t.Fatal("must not fire when first seen after the scheduled time")
	}
	if scheduledDue(at(23, 0), "04:00", &last) {
		t.Fatal("already done today")
	}
	next := at(3, 59).AddDate(0, 0, 1)
	if scheduledDue(next, "04:00", &last) {
		t.Fatal("not yet 04:00")
	}
	next = at(4, 0).AddDate(0, 0, 1)
	if !scheduledDue(next, "04:00", &last) {
		t.Fatal("should fire at 04:00 next day")
	}
	if scheduledDue(next.Add(time.Minute), "04:00", &last) {
		t.Fatal("must fire once per day")
	}
	if scheduledDue(next, "garbage", &last) || scheduledDue(next, "", &last) {
		t.Fatal("invalid schedule must never fire")
	}
}
