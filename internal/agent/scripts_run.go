//go:build !noscripts

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

func (a *Agent) runScript(ctx context.Context, c proto.Command) proto.CommandResult {
	fail := func(format string, args ...any) proto.CommandResult {
		return proto.CommandResult{OK: false, Output: fmt.Sprintf(format, args...)}
	}
	if !a.trust.strict() {
		return fail("refused: this agent does not verify signatures, so it will not run code from the server (pin the server key with -server-key)")
	}
	id, want, interp := str(c.Params, "script_id"), strings.ToLower(str(c.Params, "sha256")), str(c.Params, "interpreter")
	if id == "" || len(want) != 64 || interp == "" {
		return fail("malformed run_script command")
	}
	timeout := time.Duration(num(c.Params, "timeout_s")) * time.Second
	if timeout <= 0 || timeout > time.Hour {
		timeout = 2 * time.Minute
	}
	var args []string
	if raw, ok := c.Params["args"].([]any); ok {
		for _, x := range raw {
			s, ok := x.(string)
			if !ok {
				return fail("malformed arguments")
			}
			args = append(args, s)
		}
	}
	if !scriptMu.TryLock() {
		return fail("another script is still running on this device")
	}
	defer scriptMu.Unlock()

	body, err := a.getBytes(ctx, "/v1/scripts/"+id, maxScriptBytes)
	if err != nil {
		return fail("could not fetch the script: %v", err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != want {
		a.trust.reject("script", "its content does not match the hash the server signed")
		return fail("refused: the script's content does not match the signed hash")
	}

	dir, err := os.MkdirTemp(filepath.Join(a.o.StateDir), "script-")
	if err != nil {
		return fail("no scratch space: %v", err)
	}
	defer os.RemoveAll(dir)
	cmd, err := scriptCommand(interp, dir, body, args)
	if err != nil {
		return fail("%v", err)
	}

	var out cappedBuffer
	cmd.Stdout, cmd.Stderr, cmd.Dir = &out, &out, dir
	prepareScript(cmd)
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return fail("could not start %s: %v", interp, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var werr error
	timedOut := false
	select {
	case werr = <-done:
	case <-time.After(timeout):
		timedOut = true
		killTree(cmd.Process.Pid)
		werr = <-done
	case <-ctx.Done():
		killTree(cmd.Process.Pid)
		werr = <-done
	}
	took := time.Since(start).Round(time.Millisecond)
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	name := str(c.Params, "name")
	res := proto.CommandResult{OK: werr == nil && !timedOut}
	switch {
	case timedOut:
		res.Output = fmt.Sprintf("killed after the %s time limit\n%s", timeout, out.String())
	case werr != nil:
		res.Output = fmt.Sprintf("exit code %d after %s\n%s", code, took, out.String())
	default:
		res.Output = fmt.Sprintf("exit code 0 after %s\n%s", took, out.String())
	}
	a.QueueEvent(proto.Event{Type: "script.ran", Level: map[bool]string{true: "info", false: "warn"}[res.OK],
		Message: fmt.Sprintf("%s v%d: exit %d in %s", name, num(c.Params, "version"), code, took),
		Data:    map[string]any{"script": name, "ok": res.OK, "exit": code}})
	return res
}

// scriptCommand writes the script into dir and builds the command that runs it. The interpreter
// is chosen from a fixed list, arguments are passed as an argument vector (never through a shell
// string), and cmd.exe, which re-parses its command line, gets only plain arguments.
func scriptCommand(interp, dir string, body []byte, args []string) (*exec.Cmd, error) {
	ext := map[string]string{"powershell": ".ps1", "cmd": ".cmd", "bash": ".sh", "sh": ".sh", "python": ".py"}[interp]
	if ext == "" {
		return nil, fmt.Errorf("unsupported interpreter %q", interp)
	}
	path := filepath.Join(dir, "script"+ext)
	if interp == "powershell" { // Windows PowerShell 5 reads a BOM-less file as the ANSI code page
		body = append([]byte{0xEF, 0xBB, 0xBF}, body...)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return nil, err
	}
	find := func(names ...string) (string, error) {
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				return p, nil
			}
		}
		return "", fmt.Errorf("%s is not installed on this machine", interp)
	}
	switch interp {
	case "powershell":
		exe, err := find("powershell.exe", "pwsh")
		if err != nil {
			return nil, err
		}
		return exec.Command(exe, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, args...)...), nil
	case "cmd":
		if runtime.GOOS != "windows" {
			return nil, errors.New("cmd scripts run on Windows only")
		}
		for _, x := range args {
			if strings.ContainsAny(x, "&|<>^%\"\r\n") {
				return nil, errors.New("cmd scripts take plain arguments only (no & | < > ^ % or quotes)")
			}
		}
		return exec.Command("cmd.exe", append([]string{"/d", "/c", path}, args...)...), nil
	case "bash":
		exe, err := find("bash")
		if err != nil {
			return nil, err
		}
		return exec.Command(exe, append([]string{path}, args...)...), nil
	case "sh":
		exe, err := find("sh", "bash")
		if err != nil {
			return nil, err
		}
		return exec.Command(exe, append([]string{path}, args...)...), nil
	default: // python
		exe, err := find("python3", "python", "py")
		if err != nil {
			return nil, err
		}
		return exec.Command(exe, append([]string{path}, args...)...), nil
	}
}
