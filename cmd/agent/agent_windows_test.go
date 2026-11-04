//go:build windows

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

var agentExe, testappExe string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rc-agent-it")
	if err != nil {
		panic(err)
	}
	agentExe, testappExe = filepath.Join(dir, "agent.exe"), filepath.Join(dir, "testapp.exe")
	for exe, pkg := range map[string]string{agentExe: "remoteconfig/cmd/agent", testappExe: "remoteconfig/cmd/testapp"} {
		if out, err := exec.Command("go", "build", "-o", exe, pkg).CombinedOutput(); err != nil {
			panic("building " + pkg + ": " + err.Error() + "\n" + string(out))
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func alive(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startOfflineAgent runs the real agent.exe with a cached config that supervises the
// test app. The server is unreachable on purpose: supervision must not depend on it.
func startOfflineAgent(t *testing.T, state string, runLog string) *exec.Cmd {
	t.Helper()
	cached := map[string]any{
		"revision": 1, "etag": "e", "reload_mode": "watch", "data": map[string]any{},
		"supervisor": map[string]any{"exe": testappExe, "args": []string{"-log", runLog}, "heartbeat_timeout_s": 30},
	}
	b, _ := json.Marshal(cached)
	os.MkdirAll(state, 0o755)
	os.WriteFile(filepath.Join(state, "effective-config.json"), b, 0o600)

	cmd := exec.Command(agentExe, "run", "-state-dir", state, "-listen", freeAddr(t),
		"-server", "http://127.0.0.1:1", "-enroll-token", "unused", "-log-file", filepath.Join(state, "agent.log"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		// The app deliberately outlives its agent, so a test has to clean it up itself.
		for _, pid := range allAppPIDs(runLog) {
			if p, err := os.FindProcess(pid); err == nil {
				p.Kill()
			}
		}
	})
	return cmd
}

func allAppPIDs(runLog string) (pids []int) {
	b, _ := os.ReadFile(runLog)
	for _, m := range regexp.MustCompile(`pid=(\d+)`).FindAllStringSubmatch(string(b), -1) {
		pid, _ := strconv.Atoi(m[1])
		pids = append(pids, pid)
	}
	return pids
}

func appPID(runLog string) int {
	b, _ := os.ReadFile(runLog)
	ms := regexp.MustCompile(`pid=(\d+)`).FindAllStringSubmatch(string(b), -1)
	if len(ms) == 0 {
		return 0
	}
	pid, _ := strconv.Atoi(ms[len(ms)-1][1])
	return pid
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The app is independent of the agent: when the agent dies (crash, upgrade, Task Scheduler
// stop, taskkill) the display keeps running, and the next agent adopts the same process
// instead of launching a second copy next to it.
func TestAppSurvivesAnAgentKillAndTheNextAgentAdoptsIt(t *testing.T) {
	state, runLog := t.TempDir(), filepath.Join(t.TempDir(), "run.log")
	agent1 := startOfflineAgent(t, state, runLog)

	waitFor(t, "app launched by agent (while server unreachable)", 15*time.Second, func() bool { return appPID(runLog) != 0 })
	pid := appPID(runLog)

	agent1.Process.Kill() // TerminateProcess: no chance to clean up, like a crash
	agent1.Wait()
	time.Sleep(1500 * time.Millisecond)
	if !alive(pid) {
		t.Fatal("the app died with the agent: a crash or upgrade of the agent would blank the display")
	}

	agent2 := startOfflineAgent(t, state, runLog)
	waitFor(t, "second agent to adopt the app", 15*time.Second, func() bool {
		return strings.Contains(readFile(filepath.Join(state, "agent.log")), "app.adopted")
	})
	time.Sleep(2 * time.Second) // give a wrongly-launched duplicate time to show up
	if pids := allAppPIDs(runLog); len(pids) != 1 || pids[0] != pid {
		t.Fatalf("a duplicate app was launched: %v", pids)
	}

	// The second agent now owns it: kill the app and it comes back.
	p, _ := os.FindProcess(pid)
	p.Kill()
	waitFor(t, "relaunch by the adopting agent", 20*time.Second, func() bool { return len(allAppPIDs(runLog)) == 2 })
	if !alive(allAppPIDs(runLog)[1]) {
		t.Fatal("relaunched app is not running")
	}
	_ = agent2
}

func readFile(p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestSecondAgentForSameStateExitsCleanly(t *testing.T) {
	state, runLog := t.TempDir(), filepath.Join(t.TempDir(), "run.log")
	startOfflineAgent(t, state, runLog)
	waitFor(t, "first agent to run the app", 15*time.Second, func() bool { return appPID(runLog) != 0 })

	second := exec.Command(agentExe, "run", "-state-dir", state, "-listen", freeAddr(t), "-server", "http://127.0.0.1:1", "-enroll-token", "x")
	done := make(chan error, 1)
	go func() { done <- second.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second agent must exit 0 (non-zero would make Task Scheduler retry forever): %v", err)
		}
	case <-time.After(10 * time.Second):
		second.Process.Kill()
		t.Fatal("second agent kept running")
	}
}
