package agent

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

func hasEvent(a *Agent, typ string) bool { return count(eventTypes(a), typ) > 0 }

// An app that uses the SDK is told to quit through the lifecycle endpoint, saves its state
// and exits by itself: no kill, no crash recorded, and it comes back straight away.
func TestRestartAsksTheAppToQuitAndDoesNotKillIt(t *testing.T) {
	runLog := filepath.Join(t.TempDir(), "run.log")
	a, stop := newSupervised(t, proto.SupervisorConfig{Exe: testappExe, Args: []string{"-log", runLog}, QuitTimeoutS: 8})
	defer stop()
	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	pid1 := a.sup.Snapshot().PID
	time.Sleep(300 * time.Millisecond) // let it start polling

	t0 := time.Now()
	a.sup.RequestRestart("test")
	waitUntil(t, "relaunch", func() bool { s := a.sup.Snapshot(); return s.Running && s.PID != pid1 })

	if d := time.Since(t0); d > 4*time.Second {
		t.Fatalf("a cooperative app took %s to restart: the quit request was not delivered", d)
	}
	if !strings.Contains(readFile(runLog), "quit requested") {
		t.Fatalf("the app never saw the quit request:\n%s", readFile(runLog))
	}
	if hasEvent(a, "app.force_killed") || hasEvent(a, "app.crash") {
		t.Fatalf("an app that exited when asked must not be killed or counted as a crash: %v", eventTypes(a))
	}
}

// An app without the SDK is still closed politely: WM_CLOSE reaches its window.
func TestWindowCloseQuitsAnAppWithoutTheSDK(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("window messages are Windows only")
	}
	runLog := filepath.Join(t.TempDir(), "run.log")
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-log", runLog, "-window", "-lifecycle=false"}, QuitTimeoutS: 8,
	})
	defer stop()
	waitUntil(t, "window created", func() bool { return strings.Contains(readFile(runLog), "window: created") })
	pid1 := a.sup.Snapshot().PID

	t0 := time.Now()
	a.sup.RequestRestart("test")
	waitUntil(t, "relaunch", func() bool { s := a.sup.Snapshot(); return s.Running && s.PID != pid1 })

	if d := time.Since(t0); d > 4*time.Second {
		t.Fatalf("closing the window took %s", d)
	}
	if !strings.Contains(readFile(runLog), "window: WM_CLOSE received") {
		t.Fatalf("the window never got WM_CLOSE:\n%s", readFile(runLog))
	}
	if hasEvent(a, "app.force_killed") {
		t.Fatalf("the app was killed instead of closing: %v", eventTypes(a))
	}
}

// A misbehaving app that ignores the request is killed, but only after the grace period.
func TestAnAppThatIgnoresTheQuitRequestIsKilledAfterTheGracePeriod(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{Exe: testappExe, Args: []string{"-ignore-quit"}, QuitTimeoutS: 2})
	defer stop()
	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	pid1 := a.sup.Snapshot().PID
	time.Sleep(300 * time.Millisecond)

	t0 := time.Now()
	a.sup.RequestRestart("test")
	waitUntil(t, "force kill", func() bool { return hasEvent(a, "app.force_killed") })
	if d := time.Since(t0); d < 1800*time.Millisecond {
		t.Fatalf("killed after only %s: the grace period was not respected", d)
	}
	waitUntil(t, "relaunch", func() bool { s := a.sup.Snapshot(); return s.Running && s.PID != pid1 })
	if hasEvent(a, "app.crash") {
		t.Fatal("a deliberate restart must not count as a crash even when it had to be forced")
	}
}

// A frozen app cannot answer, so waiting the whole grace period would only delay recovery.
func TestAHungAppOnlyGetsAShortGracePeriod(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-hang-after", "300ms"}, HeartbeatTimeoutS: 1, QuitTimeoutS: 60,
	})
	defer stop()
	t0 := time.Now()
	waitUntil(t, "hang detected, killed and relaunched", func() bool {
		return hasEvent(a, "app.force_killed") && a.sup.Snapshot().Restarts >= 1
	})
	if d := time.Since(t0); d > 9*time.Second {
		t.Fatalf("recovery took %s: a 60 s grace period must be capped for a hung app", d)
	}
}

// The headline: stopping the agent leaves the app alone, and the next agent takes it over
// instead of launching a second copy.
func TestAgentExitLeavesTheAppRunningAndTheNextAgentAdoptsIt(t *testing.T) {
	state, runLog, addr := t.TempDir(), filepath.Join(t.TempDir(), "run.log"), freeAddr(t)
	sc := proto.SupervisorConfig{Exe: testappExe, Args: []string{"-log", runLog}, QuitTimeoutS: 5} // StopAppOnAgentExit left false

	a, stopA := startAgent(t, sc, state, addr)
	waitUntil(t, "app launched by the first agent", func() bool { return a.sup.Snapshot().Running })
	pid := a.sup.Snapshot().PID
	t.Cleanup(func() { killPIDQuietly(pid) })

	stopA() // the agent is upgraded / restarted
	if _, err := identityOf(pid); err != nil {
		t.Fatalf("stopping the agent took the app down: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	b, stopB := startAgent(t, sc, state, addr)
	defer stopB()
	t.Cleanup(func() { killPIDQuietly(b.sup.Snapshot().PID) }) // registered early so a failure cannot leak the app
	waitUntil(t, "second agent to take over", func() bool { return b.sup.Snapshot().Running })
	if got := b.sup.Snapshot().PID; got != pid {
		t.Fatalf("second agent runs pid %d, want the existing %d", got, pid)
	}
	if n := strings.Count(readFile(runLog), "start pid="); n != 1 {
		t.Fatalf("the app was launched %d times; adoption must not start a duplicate", n)
	}
	if !hasEvent(b, "app.adopted") || hasEvent(b, "app.started") {
		t.Fatalf("expected an adoption, got %v", eventTypes(b))
	}
	if r := b.sup.Snapshot().Restarts; r != 0 {
		t.Fatalf("adoption counted as %d restart(s)", r)
	}

	// and it really is supervising it: if the app dies, it is relaunched
	killProcess(pid)
	waitUntil(t, "relaunch after the adopted app died", func() bool { s := b.sup.Snapshot(); return s.Running && s.PID != pid })
	if !hasEvent(b, "app.crash") {
		t.Fatalf("the death of the adopted app went unnoticed: %v", eventTypes(b))
	}
	waitUntil(t, "the relaunched app to log its start", func() bool { return strings.Count(readFile(runLog), "start pid=") >= 2 })
	time.Sleep(300 * time.Millisecond)
	if n := strings.Count(readFile(runLog), "start pid="); n != 2 {
		t.Fatalf("expected exactly one relaunch, app log shows %d starts", n)
	}
}

// A recorded PID that now belongs to something else must never be adopted or touched.
func TestAStaleRecordIsNotAdopted(t *testing.T) {
	state := t.TempDir()
	self := os.Getpid() // certainly alive, certainly not our app
	id, err := identityOf(self)
	if err != nil {
		t.Skipf("process identity unavailable here: %v", err)
	}
	for name, mutate := range map[string]func(*supervisedRecord){
		"same pid, different start time": func(r *supervisedRecord) { r.Created++ },
		"same pid, different program":    func(r *supervisedRecord) { r.Image = filepath.Join(state, "other.exe") },
	} {
		t.Run(name, func(t *testing.T) {
			rec := supervisedRecord{procIdentity: id, Exe: testappExe, StartedAt: time.Now()}
			mutate(&rec)
			b, _ := json.Marshal(rec)
			os.WriteFile(filepath.Join(state, "supervised.json"), b, 0o600)

			a, stop := startAgent(t, proto.SupervisorConfig{Exe: testappExe, StopAppOnAgentExit: true}, state, freeAddr(t))
			defer stop()
			waitUntil(t, "app launched", func() bool { return a.sup.Snapshot().Running })
			if a.sup.Snapshot().PID == self || hasEvent(a, "app.adopted") {
				t.Fatalf("adopted an unrelated process: %v", eventTypes(a))
			}
			if !hasEvent(a, "app.started") {
				t.Fatalf("expected a fresh launch: %v", eventTypes(a))
			}
			if _, err := identityOf(self); err != nil {
				t.Fatal("the test process itself was disturbed")
			}
		})
	}
}

// If the configured program changed while the agent was away, the old app is taken over
// and then replaced politely.
func TestAdoptedAppRunningTheWrongProgramIsReplaced(t *testing.T) {
	state, addr := t.TempDir(), freeAddr(t)
	a, stopA := startAgent(t, proto.SupervisorConfig{Exe: testappExe, Args: []string{"-lifecycle=true"}}, state, addr)
	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	oldPID := a.sup.Snapshot().PID
	t.Cleanup(func() { killPIDQuietly(oldPID) })
	stopA()

	other := filepath.Join(t.TempDir(), "testapp2.exe") // same program, different path
	data, _ := os.ReadFile(testappExe)
	os.WriteFile(other, data, 0o755)

	time.Sleep(200 * time.Millisecond)
	b, stopB := startAgent(t, proto.SupervisorConfig{Exe: other, StopAppOnAgentExit: true, QuitTimeoutS: 5}, state, addr)
	defer stopB()
	waitUntil(t, "old app replaced by the configured program", func() bool {
		s := b.sup.Snapshot()
		return s.Running && s.PID != oldPID
	})
	if _, err := identityOf(oldPID); err == nil {
		t.Fatal("the old app is still running")
	}
	id, _ := identityOf(b.sup.Snapshot().PID)
	if !sameImage(id.Image, other) {
		t.Fatalf("now running %s, want %s", id.Image, other)
	}
	t.Cleanup(func() { killPIDQuietly(b.sup.Snapshot().PID) })
}

func TestStopAppOnAgentExitQuitsTheAppGracefully(t *testing.T) {
	runLog := filepath.Join(t.TempDir(), "run.log")
	a, stop := startAgent(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-log", runLog}, StopAppOnAgentExit: true, QuitTimeoutS: 5,
	}, t.TempDir(), freeAddr(t))
	waitUntil(t, "app running", func() bool { return a.sup.Snapshot().Running })
	pid := a.sup.Snapshot().PID
	t.Cleanup(func() { killPIDQuietly(pid) })
	time.Sleep(300 * time.Millisecond)

	t0 := time.Now()
	stop()
	if _, err := identityOf(pid); err == nil {
		t.Fatal("the app is still running after the agent stopped")
	}
	if d := time.Since(t0); d > 4*time.Second {
		t.Fatalf("shutdown took %s", d)
	}
	if !strings.Contains(readFile(runLog), "quit requested: the agent is stopping") {
		t.Fatalf("the app was not asked to quit:\n%s", readFile(runLog))
	}
}

func TestLifecycleEndpointLongPollsAndReportsQuit(t *testing.T) {
	addr := freeAddr(t)
	a, stop := startAgent(t, proto.SupervisorConfig{}, t.TempDir(), addr) // no app: only the endpoint
	defer stop()
	get := func(wait string) (int, map[string]any, time.Duration) {
		t0 := time.Now()
		req, _ := http.NewRequest("GET", "http://"+addr+"/v1/lifecycle?wait="+wait, nil)
		req.Header.Set("Authorization", "Bearer tok")
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ { // the listener starts asynchronously
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body, time.Since(t0)
	}

	if code, _, d := get("1"); code != 204 || d < 900*time.Millisecond {
		t.Fatalf("idle long-poll: code=%d after %s, want 204 after ~1s", code, d)
	}

	var woke atomic.Int32
	go func() {
		time.Sleep(300 * time.Millisecond)
		a.sup.mu.Lock()
		a.sup.signalQuitLocked("because", 7*time.Second)
		a.sup.mu.Unlock()
		woke.Store(1)
	}()
	code, body, d := get("20")
	if code != 200 || body["action"] != "quit" || body["reason"] != "because" || body["grace_s"] != 7.0 {
		t.Fatalf("quit not delivered: %d %v", code, body)
	}
	if d > 3*time.Second {
		t.Fatalf("a waiting long-poll took %s to learn of the quit", d)
	}
	// still pending for an app that polls late
	if code, _, _ := get("0"); code != 200 {
		t.Fatalf("a late poll must still see the pending quit, got %d", code)
	}
}
