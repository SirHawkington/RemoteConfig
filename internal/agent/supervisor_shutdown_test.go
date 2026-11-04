package agent

import (
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

// Stopping the agent while a frozen app is configured to go with it must not hang for the
// app's whole (long) quit timeout: the app cannot answer, so it is killed promptly.
func TestShutdownDoesNotWaitOutALongGracePeriodForAFrozenApp(t *testing.T) {
	a, stop := newSupervised(t, proto.SupervisorConfig{
		Exe: testappExe, Args: []string{"-hang-after", "200ms"}, QuitTimeoutS: 120, HeartbeatTimeoutS: 3600,
	}, func(a *Agent) { a.sup.maxShutdownGrace = 2 * time.Second }) // production default: 20 s
	waitUntil(t, "app frozen", func() bool { return a.sup.Snapshot().Running })
	pid := a.sup.Snapshot().PID
	t.Cleanup(func() { killPIDQuietly(pid) })
	time.Sleep(1 * time.Second) // frozen by now, but not yet "silent for 15 s"

	t0 := time.Now()
	stop()
	d := time.Since(t0)
	if _, err := identityOf(pid); err == nil {
		t.Fatal("the frozen app survived the agent's shutdown")
	}
	if d < 1500*time.Millisecond || d > 6*time.Second {
		t.Fatalf("shutdown took %s: want about the 2 s cap, not the 120 s quit timeout", d)
	}
}
