//go:build !noselfupdate

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

type pendingUpdate struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	ReleaseID string    `json:"release_id"`
	Exe       string    `json:"exe"`
	Boots     int       `json:"boots"` // starts of the new binary that did not reach a check-in
	At        time.Time `json:"at"`
}

func pendingPath(stateDir string) string { return filepath.Join(stateDir, "pending-update.json") }
func failedPath(stateDir string) string  { return filepath.Join(stateDir, "update-failed.json") }

func (a *Agent) installAgent(c proto.Command, file, id, version string) proto.CommandResult {
	fail := func(format string, args ...any) proto.CommandResult {
		return proto.CommandResult{OK: false, Output: fmt.Sprintf(format, args...)}
	}
	exe := a.o.ExePath
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return fail("cannot locate the running agent: %v", err)
		}
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	newPath, oldPath := exe+".new", exe+".old"
	if err := copyFile(file, newPath, 0o755); err != nil {
		return fail("cannot stage the new agent next to %s: %v", exe, err)
	}
	// Smoke test: the new binary must start and say it is the version it was released as.
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(sctx, newPath, "version").Output()
	if err != nil || !strings.Contains(string(out), version) {
		os.Remove(newPath)
		return fail("the new agent did not pass its smoke test (running it with \"version\" should print %q, got %q, error %v); nothing was changed", version, strings.TrimSpace(string(out)), err)
	}

	os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return fail("cannot move the running agent aside: %v", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		os.Rename(oldPath, exe)
		return fail("cannot put the new agent in place: %v", err)
	}
	b, _ := json.Marshal(pendingUpdate{From: a.o.Version, To: version, ReleaseID: id, Exe: exe, At: time.Now().UTC()})
	if err := writeFileAtomic(pendingPath(a.o.StateDir), b); err != nil {
		os.Rename(exe, newPath)
		os.Rename(oldPath, exe)
		return fail("cannot record the update: %v", err)
	}
	a.restartForUpdate.Store(true)
	return proto.CommandResult{OK: true, Output: fmt.Sprintf("agent %s installed (was %s); restarting into it. The app keeps running. If this agent is not started by the scheduled task, start it again.", version, a.o.Version)}
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// exitIfUpdating ends the process after the result of an agent update has been reported.
func (a *Agent) exitIfUpdating() {
	if !a.restartForUpdate.Load() {
		return
	}
	a.logf("restarting to run the updated agent")
	a.usage.save()
	exit := a.o.Exit
	if exit == nil {
		exit = os.Exit
	}
	exit(exitForUpdate) // non-zero: the scheduled task starts the new binary
}

// CheckPendingUpdate runs first thing at startup, before the agent does anything else. A freshly
// installed agent binary has to reach a check-in within a few starts; if it keeps restarting
// without getting there, the previous binary is put back. It returns true when it did that, and
// the caller should exit so the restored binary is started.
func CheckPendingUpdate(stateDir string, logf func(string, ...any)) bool {
	b, err := os.ReadFile(pendingPath(stateDir))
	if err != nil {
		return false
	}
	var p pendingUpdate
	if json.Unmarshal(b, &p) != nil || p.Exe == "" {
		os.Remove(pendingPath(stateDir))
		return false
	}
	p.Boots++
	if p.Boots <= maxTrialBoots {
		nb, _ := json.Marshal(p)
		writeFileAtomic(pendingPath(stateDir), nb)
		return false
	}
	logf("the updated agent (%s) started %d times without checking in; going back to %s", p.To, p.Boots-1, p.From)
	bad := p.Exe + ".bad"
	os.Remove(bad)
	if err := os.Rename(p.Exe, bad); err != nil {
		logf("cannot move the failed agent aside: %v", err)
		return false
	}
	if err := os.Rename(p.Exe+".old", p.Exe); err != nil {
		os.Rename(bad, p.Exe)
		logf("cannot restore the previous agent: %v", err)
		return false
	}
	os.Remove(pendingPath(stateDir))
	fb, _ := json.Marshal(p)
	writeFileAtomic(failedPath(stateDir), fb)
	return true
}

// confirmUpdate: this binary has just checked in, so the update it was installed by worked.
func (a *Agent) confirmUpdate() {
	b, err := os.ReadFile(pendingPath(a.o.StateDir))
	if err == nil {
		var p pendingUpdate
		if json.Unmarshal(b, &p) == nil && p.To == a.o.Version {
			os.Remove(pendingPath(a.o.StateDir))
			a.QueueEvent(proto.Event{Type: "agent.updated", Level: "info", Message: fmt.Sprintf("agent updated from %s to %s", p.From, p.To)})
		}
	}
	if b, err := os.ReadFile(failedPath(a.o.StateDir)); err == nil {
		var p pendingUpdate
		if json.Unmarshal(b, &p) == nil {
			a.QueueEvent(proto.Event{Type: "agent.update_failed", Level: "error",
				Message: fmt.Sprintf("agent %s would not start properly; went back to %s", p.To, p.From)})
		}
		os.Remove(failedPath(a.o.StateDir))
	}
}
