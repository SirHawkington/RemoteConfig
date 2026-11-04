package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"remoteconfig/internal/proto"
)

// Supervisor launches the managed app, restarts it when it exits or hangs (heartbeat
// stops), stops thrashing on crash loops, and performs scheduled / requested /
// config-triggered restarts. See DESIGN.md 6.7 and 6.10.
//
// Stopping the app is always polite first: the app is asked to quit (a lifecycle message
// the SDK long-polls for, plus WM_CLOSE to its windows) and only killed if it has not
// exited when the grace period runs out.
//
// The app is independent of the agent's lifetime. The agent records which process it
// started; a later agent finds that process again and adopts it instead of launching a
// duplicate, so upgrading or restarting the agent does not interrupt the display.
//
// Lock order: Supervisor.mu may be held while taking Agent.mu, never the reverse.
type Supervisor struct {
	a *Agent

	tick        time.Duration // how often the control loop runs
	backoffBase time.Duration // delay before the first crash restart; doubles per recent crash
	kick        chan struct{}
	done        chan struct{} // closed when run returns (after any shutdown handling)

	mu            sync.Mutex
	state         string // stopped | running | backoff | crashloop | monitor | disabled
	pid           int    // 0 = no process
	startedAt     time.Time
	exitCh        chan exitInfo
	crashes       []time.Time // recent crash/hang times, for crash-loop detection
	starts        int         // processes started or adopted in this agent's lifetime
	attempts      int         // launches tried, including ones that failed to start
	reportedBase  int         // restarts already reported to the server
	nextStart     time.Time
	pending       string // restart requested; reason
	lastScheduled string // YYYY-MM-DD of the last scheduled restart
	lastExit      *exitInfo
	adoptTried    bool

	// stopping: we asked the app to quit; it is killed at quitDeadline if still there.
	stopping     bool
	stopKind     string // hang | request | schedule | config | shutdown
	forced       bool
	quitDeadline time.Time
	quitTimeout  time.Duration // from config, refreshed every tick

	// maxShutdownGrace caps how long stopping the agent waits for the app, however long
	// quit_timeout_s is: the agent itself only waits so long before it exits.
	maxShutdownGrace time.Duration

	// what the SDK's lifecycle long-poll reports
	quitPending bool
	quitReason  string
	quitGrace   time.Duration
	quitSig     chan struct{} // closed + replaced when a quit is signalled
}

type exitInfo struct {
	code   int
	err    error
	uptime time.Duration
}

var errNoWindow = errors.New("the process has no visible window to close")

func newSupervisor(a *Agent) *Supervisor {
	return &Supervisor{
		a: a, tick: time.Second, backoffBase: 2 * time.Second, kick: make(chan struct{}, 1),
		done: make(chan struct{}), state: "disabled", quitTimeout: 10 * time.Second, quitSig: make(chan struct{}),
		maxShutdownGrace: 20 * time.Second,
	}
}

// SupervisorSnapshot is a point-in-time view for status reporting.
type SupervisorSnapshot struct {
	State     string
	Running   bool
	Managing  bool // true when we own the process (supervise mode with an exe)
	PID       int
	Restarts  int
	UptimeS   int64
	LastExit  string
	CrashLoop bool
	Attempts  int // launches tried so far, successful or not
}

func (s *Supervisor) Snapshot() SupervisorSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := SupervisorSnapshot{
		State: s.state, Running: s.pid != 0, PID: s.pid, CrashLoop: s.state == "crashloop", Attempts: s.attempts,
		Managing: s.state != "disabled" && s.state != "monitor",
	}
	if s.starts > 0 {
		snap.Restarts = s.starts - 1
	}
	if s.pid != 0 {
		snap.UptimeS = int64(time.Since(s.startedAt).Seconds())
	}
	if s.lastExit != nil {
		snap.LastExit = fmt.Sprintf("code %d after %s", s.lastExit.code, s.lastExit.uptime.Round(time.Second))
	}
	return snap
}

// restartsUnreported returns restarts since the last successful report to the server.
func (s *Supervisor) restartsUnreported() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.starts > 0 {
		n = s.starts - 1 - s.reportedBase
	}
	return n
}

func (s *Supervisor) markReported(n int) {
	s.mu.Lock()
	s.reportedBase += n
	s.mu.Unlock()
}

// RequestRestart asks for a graceful restart (also clears a crash loop).
func (s *Supervisor) RequestRestart(reason string) {
	s.mu.Lock()
	s.pending = reason
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Supervisor) Managing() bool { return s.Snapshot().Managing }

// lifecycle reports whether the app has been asked to quit, for the SDK's long-poll.
// The returned channel is closed the next time a quit is signalled.
func (s *Supervisor) lifecycle() (pending bool, reason string, grace time.Duration, sig <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quitPending, s.quitReason, s.quitGrace, s.quitSig
}

func (s *Supervisor) run(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.shutdown()
			return
		case <-t.C:
		case <-s.kick:
		}
		s.step(time.Now())
	}
}

// shutdown runs when the agent stops. By default the app is left running (and adopted by
// the next agent). With stop_app_on_agent_exit it is asked to quit and killed on timeout.
func (s *Supervisor) shutdown() {
	stop := false
	if ec := s.a.currentConfig(); ec != nil && ec.Supervisor != nil {
		stop = ec.Supervisor.StopAppOnAgentExit && ec.Supervisor.Exe != "" && ec.Supervisor.Mode != "monitor"
	}

	s.mu.Lock()
	if s.pid == 0 {
		s.mu.Unlock()
		return
	}
	if !stop {
		s.a.logf("supervisor: agent stopping; leaving the app (pid %d) running for the next agent to adopt", s.pid)
		s.mu.Unlock()
		return
	}
	pid, ch := s.pid, s.exitCh
	var grace time.Duration
	if s.stopping {
		// A stop is already under way (say, a hung app being killed): let it finish on its
		// own deadline rather than asking again with a fresh, longer grace period.
		grace = max(time.Until(s.quitDeadline), 0) + 500*time.Millisecond
	} else {
		// Never longer than the agent is willing to wait for us, and short for an app that
		// has stopped heartbeating: a frozen app cannot answer.
		grace = min(s.quitTimeout, s.maxShutdownGrace)
		if time.Since(s.lastSign()) > 15*time.Second {
			grace = min(grace, 3*time.Second)
		}
		s.stopping, s.stopKind = true, "shutdown"
		s.signalQuitLocked("the agent is stopping", grace)
	}
	s.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(grace):
		s.a.logf("supervisor: app did not exit within %s; killing it", grace)
		killProcess(pid)
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

func withDefaults(c proto.SupervisorConfig) proto.SupervisorConfig {
	if c.HeartbeatTimeoutS <= 0 {
		c.HeartbeatTimeoutS = 60
	}
	if c.MaxRestarts <= 0 {
		c.MaxRestarts = 3
	}
	if c.RestartWindowS <= 0 {
		c.RestartWindowS = 600
	}
	if c.QuitTimeoutS <= 0 {
		c.QuitTimeoutS = 10
	}
	return c
}

func (s *Supervisor) step(now time.Time) {
	var cfg *proto.SupervisorConfig
	if ec := s.a.currentConfig(); ec != nil {
		cfg = ec.Supervisor
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reap an exited process first.
	if s.exitCh != nil {
		select {
		case ex := <-s.exitCh:
			s.onExit(ex, now)
		default:
		}
	}

	if cfg == nil || cfg.Exe == "" {
		s.stopLocked("config", "supervision disabled")
		if s.pid == 0 {
			s.state = "disabled"
		}
		return
	}
	c := s.a.expandRelease(withDefaults(*cfg))
	s.quitTimeout = time.Duration(c.QuitTimeoutS) * time.Second
	if c.Mode == "monitor" {
		s.stopLocked("config", "switched to monitor mode")
		if s.pid == 0 {
			s.state = "monitor"
		}
		return
	}

	if !s.adoptTried { // first look: is the app from a previous agent still running?
		s.adoptTried = true
		if s.tryAdoptLocked(c, now) {
			return
		}
	}

	if s.pid != 0 { // ---- running
		switch {
		case s.stopping:
			if !s.forced && now.After(s.quitDeadline) {
				s.forced = true
				s.eventLocked("app.force_killed", "warn", fmt.Sprintf("the app did not exit within %s of being asked to; killing it", s.graceFor()), map[string]any{"pid": s.pid})
				killProcess(s.pid)
			}
		case s.pending != "":
			s.killLocked("request", "restart requested: "+s.pending)
		case now.Sub(s.lastSign()) > time.Duration(c.HeartbeatTimeoutS)*time.Second:
			s.killLocked("hang", fmt.Sprintf("no heartbeat for %ds", c.HeartbeatTimeoutS))
		case scheduledDue(now, c.ScheduledRestart, &s.lastScheduled) && now.Sub(s.startedAt) > time.Minute:
			s.killLocked("schedule", "scheduled restart "+c.ScheduledRestart)
		}
		return
	}

	// ---- not running
	if s.pending != "" {
		s.crashes, s.nextStart = nil, now // an explicit request overrides crash-loop/backoff
		s.pending = ""
	}
	if now.Before(s.nextStart) {
		return
	}
	window := time.Duration(c.RestartWindowS) * time.Second
	s.crashes = pruneBefore(s.crashes, now.Add(-window))
	if len(s.crashes) >= c.MaxRestarts {
		if s.state != "crashloop" {
			s.state = "crashloop"
			s.eventLocked("app.crashloop", "error", fmt.Sprintf("%d crashes within %s; giving up until a restart is requested", len(s.crashes), window), nil)
		}
		return
	}
	s.startLocked(c, now)
}

// lastSign is the most recent evidence the app is alive: a heartbeat or the launch.
func (s *Supervisor) lastSign() time.Time {
	s.a.mu.Lock()
	at := s.a.appAt
	s.a.mu.Unlock()
	if at.After(s.startedAt) {
		return at
	}
	return s.startedAt
}

// ---------------------------------------------------------------- launching and adopting

// supervisedRecord is what the agent remembers about the app it started, so the next
// agent can recognise that very process (not merely one with the same PID).
type supervisedRecord struct {
	procIdentity
	Exe       string    `json:"exe"`
	StartedAt time.Time `json:"started_at"`
}

func (s *Supervisor) recordPath() string { return filepath.Join(s.a.o.StateDir, "supervised.json") }

func (s *Supervisor) saveRecord(r supervisedRecord) {
	b, _ := json.Marshal(r)
	if err := writeFileAtomic(s.recordPath(), b); err != nil {
		s.a.logf("supervisor: cannot remember the app's pid (a restarted agent would not adopt it): %v", err)
	}
}

func (s *Supervisor) clearRecord() { os.Remove(s.recordPath()) }

func sameImage(a, b string) bool {
	a, b = filepath.Clean(filepath.FromSlash(a)), filepath.Clean(filepath.FromSlash(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// tryAdoptLocked takes over an app started by a previous agent, if it is still running.
func (s *Supervisor) tryAdoptLocked(c proto.SupervisorConfig, now time.Time) bool {
	b, err := os.ReadFile(s.recordPath())
	if err != nil {
		return false
	}
	var rec supervisedRecord
	if json.Unmarshal(b, &rec) != nil || rec.PID == 0 {
		s.clearRecord()
		return false
	}
	cur, err := identityOf(rec.PID)
	if err != nil || cur.Created != rec.Created || !sameImage(cur.Image, rec.Image) {
		s.clearRecord() // gone, or the PID now belongs to something else: never touch it
		return false
	}

	ch := make(chan exitInfo, 1)
	go func(pid int) {
		code := waitProcess(pid)
		ch <- exitInfo{code: code, uptime: time.Since(now)}
	}(rec.PID)
	s.pid, s.startedAt, s.exitCh, s.state = rec.PID, now, ch, "running" // heartbeat grace starts now
	s.stopping, s.stopKind, s.forced, s.quitPending = false, "", false, false
	s.starts++
	s.eventLocked("app.adopted", "info", fmt.Sprintf("pid %d was already running (started %s); not launching another", rec.PID, rec.StartedAt.Format(time.RFC3339)),
		map[string]any{"pid": rec.PID})
	if !sameImage(rec.Image, c.Exe) { // the configuration points somewhere else now
		s.pending = "the configured executable changed while the agent was away"
	}
	return true
}

func (s *Supervisor) startLocked(c proto.SupervisorConfig, now time.Time) {
	s.attempts++
	cmd := exec.Command(c.Exe, c.Args...)
	cmd.Dir = c.Workdir
	cmd.Env = append(os.Environ(),
		"REMOTECONFIG_URL=http://"+s.a.o.Listen+"/v1",
		"REMOTECONFIG_TOKEN="+s.a.localToken,
		"REMOTECONFIG_CONFIG_FILE="+s.a.cfgPath(),
	)
	for k, v := range c.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		s.crashes = append(s.crashes, now)
		s.nextStart = now.Add(s.backoffLocked())
		s.state = "backoff"
		s.eventLocked("app.start_failed", "error", err.Error(), map[string]any{"exe": c.Exe})
		return
	}
	pid := cmd.Process.Pid
	ch := make(chan exitInfo, 1)
	started := now
	go func() {
		err := cmd.Wait()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
			if code > 1<<31-1 { // Windows reports a killed process as 0xFFFFFFFF; show it as -1
				code -= 1 << 32
			}
		}
		ch <- exitInfo{code: code, err: err, uptime: time.Since(started)}
	}()
	s.pid, s.startedAt, s.exitCh, s.state = pid, now, ch, "running"
	s.stopping, s.stopKind, s.forced, s.quitPending = false, "", false, false
	s.starts++
	if id, err := identityOf(pid); err == nil {
		s.saveRecord(supervisedRecord{procIdentity: id, Exe: c.Exe, StartedAt: now})
	} else {
		s.a.logf("supervisor: cannot identify the app process, so a restarted agent will not adopt it: %v", err)
	}
	s.eventLocked("app.started", "info", fmt.Sprintf("pid %d", pid), map[string]any{"start": s.starts})
}

func (s *Supervisor) onExit(ex exitInfo, now time.Time) {
	s.pid, s.exitCh = 0, nil
	s.lastExit = &ex
	kind, wasStopping := s.stopKind, s.stopping
	s.stopping, s.stopKind, s.forced, s.quitPending = false, "", false, false
	s.clearRecord()

	switch {
	case wasStopping && kind == "shutdown":
		s.state = "stopped"
	case wasStopping && kind != "hang":
		// deliberate restart (request / schedule / config): relaunch right away
		s.state, s.nextStart = "stopped", now
	default:
		// crash, or a hang we had to kill: both count toward crash-loop detection
		s.crashes = append(s.crashes, now)
		s.nextStart = now.Add(s.backoffLocked())
		s.state = "backoff"
		if !wasStopping {
			s.eventLocked("app.crash", "error", fmt.Sprintf("exited with code %d after %s", ex.code, ex.uptime.Round(time.Second)),
				map[string]any{"exit_code": ex.code, "uptime_s": int(ex.uptime.Seconds())})
		}
	}
}

// backoffLocked: base, 2x, 4x ... capped at 30s, by number of recent crashes.
func (s *Supervisor) backoffLocked() time.Duration {
	d := s.backoffBase
	for i := 1; i < len(s.crashes) && d < 30*time.Second; i++ {
		d *= 2
	}
	return min(d, 30*time.Second)
}

// ---------------------------------------------------------------- stopping

// graceFor is how long the app being stopped is given to exit on its own.
func (s *Supervisor) graceFor() time.Duration {
	if s.stopKind == "hang" {
		// A frozen app cannot answer; do not make a restart wait the full period for nothing.
		return min(s.quitTimeout, 3*time.Second)
	}
	return s.quitTimeout
}

// killLocked begins stopping the app: ask it to quit now, kill it if it is still there
// when the grace period ends (checked every tick in step).
func (s *Supervisor) killLocked(kind, reason string) {
	if s.pid == 0 || s.stopping {
		return
	}
	s.stopping, s.stopKind, s.forced = true, kind, false
	s.pending = ""
	lvl, evt := "info", "app.restart"
	if kind == "hang" {
		lvl, evt = "error", "app.hung"
	}
	grace := s.graceFor()
	s.eventLocked(evt, lvl, reason, map[string]any{"pid": s.pid, "grace_s": int(grace.Seconds())})
	s.signalQuitLocked(reason, grace)
	if grace <= 0 {
		s.forced = true
		killProcess(s.pid)
	}
}

// signalQuitLocked asks the app to exit in the two ways an app can notice: the lifecycle
// message (the SDK long-polls for it) and a window-close request, which also works for
// apps that do not use the SDK. Neither waits.
func (s *Supervisor) signalQuitLocked(reason string, grace time.Duration) {
	s.quitDeadline = time.Now().Add(grace)
	s.quitPending, s.quitReason, s.quitGrace = true, reason, grace
	close(s.quitSig)
	s.quitSig = make(chan struct{})
	if err := quitProcess(s.pid); err != nil && !errors.Is(err, errNoWindow) {
		s.a.logf("supervisor: window-close request failed: %v", err)
	}
}

// stopLocked stops the process if running (config removed/disabled supervision).
func (s *Supervisor) stopLocked(kind, reason string) {
	if s.pid != 0 && !s.stopping {
		s.killLocked(kind, reason)
	}
}

func (s *Supervisor) eventLocked(typ, level, msg string, data map[string]any) {
	s.a.logf("supervisor: %s: %s", typ, msg)
	s.a.QueueEvent(proto.Event{Type: typ, Level: level, Message: msg, Data: data})
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// scheduledDue reports whether the daily restart at "HH:MM" (local time) is due, and
// records the day in *last so it fires once. If we first see the schedule after
// today's time has passed, today is marked done (no surprise restart on agent start).
func scheduledDue(now time.Time, hhmm string, last *string) bool {
	if hhmm == "" {
		return false
	}
	parts := strings.Split(hhmm, ":")
	if len(parts) != 2 {
		return false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return false
	}
	target := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	day := now.Format("2006-01-02")
	if *last == "" {
		if !now.Before(target) {
			*last = day
		}
		return false
	}
	if !now.Before(target) && *last != day {
		*last = day
		return true
	}
	return false
}

// ---------------------------------------------------------------- config reloads

// onConfigApplied honours the profile's reload mode after a new config was written.
func (s *Supervisor) onConfigApplied(cfg proto.EffectiveConfig) {
	if !s.Managing() || !s.Snapshot().Running {
		return
	}
	switch cfg.ReloadMode {
	case "restart":
		s.RequestRestart(fmt.Sprintf("config revision %d (reload_mode=restart)", cfg.Revision))
	case "trigger":
		go s.trigger(cfg)
	}
}

// trigger tells the app to reload, then waits for its ack; falls back to a restart.
func (s *Supervisor) trigger(cfg proto.EffectiveConfig) {
	url := ""
	if cfg.Supervisor != nil {
		url = cfg.Supervisor.ReloadURL
	}
	if url == "" {
		s.RequestRestart(fmt.Sprintf("config revision %d: trigger mode but no reload_url", cfg.Revision))
		return
	}
	body, _ := json.Marshal(map[string]int{"revision": cfg.Revision})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		s.RequestRestart(fmt.Sprintf("config revision %d: reload trigger failed: %v", cfg.Revision, err))
		return
	}
	resp.Body.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.a.appAckedRevision() >= cfg.Revision {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.RequestRestart(fmt.Sprintf("config revision %d: app did not acknowledge reload", cfg.Revision))
}
