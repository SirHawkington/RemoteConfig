// Package agent is the on-machine RemoteConfig agent: it enrolls, checks in with the
// server, caches and applies config, and exposes the same REST contract locally.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	crand "crypto/rand"
	"encoding/hex"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"remoteconfig/internal/capture"
	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

type Options struct {
	Server      string        // server base URL, e.g. http://host:8080
	EnrollToken string        // one-time token (first run only)
	StateDir    string        // identity, local token, caches
	OutDir      string        // where effective-config.json is written for the app
	Listen      string        // local API address, e.g. 127.0.0.1:7878
	Interval    time.Duration // 0 = follow the server
	Version     string
	Log         *log.Logger
	Capturer    capture.Capturer // nil = the platform's real screen capture (tests inject a fake)

	// ServerKey pins the server's public signing key (base64), as printed by the dashboard's
	// "Add device" dialog and `server keys show`. A pinned key is trusted without asking the
	// network, which is the one way to be safe against a man in the middle at install time.
	ServerKey string
	// RequireSignatures refuses unsigned config and commands even before a key is known.
	RequireSignatures bool
	// InsecureTOFU lets the agent trust a key it learns over plain HTTP from another machine.
	// Off by default: that channel proves nothing about who is answering.
	InsecureTOFU bool
	// Exit ends the process after an agent update has been installed (default os.Exit);
	// tests replace it.
	Exit func(code int)
	// ExePath is the agent's own executable, which an agent update replaces. Default: this process's.
	ExePath string
}

type identity struct {
	Server      string `json:"server"`
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	Project     string `json:"project"`
}

type Agent struct {
	o      Options
	id     identity
	client *http.Client

	localToken string

	mu          sync.Mutex
	cfg         *proto.EffectiveConfig // config currently applied (also on disk)
	cfgChanged  chan struct{}          // closed + replaced when cfg changes
	app         *proto.AppStatus
	appAt       time.Time
	events      []proto.Event // pending, sent with the next check-in
	lastCheckin time.Time
	connected   bool
	handled     map[string]bool // command ids already executed
	handledList []string        // the same ids in order, so the oldest can be dropped
	running     map[string]bool // long commands (scripts, releases) still in progress
	rel         releaseState    // the app release in force (${release} in the supervisor config)

	restartForUpdate atomic.Bool // an agent update was installed: exit once its result is reported
	updateChecked    atomic.Bool // the pending-update marker has been settled for this run

	sup      *Supervisor
	trust    *trustStore
	ackedRev int // newest config revision the app acknowledged via the local API
	session  string
	metrics  []proto.Metric // pending, flushed to the server after a successful check-in

	capturer      capture.Capturer
	outbox        *outbox
	usage         *usageTracker
	drainMu       sync.Mutex
	shots         screenState
	lastEventShot atomic.Int64
	runCtx        context.Context // set once in Run, before any goroutine that reads it

	seq      int64
	interval time.Duration
	wake     chan struct{}
	started  time.Time
}

func New(o Options) *Agent {
	if o.Log == nil {
		o.Log = log.Default()
	}
	if o.OutDir == "" {
		o.OutDir = o.StateDir
	}
	a := &Agent{
		o:          o,
		cfgChanged: make(chan struct{}),
		handled:    map[string]bool{},
		wake:       make(chan struct{}, 1),
		interval:   60 * time.Second,
		started:    time.Now(),
		capturer:   o.Capturer,
		outbox:     newOutbox(filepath.Join(o.StateDir, "outbox")),
		usage:      newUsageTracker(filepath.Join(o.StateDir, "usage.json")),
		shots:      screenState{last: map[int]lastShot{}, wasBlack: map[int]bool{}},
	}
	if a.capturer == nil {
		a.capturer = capture.New()
	}
	// Every byte to the server goes through a connection that counts it, so the data
	// budget reflects what the carrier will actually bill.
	a.client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &countingConn{Conn: c, u: a.usage}, nil
		},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     60 * time.Second,
		MaxIdleConns:        2,
		ForceAttemptHTTP2:   true,
	}}
	a.sup = newSupervisor(a)
	a.trust = newTrustStore(a)
	a.session = fmt.Sprintf("%016x", rand.Uint64())
	return a
}

func (a *Agent) logf(format string, args ...any) { a.o.Log.Printf(format, args...) }

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.o.StateDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.o.OutDir, 0o755); err != nil {
		return err
	}
	if err := a.loadLocalToken(); err != nil {
		return err
	}
	if err := a.trust.load(); err != nil {
		return err
	}
	a.loadIdentityFile()
	a.loadHandledCommands()
	a.loadReleaseState()
	a.loadCachedConfig() // works fully offline: the app can read this before we ever connect
	a.usage.load()
	defer a.usage.save()
	a.runCtx = ctx

	go a.serveLocal(ctx)
	go a.screenshotLoop(ctx)
	// Supervision runs from the cached config, so the app starts even if the server is
	// unreachable (or we are not enrolled yet).
	go a.sup.run(ctx)
	defer func() { // when stopping, give the supervisor time to finish (it may be quitting the app)
		if ctx.Err() != nil {
			select {
			case <-a.sup.done:
			case <-time.After(30 * time.Second):
			}
		}
	}()

	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}

	backoff := 5 * time.Second
	for {
		var wait time.Duration
		if err := a.checkin(ctx); err != nil {
			a.setConnected(false)
			wait = backoff
			a.logf("check-in failed (retry in %s): %v", wait, err)
			if backoff *= 2; backoff > maxDur(a.interval, 30*time.Second) {
				backoff = maxDur(a.interval, 30*time.Second)
			}
		} else {
			wait = a.interval // read after check-in: it may have just changed
			backoff = 5 * time.Second
		}
		wait += time.Duration(rand.Int63n(int64(wait)/5 + 1)) // +0..20% jitter
		select {
		case <-ctx.Done():
			return nil
		case <-a.wake:
		case <-time.After(wait):
		}
	}
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (a *Agent) setConnected(v bool) {
	a.mu.Lock()
	a.connected = v
	a.mu.Unlock()
}

// ---------------------------------------------------------------- identity

func (a *Agent) loadLocalToken() error {
	p := filepath.Join(a.o.StateDir, "local-token")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		a.localToken = strings.TrimSpace(string(b))
		return nil
	}
	raw := make([]byte, 32)
	if _, err := crand.Read(raw); err != nil {
		return err
	}
	tok := hex.EncodeToString(raw)
	a.localToken = tok
	return os.WriteFile(p, []byte(tok), 0o600)
}

// loadIdentityFile reads the enrolment saved by an earlier run. It is purely local, so it
// happens before anything that needs to know which device this is (such as checking that a
// cached config was signed for this device) and does not wait for the network.
func (a *Agent) loadIdentityFile() bool {
	b, err := os.ReadFile(filepath.Join(a.o.StateDir, "identity.json"))
	if err != nil {
		return false
	}
	var id identity
	if json.Unmarshal(b, &id) != nil || id.DeviceToken == "" {
		return false
	}
	if a.o.Server != "" {
		id.Server = a.o.Server // allow the operator to repoint the server
	}
	a.mu.Lock()
	a.id = id
	a.mu.Unlock()
	return true
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	p := filepath.Join(a.o.StateDir, "identity.json")
	if a.identitySnapshot().DeviceToken != "" || a.loadIdentityFile() {
		id := a.identitySnapshot()
		a.logf("device %s (project %s) -> %s", id.DeviceID, id.Project, id.Server)
		return nil
	}
	if a.o.Server == "" || a.o.EnrollToken == "" {
		return fmt.Errorf("not enrolled: need -server and -enroll-token on first run")
	}
	host, _ := os.Hostname()
	backoff := 5 * time.Second
	if a.trust.strict() { // with a pin, look at the server's key before spending the one-time token on it
		var k proto.KeyInfo
		if st, err := a.do(ctx, http.MethodGet, a.o.Server, "/v1/server-key", "", nil, &k, nil); err == nil && st == http.StatusOK {
			if err := a.learnEnrollmentKey(&k); err != nil {
				return err
			}
		}
	}
	for {
		var resp proto.EnrollResponse
		status, err := a.do(ctx, http.MethodPost, a.o.Server, "/v1/enroll", "", proto.EnrollRequest{
			Token: a.o.EnrollToken, Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
			AgentVersion: a.o.Version,
		}, &resp, nil)
		if err == nil && status == http.StatusCreated {
			if err := a.learnEnrollmentKey(resp.Signing); err != nil {
				return err // a different server than the one pinned: do not keep an identity for it
			}
			a.mu.Lock()
			a.id = identity{Server: a.o.Server, DeviceID: resp.DeviceID, DeviceToken: resp.DeviceToken, Project: resp.Project}
			a.mu.Unlock()
			b, _ := json.MarshalIndent(a.id, "", "  ")
			if err := os.WriteFile(p, b, 0o600); err != nil {
				return err
			}
			a.logf("enrolled as %s in project %s", a.id.DeviceID, a.id.Project)
			return nil
		}
		if err == nil && status == http.StatusUnauthorized {
			return fmt.Errorf("enrollment token rejected")
		}
		a.logf("enroll failed (retry in %s): status=%d err=%v", backoff, status, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
}

// ---------------------------------------------------------------- HTTP helper

// do performs a JSON request. Returns the HTTP status; out is decoded for 2xx with a
// body. (Data usage is counted at the socket by the client's transport, not here.)
func (a *Agent) do(ctx context.Context, method, base, path, token string, in, out any, hdr map[string]string) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && resp.StatusCode/100 == 2 && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (a *Agent) server(ctx context.Context, method, path string, in, out any, hdr map[string]string) (int, error) {
	return a.do(ctx, method, a.id.Server, path, a.id.DeviceToken, in, out, hdr)
}

// ---------------------------------------------------------------- check-in

func (a *Agent) checkin(ctx context.Context) error {
	snap := a.sup.Snapshot() // before taking a.mu (lock order: supervisor, then agent)
	restarts := a.sup.restartsUnreported()
	budget := a.reportBudget() // may queue a threshold event, so do it before building the request

	a.mu.Lock()
	a.seq++
	req := proto.CheckinRequest{
		Session: a.session, Seq: a.seq, AgentVersion: a.o.Version,
		BytesIn: budget.In, BytesOut: budget.Out, BudgetMB: budget.LimitMB, BudgetState: budget.State,
		Trust:             a.trust.report(),
		Events:            append([]proto.Event(nil), a.events...),
		System:            &proto.SystemStats{UptimeS: int64(time.Since(a.started).Seconds())},
		RestartsSinceLast: restarts,
	}
	nEvents := len(a.events)
	if a.cfg != nil {
		req.ConfigRevision, req.ConfigEtag = a.cfg.Revision, a.cfg.Etag
	}
	if a.app != nil {
		app := *a.app
		req.App = &app
		req.LastHeartbeatAgeS = int(time.Since(a.appAt).Seconds())
	}
	if snap.Managing && !snap.Running { // the process is down: say so rather than echo a stale heartbeat
		req.App = &proto.AppStatus{State: "stopped", Message: snap.State}
		if snap.CrashLoop {
			req.App = &proto.AppStatus{State: "error", Message: "crash loop: supervisor gave up"}
		}
	}
	a.mu.Unlock()

	var resp proto.CheckinResponse
	status, err := a.server(ctx, http.MethodPost, "/v1/checkin", req, &resp, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("check-in: HTTP %d", status)
	}

	a.mu.Lock()
	a.events = a.events[min(nEvents, len(a.events)):] // sent events are done; keep newer ones
	a.lastCheckin, a.connected = time.Now(), true
	a.mu.Unlock()
	a.sup.markReported(restarts)
	a.usage.save()

	a.flushMetrics(ctx)
	go a.drainOutbox(ctx) // queued screenshots; runs beside the next check-in, never delays it

	if a.o.Interval > 0 {
		a.interval = a.o.Interval
	} else if resp.NextCheckinS > 0 {
		a.interval = time.Duration(resp.NextCheckinS) * time.Second
	}

	if a.updateChecked.CompareAndSwap(false, true) {
		a.confirmUpdate() // we got as far as a check-in: a freshly installed binary is good
	}
	a.bootstrapTrust(ctx)
	if resp.ConfigChanged || a.currentConfig() == nil || a.needSignedCopy() {
		if err := a.fetchConfig(ctx); err != nil {
			a.logf("config fetch: %v", err)
		}
	}
	for _, c := range resp.Commands {
		a.runCommand(ctx, c)
	}
	return nil
}

func (a *Agent) currentConfig() *proto.EffectiveConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

func (a *Agent) runCommand(ctx context.Context, c proto.Command) {
	// With a trusted server key, act only on what the server signed for this device. A
	// command that fails the check is dropped without a reply: its id cannot be believed.
	c, err := a.trust.checkCommand(ctx, c)
	if err != nil {
		a.trust.reject("command", err.Error())
		return
	}
	a.mu.Lock()
	done := a.handled[c.ID]
	a.handled[c.ID] = true
	a.mu.Unlock()
	if !done {
		a.rememberCommand(c.ID)
	}
	if done && a.isRunning(c.ID) {
		return // still working on it; the result comes when it finishes
	}
	if done {
		// Already ran; the result report probably got lost. Re-report success quietly.
		dup := proto.CommandResult{OK: true, Output: "duplicate delivery"}
		switch c.Type {
		case "run_script":
			dup = proto.CommandResult{OK: false, Output: "no result was recorded: the agent restarted while the script was running or reporting"}
		case "apply_release":
			dup = proto.CommandResult{OK: true, Output: "already handled by an earlier run of the agent; check the version the device reports"}
		}
		a.server(ctx, http.MethodPost, "/v1/commands/"+c.ID+"/result", dup, nil, nil)
		return
	}
	res := proto.CommandResult{OK: false, Output: "not implemented yet: " + c.Type}
	switch c.Type {
	case "run_script":
		a.startAsync(ctx, c, a.runScript)
		return
	case "apply_release":
		a.startAsync(ctx, c, a.applyRelease)
		return
	case "checkin_now":
		res = proto.CommandResult{OK: true}
	case "capture_screenshot":
		queued, _, err := a.captureAndQueue("command", true)
		switch {
		case err != nil:
			res = proto.CommandResult{OK: false, Output: "capture failed: " + err.Error()}
		case !a.allowBulk():
			res = proto.CommandResult{OK: true, Output: fmt.Sprintf("captured %d display(s); upload paused: data budget exhausted", queued)}
		default:
			res = proto.CommandResult{OK: true, Output: fmt.Sprintf("captured %d display(s); uploading", queued)}
			defer func() { go a.drainOutbox(ctx) }() // after the result below is reported
		}
	case "restart_app":
		if a.sup.Managing() {
			a.sup.RequestRestart("command " + c.ID)
			res = proto.CommandResult{OK: true, Output: "restart requested"}
		} else {
			res = proto.CommandResult{OK: false, Output: "app is not supervised on this device"}
		}
	}
	a.logf("command %s (%s): ok=%v", c.ID, c.Type, res.OK)
	a.server(ctx, http.MethodPost, "/v1/commands/"+c.ID+"/result", res, nil, nil)
}

// ---------------------------------------------------------------- config

func (a *Agent) cfgPath() string { return filepath.Join(a.o.OutDir, "effective-config.json") }
func (a *Agent) lkgPath() string { return filepath.Join(a.o.StateDir, "last-known-good.json") }

// loadCachedConfig reads the config saved by a previous run, so the app can start before the
// network is up. A strict agent only trusts the signed copy: it re-verifies it, and rewrites
// the plain file the app reads from it, so tampering with that file achieves nothing.
func (a *Agent) loadCachedConfig() {
	if a.trust.strict() {
		b, err := os.ReadFile(a.signedCachePath())
		if err != nil {
			a.logf("no signed config cached yet; waiting for the server")
			return
		}
		var env signing.Envelope
		if json.Unmarshal(b, &env) != nil {
			a.trust.reject("cached config", "the signed copy on disk is unreadable")
			return
		}
		sc, err := a.trust.checkConfig(nil, &env)
		if err != nil {
			a.trust.reject("cached config", err.Error())
			return
		}
		a.cfg = &sc.Config
		a.trust.setApplied(sc.IssuedAt)
		if plain, err := json.MarshalIndent(sc.Config, "", "  "); err == nil {
			writeFileAtomic(a.cfgPath(), plain)
		}
		a.logf("loaded signed cached config revision %d", sc.Config.Revision)
		return
	}
	b, err := os.ReadFile(a.cfgPath())
	if err != nil {
		return
	}
	var c proto.EffectiveConfig
	if json.Unmarshal(b, &c) != nil || c.Data == nil {
		a.logf("cached config unreadable; ignoring")
		return
	}
	a.cfg = &c
	a.logf("loaded cached config revision %d", c.Revision)
}

func (a *Agent) fetchConfig(ctx context.Context) error {
	hdr := map[string]string{"Accept": signing.ContentType}
	needSigned := a.needSignedCopy()
	if c := a.currentConfig(); c != nil && !needSigned {
		hdr["If-None-Match"] = `"` + c.Etag + `"`
	}
	status, body, rh, err := a.serverGet(ctx, "/v1/config", hdr)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("HTTP %d", status)
	}

	var cfg proto.EffectiveConfig
	var env *signing.Envelope
	var issued time.Time
	if strings.HasPrefix(rh.Get("Content-Type"), signing.ContentType) {
		var e signing.Envelope
		if err := json.Unmarshal(body, &e); err != nil {
			a.trust.reject("config", "the signed envelope is malformed")
			return err
		}
		sc, err := a.trust.checkConfig(ctx, &e)
		if err != nil {
			a.trust.reject("config", err.Error())
			return fmt.Errorf("config refused: %w", err)
		}
		cfg, env, issued = sc.Config, &e, sc.IssuedAt
		a.trust.accepted()
	} else {
		if a.trust.strict() {
			a.trust.reject("config", "it is not signed, but this agent only accepts signed config")
			return errors.New("config refused: unsigned")
		}
		if err := json.Unmarshal(body, &cfg); err != nil {
			return err
		}
	}

	// Same content as what is running: only the signed copy needs saving (this happens when an
	// agent that used to run unsigned learns the server's key). Re-applying would restart things.
	if cur := a.currentConfig(); env != nil && cur != nil && cur.Etag == cfg.Etag {
		a.persistSigned(env, issued)
		return nil
	}

	if err := a.applyConfig(cfg, env, issued); err != nil {
		a.logf("config revision %d rejected: %v", cfg.Revision, err)
		ack := proto.ConfigAck{Revision: cfg.Revision, OK: false, Error: err.Error()}
		if c := a.currentConfig(); c != nil {
			ack.RolledBackTo = c.Revision
		}
		a.server(ctx, http.MethodPost, "/v1/config/ack", ack, nil, nil)
		return err
	}
	a.logf("applied config revision %d (%s)", cfg.Revision, cfg.Etag)
	a.server(ctx, http.MethodPost, "/v1/config/ack", proto.ConfigAck{Revision: cfg.Revision, OK: true}, nil, nil)
	return nil
}

// applyConfig validates, keeps the previous file as last-known-good, then swaps in
// the new file atomically so the app never sees a half-written config. env is the signed
// form it came in (nil for an unsigned legacy config); it is saved for the next start.
func (a *Agent) applyConfig(cfg proto.EffectiveConfig, env *signing.Envelope, issued time.Time) error {
	if cfg.Data == nil {
		return fmt.Errorf("config has no data object")
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(a.cfgPath()); err == nil {
		if err := writeFileAtomic(a.lkgPath(), old); err != nil {
			a.logf("could not save last-known-good: %v", err)
		}
	}
	if env != nil { // the signed copy first: if we die between the two writes, the next start re-verifies it
		a.persistSigned(env, issued)
	}
	if err := writeFileAtomic(a.cfgPath(), b); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = &cfg
	close(a.cfgChanged)
	a.cfgChanged = make(chan struct{})
	a.mu.Unlock()
	a.sup.onConfigApplied(cfg) // reload_mode trigger / restart
	return nil
}

func (a *Agent) appAckedRevision() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ackedRev
}

// writeFileAtomic writes to a temp file in the same directory, fsyncs, then renames.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// QueueMetrics buffers app-reported metrics (bounded; oldest dropped first).
func (a *Agent) QueueMetrics(ms []proto.Metric) {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range ms {
		if m.TS.IsZero() {
			m.TS = now
		}
		a.metrics = append(a.metrics, m)
	}
	if n := len(a.metrics); n > 2000 {
		a.metrics = a.metrics[n-2000:]
	}
}

// flushMetrics sends buffered metrics; on failure they stay queued for the next check-in.
func (a *Agent) flushMetrics(ctx context.Context) {
	if !a.allowBulk() {
		return // data budget exhausted: metrics wait for the next cycle
	}
	a.mu.Lock()
	batch := append([]proto.Metric(nil), a.metrics[:min(len(a.metrics), 500)]...)
	a.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	status, err := a.server(ctx, http.MethodPost, "/v1/metrics", map[string]any{"metrics": batch}, nil, nil)
	if err != nil || status/100 != 2 {
		return
	}
	a.mu.Lock()
	a.metrics = a.metrics[min(len(batch), len(a.metrics)):]
	a.mu.Unlock()
}

// DeviceID returns the enrolled device id ("" before enrollment).
func (a *Agent) DeviceID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.id.DeviceID
}

// QueueEvent adds an event to be sent with the next check-in (bounded).
func (a *Agent) QueueEvent(e proto.Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	a.mu.Lock()
	a.events = append(a.events, e)
	if n := len(a.events); n > 200 {
		a.events = a.events[n-200:]
	}
	a.mu.Unlock()
	a.maybeCaptureOnEvent(e)
}

// WakeNow makes the loop check in immediately.
func (a *Agent) WakeNow() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}
