package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

// serveLocal exposes the app-facing REST contract on 127.0.0.1 so apps can use the
// agent as a relay (see DESIGN.md 6.9). Same paths as the server's device API.
func (a *Agent) serveLocal(ctx context.Context) {
	if a.o.Listen == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.dashboard)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /v1/config", a.auth(a.localGetConfig))
	mux.HandleFunc("GET /v1/lifecycle", a.auth(a.localLifecycle))
	mux.HandleFunc("POST /v1/config/ack", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var ack proto.ConfigAck
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&ack)
		a.logf("app acked config revision %d ok=%v %s", ack.Revision, ack.OK, ack.Error)
		if ack.OK {
			a.mu.Lock()
			a.ackedRev = max(a.ackedRev, ack.Revision)
			a.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("PUT /v1/status", a.auth(a.localPutStatus))
	mux.HandleFunc("GET /v1/status", a.auth(a.localGetStatus))
	mux.HandleFunc("POST /v1/events", a.auth(a.localPostEvents))
	mux.HandleFunc("POST /v1/metrics", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Metrics []proto.Metric `json:"metrics"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.QueueMetrics(body.Metrics)
		w.WriteHeader(http.StatusAccepted)
	}))
	mux.HandleFunc("GET /v1/commands", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, []proto.Command{})
	}))
	mux.HandleFunc("POST /v1/agent/checkin-now", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.WakeNow()
		w.WriteHeader(http.StatusAccepted)
	}))

	a.registerUI(mux)

	srv := &http.Server{Addr: a.o.Listen, Handler: mux}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	a.logf("local API on http://%s (token in %s)", a.o.Listen, a.o.StateDir+"/local-token")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		a.logf("local API stopped: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func (a *Agent) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.localToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.localToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid local token"})
			return
		}
		h(w, r)
	}
}

func (a *Agent) localGetConfig(w http.ResponseWriter, r *http.Request) {
	inm := strings.Trim(r.Header.Get("If-None-Match"), `"`)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = max(0, min(wait, 60))
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()

	for {
		a.mu.Lock()
		cfg, ch := a.cfg, a.cfgChanged
		a.mu.Unlock()
		if cfg == nil && wait == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no config yet"})
			return
		}
		if cfg != nil && cfg.Etag != inm {
			w.Header().Set("ETag", `"`+cfg.Etag+`"`)
			writeJSON(w, http.StatusOK, cfg)
			return
		}
		if wait == 0 {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		select {
		case <-ch:
		case <-deadline.C:
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// localLifecycle is how an app learns it should shut down: it long-polls this endpoint
// (wait=N seconds, max 60) and gets 204 while nothing is requested, or 200 with
// {"action":"quit","reason":...,"grace_s":N} once the agent wants it to exit. The app
// should save its state and exit within grace_s seconds, after which it is killed.
func (a *Agent) localLifecycle(w http.ResponseWriter, r *http.Request) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	timer := time.NewTimer(time.Duration(max(0, min(wait, 60))) * time.Second)
	defer timer.Stop()
	for {
		pending, reason, grace, sig := a.sup.lifecycle()
		if pending {
			writeJSON(w, http.StatusOK, map[string]any{"action": "quit", "reason": reason, "grace_s": int(grace.Seconds())})
			return
		}
		select {
		case <-sig:
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (a *Agent) localPutStatus(w http.ResponseWriter, r *http.Request) {
	var st proto.AppStatus
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&st); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.mu.Lock()
	a.app, a.appAt = &st, time.Now()
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (a *Agent) status() proto.DeviceStatus {
	snap := a.sup.Snapshot() // before a.mu: lock order is supervisor, then agent
	a.mu.Lock()
	defer a.mu.Unlock()
	s := proto.DeviceStatus{
		DeviceID: a.id.DeviceID, Connected: a.connected, LastCheckinAt: a.lastCheckin,
		App: a.app, ProcessRunning: a.app != nil && time.Since(a.appAt) < 60*time.Second,
		Restarts: snap.Restarts,
	}
	if snap.Managing { // when we own the process its real state beats heartbeat age
		s.ProcessRunning = snap.Running
	}
	if a.cfg != nil {
		s.ConfigRevision = a.cfg.Revision
	}
	if a.app != nil {
		s.LastHeartbeatAgeS = int(time.Since(a.appAt).Seconds())
	}
	return s
}

func (a *Agent) localGetStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.status())
}

func (a *Agent) localPostEvents(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Events []proto.Event `json:"events"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for _, e := range body.Events {
		a.QueueEvent(e)
	}
	w.WriteHeader(http.StatusAccepted)
}

// dashboard is the Phase 0 stand-in for the local dashboard: read-only status, no
// secrets, so it needs no token.
func (a *Agent) dashboard(w http.ResponseWriter, r *http.Request) {
	st := a.status()
	a.mu.Lock()
	var cfgJSON []byte
	if a.cfg != nil {
		cfgJSON, _ = json.MarshalIndent(a.cfg, "", "  ")
	}
	nEvents := len(a.events)
	a.mu.Unlock()
	use := a.usage.view(a.budgetPolicy())
	data := fmt.Sprintf("%.1f MB out / %.1f MB in this cycle", float64(use.Out)/1e6, float64(use.In)/1e6)
	if use.LimitMB > 0 {
		data += fmt.Sprintf(" (%d%% of %d MB budget, %s)", use.UsedPct, use.LimitMB, use.State)
	}
	queued := len(a.outbox.list())

	app := "no heartbeat yet"
	if st.App != nil {
		app = fmt.Sprintf("%s (heartbeat %ds ago)", st.App.State, st.LastHeartbeatAgeS)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>RemoteConfig agent</title>
<style>body{font:15px system-ui;margin:2rem auto;max-width:44rem;padding:0 1rem}pre{background:#8881;padding:1rem;overflow:auto}</style>
<h1>RemoteConfig agent</h1>
<p>Device <b>%s</b> &middot; server %s &middot; <b>%s</b></p>
<p>App: %s<br>Config revision: %d<br>Last check-in: %s<br>Pending events: %d<br>Screenshots waiting to upload: %d<br>Data used: %s</p>
<h2>Effective config</h2><pre>%s</pre>`,
		html.EscapeString(st.DeviceID), html.EscapeString(a.id.Server),
		map[bool]string{true: "connected", false: "offline"}[st.Connected],
		html.EscapeString(app), st.ConfigRevision, st.LastCheckinAt.Format(time.RFC3339), nEvents,
		queued, html.EscapeString(data), html.EscapeString(string(cfgJSON)))
}
