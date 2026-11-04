package agent

import (
	"fmt"
	"net/http"
	"time"

	"remoteconfig/internal/proto"
)

func (a *Agent) overview() proto.Overview {
	snap := a.sup.Snapshot() // before a.mu: lock order is supervisor, then agent
	use := a.usage.view(a.budgetPolicy())
	queued := len(a.outbox.list())
	id := a.identitySnapshot()

	a.mu.Lock()
	defer a.mu.Unlock()
	o := proto.Overview{
		Version: a.o.Version, Enrolled: id.DeviceToken != "", DeviceID: id.DeviceID, Project: id.Project,
		Server: id.Server, Connected: a.connected, LastCheckinAt: a.lastCheckin, StartedAt: a.started,
		ConfigAcked: a.ackedRev, PendingEvents: len(a.events), QueuedScreenshots: queued,
		Supervisor: proto.OverviewSupervisor{
			Managing: snap.Managing, State: snap.State, Running: snap.Running, PID: snap.PID,
			Restarts: snap.Restarts, UptimeS: snap.UptimeS, LastExit: snap.LastExit, CrashLoop: snap.CrashLoop,
		},
		Data: proto.OverviewData{InBytes: use.In, OutBytes: use.Out, LimitMB: use.LimitMB, UsedPct: use.UsedPct, State: use.State},
	}
	if o.Server == "" {
		o.Server = a.o.Server
	}
	if a.cfg != nil {
		o.ConfigRevision = a.cfg.Revision
	}
	if a.app != nil {
		app := *a.app
		o.App, o.HeartbeatAge = &app, int(time.Since(a.appAt).Seconds())
	}
	return o
}

// registerUI adds the endpoints behind the desktop UI. They share the app-facing local
// token, so only an account that can read the state directory can use them.
func (a *Agent) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/ui/overview", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.overview())
	}))
	mux.HandleFunc("POST /v1/ui/capture", a.auth(a.uiCapture))
	mux.HandleFunc("POST /v1/ui/restart-app", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if !a.sup.Managing() {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "the app is not supervised on this device"})
			return
		}
		a.logf("ui: app restart requested")
		a.sup.RequestRestart("requested from the local UI")
		writeJSON(w, http.StatusAccepted, map[string]string{"message": "restart requested"})
	}))
}

func (a *Agent) uiCapture(w http.ResponseWriter, r *http.Request) {
	queued, _, err := a.captureAndQueue("local-ui", true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "capture failed: " + err.Error()})
		return
	}
	msg := fmt.Sprintf("captured %d display(s); uploading", queued)
	if !a.allowBulk() {
		msg = fmt.Sprintf("captured %d display(s); upload paused: data budget exhausted", queued)
	} else if a.runCtx != nil {
		go a.drainOutbox(a.runCtx)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": msg})
}
