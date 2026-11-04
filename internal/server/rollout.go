package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"remoteconfig/internal/proto"
)

// Staged rollouts. A bad release sent to the whole fleet at once is the failure that matters
// most here: the machines are unattended and the links are poor, so a broken build is hard to
// fix remotely. A rollout sends to the canary devices first, waits for them to report success
// and then to stay healthy for a soak period, and only then sends to the rest, in waves if asked.
// Any failure, or an error-level event from a canary during the soak, halts the rollout:
// nothing further is sent. (Devices that already have the command still run it.)

const rolloutSchema = `
CREATE TABLE IF NOT EXISTS rollouts (
	id TEXT PRIMARY KEY,
	project TEXT NOT NULL,
	state TEXT NOT NULL,
	created_at TEXT NOT NULL,
	json TEXT NOT NULL
);
`

const (
	rolloutTick        = 2 * time.Second
	defaultSoakS       = 120
	maxRolloutDevices  = 500
	canaryOfflineGrace = 10 * time.Minute // after the soak, how long to wait for a canary that is restarting
)

var rolloutTypes = map[string]bool{"apply_release": true, "run_script": true}

func (s *Store) saveRollout(r *proto.Rollout) {
	b, _ := json.Marshal(r)
	s.exec(`INSERT INTO rollouts(id,project,state,created_at,json) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, json=excluded.json`,
		r.ID, r.Project, r.State, r.CreatedAt.Format(time.RFC3339Nano), string(b))
}

func (s *Store) loadRollouts(where string, args ...any) []*proto.Rollout {
	rows, err := s.db.Query(`SELECT json FROM rollouts `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*proto.Rollout
	for rows.Next() {
		var js string
		var r proto.Rollout
		if rows.Scan(&js) == nil && json.Unmarshal([]byte(js), &r) == nil {
			out = append(out, &r)
		}
	}
	return out
}

// rolloutLoop advances active rollouts until the store is closed.
func (s *Server) rolloutLoop() {
	every := s.opts.RolloutTick
	if every <= 0 {
		every = rolloutTick
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.st.closing:
			return
		case <-t.C:
			s.st.mu.Lock()
			select {
			case <-s.st.closing:
				s.st.mu.Unlock()
				return
			default:
			}
			s.rolloutPass(time.Now().UTC())
			s.st.mu.Unlock()
		}
	}
}

// rolloutPass moves every active rollout as far as it can. Caller holds s.st.mu.
func (s *Server) rolloutPass(now time.Time) {
	for _, r := range s.st.loadRollouts(`WHERE state IN ('canary','soaking','rolling')`) {
		before, _ := json.Marshal(r)
		s.advance(r, now)
		if after, _ := json.Marshal(r); string(after) != string(before) {
			s.st.saveRollout(r)
		}
	}
}

func (s *Server) halt(r *proto.Rollout, reason string) {
	r.State, r.Reason = "halted", reason
	s.st.Audit(nil, "rollout.halted", r.Project, r.ID, truncate(reason, 400))
}

// commandOf finds the command a rollout sent to a device.
func commandOf(d *Device, id string) (proto.Command, bool) {
	for _, c := range d.Commands {
		if c.ID == id {
			return c, true
		}
	}
	return proto.Command{}, false
}

func terminal(status string) bool {
	return status == "succeeded" || status == "failed" || status == "expired"
}

func resultOf(c proto.Command) string {
	res, _ := c.Params["result"].(string)
	return res
}

// send queues the rollout's command on a device (once).
func (s *Server) sendRollout(r *proto.Rollout, id string) error {
	if _, done := r.Sent[id]; done {
		return nil
	}
	d, ok := s.st.D.Devices[id]
	if !ok || d.Project != r.Project {
		r.Sent[id] = "removed"
		return nil
	}
	params, ttl, err := s.resolveCommand(d, r.Type, r.Params, 0)
	if err != nil {
		return fmt.Errorf("%s: %v", d.Name, err)
	}
	r.Sent[id] = s.enqueueLocked(d, r.Type, params, ttl).ID
	return nil
}

func (s *Server) advance(r *proto.Rollout, now time.Time) {
	if r.Sent == nil {
		r.Sent = map[string]string{}
	}
	canary := r.Targets[:min(r.Canary, len(r.Targets))]
	status := func(id string) (string, proto.Command) {
		cid, sent := r.Sent[id]
		if !sent {
			return "waiting", proto.Command{}
		}
		d, ok := s.st.D.Devices[id]
		if !ok || cid == "removed" {
			return "removed", proto.Command{}
		}
		c, ok := commandOf(d, cid)
		if !ok {
			return "failed", proto.Command{Params: map[string]any{"result": "the command is no longer in the device's history"}}
		}
		return c.Status, c
	}
	name := func(id string) string {
		if d, ok := s.st.D.Devices[id]; ok {
			return d.Name
		}
		return id
	}

	switch r.State {
	case "canary":
		for _, id := range canary {
			if err := s.sendRollout(r, id); err != nil {
				s.halt(r, "could not send to the canary: "+err.Error())
				return
			}
		}
		allOK := true
		for _, id := range canary {
			st, c := status(id)
			switch {
			case st == "failed" || st == "expired":
				s.halt(r, fmt.Sprintf("canary %s %s: %s", name(id), st, truncate(resultOf(c), 200)))
				return
			case st != "succeeded" && st != "removed":
				allOK = false
			}
		}
		if allOK {
			r.State, r.SoakStart, r.SoakUntil = "soaking", now, now.Add(time.Duration(r.SoakS)*time.Second)
			s.st.Audit(nil, "rollout.soaking", r.Project, r.ID, fmt.Sprintf("canary succeeded; waiting %ds", r.SoakS))
			s.advance(r, now) // with no soak, carry straight on
		}

	case "soaking":
		for _, id := range canary {
			if why := s.unhealthy(id, r.SoakStart); why != "" {
				s.halt(r, fmt.Sprintf("canary %s is unhealthy: %s", name(id), why))
				return
			}
		}
		if now.Before(r.SoakUntil) {
			return
		}
		for _, id := range canary { // after the soak they must be back: an update restarts the agent
			if d, ok := s.st.D.Devices[id]; ok && s.reachability(d) != "online" {
				if now.After(r.SoakUntil.Add(canaryOfflineGrace)) {
					s.halt(r, fmt.Sprintf("canary %s did not come back online", name(id)))
				}
				return
			}
		}
		r.State = "rolling"
		s.st.Audit(nil, "rollout.rolling", r.Project, r.ID, "canary healthy; sending to the rest")
		s.advance(r, now)

	case "rolling":
		var failed string
		for id := range r.Sent {
			if st, c := status(id); st == "failed" || st == "expired" {
				failed = fmt.Sprintf("%s %s: %s", name(id), st, truncate(resultOf(c), 200))
				break
			}
		}
		if failed != "" {
			s.halt(r, "stopped sending after a failure on "+failed)
			return
		}
		// A wave is finished when everything sent so far has succeeded.
		inFlight, unsent := 0, []string{}
		for _, id := range r.Targets {
			if _, sent := r.Sent[id]; !sent {
				unsent = append(unsent, id)
			} else if st, _ := status(id); !terminal(st) && st != "removed" {
				inFlight++
			}
		}
		if len(unsent) == 0 && inFlight == 0 {
			r.State = "done"
			s.st.Audit(nil, "rollout.done", r.Project, r.ID, "")
			return
		}
		if inFlight > 0 || len(unsent) == 0 {
			return
		}
		wave := unsent
		if r.Batch > 0 && r.Batch < len(wave) {
			wave = wave[:r.Batch]
		}
		for _, id := range wave {
			if err := s.sendRollout(r, id); err != nil {
				s.halt(r, "could not send: "+err.Error())
				return
			}
		}
	}
}

// unhealthy says why a canary looks bad since `since`, or "".
func (s *Server) unhealthy(id string, since time.Time) string {
	d, ok := s.st.D.Devices[id]
	if !ok {
		return ""
	}
	if signatureState(d.Trust) == "rejecting" {
		return "it is refusing signed content"
	}
	for _, e := range s.st.listEvents(id, 40) {
		if e.Level == "error" && e.TS.After(since) {
			return e.Type + ": " + truncate(e.Message, 160)
		}
	}
	return ""
}

// ---------------------------------------------------------------- API

func (s *Server) createRollout(w http.ResponseWriter, r *http.Request) {
	var in proto.RolloutRequest
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	project := r.PathValue("project")
	switch {
	case !rolloutTypes[in.Type]:
		writeErr(w, http.StatusBadRequest, "type must be apply_release or run_script")
		return
	case len(in.Devices) == 0 || len(in.Devices) > maxRolloutDevices:
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("devices: between 1 and %d", maxRolloutDevices))
		return
	}
	canary := in.Canary
	if canary <= 0 {
		canary = 1
	}
	canary = min(canary, len(in.Devices))
	soak := defaultSoakS
	if in.SoakS != nil {
		soak = *in.SoakS
	}
	if soak < 0 || soak > 86400 || in.Batch < 0 {
		writeErr(w, http.StatusBadRequest, "soak_s must be 0-86400 and batch 0 or more")
		return
	}

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	seen := map[string]bool{}
	for _, id := range in.Devices {
		d, ok := s.st.D.Devices[id]
		if !ok || d.Project != project || seen[id] {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("device %q: unknown, in another project, or listed twice", id))
			return
		}
		seen[id] = true
		// Refuse up front what would only fail later (wrong platform, unknown release or script).
		if _, _, err := s.resolveCommand(d, in.Type, in.Params, 0); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s: %v", d.Name, err))
			return
		}
	}
	ro := &proto.Rollout{
		ID: "ro_" + NewToken(5), Project: project, Type: in.Type, Params: in.Params, Targets: in.Devices,
		Canary: canary, SoakS: soak, Batch: in.Batch, State: "canary", Sent: map[string]string{},
		CreatedAt: time.Now().UTC(), CreatedBy: userName(r),
	}
	s.advance(ro, time.Now().UTC()) // the canary gets its command now, not at the next tick
	s.st.saveRollout(ro)
	s.audit(r, "rollout.created", project, ro.ID, fmt.Sprintf("%s to %d devices, %d canary, soak %ds", in.Type, len(in.Devices), canary, soak))
	writeJSON(w, http.StatusCreated, s.rolloutView(ro))
}

func (s *Server) rolloutView(ro *proto.Rollout) *proto.Rollout {
	v := *ro
	v.Devices = nil
	for i, id := range ro.Targets {
		rd := proto.RolloutDevice{ID: id, Name: id, Stage: "rest", Status: "waiting"}
		if i < ro.Canary {
			rd.Stage = "canary"
		}
		d, ok := s.st.D.Devices[id]
		if ok {
			rd.Name = d.Name
		}
		if cid, sent := ro.Sent[id]; sent {
			rd.Command = cid
			switch {
			case cid == "removed" || !ok:
				rd.Status = "removed"
			default:
				if c, found := commandOf(d, cid); found {
					rd.Status, rd.Result = c.Status, truncate(resultOf(c), 300)
				} else {
					rd.Status = "unknown"
				}
			}
		}
		v.Devices = append(v.Devices, rd)
	}
	return &v
}

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	out := []*proto.Rollout{}
	for _, ro := range s.st.loadRollouts(`WHERE project=? ORDER BY created_at DESC LIMIT 30`, r.PathValue("project")) {
		out = append(out, s.rolloutView(ro))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) haltRollout(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	list := s.st.loadRollouts(`WHERE id=? AND project=?`, r.PathValue("id"), r.PathValue("project"))
	if len(list) == 0 {
		writeErr(w, http.StatusNotFound, "no such rollout")
		return
	}
	ro := list[0]
	if ro.State == "done" || ro.State == "halted" {
		writeErr(w, http.StatusConflict, "this rollout has already finished")
		return
	}
	s.halt(ro, "halted by "+userName(r))
	s.st.saveRollout(ro)
	writeJSON(w, http.StatusOK, s.rolloutView(ro))
}
