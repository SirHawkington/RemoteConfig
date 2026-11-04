package server

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

//go:embed web
var webFS embed.FS

type Options struct {
	CheckinInterval time.Duration
	RolloutTick     time.Duration // how often staged rollouts are advanced (default 2 s)
}

type Server struct {
	st       *Store
	opts     Options
	mux      *http.ServeMux
	throttle *loginThrottle
	signer   *Signer
}

func New(st *Store, opts Options) *Server {
	if opts.CheckinInterval <= 0 {
		opts.CheckinInterval = 5 * time.Minute
	}
	sg, err := st.Signer()
	if err != nil {
		panic("the signing key is unusable: " + err.Error()) // main checks first and reports it nicely
	}
	s := &Server{st: st, opts: opts, mux: http.NewServeMux(), throttle: newLoginThrottle(), signer: sg}
	s.routes()
	go s.rolloutLoop()
	return s
}

// securePage adds the headers a page that handles passwords and session tokens should have:
// no inline script or foreign origins (so an injected snippet cannot run or phone home),
// no framing, no referrer leaks.
func securePage(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-cache") // always revalidate, so a fixed dashboard is picked up
		h.ServeHTTP(w, r)
	})
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// dashboard (static; it signs in through /v1/auth/login and then calls the admin API)
	web, _ := fs.Sub(webFS, "web")
	m.Handle("GET /{$}", securePage(http.FileServerFS(web)))
	m.Handle("GET /static/", securePage(http.StripPrefix("/static/", http.FileServerFS(web))))

	// accounts
	m.HandleFunc("POST /v1/auth/login", s.login)
	m.HandleFunc("POST /v1/auth/logout", s.anyUser(s.logout))
	m.HandleFunc("GET /v1/admin/me", s.anyUser(s.me))
	m.HandleFunc("POST /v1/admin/me/password", s.anyUser(s.changePassword))
	m.HandleFunc("GET /v1/admin/me/tokens", s.anyUser(s.listMyTokens))
	m.HandleFunc("POST /v1/admin/me/tokens", s.anyUser(s.createMyToken))
	m.HandleFunc("DELETE /v1/admin/me/tokens/{id}", s.anyUser(s.deleteMyToken))
	m.HandleFunc("GET /v1/admin/users", s.serverAdmin(s.listUsersAPI))
	m.HandleFunc("POST /v1/admin/users", s.serverAdmin(s.createUserAPI))
	m.HandleFunc("PATCH /v1/admin/users/{username}", s.serverAdmin(s.patchUserAPI))
	m.HandleFunc("DELETE /v1/admin/users/{username}", s.serverAdmin(s.deleteUserAPI))
	m.HandleFunc("GET /v1/admin/audit", s.anyUser(s.listAuditAPI))
	m.HandleFunc("GET /v1/admin/signing", s.serverAdmin(s.getSigning))
	m.HandleFunc("POST /v1/admin/signing/rotate", s.serverAdmin(s.rotateSigning))

	// device-facing
	m.HandleFunc("POST /v1/enroll", s.enroll)
	m.HandleFunc("POST /v1/checkin", s.withDevice(s.checkin))
	m.HandleFunc("GET /v1/config", s.withDevice(s.getConfig))
	m.HandleFunc("POST /v1/config/ack", s.withDevice(s.configAck))
	m.HandleFunc("PUT /v1/status", s.withDevice(s.putStatus))
	m.HandleFunc("POST /v1/events", s.withDevice(s.postEvents))
	m.HandleFunc("POST /v1/metrics", s.withDevice(s.postMetrics))
	m.HandleFunc("GET /v1/commands", s.withDevice(s.getCommands))
	m.HandleFunc("POST /v1/commands/{id}/result", s.withDevice(s.commandResult))
	m.HandleFunc("GET /v1/keys", s.withDevice(s.deviceKeys))
	m.HandleFunc("GET /v1/server-key", s.serverKey)
	m.HandleFunc("GET /v1/scripts/{id}", s.withDevice(s.deviceScript))
	m.HandleFunc("GET /v1/releases/{id}/file", s.withDevice(s.deviceRelease))
	m.HandleFunc("POST /v1/artifacts", s.withDevice(s.createArtifact))
	m.HandleFunc("HEAD /v1/artifacts/{id}", s.withDevice(s.headArtifact))
	m.HandleFunc("PATCH /v1/artifacts/{id}", s.withDevice(s.patchArtifact))

	// Project administration. The role in each line is the least a caller needs in that
	// project (server admins count as admin everywhere):
	//   viewer    read everything
	//   operator  send commands, rename and retag devices, edit config (except the supervisor section)
	//   admin     everything, including enrolment, device removal, the supervisor section, members
	const p = "/v1/admin/projects"
	m.HandleFunc("GET "+p, s.anyUser(s.listProjects)) // only the projects you have a role in
	m.HandleFunc("POST "+p, s.serverAdmin(s.createProject))
	m.HandleFunc("PATCH "+p+"/{project}", s.project(RoleAdmin, s.renameProject))
	m.HandleFunc("POST "+p+"/{project}/enrollment-tokens",s.project(RoleAdmin, s.createEnrollToken))
	m.HandleFunc("GET "+p+"/{project}/devices", s.project(RoleViewer, s.listDevices))
	m.HandleFunc("GET "+p+"/{project}/devices/{device}", s.project(RoleViewer, s.getDevice))
	m.HandleFunc("GET "+p+"/{project}/devices/{device}/detail", s.project(RoleViewer, s.getDeviceDetail))
	m.HandleFunc("PATCH "+p+"/{project}/devices/{device}", s.project(RoleOperator, s.patchDevice))
	m.HandleFunc("DELETE "+p+"/{project}/devices/{device}", s.project(RoleAdmin, s.deleteDevice))
	m.HandleFunc("GET "+p+"/{project}/devices/{device}/metrics", s.project(RoleViewer, s.getDeviceMetrics))
	m.HandleFunc("POST "+p+"/{project}/devices/{device}/commands", s.project(RoleOperator, s.queueCommand)) // some types need admin
	m.HandleFunc("GET "+p+"/{project}/devices/{device}/artifacts", s.project(RoleViewer, s.listDeviceArtifacts))
	m.HandleFunc("GET "+p+"/{project}/artifacts/{id}", s.project(RoleViewer, s.getArtifactFile))
	m.HandleFunc("DELETE "+p+"/{project}/artifacts/{id}", s.project(RoleOperator, s.deleteArtifact))
	m.HandleFunc("GET "+p+"/{project}/config", s.project(RoleViewer, s.listConfigDocs))
	m.HandleFunc("PUT "+p+"/{project}/config/{scope}", s.project(RoleOperator, s.putConfigDoc)) // supervisor section needs admin
	m.HandleFunc("GET "+p+"/{project}/config/{scope}", s.project(RoleViewer, s.getConfigDoc))
	m.HandleFunc("DELETE "+p+"/{project}/config/{scope}", s.project(RoleOperator, s.deleteConfigDoc)) // a layer with a supervisor section needs admin
	// Scripts and releases run code on the devices, so uploading them and sending them are admin
	// actions. Viewers and operators can see what exists.
	m.HandleFunc("GET "+p+"/{project}/scripts", s.project(RoleViewer, s.listScripts))
	m.HandleFunc("POST "+p+"/{project}/scripts", s.project(RoleAdmin, s.createScript))
	m.HandleFunc("GET "+p+"/{project}/scripts/{id}/content", s.project(RoleAdmin, s.getScriptContent))
	m.HandleFunc("DELETE "+p+"/{project}/scripts/{id}", s.project(RoleAdmin, s.deleteScript))
	m.HandleFunc("GET "+p+"/{project}/releases", s.project(RoleViewer, s.listReleases))
	m.HandleFunc("POST "+p+"/{project}/releases", s.project(RoleAdmin, s.createRelease))
	m.HandleFunc("DELETE "+p+"/{project}/releases/{id}", s.project(RoleAdmin, s.deleteRelease))
	m.HandleFunc("GET "+p+"/{project}/rollouts", s.project(RoleViewer, s.listRollouts))
	m.HandleFunc("POST "+p+"/{project}/rollouts", s.project(RoleAdmin, s.createRollout))
	m.HandleFunc("POST "+p+"/{project}/rollouts/{id}/halt", s.project(RoleAdmin, s.haltRollout))
	m.HandleFunc("GET "+p+"/{project}/members", s.project(RoleAdmin, s.listMembersAPI))
	m.HandleFunc("PUT "+p+"/{project}/members/{username}", s.project(RoleAdmin, s.putMemberAPI))
	m.HandleFunc("DELETE "+p+"/{project}/members/{username}", s.project(RoleAdmin, s.deleteMemberAPI))
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	const maxJSON = 4 << 20
	var body io.Reader = http.MaxBytesReader(nil, r.Body, maxJSON)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = io.LimitReader(gz, maxJSON) // cap the decompressed size too (gzip bomb)
	}
	return json.NewDecoder(body).Decode(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func (s *Server) withDevice(h func(http.ResponseWriter, *http.Request, *Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		var dev *Device
		s.st.mu.Lock()
		if tok != "" {
			for _, d := range s.st.D.Devices {
				if d.Token == tok {
					dev = d
					break
				}
			}
		}
		s.st.mu.Unlock()
		if dev == nil {
			writeErr(w, http.StatusUnauthorized, "invalid device token")
			return
		}
		h(w, r, dev)
	}
}

// currentSaved computes the device's effective config and persists if its revision
// advanced. Caller must hold the store lock.
func (s *Server) currentSaved(dev *Device) proto.EffectiveConfig {
	old := dev.EffEtag
	cfg := s.st.current(dev)
	if dev.EffEtag != old {
		s.st.saveDevice(dev)
	}
	return cfg
}

func (s *Server) reachability(dev *Device) string {
	if dev.LastSeen.IsZero() {
		return "offline"
	}
	since := time.Since(dev.LastSeen)
	switch {
	case since < s.opts.CheckinInterval*5/2:
		return "online"
	case since < s.opts.CheckinInterval*6:
		return "stale"
	}
	return "offline"
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// ---------------------------------------------------------------- device API

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t, ok := s.st.D.Tokens[req.Token]
	if !ok || t.Used || time.Now().After(t.ExpiresAt) {
		writeErr(w, http.StatusUnauthorized, "invalid or expired enrollment token")
		return
	}
	t.Used = true
	s.st.saveToken(t)
	name := req.Name
	if name == "" {
		name = req.Hostname
	}
	dev := &Device{
		ID: "dev_" + NewToken(4), Project: t.Project, Name: name, Hostname: req.Hostname,
		OS: req.OS, Arch: req.Arch, AgentVersion: req.AgentVersion, Tags: t.Tags,
		Token: NewToken(24), EnrolledAt: time.Now().UTC(),
	}
	s.st.D.Devices[dev.ID] = dev
	s.st.saveDevice(dev)
	s.st.appendEvents(dev.ID, []proto.Event{{Type: "device.enrolled", Message: "enrolled from " + req.Hostname}})
	key := s.signer.Current()
	writeJSON(w, http.StatusCreated, proto.EnrollResponse{
		DeviceID: dev.ID, DeviceToken: dev.Token, Project: dev.Project, Tags: dev.Tags,
		CheckinIntervalS: int(s.opts.CheckinInterval / time.Second), Signing: &key,
	})
}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request, dev *Device) {
	var req proto.CheckinRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()

	now := time.Now().UTC()
	dev.LastSeen = now
	if req.AgentVersion != "" {
		dev.AgentVersion = req.AgentVersion
	}
	dev.ReportedRevision = req.ConfigRevision
	if req.App != nil {
		dev.App = req.App
	}
	if req.System != nil {
		dev.System = req.System
	}
	dev.BytesIn, dev.BytesOut = req.BytesIn, req.BytesOut // agent-reported, current budget cycle
	dev.BudgetMB, dev.BudgetState = req.BudgetMB, req.BudgetState
	if req.Trust != nil {
		dev.Trust = req.Trust
	}

	if req.Session != dev.Session { // new agent run: its seq counter started over
		dev.Session, dev.LastSeq = req.Session, 0
	}
	if req.Seq > dev.LastSeq { // retries of an already-seen check-in must not double count
		dev.LastSeq = req.Seq
		dev.Restarts += req.RestartsSinceLast
		s.st.appendEvents(dev.ID, req.Events)
	}

	cfg := s.currentSaved(dev)
	resp := proto.CheckinResponse{
		ServerTime:      now,
		DesiredRevision: cfg.Revision,
		DesiredEtag:     cfg.Etag,
		ConfigChanged:   cfg.Etag != req.ConfigEtag,
		NextCheckinS:    int(s.opts.CheckinInterval / time.Second),
		Profile:         "normal",
		Commands:        s.dispatchCommands(dev, now),
	}
	s.st.saveDevice(dev)
	writeJSON(w, http.StatusOK, resp)
}

// dispatchCommands returns non-terminal, unexpired commands (re-sent until a result
// arrives, so a lost response can't drop one) and expires stale ones.
func (s *Server) dispatchCommands(dev *Device, now time.Time) []proto.Command {
	var out []proto.Command
	for i := range dev.Commands {
		c := &dev.Commands[i]
		if c.Status != "queued" && c.Status != "delivered" {
			continue
		}
		if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
			c.Status = "expired"
			continue
		}
		c.Status = "delivered"
		if c.Signed == nil { // sign once; the same signed command is re-sent until its result arrives
			if env, err := s.signer.SignCommand(dev.ID, *c); err == nil {
				c.Signed = env
			}
		}
		out = append(out, *c)
	}
	return out
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request, dev *Device) {
	inm := strings.Trim(r.Header.Get("If-None-Match"), `"`)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait < 0 {
		wait = 0
	} else if wait > 60 {
		wait = 60
	}
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()

	for {
		s.st.mu.Lock()
		dev.LastSeen = time.Now().UTC()
		cfg := s.currentSaved(dev)
		ch := s.st.changed
		s.st.mu.Unlock()

		if cfg.Etag != inm {
			w.Header().Set("ETag", `"`+cfg.Etag+`"`)
			// An agent that verifies signatures asks for the signed form; older agents get the
			// plain config as before. (A strict agent refuses the plain form, so a network
			// attacker gains nothing by stripping the Accept header.)
			if strings.Contains(r.Header.Get("Accept"), signing.ContentType) {
				env, err := s.signer.SignConfig(dev.ID, dev.Project, cfg)
				if err != nil {
					writeErr(w, http.StatusInternalServerError, "could not sign the config")
					return
				}
				w.Header().Set("Content-Type", signing.ContentType)
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(env)
				return
			}
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

func (s *Server) configAck(w http.ResponseWriter, r *http.Request, dev *Device) {
	var ack proto.ConfigAck
	if err := readJSON(r, &ack); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if ack.OK {
		dev.ReportedRevision = ack.Revision
		s.st.saveDevice(dev)
	} else {
		s.st.appendEvents(dev.ID, []proto.Event{{
			Type: "config.apply_failed", Level: "error", Message: ack.Error,
			Data: map[string]any{"revision": ack.Revision, "rolled_back_to": ack.RolledBackTo},
		}})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putStatus(w http.ResponseWriter, r *http.Request, dev *Device) {
	var st proto.AppStatus
	if err := readJSON(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	dev.App = &st
	dev.LastSeen = time.Now().UTC()
	s.st.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postEvents(w http.ResponseWriter, r *http.Request, dev *Device) {
	var body struct {
		Events []proto.Event `json:"events"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	s.st.appendEvents(dev.ID, body.Events)
	s.st.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postMetrics(w http.ResponseWriter, r *http.Request, dev *Device) {
	var body struct {
		Metrics []proto.Metric `json:"metrics"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	s.st.appendMetrics(dev.ID, body.Metrics)
	s.st.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) getCommands(w http.ResponseWriter, r *http.Request, dev *Device) {
	s.st.mu.Lock()
	cmds := s.dispatchCommands(dev, time.Now().UTC())
	s.st.saveDevice(dev)
	s.st.mu.Unlock()
	if cmds == nil {
		cmds = []proto.Command{}
	}
	writeJSON(w, http.StatusOK, cmds)
}

func (s *Server) commandResult(w http.ResponseWriter, r *http.Request, dev *Device) {
	var res proto.CommandResult
	if err := readJSON(r, &res); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	for i := range dev.Commands {
		c := &dev.Commands[i]
		if c.ID != id {
			continue
		}
		c.Status = "failed"
		if res.OK {
			c.Status = "succeeded"
		}
		if c.Params == nil {
			c.Params = map[string]any{}
		}
		c.Params["result"] = res.Output
		s.st.saveDevice(dev)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeErr(w, http.StatusNotFound, "no such command")
}

// ---------------------------------------------------------------- admin API

// listProjects returns only the projects the caller has a role in, each with that role.
func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.visibleProjects(principalOf(r).User))
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || slug(body.Name) == "" || len(body.Name) > maxProjectName {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("give the project a name of 1 to %d characters with at least one letter or digit", maxProjectName))
		return
	}
	p := &Project{ID: slug(body.Name), Name: body.Name}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if old, ok := s.st.D.Projects[p.ID]; ok {
		writeErr(w, http.StatusConflict, fmt.Sprintf("a project with the id %q already exists (%s)", p.ID, old.Name))
		return
	}
	s.st.D.Projects[p.ID] = p
	s.st.saveProject(p)
	s.audit(r, "project.created", p.ID, p.Name, "")
	writeJSON(w, http.StatusCreated, p)
}

const maxProjectName = 80

// renameProject changes the display name only: the id stays, so enrolled devices, tokens
// and links keep working.
func (s *Server) renameProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > maxProjectName {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("give the project a name of 1 to %d characters", maxProjectName))
		return
	}
	id := r.PathValue("project")
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	p, ok := s.st.D.Projects[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "no such project")
		return
	}
	old := p.Name
	p.Name = body.Name
	s.st.saveProject(p)
	s.audit(r, "project.renamed", id, body.Name, "was "+old)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	var body struct {
		Tags     []string `json:"tags"`
		TTLHours int      `json:"ttl_hours"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if body.TTLHours <= 0 {
		body.TTLHours = 72
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if _, ok := s.st.D.Projects[project]; !ok {
		writeErr(w, http.StatusNotFound, "no such project")
		return
	}
	t := &EnrollToken{
		Token: NewToken(12), Project: project, Tags: body.Tags,
		ExpiresAt: time.Now().Add(time.Duration(body.TTLHours) * time.Hour).UTC(),
	}
	s.st.D.Tokens[t.Token] = t
	s.st.saveToken(t)
	s.audit(r, "enrollment_token.created", project, "", strings.Join(body.Tags, ","))
	key := s.signer.Current()
	writeJSON(w, http.StatusCreated, map[string]any{"token": t.Token, "expires_at": t.ExpiresAt, "server_key": key.Public, "key_id": key.KeyID})
}

func (s *Server) summary(dev *Device) proto.DeviceSummary {
	cfg := s.currentSaved(dev)
	sum := proto.DeviceSummary{
		ID: dev.ID, Name: dev.Name, Hostname: dev.Hostname, OS: dev.OS, Tags: dev.Tags,
		AgentVersion: dev.AgentVersion, Reachability: s.reachability(dev), LastSeenAt: dev.LastSeen,
		DesiredRevision: cfg.Revision, ReportedRevision: dev.ReportedRevision,
		InSync: cfg.Revision == dev.ReportedRevision, Restarts: dev.Restarts,
		BudgetState: dev.BudgetState,
	}
	if dev.App != nil {
		sum.AppState, sum.AppMessage = dev.App.State, dev.App.Message
	}
	sum.SignatureState = signatureState(dev.Trust)
	return sum
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	out := []proto.DeviceSummary{}
	for _, d := range s.st.D.Devices {
		if d.Project == project {
			out = append(out, s.summary(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

// deviceFor looks up a device in the URL's project. Caller holds the store lock.
func (s *Server) deviceFor(w http.ResponseWriter, r *http.Request) *Device {
	d, ok := s.st.D.Devices[r.PathValue("device")]
	if !ok || d.Project != r.PathValue("project") {
		writeErr(w, http.StatusNotFound, "no such device")
		return nil
	}
	return d
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if d := s.deviceFor(w, r); d != nil {
		writeJSON(w, http.StatusOK, s.summary(d))
	}
}

func (s *Server) getDeviceDetail(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	cmds := append([]proto.Command{}, d.Commands...)
	for i, j := 0, len(cmds)-1; i < j; i, j = i+1, j-1 { // newest first
		cmds[i], cmds[j] = cmds[j], cmds[i]
	}
	eff := s.currentSaved(d)
	if s.roleFor(r) < RoleOperator {
		eff.Supervisor = redactForViewer(eff.Supervisor)
	}
	writeJSON(w, http.StatusOK, proto.DeviceDetail{
		DeviceSummary: s.summary(d), Arch: d.Arch, EnrolledAt: d.EnrolledAt,
		App: d.App, System: d.System, BytesIn: d.BytesIn, BytesOut: d.BytesOut, BudgetMB: d.BudgetMB,
		Effective: eff, Trust: d.Trust, Events: s.st.listEvents(d.ID, 100),
		Commands: cmds, Metrics: s.st.latestMetrics(d.ID),
	})
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	var p proto.DevicePatch
	if err := readJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if p.Name != nil && strings.TrimSpace(*p.Name) != "" {
		d.Name = strings.TrimSpace(*p.Name)
	}
	if p.Tags != nil {
		tags := []string{}
		for _, t := range *p.Tags {
			if t = slug(t); t != "" {
				tags = append(tags, t)
			}
		}
		d.Tags = tags
	}
	s.st.saveDevice(d)
	s.st.notifyChanged() // tags change the effective config; wake long-pollers
	s.audit(r, "device.updated", d.Project, d.Name, "tags="+strings.Join(d.Tags, ","))
	writeJSON(w, http.StatusOK, s.summary(d))
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	s.st.deleteDevice(d.ID)
	s.audit(r, "device.deleted", d.Project, d.Name, d.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getDeviceMetrics(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name query parameter required")
		return
	}
	writeJSON(w, http.StatusOK, s.st.metricSeries(d.ID, name, limit))
}

// validatePolicies rejects unknown fields and out-of-range values in the agent-consumed
// sections, so a typo is an error when saved rather than a silently ignored setting.
func validatePolicies(doc *proto.ConfigDocument) error {
	if s := doc.Supervisor; s != nil && (s.QuitTimeoutS < 0 || s.QuitTimeoutS > 600) {
		return errors.New("supervisor.quit_timeout_s must be between 0 and 600")
	}
	if len(doc.Screenshots) > 0 {
		var p proto.ScreenshotPolicy
		if err := decodeStrict(doc.Screenshots, &p); err != nil {
			return fmt.Errorf("screenshots: %v", err)
		}
		switch {
		case p.IntervalS != 0 && p.IntervalS < 10:
			return errors.New("screenshots.interval_s must be at least 10")
		case p.MaxWidth != 0 && (p.MaxWidth < 64 || p.MaxWidth > 7680):
			return errors.New("screenshots.max_width must be between 64 and 7680")
		case p.Quality != 0 && (p.Quality < 1 || p.Quality > 100):
			return errors.New("screenshots.quality must be between 1 and 100")
		case p.UnchangedEveryS < 0:
			return errors.New("screenshots.unchanged_every_s cannot be negative")
		}
	}
	if len(doc.Budget) > 0 {
		var b proto.BudgetPolicy
		if err := decodeStrict(doc.Budget, &b); err != nil {
			return fmt.Errorf("budget: %v", err)
		}
		switch {
		case b.MonthlyMB < 0:
			return errors.New("budget.monthly_mb cannot be negative")
		case b.ResetDay != 0 && (b.ResetDay < 1 || b.ResetDay > 28):
			return errors.New("budget.reset_day must be between 1 and 28")
		case b.SoftPct != 0 && (b.SoftPct < 1 || b.SoftPct > 99):
			return errors.New("budget.soft_pct must be between 1 and 99")
		}
	}
	return nil
}

func validScope(scope string) bool {
	return scope == "global" || strings.HasPrefix(scope, "tag:") && len(scope) > 4 || strings.HasPrefix(scope, "device:") && len(scope) > 7
}

// forRole is a copy of a stored layer as the caller may see it.
func forRole(doc *proto.ConfigDocument, role Role) *proto.ConfigDocument {
	if role >= RoleOperator || doc.Supervisor == nil {
		return doc
	}
	c := *doc
	c.Supervisor = redactForViewer(doc.Supervisor)
	return &c
}

func supervisorDiffers(a, b *proto.SupervisorConfig) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) != string(y)
}

// The supervisor section decides which program the agent runs on a machine, so changing it
// is more than a settings change: it needs the project admin role.
const needAdminForSupervisor = "changing the supervisor section decides which program runs on the machines, so it needs the project admin role"

func (s *Server) listConfigDocs(w http.ResponseWriter, r *http.Request) {
	prefix := r.PathValue("project") + "|"
	role := s.roleFor(r)
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	out := map[string]*proto.ConfigDocument{}
	for k, doc := range s.st.D.Configs {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = forRole(doc, role)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putConfigDoc(w http.ResponseWriter, r *http.Request) {
	project, scope := r.PathValue("project"), r.PathValue("scope")
	var doc proto.ConfigDocument
	if err := readJSON(r, &doc); err != nil || doc.Data == nil {
		writeErr(w, http.StatusBadRequest, "body must be {\"data\": {...}}")
		return
	}
	if !validScope(scope) {
		writeErr(w, http.StatusBadRequest, "scope must be global, tag:<name> or device:<id>")
		return
	}
	switch doc.ReloadMode {
	case "", "none", "watch", "trigger", "restart":
	default:
		writeErr(w, http.StatusBadRequest, "reload_mode must be none, watch, trigger or restart")
		return
	}
	if err := validatePolicies(&doc); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if _, ok := s.st.D.Projects[project]; !ok {
		writeErr(w, http.StatusNotFound, "no such project")
		return
	}
	var before *proto.SupervisorConfig
	if old, ok := s.st.D.Configs[project+"|"+scope]; ok {
		before = old.Supervisor
	}
	if supervisorDiffers(before, doc.Supervisor) && s.roleFor(r) < RoleAdmin {
		s.audit(r, "config.denied", project, scope, "tried to change the supervisor section")
		writeErr(w, http.StatusForbidden, needAdminForSupervisor)
		return
	}
	s.st.D.Configs[project+"|"+scope] = &doc
	s.st.saveConfig(project+"|"+scope, &doc)
	s.st.notifyChanged()
	s.audit(r, "config.put", project, scope, configSummary(&doc))
	writeJSON(w, http.StatusOK, doc)
}

// configSummary says what a layer contains, for the audit log. Never the values themselves.
func configSummary(doc *proto.ConfigDocument) string {
	var parts []string
	if len(doc.Data) > 0 {
		parts = append(parts, fmt.Sprintf("%d data keys", len(doc.Data)))
	}
	if doc.Supervisor != nil {
		parts = append(parts, "supervisor")
	}
	if len(doc.Screenshots) > 0 {
		parts = append(parts, "screenshots")
	}
	if len(doc.Budget) > 0 {
		parts = append(parts, "budget")
	}
	if doc.ReloadMode != "" {
		parts = append(parts, "reload="+doc.ReloadMode)
	}
	return strings.Join(parts, ", ")
}

func (s *Server) getConfigDoc(w http.ResponseWriter, r *http.Request) {
	role := s.roleFor(r)
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	doc, ok := s.st.D.Configs[r.PathValue("project")+"|"+r.PathValue("scope")]
	if !ok {
		writeErr(w, http.StatusNotFound, "no config for scope")
		return
	}
	writeJSON(w, http.StatusOK, forRole(doc, role))
}

func (s *Server) deleteConfigDoc(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("project") + "|" + r.PathValue("scope")
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	doc, ok := s.st.D.Configs[key]
	if !ok {
		writeErr(w, http.StatusNotFound, "no config for scope")
		return
	}
	if doc.Supervisor != nil && s.roleFor(r) < RoleAdmin { // deleting it removes a supervisor section
		s.audit(r, "config.denied", r.PathValue("project"), r.PathValue("scope"), "tried to delete a layer with a supervisor section")
		writeErr(w, http.StatusForbidden, needAdminForSupervisor)
		return
	}
	s.st.deleteConfig(key)
	s.st.notifyChanged()
	s.audit(r, "config.deleted", r.PathValue("project"), r.PathValue("scope"), "")
	w.WriteHeader(http.StatusNoContent)
}

// Commands an operator may send. Anything else (reboot, running a script, types this server
// does not know yet) can do more than restart the app, so it needs the project admin role.
var operatorCommands = map[string]bool{"restart_app": true, "capture_screenshot": true, "checkin_now": true}

func (s *Server) queueCommand(w http.ResponseWriter, r *http.Request) {
	var req proto.CommandRequest
	if err := readJSON(r, &req); err != nil || req.Type == "" {
		writeErr(w, http.StatusBadRequest, "type required")
		return
	}
	if !operatorCommands[req.Type] && s.roleFor(r) < RoleAdmin {
		s.audit(r, "command.denied", r.PathValue("project"), r.PathValue("device"), req.Type)
		writeErr(w, http.StatusForbidden, fmt.Sprintf("the %q command needs the project admin role", req.Type))
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	var err error // scripts and releases: the signed parameters come from the library, not from the caller
	if req.Params, req.TTLS, err = s.resolveCommand(d, req.Type, req.Params, req.TTLS); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "command.queued", d.Project, d.Name, req.Type)
	writeJSON(w, http.StatusCreated, s.enqueueLocked(d, req.Type, req.Params, req.TTLS))
}

// enqueueLocked adds an already-resolved command to a device's queue. Caller holds s.st.mu.
func (s *Server) enqueueLocked(d *Device, typ string, params map[string]any, ttlS int) proto.Command {
	if ttlS <= 0 {
		ttlS = 3600
	}
	c := proto.Command{
		ID: "cmd_" + NewToken(4), Type: typ, Params: params, Status: "queued",
		ExpiresAt: time.Now().Add(time.Duration(ttlS) * time.Second).UTC(),
	}
	d.Commands = append(d.Commands, c)
	if n := len(d.Commands); n > 50 { // keep recent history only
		d.Commands = d.Commands[n-50:]
	}
	s.st.saveDevice(d)
	return c
}

// resolveCommand turns a request into the parameters that will be signed. Caller holds s.st.mu.
func (s *Server) resolveCommand(d *Device, typ string, params map[string]any, ttlS int) (map[string]any, int, error) {
	switch typ {
	case "run_script":
		p, err := s.resolveRunScript(d.Project, params)
		return p, ttlS, err
	case "apply_release":
		p, err := s.resolveApplyRelease(d, params)
		if ttlS < 600 {
			ttlS = 6 * 3600 // a download over a poor link takes a while
		}
		return p, ttlS, err
	}
	return params, ttlS, nil
}

// ---------------------------------------------------------------- signing keys

func signatureState(t *proto.TrustReport) string {
	switch {
	case t == nil:
		return "unknown"
	case t.State == "legacy":
		return "legacy"
	case !t.LastRejectedAt.IsZero() && t.LastRejectedAt.After(t.LastAcceptedAt) && time.Since(t.LastRejectedAt) < 24*time.Hour:
		return "rejecting"
	}
	return "strict"
}

// deviceKeys lets an agent learn the server's keys and the endorsement chain between them,
// which is how it follows a rotation. The keys are public.
func (s *Server) deviceKeys(w http.ResponseWriter, r *http.Request, dev *Device) {
	writeJSON(w, http.StatusOK, s.signer.KeySet())
}

// serverKey is the current public key, open to anyone, so an agent can compare it with its
// pin before it hands over a one-time enrollment token.
func (s *Server) serverKey(w http.ResponseWriter, r *http.Request) {
	ks := s.signer.KeySet()
	for _, k := range ks.Keys {
		if k.KeyID == ks.Current {
			k.Endorsement = nil
			writeJSON(w, http.StatusOK, k)
			return
		}
	}
	writeErr(w, http.StatusInternalServerError, "no current key")
}

func (s *Server) getSigning(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.signer.KeySet())
}

func (s *Server) rotateSigning(w http.ResponseWriter, r *http.Request) {
	kid, err := s.signer.Rotate()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rotation failed: "+err.Error())
		return
	}
	s.audit(r, "signing.rotated", "", kid, "")
	writeJSON(w, http.StatusOK, s.signer.KeySet())
}
