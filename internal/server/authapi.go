package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"remoteconfig/internal/proto"
)

// ---------------------------------------------------------------- who is calling

type principalKey struct{}

// Principal is the authenticated caller of an admin API request.
type Principal struct {
	User    *User
	Session *Session
}

func principalOf(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalKey{}).(*Principal)
	return p
}

// authenticate resolves the bearer token. Failures are all the same 401 to the caller;
// only the log would know whether the token was unknown, expired or the account disabled.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	u, sess, err := s.st.lookupToken(bearer(r))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "sign in required")
		return nil, false
	}
	return &Principal{User: u, Session: sess}, true
}

func withPrincipal(r *http.Request, p *Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

// anyUser: any signed-in account.
func (s *Server) anyUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		h(w, withPrincipal(r, p))
	}
}

// serverAdmin: accounts flagged as server administrators.
func (s *Server) serverAdmin(h http.HandlerFunc) http.HandlerFunc {
	return s.anyUser(func(w http.ResponseWriter, r *http.Request) {
		if !principalOf(r).User.IsAdmin {
			writeErr(w, http.StatusForbidden, "this needs a server administrator")
			return
		}
		h(w, r)
	})
}

// project: at least `min` in the project named by the {project} path segment. A project
// the caller has no role in answers 404, as if it did not exist, rather than 403.
func (s *Server) project(min Role, h http.HandlerFunc) http.HandlerFunc {
	return s.anyUser(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		role := s.st.roleIn(p.User, r.PathValue("project"))
		if role == RoleNone {
			writeErr(w, http.StatusNotFound, "no such project")
			return
		}
		if role < min {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("this needs the %q role in this project (you are %s)", min, role))
			return
		}
		h(w, r)
	})
}

// roleFor is the caller's role in the request's project.
func (s *Server) roleFor(r *http.Request) Role {
	return s.st.roleIn(principalOf(r).User, r.PathValue("project"))
}

func (s *Server) audit(r *http.Request, action, project, target, detail string) {
	var u *User
	if p := principalOf(r); p != nil {
		u = p.User
	}
	s.st.Audit(u, action, project, target, detail)
}

// redactForViewer hides what a read-only user has no business reading: environment variables
// handed to the supervised program often carry keys.
func redactForViewer(sup *proto.SupervisorConfig) *proto.SupervisorConfig {
	if sup == nil || len(sup.Env) == 0 {
		return sup
	}
	c := *sup
	c.Env = map[string]string{}
	for k := range sup.Env {
		c.Env[k] = "(hidden)"
	}
	return &c
}

// ---------------------------------------------------------------- login throttling

// loginThrottle slows password guessing: five failures for one account from one address,
// or thirty from one address, lock that key for fifteen minutes.
type loginThrottle struct {
	mu   sync.Mutex
	fail map[string]*throttleEntry
}

type throttleEntry struct {
	count int
	until time.Time
	first time.Time
}

const (
	throttleWindow   = 15 * time.Minute
	throttlePerUser  = 5
	throttlePerAddr  = 30
	throttleLockTime = 15 * time.Minute
)

func newLoginThrottle() *loginThrottle { return &loginThrottle{fail: map[string]*throttleEntry{}} }

func (t *loginThrottle) keys(username, ip string) []string {
	return []string{"u|" + normUsername(username) + "|" + ip, "ip|" + ip}
}

// wait returns how long the caller must wait, or 0.
func (t *loginThrottle) wait(username, ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var longest time.Duration
	for _, k := range t.keys(username, ip) {
		if e := t.fail[k]; e != nil && time.Now().Before(e.until) {
			longest = max(longest, time.Until(e.until))
		}
	}
	return longest
}

func (t *loginThrottle) failed(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for i, k := range t.keys(username, ip) {
		e := t.fail[k]
		if e == nil || now.Sub(e.first) > throttleWindow {
			e = &throttleEntry{first: now}
			t.fail[k] = e
		}
		e.count++
		limit := throttlePerUser
		if i == 1 {
			limit = throttlePerAddr
		}
		if e.count >= limit {
			e.until = now.Add(throttleLockTime)
		}
	}
	if len(t.fail) > 5000 { // bounded memory under a spray from many addresses
		for k, e := range t.fail {
			if now.Sub(e.first) > throttleWindow && now.After(e.until) {
				delete(t.fail, k)
			}
		}
	}
}

func (t *loginThrottle) succeeded(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fail, t.keys(username, ip)[0])
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------- login, logout, me

type userView struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	Disabled    bool      `json:"disabled"`
	HasPassword bool      `json:"has_password"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
}

func viewOf(u *User) userView {
	return userView{u.ID, u.Username, u.DisplayName, u.IsAdmin, u.Disabled, u.HasPassword, u.CreatedAt, u.LastLogin}
}

type projectView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"` // the caller's role in it
}

// visibleProjects lists the projects the user can see, with their role in each.
func (s *Server) visibleProjects(u *User) []projectView {
	roles := s.st.rolesOf(u)
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	out := []projectView{}
	for id, p := range s.st.D.Projects {
		role := roles[id]
		if u.IsAdmin {
			role = RoleAdmin
		}
		if role != RoleNone {
			out = append(out, projectView{id, p.Name, role.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	ip := remoteIP(r)
	if wait := s.throttle.wait(req.Username, ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		s.st.Audit(nil, "login.blocked", "", normUsername(req.Username), ip)
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}
	u, ok := s.st.Verify(req.Username, req.Password)
	if !ok {
		s.throttle.failed(req.Username, ip)
		s.st.Audit(nil, "login.failed", "", normUsername(req.Username), ip)
		writeErr(w, http.StatusUnauthorized, "wrong username or password") // same answer for unknown user, wrong password, disabled
		return
	}
	s.throttle.succeeded(req.Username, ip)
	token, sess, err := s.st.createSession(u, "session", "dashboard", r.UserAgent(), sessionMaxAge)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	s.st.touchLogin(u)
	s.st.Audit(u, "login.ok", "", "", ip)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": sess.ExpiresAt, "user": viewOf(u), "projects": s.visibleProjects(u)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if p.Session.Kind == "session" {
		s.st.revokeSessionByHash(p.Session.hash)
	}
	s.st.Audit(p.User, "logout", "", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := principalOf(r).User
	writeJSON(w, http.StatusOK, map[string]any{"user": viewOf(u), "projects": s.visibleProjects(u)})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := s.st.Verify(p.User.Username, req.Current); !ok {
		writeErr(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	// every other dashboard session is signed out; the one making this request stays
	if err := s.st.setPasswordKeeping(p.User, req.New, p.Session.hash); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(p.User, "password.changed", "", "", "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- personal access tokens

func (s *Server) listMyTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.st.listAPITokens(principalOf(r).User.ID))
}

func (s *Server) createMyToken(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Name    string `json:"name"`
		TTLDays int    `json:"ttl_days"`
	}
	if err := readJSON(r, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if req.TTLDays < 0 || req.TTLDays > 3650 {
		writeErr(w, http.StatusBadRequest, "ttl_days must be between 0 (never expires) and 3650")
		return
	}
	token, sess, err := s.st.createSession(p.User, "api", strings.TrimSpace(req.Name), r.UserAgent(), time.Duration(req.TTLDays)*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create the token")
		return
	}
	s.st.Audit(p.User, "token.created", "", sess.ID, sess.Name)
	// The token is shown this once; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"id": sess.ID, "name": sess.Name, "token": token, "expires_at": sess.ExpiresAt})
}

func (s *Server) deleteMyToken(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !s.st.revokeToken(p.User.ID, r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "no such token")
		return
	}
	s.st.Audit(p.User, "token.revoked", "", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- user management (server admins)

func (s *Server) listUsersAPI(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.listUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		userView
		Projects map[string]string `json:"projects"`
	}
	out := []row{}
	for i := range users {
		roles := map[string]string{}
		for proj, role := range s.st.rolesOf(&users[i]) {
			roles[proj] = role.String()
		}
		out = append(out, row{viewOf(&users[i]), roles})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUserAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"is_admin"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password required")
		return
	}
	u, err := s.st.CreateUser(req.Username, req.DisplayName, req.Password, req.IsAdmin)
	switch {
	case errors.Is(err, ErrExists):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "user.created", "", u.Username, "admin="+strconv.FormatBool(u.IsAdmin))
	writeJSON(w, http.StatusCreated, viewOf(u))
}

func (s *Server) userFor(w http.ResponseWriter, r *http.Request) *User {
	u, err := s.st.userByName(r.PathValue("username"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such user")
		return nil
	}
	return u
}

func (s *Server) patchUserAPI(w http.ResponseWriter, r *http.Request) {
	u := s.userFor(w, r)
	if u == nil {
		return
	}
	var patch UserPatch
	if err := readJSON(r, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.updateUser(u, patch); err != nil {
		switch {
		case errors.Is(err, ErrLastAdmin):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	var what []string
	if patch.IsAdmin != nil {
		what = append(what, "admin="+strconv.FormatBool(*patch.IsAdmin))
	}
	if patch.Disabled != nil {
		what = append(what, "disabled="+strconv.FormatBool(*patch.Disabled))
	}
	if patch.Password != nil {
		what = append(what, "password reset")
	}
	if patch.DisplayName != nil {
		what = append(what, "display name")
	}
	s.audit(r, "user.updated", "", u.Username, strings.Join(what, ", "))
	updated, _ := s.st.userByID(u.ID)
	writeJSON(w, http.StatusOK, viewOf(updated))
}

func (s *Server) deleteUserAPI(w http.ResponseWriter, r *http.Request) {
	u := s.userFor(w, r)
	if u == nil {
		return
	}
	if u.ID == principalOf(r).User.ID {
		writeErr(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := s.st.deleteUser(u); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			writeErr(w, http.StatusConflict, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.audit(r, "user.deleted", "", u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- project members (project admins)

func (s *Server) listMembersAPI(w http.ResponseWriter, r *http.Request) {
	m, err := s.st.listMembers(r.PathValue("project"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) putMemberAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role string `json:"role"`
	}
	role, ok := RoleNone, false
	if err := readJSON(r, &req); err == nil {
		role, ok = ParseRole(req.Role)
	}
	if !ok {
		writeErr(w, http.StatusBadRequest, "role must be viewer, operator or admin")
		return
	}
	u := s.userFor(w, r)
	if u == nil {
		return
	}
	project := r.PathValue("project")
	if err := s.st.setMember(project, u, role); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "member.set", project, u.Username, role.String())
	writeJSON(w, http.StatusOK, Member{Username: u.Username, DisplayName: u.DisplayName, Role: role.String(), Disabled: u.Disabled})
}

func (s *Server) deleteMemberAPI(w http.ResponseWriter, r *http.Request) {
	u := s.userFor(w, r)
	if u == nil {
		return
	}
	project := r.PathValue("project")
	if err := s.st.removeMember(project, u); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "member.removed", project, u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- audit

func (s *Server) listAuditAPI(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	project := r.URL.Query().Get("project")
	switch {
	case project == "" && !p.User.IsAdmin:
		writeErr(w, http.StatusForbidden, "name a project (?project=...); the whole log is for server administrators")
		return
	case project != "" && s.st.roleIn(p.User, project) == RoleNone:
		writeErr(w, http.StatusNotFound, "no such project")
		return
	case project != "" && s.st.roleIn(p.User, project) < RoleAdmin:
		writeErr(w, http.StatusForbidden, "the audit log needs the project admin role")
		return
	}
	writeJSON(w, http.StatusOK, s.st.listAudit(project, limit))
}
