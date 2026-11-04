package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

// ---------------------------------------------------------------- fixture

type authFixture struct {
	t   *testing.T
	st  *Store
	h   http.Handler
	dev proto.EnrollResponse // a device in project "demo"
	tok map[string]string    // username -> a dashboard token
}

func newAuthFixture(t *testing.T) *authFixture {
	st, err := OpenStore("", "adm") // "adm" is the bootstrap token of the "admin" server administrator
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{"a": 1.0}})
	st.Seed("other", "Other", &proto.ConfigDocument{Data: map[string]any{}})
	h := New(st, Options{CheckinInterval: time.Minute}).Handler()
	return &authFixture{t: t, st: st, h: h, dev: enrollDevice(t, st, h), tok: map[string]string{}}
}

// user makes an account and gives it a dashboard session token.
func (f *authFixture) user(name string, admin bool, roles map[string]Role) string {
	f.t.Helper()
	u, err := f.st.CreateUser(name, "", "correct horse battery", admin)
	if err != nil {
		f.t.Fatal(err)
	}
	for project, role := range roles {
		if err := f.st.setMember(project, u, role); err != nil {
			f.t.Fatal(err)
		}
	}
	token, _, err := f.st.createSession(u, "session", "test", "", sessionMaxAge)
	if err != nil {
		f.t.Fatal(err)
	}
	f.tok[name] = token
	return token
}

func (f *authFixture) call(method, path, token string, body any) (int, map[string]any, http.Header) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.10:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

func (f *authFixture) login(user, pass string) (int, map[string]any) {
	code, out, _ := f.call("POST", "/v1/auth/login", "", map[string]string{"username": user, "password": pass})
	return code, out
}

const A = "/v1/admin/projects/demo"

// ---------------------------------------------------------------- passwords

func TestPasswordsAreHashedSaltedAndVerifiable(t *testing.T) {
	h1, _ := hashPassword("correct horse battery")
	h2, _ := hashPassword("correct horse battery")
	if h1 == h2 {
		t.Fatal("two hashes of one password are identical: no salt")
	}
	if !strings.HasPrefix(h1, "pbkdf2-sha256$1000$") || strings.Contains(h1, "correct") {
		t.Fatalf("unexpected hash format: %s", h1)
	}
	if !checkPassword(h1, "correct horse battery") || checkPassword(h1, "correct horse batter") || checkPassword(h1, "") {
		t.Fatal("verification wrong")
	}
	// a hash made at another cost still verifies, so the cost can be raised later
	old := passwordCost
	passwordCost = 2000
	h3, _ := hashPassword("another passphrase")
	passwordCost = old
	if !checkPassword(h3, "another passphrase") || checkPassword(h3, "nope") {
		t.Fatal("hash at a different cost no longer verifies")
	}
	for _, bad := range []string{"", "pbkdf2-sha256$x$a$b", "md5$1$a$b", "pbkdf2-sha256$1000$!!$!!"} {
		if checkPassword(bad, "x") {
			t.Fatalf("garbage hash %q accepted", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	for pw, ok := range map[string]bool{"short": false, "ninechars": false, "tencharsok": true, strings.Repeat("x", 201): false, "alice-is-in-here": false, "a perfectly fine passphrase": true} {
		if err := validPassword("alice", pw); (err == nil) != ok {
			t.Errorf("validPassword(%q) = %v, want ok=%v", pw, err, ok)
		}
	}
}

// ---------------------------------------------------------------- login

func TestLoginSucceedsAndTheTokenIsNeverStoredInTheClear(t *testing.T) {
	f := newAuthFixture(t)
	f.user("alice", false, map[string]Role{"demo": RoleViewer})

	code, out := f.login("Alice", "correct horse battery") // usernames are case-insensitive
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	token := out["token"].(string)
	if !strings.HasPrefix(token, "rcs_") || out["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("unexpected login result: %v", out)
	}
	if code, _, _ := f.call("GET", A+"/devices", token, nil); code != 200 {
		t.Fatalf("the new token does not work: %d", code)
	}
	var n int
	f.st.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE hash=? OR id=?`, token, token).Scan(&n)
	if n != 0 {
		t.Fatal("the session token is stored in the clear")
	}
	f.st.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE hash=?`, hashToken(token)).Scan(&n)
	if n != 1 {
		t.Fatal("its hash should be stored")
	}
}

func TestLoginFailuresAllLookAlike(t *testing.T) {
	f := newAuthFixture(t)
	f.user("alice", false, nil)
	f.user("dave", false, nil)
	f.st.UpdateUser("dave", UserPatch{Disabled: ptr(true)})
	f.st.CreateUser("robot", "", "", false) // token-only: has no password

	var msgs []string
	for _, c := range [][2]string{{"alice", "wrong password!!"}, {"nobody", "correct horse battery"}, {"dave", "correct horse battery"}, {"robot", "anything at all"}} {
		code, out := f.login(c[0], c[1])
		if code != 401 {
			t.Fatalf("%v: want 401, got %d", c, code)
		}
		msgs = append(msgs, out["error"].(string))
	}
	for _, m := range msgs[1:] {
		if m != msgs[0] {
			t.Fatalf("different failures give different messages, which reveals which usernames exist: %q vs %q", m, msgs[0])
		}
	}
}

func TestRepeatedFailuresLockOutTheGuessing(t *testing.T) {
	f := newAuthFixture(t)
	f.user("alice", false, nil)
	f.user("bob", false, nil)

	for i := 0; i < throttlePerUser; i++ {
		if code, _ := f.login("alice", "guess number "+fmt.Sprint(i)+"!!"); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	code, _, hdr := f.call("POST", "/v1/auth/login", "", map[string]string{"username": "alice", "password": "correct horse battery"})
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("after %d failures even the right password must wait: %d retry-after=%q", throttlePerUser, code, hdr.Get("Retry-After"))
	}
	if code, _ := f.login("bob", "correct horse battery"); code != 200 {
		t.Fatalf("one account being attacked must not lock out the others: %d", code)
	}
}

func TestASuccessfulLoginResetsTheFailureCount(t *testing.T) {
	f := newAuthFixture(t)
	f.user("alice", false, nil)
	for round := 0; round < 3; round++ {
		for i := 0; i < throttlePerUser-1; i++ {
			f.login("alice", "wrong wrong wrong")
		}
		if code, _ := f.login("alice", "correct horse battery"); code != 200 {
			t.Fatalf("round %d: %d (the count should have reset)", round, code)
		}
	}
}

// ---------------------------------------------------------------- sessions and tokens

func TestSessionsExpireWhenIdleAndAtTheirAbsoluteLimit(t *testing.T) {
	f := newAuthFixture(t)
	idle := f.user("idle", false, map[string]Role{"demo": RoleViewer})
	old := f.user("old", false, map[string]Role{"demo": RoleViewer})
	fresh := f.user("fresh", false, map[string]Role{"demo": RoleViewer})

	f.st.db.Exec(`UPDATE sessions SET last_used=? WHERE hash=?`, time.Now().Add(-sessionIdleTimeout-time.Hour).UTC().Format(time.RFC3339Nano), hashToken(idle))
	f.st.db.Exec(`UPDATE sessions SET expires_at=? WHERE hash=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), hashToken(old))

	for name, want := range map[string]int{"idle": 401, "old": 401, "fresh": 200} {
		if code, _, _ := f.call("GET", A+"/devices", map[string]string{"idle": idle, "old": old, "fresh": fresh}[name], nil); code != want {
			t.Errorf("%s: got %d, want %d", name, code, want)
		}
	}
}

func TestLogoutEndsTheSessionImmediately(t *testing.T) {
	f := newAuthFixture(t)
	tok := f.user("alice", false, map[string]Role{"demo": RoleViewer})
	if code, _, _ := f.call("POST", "/v1/auth/logout", tok, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _, _ := f.call("GET", A+"/devices", tok, nil); code != 401 {
		t.Fatalf("a logged-out token still works: %d", code)
	}
}

func TestPersonalAccessTokens(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.user("alice", false, map[string]Role{"demo": RoleOperator})
	bob := f.user("bob", false, map[string]Role{"demo": RoleOperator})

	code, out, _ := f.call("POST", "/v1/admin/me/tokens", alice, map[string]any{"name": "ci"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	token, id := out["token"].(string), out["id"].(string)
	if !strings.HasPrefix(token, "rct_") {
		t.Fatalf("token %q", token)
	}
	// it carries Alice's permissions
	if code, _, _ := f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", token, proto.CommandRequest{Type: "checkin_now"}); code != 201 {
		t.Fatalf("api token cannot do what its owner can: %d", code)
	}
	// the list never shows the secret again
	code, _, _ = f.call("GET", "/v1/admin/me/tokens", alice, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/admin/me/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+alice)
	f.h.ServeHTTP(rec, req)
	if code != 200 || strings.Contains(rec.Body.String(), token) || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("listing leaked the token or lost the entry: %s", rec.Body.String())
	}
	// someone else cannot revoke it; its owner can, and it stops at once
	if code, _, _ := f.call("DELETE", "/v1/admin/me/tokens/"+id, bob, nil); code != 404 {
		t.Fatalf("another user could revoke it: %d", code)
	}
	if code, _, _ := f.call("DELETE", "/v1/admin/me/tokens/"+id, alice, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ := f.call("GET", A+"/devices", token, nil); code != 401 {
		t.Fatalf("a revoked token still works: %d", code)
	}
}

func TestAPITokensCanExpire(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.user("alice", false, map[string]Role{"demo": RoleViewer})
	_, out, _ := f.call("POST", "/v1/admin/me/tokens", alice, map[string]any{"name": "short", "ttl_days": 1})
	token := out["token"].(string)
	if code, _, _ := f.call("GET", A+"/devices", token, nil); code != 200 {
		t.Fatal("fresh token rejected")
	}
	f.st.db.Exec(`UPDATE sessions SET expires_at=? WHERE hash=?`, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), hashToken(token))
	if code, _, _ := f.call("GET", A+"/devices", token, nil); code != 401 {
		t.Fatalf("an expired token still works: %d", code)
	}
	for _, bad := range []any{-1, 99999} {
		if code, _, _ := f.call("POST", "/v1/admin/me/tokens", alice, map[string]any{"name": "x", "ttl_days": bad}); code != 400 {
			t.Errorf("ttl_days=%v accepted", bad)
		}
	}
}

func TestChangingYourPasswordSignsOutYourOtherSessionsOnly(t *testing.T) {
	f := newAuthFixture(t)
	f.user("alice", false, map[string]Role{"demo": RoleViewer})
	_, a, _ := f.call("POST", "/v1/auth/login", "", map[string]string{"username": "alice", "password": "correct horse battery"})
	_, b, _ := f.call("POST", "/v1/auth/login", "", map[string]string{"username": "alice", "password": "correct horse battery"})
	here, elsewhere := a["token"].(string), b["token"].(string)
	_, api, _ := f.call("POST", "/v1/admin/me/tokens", here, map[string]any{"name": "keep me"})

	if code, _, _ := f.call("POST", "/v1/admin/me/password", here, map[string]string{"current": "not it at all", "new": "a brand new passphrase"}); code != 403 {
		t.Fatalf("wrong current password accepted: %d", code)
	}
	if code, _, _ := f.call("POST", "/v1/admin/me/password", here, map[string]string{"current": "correct horse battery", "new": "short"}); code != 400 {
		t.Fatalf("weak new password accepted: %d", code)
	}
	if code, _, _ := f.call("POST", "/v1/admin/me/password", here, map[string]string{"current": "correct horse battery", "new": "a brand new passphrase"}); code != 204 {
		t.Fatalf("change: %d", code)
	}
	if code, _, _ := f.call("GET", "/v1/admin/me", here, nil); code != 200 {
		t.Fatal("the session that changed the password must stay signed in")
	}
	if code, _, _ := f.call("GET", "/v1/admin/me", elsewhere, nil); code != 401 {
		t.Fatal("another session survived a password change")
	}
	if code, _, _ := f.call("GET", "/v1/admin/me", api["token"].(string), nil); code != 200 {
		t.Fatal("a personal access token should survive a password change (revoke it explicitly)")
	}
	if code, _ := f.login("alice", "correct horse battery"); code != 401 {
		t.Fatal("the old password still works")
	}
	if code, _ := f.login("alice", "a brand new passphrase"); code != 200 {
		t.Fatal("the new password does not work")
	}
}

func TestDisablingAUserCutsThemOffEverywhere(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.user("alice", false, map[string]Role{"demo": RoleAdmin})
	_, api, _ := f.call("POST", "/v1/admin/me/tokens", alice, map[string]any{"name": "t"})
	admin := "adm"

	if code, _, _ := f.call("PATCH", "/v1/admin/users/alice", admin, map[string]any{"disabled": true}); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	for name, tok := range map[string]string{"session": alice, "api token": api["token"].(string)} {
		if code, _, _ := f.call("GET", A+"/devices", tok, nil); code != 401 {
			t.Errorf("a disabled user's %s still works: %d", name, code)
		}
	}
	if code, _ := f.login("alice", "correct horse battery"); code != 401 {
		t.Error("a disabled user can log in")
	}
}

// ---------------------------------------------------------------- the permission matrix

// Every project route, what role it needs, and a request that succeeds when allowed.
func TestPermissionMatrix(t *testing.T) {
	f := newAuthFixture(t)
	id := f.dev.DeviceID
	users := map[string]string{ // name -> token
		"outsider": f.user("outsider", false, map[string]Role{"other": RoleAdmin}), // admin of ANOTHER project
		"viewer":   f.user("viewer", false, map[string]Role{"demo": RoleViewer}),
		"operator": f.user("operator", false, map[string]Role{"demo": RoleOperator}),
		"admin":    f.user("padmin", false, map[string]Role{"demo": RoleAdmin}),
		"server":   f.user("server", true, nil),
	}
	f.user("target", false, nil) // someone to add as a member
	code, made, _ := f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: "echo hi"})
	if code != 201 {
		t.Fatalf("seeding a script: %d", code)
	}
	scriptID, _ := made["id"].(string)

	rank := map[string]Role{"outsider": RoleNone, "viewer": RoleViewer, "operator": RoleOperator, "admin": RoleAdmin, "server": RoleAdmin}
	routes := []struct {
		name         string
		method, path string
		body         any
		min          Role
	}{
		{"list devices", "GET", A + "/devices", nil, RoleViewer},
		{"get device", "GET", A + "/devices/" + id, nil, RoleViewer},
		{"device detail", "GET", A + "/devices/" + id + "/detail", nil, RoleViewer},
		{"device metrics", "GET", A + "/devices/" + id + "/metrics?name=x", nil, RoleViewer},
		{"device artifacts", "GET", A + "/devices/" + id + "/artifacts", nil, RoleViewer},
		{"list config", "GET", A + "/config", nil, RoleViewer},
		{"get config layer", "GET", A + "/config/global", nil, RoleViewer},
		{"rename device", "PATCH", A + "/devices/" + id, map[string]any{"name": "kiosk"}, RoleOperator},
		{"restart command", "POST", A + "/devices/" + id + "/commands", proto.CommandRequest{Type: "restart_app"}, RoleOperator},
		{"screenshot command", "POST", A + "/devices/" + id + "/commands", proto.CommandRequest{Type: "capture_screenshot"}, RoleOperator},
		{"run_script command", "POST", A + "/devices/" + id + "/commands", proto.CommandRequest{Type: "run_script", Params: map[string]any{"script": "hello"}}, RoleAdmin},
		{"list scripts", "GET", A + "/scripts", nil, RoleViewer},
		{"upload a script", "POST", A + "/scripts", proto.ScriptCreate{Name: "other", Interpreter: "sh", Content: "echo other"}, RoleAdmin},
		{"read a script", "GET", A + "/scripts/" + scriptID + "/content", nil, RoleAdmin},
		{"list releases", "GET", A + "/releases", nil, RoleViewer},
		{"reboot command", "POST", A + "/devices/" + id + "/commands", proto.CommandRequest{Type: "reboot"}, RoleAdmin},
		{"edit config data", "PUT", A + "/config/global", proto.ConfigDocument{Data: map[string]any{"a": 2.0}}, RoleOperator},
		{"delete config layer", "DELETE", A + "/config/tag:lobby", nil, RoleOperator},
		{"create enrollment token", "POST", A + "/enrollment-tokens", nil, RoleAdmin},
		{"list members", "GET", A + "/members", nil, RoleAdmin},
		{"add member", "PUT", A + "/members/target", map[string]string{"role": "viewer"}, RoleAdmin},
		{"remove member", "DELETE", A + "/members/target", nil, RoleAdmin},
		{"read audit log", "GET", "/v1/admin/audit?project=demo", nil, RoleAdmin},
	}
	for _, rt := range routes {
		for _, who := range []string{"outsider", "viewer", "operator", "admin", "server"} {
			// the delete targets a layer that must exist for the allowed case to succeed
			f.st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
			f.call("PUT", A+"/config/tag:lobby", "adm", proto.ConfigDocument{Data: map[string]any{"x": 1.0}})

			code, _, _ := f.call(rt.method, rt.path, users[who], rt.body)
			allowed := rank[who] >= rt.min
			switch {
			case allowed && code >= 400:
				t.Errorf("%-24s %-8s should be allowed but got %d", rt.name, who, code)
			case !allowed && who == "outsider" && code != 404:
				t.Errorf("%-24s %-8s must not even learn the project exists (want 404), got %d", rt.name, who, code)
			case !allowed && who != "outsider" && code != 403:
				t.Errorf("%-24s %-8s should be forbidden (want 403), got %d", rt.name, who, code)
			}
		}
	}

	// not signed in at all
	for _, rt := range routes {
		if code, _, _ := f.call(rt.method, rt.path, "", rt.body); code != 401 {
			t.Errorf("%s without a token: want 401, got %d", rt.name, code)
		}
	}
}

func TestOnlyAdminsMayRemoveDevicesAndOnlyServerAdminsManageAccounts(t *testing.T) {
	f := newAuthFixture(t)
	op := f.user("op", false, map[string]Role{"demo": RoleOperator})
	pa := f.user("pa", false, map[string]Role{"demo": RoleAdmin})
	f.user("someone", false, nil) // target of the edit
	f.user("doomed", false, nil)  // target of the delete: separate, because map order is random

	if code, _, _ := f.call("DELETE", A+"/devices/"+f.dev.DeviceID, op, nil); code != 403 {
		t.Fatalf("an operator removed a device: %d", code)
	}
	if code, _, _ := f.call("DELETE", A+"/devices/"+f.dev.DeviceID, pa, nil); code != 204 {
		t.Fatalf("a project admin could not remove a device: %d", code)
	}

	// account management and project creation: server administrators only, even for project admins
	for name, rt := range map[string][3]any{
		"list users":     {"GET", "/v1/admin/users", nil},
		"create user":    {"POST", "/v1/admin/users", map[string]any{"username": "x1", "password": "some long password"}},
		"edit user":      {"PATCH", "/v1/admin/users/someone", map[string]any{"is_admin": true}},
		"delete user":    {"DELETE", "/v1/admin/users/doomed", nil},
		"create project": {"POST", "/v1/admin/projects", map[string]any{"name": "New"}},
	} {
		if code, _, _ := f.call(rt[0].(string), rt[1].(string), pa, rt[2]); code != 403 {
			t.Errorf("a project admin could %s: %d", name, code)
		}
		if code, _, _ := f.call(rt[0].(string), rt[1].(string), "adm", rt[2]); code >= 400 {
			t.Errorf("a server admin could not %s: %d", name, code)
		}
	}
}

func TestProjectsAreIsolatedFromEachOther(t *testing.T) {
	f := newAuthFixture(t)
	other := f.user("other-admin", false, map[string]Role{"other": RoleAdmin})
	id := f.dev.DeviceID
	for _, rt := range [][2]string{{"GET", A + "/devices"}, {"GET", A + "/devices/" + id + "/detail"}, {"GET", A + "/config"}, {"GET", A + "/members"}} {
		if code, _, _ := f.call(rt[0], rt[1], other, nil); code != 404 {
			t.Errorf("%s %s: another project's admin gets %d, want 404", rt[0], rt[1], code)
		}
	}
	// the device exists in demo; asking for it through your own project must not find it either
	if code, _, _ := f.call("GET", "/v1/admin/projects/other/devices/"+id+"/detail", other, nil); code != 404 {
		t.Fatalf("a device is reachable through the wrong project: %d", code)
	}
	// listing projects shows only yours
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/admin/projects", nil)
	req.Header.Set("Authorization", "Bearer "+other)
	f.h.ServeHTTP(rec, req)
	var ps []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &ps)
	if len(ps) != 1 || ps[0]["id"] != "other" || ps[0]["role"] != "admin" {
		t.Fatalf("project list leaks or lacks roles: %v", ps)
	}
}

// ---------------------------------------------------------------- the supervisor rule

func TestChangingTheSupervisorSectionNeedsProjectAdmin(t *testing.T) {
	f := newAuthFixture(t)
	op := f.user("op", false, map[string]Role{"demo": RoleOperator})
	pa := f.user("pa", false, map[string]Role{"demo": RoleAdmin})
	sup := &proto.SupervisorConfig{Exe: `C:\Kiosk\app.exe`, Env: map[string]string{"API_KEY": "s3cret"}}
	put := func(tok string, doc proto.ConfigDocument) int {
		code, _, _ := f.call("PUT", A+"/config/global", tok, doc)
		return code
	}

	if put(op, proto.ConfigDocument{Data: map[string]any{}, Supervisor: sup}) != 403 {
		t.Fatal("an operator set a supervisor section: that chooses the program that runs on the machines")
	}
	// a refused attempt is itself worth knowing about
	denied := f.st.listAudit("demo", 50)
	var saw bool
	for _, e := range denied {
		saw = saw || e.Action == "config.denied" && e.Username == "op"
	}
	if !saw {
		t.Fatalf("the refused attempt was not audited: %+v", denied)
	}
	if put(pa, proto.ConfigDocument{Data: map[string]any{}, Supervisor: sup}) != 200 {
		t.Fatal("a project admin could not")
	}
	if put(op, proto.ConfigDocument{Data: map[string]any{"volume": 0.5}, Supervisor: sup}) != 200 {
		t.Fatal("an operator may edit everything else while leaving the supervisor section as it is")
	}
	changed := *sup
	changed.Exe = `C:\Evil\app.exe`
	if put(op, proto.ConfigDocument{Data: map[string]any{}, Supervisor: &changed}) != 403 {
		t.Fatal("an operator changed the executable")
	}
	if put(op, proto.ConfigDocument{Data: map[string]any{}}) != 403 {
		t.Fatal("an operator removed the supervisor section by omitting it")
	}
	if code, _, _ := f.call("DELETE", A+"/config/global", op, nil); code != 403 {
		t.Fatalf("an operator deleted a layer that carries a supervisor section: %d", code)
	}
	if code, _, _ := f.call("DELETE", A+"/config/global", pa, nil); code != 204 {
		t.Fatalf("a project admin could not delete it: %d", code)
	}
}

func TestViewersDoNotSeeSecretsInTheSupervisorEnvironment(t *testing.T) {
	f := newAuthFixture(t)
	viewer := f.user("viewer1", false, map[string]Role{"demo": RoleViewer})
	op := f.user("operator1", false, map[string]Role{"demo": RoleOperator})
	f.call("PUT", A+"/config/global", "adm", proto.ConfigDocument{Data: map[string]any{}, Supervisor: &proto.SupervisorConfig{Exe: "x.exe", Env: map[string]string{"API_KEY": "s3cret"}}})

	body := func(method, path, tok string) string {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	for _, path := range []string{A + "/config", A + "/config/global", A + "/devices/" + f.dev.DeviceID + "/detail"} {
		if v := body("GET", path, viewer); strings.Contains(v, "s3cret") || !strings.Contains(v, "(hidden)") {
			t.Errorf("viewer on %s: secret not redacted: %s", path, v)
		}
		if o := body("GET", path, op); !strings.Contains(o, "s3cret") {
			t.Errorf("operator on %s should see the real value", path)
		}
	}
}

// ---------------------------------------------------------------- accounts

func TestTheLastEnabledAdministratorCannotBeRemoved(t *testing.T) {
	f := newAuthFixture(t) // "admin" is the only server administrator
	for name, rt := range map[string][3]any{
		"demote":  {"PATCH", "/v1/admin/users/admin", map[string]any{"is_admin": false}},
		"disable": {"PATCH", "/v1/admin/users/admin", map[string]any{"disabled": true}},
	} {
		if code, _, _ := f.call(rt[0].(string), rt[1].(string), "adm", rt[2]); code != 409 {
			t.Errorf("%s the last admin: want 409, got %d", name, code)
		}
	}
	// deleting yourself is refused outright, and so is deleting the last admin through another account
	if code, _, _ := f.call("DELETE", "/v1/admin/users/admin", "adm", nil); code != 400 {
		t.Errorf("deleting your own account: want 400, got %d", code)
	}

	second := f.user("second", true, nil)
	if code, _, _ := f.call("PATCH", "/v1/admin/users/admin", second, map[string]any{"disabled": true}); code != 200 {
		t.Fatalf("with a second administrator the first can be disabled: %d", code)
	}
	if code, _, _ := f.call("PATCH", "/v1/admin/users/second", "adm", map[string]any{"is_admin": false}); code != 401 {
		t.Fatalf("the disabled admin's bootstrap token should be dead: %d", code)
	}
	if code, _, _ := f.call("DELETE", "/v1/admin/users/second", second, nil); code != 400 {
		t.Fatalf("self-delete: %d", code)
	}
	if err := f.st.DeleteUser("second"); err == nil {
		t.Fatal("deleting the only remaining enabled administrator through the CLI path succeeded")
	}
}

func TestUserCreationValidatesAndRejectsDuplicates(t *testing.T) {
	f := newAuthFixture(t)
	create := func(u, p string) int {
		code, _, _ := f.call("POST", "/v1/admin/users", "adm", map[string]any{"username": u, "password": p})
		return code
	}
	if create("alice", "a long enough password") != 201 {
		t.Fatal("valid user rejected")
	}
	if create("ALICE", "a long enough password") != 409 {
		t.Fatal("a duplicate (case-insensitive) username was accepted")
	}
	for _, bad := range []string{"", "a", "has space", "semi;colon", strings.Repeat("x", 41)} {
		if create(bad, "a long enough password") != 400 {
			t.Errorf("username %q accepted", bad)
		}
	}
	if create("bob", "short") != 400 {
		t.Error("a short password was accepted")
	}
	if code, _, _ := f.call("POST", "/v1/admin/users", "adm", map[string]any{"username": "nopass"}); code != 400 {
		t.Errorf("a password-less account through the API: %d", code)
	}
}

func TestMembershipManagement(t *testing.T) {
	f := newAuthFixture(t)
	pa := f.user("pa", false, map[string]Role{"demo": RoleAdmin})
	f.user("newbie", false, nil)

	if code, _, _ := f.call("PUT", A+"/members/newbie", pa, map[string]string{"role": "boss"}); code != 400 {
		t.Fatalf("a bogus role: %d", code)
	}
	if code, _, _ := f.call("PUT", A+"/members/ghost", pa, map[string]string{"role": "viewer"}); code != 404 {
		t.Fatalf("an unknown user: %d", code)
	}
	if code, _, _ := f.call("PUT", A+"/members/newbie", pa, map[string]string{"role": "operator"}); code != 200 {
		t.Fatalf("add: %d", code)
	}
	newbieTok, _, _ := f.st.createSession(mustUser(t, f.st, "newbie"), "session", "t", "", sessionMaxAge)
	if code, _, _ := f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", newbieTok, proto.CommandRequest{Type: "checkin_now"}); code != 201 {
		t.Fatalf("the new operator cannot operate: %d", code)
	}
	// demote, then remove: the very next request reflects it (roles are read live, not cached in the token)
	f.call("PUT", A+"/members/newbie", pa, map[string]string{"role": "viewer"})
	if code, _, _ := f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", newbieTok, proto.CommandRequest{Type: "checkin_now"}); code != 403 {
		t.Fatalf("a demoted user kept operator rights: %d", code)
	}
	f.call("DELETE", A+"/members/newbie", pa, nil)
	if code, _, _ := f.call("GET", A+"/devices", newbieTok, nil); code != 404 {
		t.Fatalf("a removed member still sees the project: %d", code)
	}
	code, _, _ := f.call("GET", A+"/members", pa, nil)
	if code != 200 {
		t.Fatalf("list members: %d", code)
	}
}

func mustUser(t *testing.T, st *Store, name string) *User {
	t.Helper()
	u, err := st.userByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func ptr[T any](v T) *T { return &v }

// ---------------------------------------------------------------- audit

func TestAuditRecordsWhoDidWhatWithoutLeakingValues(t *testing.T) {
	f := newAuthFixture(t)
	op := f.user("op", false, map[string]Role{"demo": RoleOperator})
	pa := f.user("pa", false, map[string]Role{"demo": RoleAdmin})
	f.login("op", "correct horse battery")
	f.login("op", "wrong wrong wrong")
	f.call("PUT", A+"/config/global", op, proto.ConfigDocument{Data: map[string]any{"password_for_wifi": "hunter2hunter2"}})
	f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", op, proto.CommandRequest{Type: "restart_app"})
	f.call("POST", "/v1/admin/me/password", pa, map[string]string{"current": "correct horse battery", "new": "brand new secret phrase"})

	read := func(tok, query string) (int, []AuditEntry) {
		req := httptest.NewRequest("GET", "/v1/admin/audit"+query, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		var e []AuditEntry
		json.Unmarshal(rec.Body.Bytes(), &e)
		return rec.Code, e
	}
	code, entries := read(pa, "?project=demo")
	if code != 200 {
		t.Fatalf("project admin audit: %d", code)
	}
	var cfg, cmd *AuditEntry
	for i := range entries {
		switch entries[i].Action {
		case "config.put":
			cfg = &entries[i]
		case "command.queued":
			cmd = &entries[i]
		}
	}
	if cfg == nil || cfg.Username != "op" || cfg.Project != "demo" || cfg.Target != "global" {
		t.Fatalf("config change not recorded properly: %+v", cfg)
	}
	if cmd == nil || cmd.Username != "op" || cmd.Detail != "restart_app" {
		t.Fatalf("command not recorded: %+v", cmd)
	}
	all, _ := json.Marshal(entries)
	if strings.Contains(string(all), "hunter2") {
		t.Fatal("the audit log contains a config value")
	}

	// logins and password changes are server-wide events; the full log is for server admins
	_, everything := read("adm", "")
	var sawOK, sawFail, sawPw bool
	for _, e := range everything {
		sawOK = sawOK || e.Action == "login.ok" && e.Username == "op"
		sawFail = sawFail || e.Action == "login.failed" && e.Target == "op"
		sawPw = sawPw || e.Action == "password.changed" && e.Username == "pa"
	}
	if !sawOK || !sawFail || !sawPw {
		t.Fatalf("missing login/password events: ok=%v failed=%v pw=%v", sawOK, sawFail, sawPw)
	}
	blob, _ := json.Marshal(everything)
	for _, secret := range []string{"correct horse battery", "wrong wrong wrong", "brand new secret phrase"} {
		if strings.Contains(string(blob), secret) {
			t.Fatalf("a password is in the audit log: %q", secret)
		}
	}

	if code, _ := read(op, "?project=demo"); code != 403 {
		t.Errorf("an operator read the audit log: %d", code)
	}
	if code, _ := read(pa, ""); code != 403 {
		t.Errorf("a project admin read the whole server's log: %d", code)
	}
	if code, _ := read(pa, "?project=other"); code != 404 {
		t.Errorf("a project admin read another project's log: %d", code)
	}
}

// ---------------------------------------------------------------- bootstrap and migration

func TestFirstRunAdminLoginIsCreatedOnceAndOnlyWhenNeeded(t *testing.T) {
	st, _ := OpenStore("", "")
	defer st.Close()
	pw, err := st.EnsureAdminLogin("")
	if err != nil || len(pw) != 16 {
		t.Fatalf("first run: %q %v", pw, err)
	}
	if u, ok := st.Verify("admin", pw); !ok || !u.IsAdmin {
		t.Fatal("the generated password does not log in")
	}
	if again, _ := st.EnsureAdminLogin(""); again != "" {
		t.Fatal("a second start created or reset the password again")
	}
}

func TestTheOldTokenOnlyAdminGetsAPasswordOnce(t *testing.T) {
	st, _ := OpenStore("", "scripted-token")
	defer st.Close()
	u, _ := st.userByName("admin")
	if u == nil || u.HasPassword {
		t.Fatal("expected a token-only admin")
	}
	pw, _ := st.EnsureAdminLogin("chosen by the owner")
	if pw != "chosen by the owner" {
		t.Fatalf("got %q", pw)
	}
	if _, ok := st.Verify("admin", pw); !ok {
		t.Fatal("password not set")
	}
	if _, _, err := st.lookupToken("scripted-token"); err != nil {
		t.Fatal("the legacy token stopped working when a password was added")
	}
}

func TestADatabaseFromBeforeAccountsKeepsItsAdminTokenButHashed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := OpenStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	// make it look like a pre-accounts database: no users, the admin token in meta in plain text
	st.db.Exec(`DELETE FROM users`)
	st.db.Exec(`DELETE FROM sessions`)
	st.db.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES('admin_token','the-old-shared-token')`)
	st.Close()

	st2, err := OpenStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	u, sess, err := st2.lookupToken("the-old-shared-token")
	if err != nil || u.Username != "admin" || !u.IsAdmin || sess.Kind != "api" {
		t.Fatalf("the old token should be an API token of the admin account: %v %+v", err, u)
	}
	var plain int
	st2.db.QueryRow(`SELECT COUNT(*) FROM meta WHERE k='admin_token'`).Scan(&plain)
	if plain != 0 {
		t.Fatal("the plain-text copy was not removed")
	}
	st2.Close()
	raw, _ := readAll(path)
	if bytes.Contains(raw, []byte("the-old-shared-token")) {
		t.Fatal("the old token is still in the database file in the clear")
	}
	// reopening again is a no-op
	st3, err := OpenStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	if _, _, err := st3.lookupToken("the-old-shared-token"); err != nil {
		t.Fatal("token lost on the second reopen")
	}
}

func readAll(path string) ([]byte, error) {
	var out []byte
	for _, p := range []string{path, path + "-wal"} {
		b, err := readFileIfExists(p)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// ---------------------------------------------------------------- the page itself

func TestDashboardIsServedWithStrictSecurityHeaders(t *testing.T) {
	f := newAuthFixture(t)
	for _, path := range []string{"/", "/static/app.js"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		csp := rec.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP lacks %q: %s", path, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP allows inline code: %s", path, csp)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing hardening headers: %v", path, rec.Header())
		}
	}
}

func TestCreateAndRenameProject(t *testing.T) {
	f := newAuthFixture(t)
	pa := f.user("proj-admin", false, map[string]Role{"demo": RoleAdmin})
	op := f.user("proj-op", false, map[string]Role{"demo": RoleOperator})

	code, body, _ := f.call("POST", "/v1/admin/projects", "adm", map[string]any{"name": "  Lobby Screens  "})
	if code != 201 || body["id"] != "lobby-screens" || body["name"] != "Lobby Screens" {
		t.Fatalf("create: %d %v", code, body)
	}
	if code, body, _ := f.call("POST", "/v1/admin/projects", "adm", map[string]any{"name": "lobby screens"}); code != 409 {
		t.Fatalf("a second project with the same id must be refused, not replace the first: %d %v", code, body)
	}
	if f.st.D.Projects["lobby-screens"].Name != "Lobby Screens" {
		t.Fatal("the refused create overwrote the existing project")
	}
	for _, name := range []string{"", "   ", "!!!", strings.Repeat("x", maxProjectName+1)} {
		if code, _, _ := f.call("POST", "/v1/admin/projects", "adm", map[string]any{"name": name}); code != 400 {
			t.Errorf("name %q accepted: %d", name, code)
		}
	}

	if code, _, _ := f.call("PATCH", A, op, map[string]any{"name": "Nope"}); code != 403 {
		t.Fatalf("an operator renamed a project: %d", code)
	}
	if code, body, _ := f.call("PATCH", A, pa, map[string]any{"name": " Demo Floor "}); code != 200 || body["name"] != "Demo Floor" || body["id"] != "demo" {
		t.Fatalf("rename by a project admin: %d %v", code, body)
	}
	if code, _, _ := f.call("PATCH", A, pa, map[string]any{"name": " "}); code != 400 {
		t.Fatalf("empty name: %d", code)
	}
	if code, _, _ := f.call("PATCH", "/v1/admin/projects/other", pa, map[string]any{"name": "Mine now"}); code != 404 {
		t.Fatalf("a project admin renamed someone else's project: %d", code)
	}
	if code, _, _ := f.call("PATCH", "/v1/admin/projects/ghost", "adm", map[string]any{"name": "x"}); code != 404 {
		t.Fatalf("unknown project: %d", code)
	}
	// the rename is stored, and devices and tokens keep working under the same id
	if f.st.D.Projects["demo"].Name != "Demo Floor" {
		t.Fatal("not stored")
	}
	if code, _, _ := f.call("GET", A+"/devices", pa, nil); code != 200 {
		t.Fatalf("devices after rename: %d", code)
	}
}
