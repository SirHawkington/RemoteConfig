package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

func init() { SetPasswordCost(1000) } // real hashing costs ~0.3 s a password: far too slow for tests

func do(t *testing.T, h http.Handler, method, path, token string, body, out any) int {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil && rec.Code/100 == 2 && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func enrollDevice(t *testing.T, st *Store, h http.Handler, tags ...string) proto.EnrollResponse {
	t.Helper()
	tok := st.NewEnrollToken("demo", tags, time.Hour)
	var er proto.EnrollResponse
	if code := do(t, h, "POST", "/v1/enroll", "", proto.EnrollRequest{Token: tok, Hostname: "kiosk-1", OS: "windows"}, &er); code != 201 {
		t.Fatalf("enroll: %d", code)
	}
	return er
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rc.db")
	st, err := OpenStore(path, "adm")
	if err != nil {
		t.Fatal(err)
	}
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{"volume": 0.8}})
	h := New(st, Options{CheckinInterval: time.Minute}).Handler()
	er := enrollDevice(t, st, h, "lobby")

	do(t, h, "POST", "/v1/checkin", er.DeviceToken, proto.CheckinRequest{
		Session: "s1", Seq: 1, ConfigRevision: 1, RestartsSinceLast: 2,
		App:    &proto.AppStatus{State: "running", Build: "1.2"},
		Events: []proto.Event{{Type: "app.crash", Level: "error", Message: "boom", Data: map[string]any{"exit_code": 3}}},
	}, nil)
	do(t, h, "POST", "/v1/metrics", er.DeviceToken, map[string]any{"metrics": []proto.Metric{{Name: "visitors", Value: 41}, {Name: "visitors", Value: 42}}}, nil)
	do(t, h, "PUT", "/v1/admin/projects/demo/config/tag:lobby", "adm", proto.ConfigDocument{Data: map[string]any{"lang": "fr"}}, nil)
	st.Close()

	// "restart the server"
	st2, err := OpenStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	h2 := New(st2, Options{CheckinInterval: time.Minute}).Handler()

	if code := do(t, h2, "GET", "/v1/admin/projects", "adm", nil, nil); code != 200 {
		t.Fatalf("the admin token stopped working after a restart: %d", code)
	}
	var d proto.DeviceDetail
	if code := do(t, h2, "GET", "/v1/admin/projects/demo/devices/"+er.DeviceID+"/detail", "adm", nil, &d); code != 200 {
		t.Fatalf("detail after restart: %d", code)
	}
	if d.Restarts != 2 || d.App == nil || d.App.Build != "1.2" {
		t.Fatalf("device state lost: %+v", d)
	}
	if len(d.Events) != 2 || d.Events[0].Type != "app.crash" || d.Events[0].Data["exit_code"] != float64(3) {
		t.Fatalf("events lost or misordered (want crash newest, then enrolled): %+v", d.Events)
	}
	if d.Metrics["visitors"] != 42 {
		t.Fatalf("latest metric: %v", d.Metrics)
	}
	if d.Effective.Data["lang"] != "fr" || d.Effective.Data["volume"] != 0.8 {
		t.Fatalf("config layers lost: %+v", d.Effective.Data)
	}
	// device token still valid after restart
	if code := do(t, h2, "GET", "/v1/commands", er.DeviceToken, nil, nil); code != 200 {
		t.Fatalf("device token rejected after restart: %d", code)
	}
}

func TestCheckinRetryAndAgentRestartAccounting(t *testing.T) {
	st, _ := OpenStore("", "adm")
	defer st.Close()
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
	h := New(st, Options{CheckinInterval: time.Minute}).Handler()
	er := enrollDevice(t, st, h)

	ev := func(msg string) []proto.Event { return []proto.Event{{Type: "x", Message: msg}} }
	checkin := func(session string, seq int64, restarts int, msg string) {
		do(t, h, "POST", "/v1/checkin", er.DeviceToken, proto.CheckinRequest{Session: session, Seq: seq, RestartsSinceLast: restarts, Events: ev(msg)}, nil)
	}
	checkin("A", 5, 1, "first")
	checkin("A", 5, 1, "retry-of-first") // lost response, agent resent the same check-in
	checkin("A", 6, 0, "second")
	checkin("B", 1, 3, "after-agent-restart") // new session: seq starts over and must still count

	var d proto.DeviceDetail
	do(t, h, "GET", "/v1/admin/projects/demo/devices/"+er.DeviceID+"/detail", "adm", nil, &d)
	if d.Restarts != 4 {
		t.Fatalf("restarts = %d, want 4 (retry must not double count, new session must count)", d.Restarts)
	}
	got := map[string]bool{}
	for _, e := range d.Events {
		got[e.Message] = true
	}
	if got["retry-of-first"] || !got["first"] || !got["second"] || !got["after-agent-restart"] {
		t.Fatalf("event dedupe wrong: %v", got)
	}
}

func TestAdminAuthAndDeviceManagement(t *testing.T) {
	st, _ := OpenStore("", "adm")
	defer st.Close()
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{"a": 1.0}})
	h := New(st, Options{CheckinInterval: time.Minute}).Handler()
	er := enrollDevice(t, st, h)
	base := "/v1/admin/projects/demo/devices/" + er.DeviceID

	if code := do(t, h, "GET", "/v1/admin/projects", "", nil, nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code := do(t, h, "GET", "/v1/admin/projects", er.DeviceToken, nil, nil); code != 401 {
		t.Fatalf("a device token must not grant admin access: %d", code)
	}
	if code := do(t, h, "PUT", "/v1/admin/projects/demo/config/bogus", "adm", proto.ConfigDocument{Data: map[string]any{}}, nil); code != 400 {
		t.Fatalf("bad scope accepted: %d", code)
	}
	if code := do(t, h, "PUT", "/v1/admin/projects/demo/config/global", "adm", proto.ConfigDocument{Data: map[string]any{}, ReloadMode: "sideways"}, nil); code != 400 {
		t.Fatalf("bad reload mode accepted: %d", code)
	}

	// retagging changes the effective config
	do(t, h, "PUT", "/v1/admin/projects/demo/config/tag:vip", "adm", proto.ConfigDocument{Data: map[string]any{"a": 2.0}}, nil)
	var before, after proto.DeviceDetail
	do(t, h, "GET", base+"/detail", "adm", nil, &before)
	tags := []string{"VIP"}
	do(t, h, "PATCH", base, "adm", proto.DevicePatch{Tags: &tags}, nil)
	do(t, h, "GET", base+"/detail", "adm", nil, &after)
	if before.Effective.Data["a"] != 1.0 || after.Effective.Data["a"] != 2.0 || after.Effective.Revision <= before.Effective.Revision {
		t.Fatalf("retag did not change effective config: before=%+v after=%+v", before.Effective, after.Effective)
	}

	// delete layer, then device
	if code := do(t, h, "DELETE", "/v1/admin/projects/demo/config/tag:vip", "adm", nil, nil); code != 204 {
		t.Fatalf("delete layer: %d", code)
	}
	if code := do(t, h, "DELETE", base, "adm", nil, nil); code != 204 {
		t.Fatalf("delete device: %d", code)
	}
	if code := do(t, h, "GET", "/v1/commands", er.DeviceToken, nil, nil); code != 401 {
		t.Fatalf("removed device's token still works: %d", code)
	}
}

func TestSupervisorQuitTimeoutIsValidated(t *testing.T) {
	f := newFixture(t)
	put := func(sc proto.SupervisorConfig) int {
		return do(t, f.h, "PUT", "/v1/admin/projects/demo/config/global", "adm", proto.ConfigDocument{Data: map[string]any{}, Supervisor: &sc}, nil)
	}
	if put(proto.SupervisorConfig{Exe: "x", QuitTimeoutS: -1}) != 400 || put(proto.SupervisorConfig{Exe: "x", QuitTimeoutS: 601}) != 400 {
		t.Fatal("out-of-range quit_timeout_s accepted")
	}
	if put(proto.SupervisorConfig{Exe: "x", QuitTimeoutS: 20, StopAppOnAgentExit: true}) != 200 {
		t.Fatal("valid supervisor settings rejected")
	}
}

func TestEventRetentionCap(t *testing.T) {
	st, _ := OpenStore("", "adm")
	defer st.Close()
	evs := make([]proto.Event, maxEventsPerDevice+50)
	for i := range evs {
		evs[i] = proto.Event{Type: "e"}
	}
	st.mu.Lock()
	st.appendEvents("d1", evs)
	n := len(st.listEvents("d1", 100000))
	st.mu.Unlock()
	if n != maxEventsPerDevice {
		t.Fatalf("kept %d events, want cap %d", n, maxEventsPerDevice)
	}
}

func TestDashboardServed(t *testing.T) {
	st, _ := OpenStore("", "adm")
	defer st.Close()
	h := New(st, Options{}).Handler()
	for path, want := range map[string]string{"/": "text/html", "/static/app.js": "javascript", "/static/app.css": "text/css"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || !bytes.Contains([]byte(rec.Header().Get("Content-Type")), []byte(want)) {
			t.Fatalf("%s: code=%d type=%q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
