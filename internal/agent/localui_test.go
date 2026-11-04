package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"remoteconfig/internal/proto"
)

func uiTestAgent(t *testing.T) (*Agent, *http.ServeMux) {
	t.Helper()
	a := New(Options{StateDir: t.TempDir(), Version: "9.9"})
	a.localToken = "tok"
	mux := http.NewServeMux()
	a.registerUI(mux)
	return a, mux
}

func uiCall(mux *http.ServeMux, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestUIEndpointsNeedTheLocalToken(t *testing.T) {
	_, mux := uiTestAgent(t)
	for _, c := range [][2]string{{"GET", "/v1/ui/overview"}, {"POST", "/v1/ui/capture"}, {"POST", "/v1/ui/restart-app"}} {
		if w := uiCall(mux, c[0], c[1], ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d", c[0], c[1], w.Code)
		}
		if w := uiCall(mux, c[0], c[1], "wrong"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a wrong token: %d", c[0], c[1], w.Code)
		}
	}
}

func TestUIOverview(t *testing.T) {
	a, mux := uiTestAgent(t)

	var o proto.Overview
	w := uiCall(mux, "GET", "/v1/ui/overview", "tok")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &o) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if o.Enrolled || o.Version != "9.9" || o.Connected || o.Supervisor.Managing {
		t.Fatalf("fresh agent: %+v", o)
	}

	a.mu.Lock()
	a.id = identity{Server: "http://s", DeviceID: "dev_1", DeviceToken: "x", Project: "demo"}
	a.connected = true
	a.app = &proto.AppStatus{State: "running", FPS: 59}
	a.events = append(a.events, proto.Event{Type: "x"})
	a.mu.Unlock()

	w = uiCall(mux, "GET", "/v1/ui/overview", "tok")
	o = proto.Overview{}
	json.Unmarshal(w.Body.Bytes(), &o)
	if !o.Enrolled || o.DeviceID != "dev_1" || o.Project != "demo" || !o.Connected || o.PendingEvents != 1 {
		t.Fatalf("enrolled agent: %+v", o)
	}
	if o.App == nil || o.App.State != "running" {
		t.Fatalf("app status missing: %+v", o)
	}
}

func TestUIRestartWithoutSupervision(t *testing.T) {
	_, mux := uiTestAgent(t)
	w := uiCall(mux, "POST", "/v1/ui/restart-app", "tok")
	if w.Code != http.StatusConflict {
		t.Fatalf("an agent that is not supervising must refuse: %d %s", w.Code, w.Body)
	}
}
