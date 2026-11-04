package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

func TestResolveInstallDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	in, s, err := resolveInstall(dir, overrides{})
	if err != nil || len(s) != 0 {
		t.Fatalf("empty dir: %v %v", s, err)
	}
	if in.StateDir != filepath.Join(dir, "state") || in.LogFile != filepath.Join(dir, "agent.log") || in.Listen != defaultListen {
		t.Fatalf("defaults: %+v", in)
	}

	os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{"server":"https://x","state_dir":"st","log_file":"logs/a.log","listen":"127.0.0.1:9999","keep":"me"}`), 0o600)
	in, s, err = resolveInstall(dir, overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if in.StateDir != filepath.Join(dir, "st") || in.LogFile != filepath.Join(dir, "logs", "a.log") || in.Listen != "127.0.0.1:9999" {
		t.Fatalf("from file (relative paths are relative to agent.json): %+v", in)
	}
	in, _, _ = resolveInstall(dir, overrides{StateDir: `C:\s`, LogFile: `C:\l.log`, Listen: "127.0.0.1:1"})
	if in.StateDir != `C:\s` || in.LogFile != `C:\l.log` || in.Listen != "127.0.0.1:1" {
		t.Fatalf("overrides: %+v", in)
	}
	if s["keep"] != "me" {
		t.Fatal("unknown keys must be kept")
	}
}

func TestBadAgentJSONIsAnError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{nope`), 0o600)
	if _, _, err := resolveInstall(dir, overrides{}); err == nil {
		t.Fatal("expected an error for malformed agent.json")
	}
}

func TestFormValidate(t *testing.T) {
	ok := form{Server: "https://rc.example.com", Interval: "5m", Listen: "127.0.0.1:7878"}
	if m := ok.validate(); m != "" {
		t.Fatalf("valid form rejected: %s", m)
	}
	for name, f := range map[string]form{
		"no server":      {},
		"no scheme":      {Server: "rc.example.com"},
		"ftp":            {Server: "ftp://x"},
		"short interval": {Server: "http://x", Interval: "1s"},
		"bad interval":   {Server: "http://x", Interval: "soon"},
		"public listen":  {Server: "http://x", Listen: "0.0.0.0:7878"},
		"lan listen":     {Server: "http://x", Listen: "192.168.1.5:7878"},
		"no port":        {Server: "http://x", Listen: "127.0.0.1"},
	} {
		if f.validate() == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, l := range []string{"localhost:1", "[::1]:1", "127.0.0.2:1"} {
		if m := (form{Server: "http://x", Listen: l}).validate(); m != "" {
			t.Errorf("%s rejected: %s", l, m)
		}
	}
}

func TestFormApplyKeepsUnknownKeysAndSavedToken(t *testing.T) {
	cur := settings{"server": "https://old", "enroll_token": "tok", "require_signatures": true, "interval": "1m"}
	got := form{Server: " https://new ", Interval: "", Listen: "127.0.0.1:7000"}.apply(cur)
	if got["server"] != "https://new" || got["listen"] != "127.0.0.1:7000" {
		t.Fatalf("%v", got)
	}
	if _, has := got["interval"]; has {
		t.Fatal("empty interval should be removed so the server's applies")
	}
	if got["enroll_token"] != "tok" || got["require_signatures"] != true {
		t.Fatalf("saved token / unknown keys lost: %v", got)
	}
	if cur["server"] != "https://old" {
		t.Fatal("apply must not modify its input")
	}
	if got := (form{Server: "https://x", Token: "new"}).apply(cur); got["enroll_token"] != "new" {
		t.Fatalf("a typed token replaces the saved one: %v", got)
	}
}

func TestClient(t *testing.T) {
	state := t.TempDir()
	os.WriteFile(filepath.Join(state, "local-token"), []byte("secret\n"), 0o600)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/ui/overview":
			json.NewEncoder(w).Encode(proto.Overview{DeviceID: "dev_1", Enrolled: true, Connected: true})
		case "/v1/ui/capture":
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"message":"captured 2 display(s); uploading"}`))
		case "/v1/ui/restart-app":
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"the app is not supervised on this device"}`))
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()
	c := newClient(install{StateDir: state, Listen: strings.TrimPrefix(srv.URL, "http://")})

	o, err := c.overview()
	if err != nil || o.DeviceID != "dev_1" || !o.Connected {
		t.Fatalf("overview: %+v %v", o, err)
	}
	if msg, err := c.captureNow(); err != nil || !strings.HasPrefix(msg, "captured 2") {
		t.Fatalf("capture: %q %v", msg, err)
	}
	if _, err := c.restartApp(); err == nil || !strings.Contains(err.Error(), "not supervised") {
		t.Fatalf("the agent's own error text should reach the user: %v", err)
	}
	if err := c.checkinNow(); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(state, "local-token"), []byte("wrong"), 0o600)
	if _, err := c.overview(); err != errUnauthorize {
		t.Fatalf("wrong token: %v", err)
	}
}

func TestClientAgentDownAndNoToken(t *testing.T) {
	state := t.TempDir()
	c := newClient(install{StateDir: state, Listen: "127.0.0.1:1"})
	if _, err := c.overview(); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("no token yet: %v", err)
	}
	os.WriteFile(filepath.Join(state, "local-token"), []byte("t"), 0o600)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close() // nothing listens here now
	c = newClient(install{StateDir: state, Listen: addr})
	if _, err := c.overview(); err != errAgentDown {
		t.Fatalf("agent down: %v", err)
	}
}

func TestFormatting(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		got, want string
	}{
		{ago(time.Time{}, now), "never"},
		{ago(now.Add(-5*time.Second), now), "5s ago"},
		{ago(now.Add(2*time.Second), now), "0s ago"}, // clock skew must not print a negative
		{dur(95 * time.Second), "1m 35s"},
		{dur(3*time.Hour + 5*time.Minute), "3h 5m"},
		{dur(50*time.Hour + 30*time.Minute), "2d 2h"},
		{megabytes(1_500_000), "1.5 MB"},
	} {
		if c.got != c.want {
			t.Errorf("got %q want %q", c.got, c.want)
		}
	}
}

func TestTailFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	if _, err := tailFile(p, 10); err == nil {
		t.Fatal("missing file should error")
	}
	os.WriteFile(p, []byte("one\ntwo\nthree\nfour\n"), 0o600)
	if s, _ := tailFile(p, 1000); s != "one\ntwo\nthree\nfour\n" {
		t.Fatalf("whole file: %q", s)
	}
	// A cut that lands mid-line drops the partial first line.
	if s, _ := tailFile(p, 8); s != "four\n" {
		t.Fatalf("tail: %q", s)
	}
}
