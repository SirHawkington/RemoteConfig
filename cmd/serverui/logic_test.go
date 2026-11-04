package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as a stand-in for server.exe: the runner tests start this same binary.
func TestMain(m *testing.M) {
	switch os.Getenv("RC_FAKE_SERVER") {
	case "run":
		fmt.Println("2026/01/01 00:00:00 config and commands are signed with key k1. Pin it on agents with: -server-key PUBKEY=")
		fmt.Println("\nFirst-run administrator account created.\n  username: admin\n  password: s3cret-pw\nSign in.")
		fmt.Fprintln(os.Stderr, "2026/01/01 00:00:00 listening on :8080 (check-in interval 5m0s)")
		time.Sleep(time.Minute)
		os.Exit(0)
	case "crash":
		fmt.Fprintln(os.Stderr, "listen tcp :8080: bind: address already in use")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestConfigDefaultsLoadAndSave(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, configName)
	c, err := loadConfig(path, base)
	if err != nil || c.Port != 8080 || c.DataDir != filepath.Join(base, "data") || c.Interval != "5m" || !c.AutoStart || c.Network {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c.Port, c.Network = 9000, true
	if err := saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path, base)
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	os.WriteFile(path, []byte(`{"port": 7000}`), 0o644)
	if got, _ := loadConfig(path, base); got.Port != 7000 || got.Interval != "5m" || got.DataDir == "" {
		t.Fatalf("a partial file must be topped up with defaults: %+v", got)
	}
	os.WriteFile(path, []byte(`{nope`), 0o644)
	if _, err := loadConfig(path, base); err == nil {
		t.Fatal("a damaged settings file must be reported, not replaced")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := defaults(t.TempDir())
	if m := ok.validate(); m != "" {
		t.Fatalf("defaults rejected: %s", m)
	}
	for name, mod := range map[string]func(*config){
		"port zero":      func(c *config) { c.Port = 0 },
		"port too big":   func(c *config) { c.Port = 70000 },
		"no folder":      func(c *config) { c.DataDir = " " },
		"bad interval":   func(c *config) { c.Interval = "soon" },
		"short interval": func(c *config) { c.Interval = "1s" },
		"empty interval": func(c *config) { c.Interval = "" },
	} {
		c := ok
		mod(&c)
		if c.validate() == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServerArgs(t *testing.T) {
	c := config{Port: 8123, DataDir: filepath.Join("d", "x"), Interval: " 30s "}
	got := strings.Join(c.args(), " ")
	if want := "-addr 127.0.0.1:8123 -data " + filepath.Join("d", "x", "remoteconfig.db") + " -checkin-interval 30s"; got != want {
		t.Fatalf("local only:\n got %s\nwant %s", got, want)
	}
	c.Network, c.DevSeed = true, true
	got = strings.Join(c.args(), " ")
	if !strings.HasPrefix(got, "-addr :8123 ") || !strings.HasSuffix(got, " -dev-seed") {
		t.Fatalf("network + seed: %s", got)
	}
	if c.dashboardURL() != "http://localhost:8123/" {
		t.Fatal(c.dashboardURL())
	}
	if (config{Port: 1}).agentURLs() != nil {
		t.Fatal("a local-only server has no address for other PCs")
	}
}

func TestParsePort(t *testing.T) {
	if n, err := parsePort(" 8080 "); err != nil || n != 8080 {
		t.Fatal(n, err)
	}
	if _, err := parsePort("eighty"); err == nil {
		t.Fatal("non-numeric port accepted")
	}
}

func TestScanState(t *testing.T) {
	var s scanState
	for _, l := range []string{
		"2026/01/01 config and commands are signed with key abc. Pin it on agents with: -server-key PUB+KEY/=",
		"password: not-the-admin-one", // before the first-run banner: must be ignored
		"First-run administrator account created.",
		"  username: admin",
		"  password: s3cret",
		"2026/01/01 listening on :8080 (check-in interval 5m0s)",
	} {
		s.line(l)
	}
	if s.ServerKey != "PUB+KEY/=" || s.AdminPassword != "s3cret" || !s.Listening {
		t.Fatalf("%+v", s)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunnerStartCaptureAndStop(t *testing.T) {
	t.Setenv("RC_FAKE_SERVER", "run")
	r := &runner{exe: os.Args[0]}
	if err := r.start(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.start(nil, nil); err == nil {
		t.Fatal("a second start while running must be refused")
	}
	waitFor(t, "the server to report it is listening", func() bool { return r.snapshot().Scan.Listening })
	s := r.snapshot()
	if !s.Running || s.Scan.ServerKey != "PUBKEY=" || s.Scan.AdminPassword != "s3cret-pw" {
		t.Fatalf("%+v", s)
	}
	r.stop()
	s = r.snapshot()
	if s.Running || s.ExitMsg != "stopped" {
		t.Fatalf("after stop: %+v", s)
	}
	if !strings.Contains(r.text(), "--- server stopped") {
		t.Fatalf("log: %q", r.text())
	}
	// It can be started again, and the first-run password stays visible.
	if err := r.start(nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second run", func() bool { return r.snapshot().Scan.Listening })
	if r.snapshot().Scan.AdminPassword != "s3cret-pw" {
		t.Fatal("first-run password lost across a restart")
	}
	r.stop()
}

func TestRunnerReportsACrash(t *testing.T) {
	t.Setenv("RC_FAKE_SERVER", "crash")
	r := &runner{exe: os.Args[0]}
	if err := r.start(nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the exit", func() bool { return !r.snapshot().Running && r.snapshot().ExitMsg != "" })
	m := r.snapshot().ExitMsg
	if !strings.Contains(m, "exited unexpectedly") || !strings.Contains(m, "address already in use") {
		t.Fatalf("the user needs the server's own reason: %q", m)
	}
}

func TestRunnerMissingExe(t *testing.T) {
	r := &runner{exe: filepath.Join(t.TempDir(), "nope.exe")}
	if err := r.start(nil, nil); err == nil || r.snapshot().Running {
		t.Fatalf("start of a missing exe: %v", err)
	}
}

func TestDur(t *testing.T) {
	for in, want := range map[time.Duration]string{
		5 * time.Second: "5s", 95 * time.Second: "1m 35s", 3*time.Hour + 5*time.Minute: "3h 5m", 50*time.Hour + 30*time.Minute: "2d 2h",
	} {
		if got := dur(in); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

func TestInstallCommand(t *testing.T) {
	if installCommand("http://h:1", "", "k") != "" {
		t.Fatal("no token, no command")
	}
	if got := installCommand("http://h:1", "tok", "key"); got != "agent.exe install -server http://h:1 -enroll-token tok -server-key key" {
		t.Fatal(got)
	}
	if got := installCommand("http://h:1", "tok", ""); strings.Contains(got, "-server-key") {
		t.Fatal(got)
	}
	if c := (config{Port: 9}); c.agentURL() != "http://localhost:9" {
		t.Fatal(c.agentURL())
	}
}

func TestAPIClient(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sekret" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/admin/projects":
			w.Write([]byte(`[{"id":"demo","name":"Demo","role":"admin"}]`))
		case "POST /v1/admin/projects":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"main","name":"Main"}`))
		case "POST /v1/admin/projects/demo/enrollment-tokens":
			var b struct {
				TTL int `json:"ttl_hours"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			if b.TTL != 72 {
				http.Error(w, `{"error":"bad ttl"}`, 400)
				return
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"token":"abc123","expires_at":"2030-01-01T00:00:00Z","server_key":"KEY="}`))
		case "GET /v1/admin/me/tokens":
			w.Write([]byte(`[{"id":"tok_1","name":"bootstrap (-admin-token)"},{"id":"tok_2","name":"my script"},{"id":"tok_3","name":"bootstrap (-admin-token)"}]`))
		case "POST /v1/admin/projects/nope/enrollment-tokens":
			http.Error(w, `{"error":"no such project"}`, 404)
		default:
			if r.Method == "DELETE" {
				deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/v1/admin/me/tokens/"))
				w.WriteHeader(204)
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port, _ := parsePort(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	a := newAPI(config{Port: port}, "sekret")

	if ps, err := a.projects(); err != nil || len(ps) != 1 || ps[0].ID != "demo" {
		t.Fatalf("projects: %v %v", ps, err)
	}
	if p, err := a.createProject("Main"); err != nil || p.ID != "main" {
		t.Fatalf("createProject: %v %v", p, err)
	}
	if e, err := a.newEnrollment("demo", 72); err != nil || e.Token != "abc123" || e.ServerKey != "KEY=" {
		t.Fatalf("newEnrollment: %v %v", e, err)
	}
	if _, err := a.newEnrollment("nope", 72); err == nil || err.Error() != "no such project" {
		t.Fatalf("the server's own message should reach the user: %v", err)
	}
	a.dropBootstrapTokens()
	if strings.Join(deleted, ",") != "tok_1,tok_3" {
		t.Fatalf("only the bootstrap tokens may be revoked: %v", deleted)
	}
	if _, err := newAPI(config{Port: port}, "wrong").projects(); err == nil {
		t.Fatal("a wrong token must be refused")
	}
}
