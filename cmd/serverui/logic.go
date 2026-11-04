package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	configName      = "server-ui.json"
	defaultPort     = 8080
	defaultInterval = "5m"
	minInterval     = 5 * time.Second
)

// config is what the window remembers between runs. It is turned into server flags on every
// start, so the window never owns anything the server itself does not already understand.
type config struct {
	Port      int    `json:"port"`
	Network   bool   `json:"network"` // listen on every interface, not just this PC
	DataDir   string `json:"data_dir"`
	Interval  string `json:"checkin_interval"`
	DevSeed   bool   `json:"demo_project"`
	AutoStart bool   `json:"auto_start"`
}

func defaults(base string) config {
	return config{Port: defaultPort, DataDir: filepath.Join(base, "data"), Interval: defaultInterval, AutoStart: true}
}

// loadConfig reads path; a missing file gives the defaults and a damaged one is an error rather
// than being silently replaced.
func loadConfig(path, base string) (config, error) {
	c := defaults(base)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return defaults(base), fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	d := defaults(base)
	if c.Port == 0 {
		c.Port = d.Port
	}
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.Interval == "" {
		c.Interval = d.Interval
	}
	return c, nil
}

func saveConfig(path string, c config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// validate returns a message for the user, or "" when the settings can be used.
func (c config) validate() string {
	if c.Port < 1 || c.Port > 65535 {
		return "The port must be a number between 1 and 65535."
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return "Choose a folder for the server's data."
	}
	d, err := time.ParseDuration(strings.TrimSpace(c.Interval))
	if err != nil || d < minInterval {
		return "The check-in interval must be a duration such as 5m or 30s, at least 5s."
	}
	return ""
}

func (c config) addr() string {
	if c.Network {
		return fmt.Sprintf(":%d", c.Port)
	}
	return fmt.Sprintf("127.0.0.1:%d", c.Port)
}

func (c config) dbPath() string { return filepath.Join(c.DataDir, "remoteconfig.db") }

// args are the server's command-line flags for these settings.
func (c config) args() []string {
	a := []string{"-addr", c.addr(), "-data", c.dbPath(), "-checkin-interval", strings.TrimSpace(c.Interval)}
	if c.DevSeed {
		a = append(a, "-dev-seed")
	}
	return a
}

func (c config) dashboardURL() string { return fmt.Sprintf("http://localhost:%d/", c.Port) }

// agentURLs are the addresses other PCs can reach the server on (empty when it listens locally only).
func (c config) agentURLs() []string {
	if !c.Network {
		return nil
	}
	var out []string
	for _, ip := range lanIPs() {
		out = append(out, fmt.Sprintf("http://%s:%d", ip, c.Port))
	}
	return out
}

func lanIPs() []string {
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			out = append(out, n.IP.String())
		}
	}
	return out
}

// agentURL is the address an agent should be given: a network address when other PCs may
// connect, otherwise this PC.
func (c config) agentURL() string {
	if u := c.agentURLs(); len(u) > 0 {
		return u[0]
	}
	return fmt.Sprintf("http://localhost:%d", c.Port)
}

// installCommand is what the dashboard's "Add device" shows, so it can be pasted on the kiosk.
func installCommand(server, token, key string) string {
	if token == "" {
		return ""
	}
	cmd := "agent.exe install -server " + server + " -enroll-token " + token
	if key != "" {
		cmd += " -server-key " + key
	}
	return cmd
}

func newAPIToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// bootstrapName is what the server calls the token it is given with RC_ADMIN_TOKEN.
const bootstrapName = "bootstrap (-admin-token)"

// apiClient talks to the running server's admin API as the "admin" account, using the
// one-off token this window gave the server when it started it.
type apiClient struct {
	base, token string
	hc          *http.Client
}

func newAPI(c config, token string) *apiClient {
	return &apiClient{base: fmt.Sprintf("http://127.0.0.1:%d", c.Port), token: token, hc: &http.Client{Timeout: 5 * time.Second}}
}

func (a *apiClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("the server answered HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type enrollment struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	ServerKey string    `json:"server_key"`
}

func (a *apiClient) projects() ([]project, error) {
	var out []project
	err := a.do("GET", "/v1/admin/projects", nil, &out)
	return out, err
}

func (a *apiClient) createProject(name string) (project, error) {
	var p project
	err := a.do("POST", "/v1/admin/projects", map[string]string{"name": name}, &p)
	return p, err
}

func (a *apiClient) newEnrollment(projectID string, hours int) (enrollment, error) {
	var e enrollment
	err := a.do("POST", "/v1/admin/projects/"+url.PathEscape(projectID)+"/enrollment-tokens", map[string]int{"ttl_hours": hours}, &e)
	return e, err
}

// dropBootstrapTokens revokes the tokens the server was started with, this window's and any
// left behind by a window that was killed, so they do not pile up in the account's token list.
func (a *apiClient) dropBootstrapTokens() {
	var toks []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if a.do("GET", "/v1/admin/me/tokens", nil, &toks) != nil {
		return
	}
	for _, t := range toks {
		if t.Name == bootstrapName {
			a.do("DELETE", "/v1/admin/me/tokens/"+url.PathEscape(t.ID), nil, nil)
		}
	}
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("the port must be a number")
	}
	return n, nil
}

// scanState picks the few facts worth showing out of the server's own output.
type scanState struct {
	ServerKey     string
	AdminPassword string
	Listening     bool
	firstRun      bool
}

var (
	keyRe = regexp.MustCompile(`-server-key (\S+)`)
	pwRe  = regexp.MustCompile(`^\s*password:\s+(\S+)`)
)

func (s *scanState) line(l string) {
	if m := keyRe.FindStringSubmatch(l); m != nil {
		s.ServerKey = m[1]
	}
	if strings.Contains(l, "First-run administrator account created") {
		s.firstRun = true
	}
	if s.firstRun {
		if m := pwRe.FindStringSubmatch(l); m != nil {
			s.AdminPassword = m[1]
			s.firstRun = false
		}
	}
	if strings.Contains(l, "listening on ") {
		s.Listening = true
	}
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d/time.Minute), int(d%time.Minute/time.Second))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%dd %dh", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
}
