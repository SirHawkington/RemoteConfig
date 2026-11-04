package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

const defaultListen = "127.0.0.1:7878"

// install is where the agent lives: its binary, agent.json, state and log.
type install struct {
	Dir      string
	CfgPath  string
	StateDir string
	LogFile  string
	Listen   string
}

// overrides are command-line values for running the UI against an agent that was not
// installed with `agent install` (for example `agent run -state-dir .\agent-state`).
type overrides struct {
	StateDir, LogFile, Listen string
}

// settings is agent.json, kept as a generic map so keys this UI does not know about
// survive a save.
type settings map[string]any

func (s settings) str(key string) string { v, _ := s[key].(string); return v }

func loadSettings(path string) (settings, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return settings{}, nil
	}
	if err != nil {
		return nil, err
	}
	s := settings{}
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// resolveInstall works out where everything is from agent.json in dir (relative paths in it
// are relative to the file, as the agent reads them), then applies overrides.
func resolveInstall(dir string, ov overrides) (install, settings, error) {
	in := install{Dir: dir, CfgPath: filepath.Join(dir, "agent.json")}
	s, err := loadSettings(in.CfgPath)
	if err != nil {
		return in, nil, err
	}
	abs := func(p, fallback string) string {
		switch {
		case p == "":
			return fallback
		case filepath.IsAbs(p):
			return p
		}
		return filepath.Join(dir, p)
	}
	in.StateDir = abs(s.str("state_dir"), filepath.Join(dir, "state"))
	in.LogFile = abs(s.str("log_file"), filepath.Join(dir, "agent.log"))
	in.Listen = s.str("listen")
	if in.Listen == "" {
		in.Listen = defaultListen
	}
	if ov.StateDir != "" {
		in.StateDir = ov.StateDir
	}
	if ov.LogFile != "" {
		in.LogFile = ov.LogFile
	}
	if ov.Listen != "" {
		in.Listen = ov.Listen
	}
	return in, s, nil
}

// ---------------------------------------------------------------- local API client

var (
	errAgentDown   = errors.New("The agent is not answering on its local address. Is it running?")
	errUnauthorize = errors.New("The agent rejected the local token; this UI is reading a different state folder than the agent uses.")
)

type apiClient struct {
	listen    string
	tokenPath string
	http      *http.Client
}

func newClient(in install) *apiClient {
	return &apiClient{
		listen:    in.Listen,
		tokenPath: filepath.Join(in.StateDir, "local-token"),
		http:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *apiClient) call(method, path string, out any) (string, error) {
	tok, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("The agent has not started for this install yet (no local token at %s).", c.tokenPath)
	}
	req, err := http.NewRequest(method, "http://"+c.listen+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	resp, err := c.http.Do(req)
	if err != nil {
		return "", errAgentDown
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", errUnauthorize
	case resp.StatusCode/100 != 2:
		var e struct{ Error string }
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return "", errors.New(e.Error)
		}
		return "", fmt.Errorf("agent answered HTTP %d", resp.StatusCode)
	}
	var m struct{ Message string }
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return "", err
		}
	} else {
		json.Unmarshal(body, &m)
	}
	return m.Message, nil
}

func (c *apiClient) overview() (*proto.Overview, error) {
	var o proto.Overview
	if _, err := c.call(http.MethodGet, "/v1/ui/overview", &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func (c *apiClient) checkinNow() error {
	_, err := c.call(http.MethodPost, "/v1/agent/checkin-now", nil)
	return err
}

func (c *apiClient) captureNow() (string, error) {
	return c.call(http.MethodPost, "/v1/ui/capture", nil)
}

func (c *apiClient) restartApp() (string, error) {
	return c.call(http.MethodPost, "/v1/ui/restart-app", nil)
}

// ---------------------------------------------------------------- settings form

// form holds what the Settings tab edits.
type form struct {
	Server, Token, ServerKey, Interval, Listen string
}

func formFrom(s settings) form {
	return form{
		Server: s.str("server"), ServerKey: s.str("server_key"),
		Interval: s.str("interval"), Listen: s.str("listen"),
	}
}

// validate returns a message for the first problem, "" when the form is fine.
func (f form) validate() string {
	u, err := url.Parse(strings.TrimSpace(f.Server))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "Server URL must look like https://rc.example.com"
	}
	if f.Interval != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(f.Interval)); err != nil || d < 5*time.Second {
			return "Check-in interval must be a duration of at least 5s, such as 5m (or empty to follow the server)"
		}
	}
	if f.Listen != "" {
		host, _, err := net.SplitHostPort(strings.TrimSpace(f.Listen))
		if err != nil {
			return "Local API address must look like 127.0.0.1:7878"
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "Local API address must be on this machine (127.0.0.1, ::1 or localhost): it controls the app"
		}
	}
	return ""
}

// apply returns s updated with the form. Empty optional fields are removed so the agent's
// defaults apply. An empty token leaves the saved one alone: it is single use and the form
// never shows it, so empty means "unchanged", not "forget it".
func (f form) apply(s settings) settings {
	out := settings{}
	for k, v := range s {
		out[k] = v
	}
	set := func(key, v string) {
		if v = strings.TrimSpace(v); v == "" {
			delete(out, key)
		} else {
			out[key] = v
		}
	}
	set("server", f.Server)
	if strings.TrimSpace(f.Token) != "" {
		set("enroll_token", f.Token)
	}
	set("server_key", f.ServerKey)
	set("interval", f.Interval)
	set("listen", f.Listen)
	return out
}

// ---------------------------------------------------------------- formatting

func ago(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return dur(now.Sub(t)) + " ago"
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

func megabytes(b int64) string { return fmt.Sprintf("%.1f MB", float64(b)/1e6) }

// tailFile returns roughly the last maxBytes of the file, starting at a line boundary.
func tailFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := max(0, st.Size()-maxBytes)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	s := string(b)
	if off > 0 {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return s, nil
}
