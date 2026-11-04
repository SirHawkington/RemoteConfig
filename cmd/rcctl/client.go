package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"remoteconfig/internal/proto"
)

type client struct {
	base, token, project string
	http                 *http.Client
	out, err             io.Writer
	getenv               func(string) string
}

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.msg, e.status) }

func newClient(getenv func(string) string, out, errOut io.Writer) (*client, error) {
	base := strings.TrimRight(getenv("RCCTL_SERVER"), "/")
	if base == "" {
		return nil, errors.New("set RCCTL_SERVER to the server address, e.g. https://rc.example.com")
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("RCCTL_SERVER is not a URL: %v", err)
	}
	tok := getenv("RCCTL_TOKEN")
	if f := getenv("RCCTL_TOKEN_FILE"); f != "" && tok == "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return nil, errors.New("set RCCTL_TOKEN (an API token from the dashboard's account menu) or RCCTL_TOKEN_FILE")
	}
	if strings.HasPrefix(base, "http://") && !isLocal(base) {
		fmt.Fprintln(errOut, "warning: the server address is plain http: the token travels in clear text. Use https.")
	}
	return &client{base: base, token: tok, project: getenv("RCCTL_PROJECT"), out: out, err: errOut, getenv: getenv,
		http: &http.Client{Timeout: 0}}, nil // uploads of big builds take as long as they take
}

func isLocal(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (c *client) do(method, path string, body io.Reader, contentType string, out any) error {
	req, err := http.NewRequest(method, c.base+"/v1/admin"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &apiError{resp.StatusCode, e.Error}
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (c *client) getJSON(path string, out any) error { return c.do("GET", path, nil, "", out) }

func (c *client) postJSON(path string, in, out any) error {
	b, _ := json.Marshal(in)
	return c.do("POST", path, bytes.NewReader(b), "application/json", out)
}

// proj resolves the project: RCCTL_PROJECT, or the only one the account can see.
func (c *client) proj() (string, error) {
	if c.project != "" {
		return c.project, nil
	}
	var me struct {
		Projects []struct {
			ID string `json:"id"`
		} `json:"projects"`
	}
	if err := c.getJSON("/me", &me); err != nil {
		return "", err
	}
	switch len(me.Projects) {
	case 0:
		return "", errors.New("this account is not a member of any project")
	case 1:
		c.project = me.Projects[0].ID
		return c.project, nil
	}
	var ids []string
	for _, p := range me.Projects {
		ids = append(ids, p.ID)
	}
	return "", fmt.Errorf("more than one project (%s): set RCCTL_PROJECT", strings.Join(ids, ", "))
}

func (c *client) fail(err error) int {
	fmt.Fprintln(c.err, "error:", err)
	var ae *apiError
	if errors.As(err, &ae) && (ae.status == 401 || ae.status == 403) {
		return 3
	}
	return 1
}

// pick turns -devices / -tag / -all into device ids, in the order given (the first are the canary).
func (c *client) pick(project, names, tag string, all bool) ([]string, error) {
	var devs []proto.DeviceSummary
	if err := c.getJSON("/projects/"+project+"/devices", &devs); err != nil {
		return nil, err
	}
	var ids []string
	switch {
	case names != "":
		for _, want := range strings.Split(names, ",") {
			want = strings.TrimSpace(want)
			var hit []string
			for _, d := range devs {
				if d.ID == want || strings.EqualFold(d.Name, want) {
					hit = append(hit, d.ID)
				}
			}
			switch len(hit) {
			case 0:
				return nil, fmt.Errorf("no device %q in %s", want, project)
			case 1:
				ids = append(ids, hit[0])
			default:
				return nil, fmt.Errorf("%q matches %d devices: use the id", want, len(hit))
			}
		}
	case tag != "":
		for _, d := range devs {
			for _, t := range d.Tags {
				if strings.EqualFold(t, tag) {
					ids = append(ids, d.ID)
					break
				}
			}
		}
	case all:
		for _, d := range devs {
			ids = append(ids, d.ID)
		}
	default:
		return nil, errors.New("say which devices: -devices a,b (names or ids), -tag <tag> or -all")
	}
	if len(ids) == 0 {
		return nil, errors.New("no devices match")
	}
	return ids, nil
}

func (c *client) devices(args []string) int {
	project, err := c.proj()
	if err != nil {
		return c.fail(err)
	}
	var devs []proto.DeviceSummary
	if err := c.getJSON("/projects/"+project+"/devices", &devs); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.out, "%-14s %-22s %-8s %-9s %-10s %s\n", "ID", "NAME", "OS", "STATE", "AGENT", "TAGS")
	for _, d := range devs {
		fmt.Fprintf(c.out, "%-14s %-22s %-8s %-9s %-10s %s\n", d.ID, d.Name, d.OS, d.Reachability, d.AgentVersion, strings.Join(d.Tags, ","))
	}
	return 0
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}
