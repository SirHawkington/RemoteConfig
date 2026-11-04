package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/server"
)

type rig struct {
	t    *testing.T
	st   *server.Store
	srv  *httptest.Server
	devs []proto.EnrollResponse
	env  map[string]string
}

func newRig(t *testing.T, devices int) *rig {
	t.Helper()
	st, err := server.OpenStore("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
	srv := httptest.NewServer(server.New(st, server.Options{CheckinInterval: time.Minute, RolloutTick: 50 * time.Millisecond}).Handler())
	t.Cleanup(func() { srv.Close(); st.Close() })
	watchEvery = 50 * time.Millisecond
	r := &rig{t: t, st: st, srv: srv, env: map[string]string{"RCCTL_SERVER": srv.URL, "RCCTL_TOKEN": "adm"}}
	for i := 0; i < devices; i++ {
		tok := st.NewEnrollToken("demo", []string{"lobby"}, time.Hour)
		b, _ := json.Marshal(proto.EnrollRequest{Token: tok, Hostname: "kiosk", OS: "windows", Arch: "amd64"})
		resp, err := http.Post(srv.URL+"/v1/enroll", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		var er proto.EnrollResponse
		json.NewDecoder(resp.Body).Decode(&er)
		resp.Body.Close()
		r.devs = append(r.devs, er)
		// give each a distinct name through the admin API
		nb, _ := json.Marshal(map[string]string{"name": []string{"alpha", "beta", "gamma"}[i]})
		req, _ := http.NewRequest("PATCH", srv.URL+"/v1/admin/projects/demo/devices/"+er.DeviceID, bytes.NewReader(nb))
		req.Header.Set("Authorization", "Bearer adm")
		pr, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		pr.Body.Close()
	}
	return r
}

func (r *rig) rc(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, func(k string) string { return r.env[k] }, &out, &errb)
	return code, out.String(), errb.String()
}

func (r *rig) file(name, content string) string {
	p := filepath.Join(r.t.TempDir(), name)
	os.WriteFile(p, []byte(content), 0o600)
	return p
}

func (r *rig) zip() string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("app.exe")
	w.Write([]byte("build"))
	zw.Close()
	p := filepath.Join(r.t.TempDir(), "kiosk.zip")
	os.WriteFile(p, buf.Bytes(), 0o600)
	return p
}

func (r *rig) commandsOf(i int) []proto.Command {
	req, _ := http.NewRequest("GET", r.srv.URL+"/v1/commands", nil)
	req.Header.Set("Authorization", "Bearer "+r.devs[i].DeviceToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var cmds []proto.Command
	json.NewDecoder(resp.Body).Decode(&cmds)
	return cmds
}

func (r *rig) report(i int, id string, ok bool, out string) {
	b, _ := json.Marshal(proto.CommandResult{OK: ok, Output: out})
	req, _ := http.NewRequest("POST", r.srv.URL+"/v1/commands/"+id+"/result", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+r.devs[i].DeviceToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	resp.Body.Close()
	// a device that has just finished is checking in: a canary must be seen online before the rest follow
	cb, _ := json.Marshal(proto.CheckinRequest{Session: "s", Seq: 1, AgentVersion: "t"})
	creq, _ := http.NewRequest("POST", r.srv.URL+"/v1/checkin", bytes.NewReader(cb))
	creq.Header.Set("Authorization", "Bearer "+r.devs[i].DeviceToken)
	cresp, err := http.DefaultClient.Do(creq)
	if err != nil {
		r.t.Fatal(err)
	}
	cresp.Body.Close()
}

func lastWord(s, prefix string) string { // "rollout ro_xxx started" -> "ro_xxx"
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+len(prefix):])
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// ---------------------------------------------------------------- setup and errors

func TestItExplainsWhatIsMissing(t *testing.T) {
	r := newRig(t, 0)
	r.env = map[string]string{}
	if code, _, e := r.rc("devices"); code != 2 || !strings.Contains(e, "RCCTL_SERVER") {
		t.Fatalf("%d %q", code, e)
	}
	r.env = map[string]string{"RCCTL_SERVER": r.srv.URL}
	if code, _, e := r.rc("devices"); code != 2 || !strings.Contains(e, "RCCTL_TOKEN") {
		t.Fatalf("%d %q", code, e)
	}
	r.env["RCCTL_TOKEN"] = "wrong"
	if code, _, e := r.rc("devices"); code != 3 {
		t.Fatalf("a bad token should exit 3, got %d %q", code, e)
	}
	if code, _, _ := r.rc("nonsense"); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
	if code, out, _ := r.rc("help"); code != 0 || !strings.Contains(out, "rollout watch") {
		t.Fatalf("help: %d", code)
	}
}

func TestATokenFileIsReadAndPlainHTTPToAnotherHostIsWarnedAbout(t *testing.T) {
	r := newRig(t, 1)
	r.env = map[string]string{"RCCTL_SERVER": r.srv.URL, "RCCTL_TOKEN_FILE": r.file("tok", "adm\n")}
	if code, out, _ := r.rc("devices"); code != 0 || !strings.Contains(out, "alpha") {
		t.Fatalf("token file: %d %q", code, out)
	}
	var e bytes.Buffer
	if _, err := newClient(func(k string) string {
		return map[string]string{"RCCTL_SERVER": "http://rc.example.com", "RCCTL_TOKEN": "x"}[k]
	}, &bytes.Buffer{}, &e); err != nil || !strings.Contains(e.String(), "plain http") {
		t.Fatalf("no warning about a token sent over http to a remote host: %v %q", err, e.String())
	}
}

func TestSeveralProjectsNeedAChoice(t *testing.T) {
	r := newRig(t, 1)
	r.st.Seed("other", "Other", &proto.ConfigDocument{Data: map[string]any{}})
	if code, _, e := r.rc("devices"); code != 1 || !strings.Contains(e, "RCCTL_PROJECT") {
		t.Fatalf("%d %q", code, e)
	}
	r.env["RCCTL_PROJECT"] = "demo"
	if code, out, _ := r.rc("devices"); code != 0 || !strings.Contains(out, "alpha") {
		t.Fatalf("%d %q", code, out)
	}
}

// ---------------------------------------------------------------- scripts

func TestAddingAndRunningAScriptInStages(t *testing.T) {
	r := newRig(t, 3)
	f := r.file("clear.cmd", "@echo off\r\necho hi\r\n")
	code, out, e := r.rc("script", "add", "clear-cache", f, "-desc", "demo")
	if code != 0 || !strings.Contains(out, "clear-cache v1 stored (cmd") {
		t.Fatalf("add: %d %q %q", code, out, e)
	}
	if code, out, _ := r.rc("script", "list"); code != 0 || !strings.Contains(out, "clear-cache") {
		t.Fatalf("list: %q", out)
	}
	// the devices come after the positional name, flags in any order
	code, out, e = r.rc("script", "run", "clear-cache", "-devices", "beta,alpha,gamma", "-arg", "one", "-arg", "two words", "-soak", "600")
	if code != 0 || !strings.Contains(out, "rollout ") || !strings.Contains(out, "3 devices, 1 canary") {
		t.Fatalf("run: %d %q %q", code, out, e)
	}
	if got := len(r.commandsOf(1)); got != 1 { // beta was named first: it is the canary
		t.Fatalf("the first named device should be the canary and have the command: %d", got)
	}
	if len(r.commandsOf(0)) != 0 || len(r.commandsOf(2)) != 0 {
		t.Fatal("the others were sent the script before the canary finished")
	}
	c := r.commandsOf(1)[0]
	if a, _ := c.Params["args"].([]any); len(a) != 2 || a[1] != "two words" {
		t.Fatalf("arguments were not passed intact: %v", c.Params["args"])
	}
}

func TestSendingNowSkipsTheStaging(t *testing.T) {
	r := newRig(t, 2)
	r.rc("script", "add", "x", r.file("x.sh", "echo x"))
	code, out, _ := r.rc("script", "run", "x", "-all", "-now")
	if code != 0 || strings.Count(out, "queued") != 2 || len(r.commandsOf(0)) != 1 || len(r.commandsOf(1)) != 1 {
		t.Fatalf("%d %q", code, out)
	}
}

func TestBadDeviceChoicesAreRefused(t *testing.T) {
	r := newRig(t, 2)
	r.rc("script", "add", "x", r.file("x.sh", "echo x"))
	for name, args := range map[string][]string{
		"no devices named":    {"script", "run", "x"},
		"unknown device":      {"script", "run", "x", "-devices", "nobody"},
		"unknown script":      {"script", "run", "missing", "-devices", "alpha"},
		"a tag nobody has":    {"script", "run", "x", "-tag", "basement"},
		"unknown interpreter": {"script", "add", "y", r.file("y.txt", "x")},
	} {
		if code, _, _ := r.rc(args...); code == 0 {
			t.Errorf("%s: succeeded", name)
		}
	}
	if len(r.commandsOf(0))+len(r.commandsOf(1)) != 0 {
		t.Fatal("a refused request still sent something")
	}
	if code, out, _ := r.rc("script", "run", "x", "-tag", "LOBBY", "-now"); code != 0 || strings.Count(out, "queued") != 2 {
		t.Fatalf("tags should match without regard to case: %d %q", code, out)
	}
}

// ---------------------------------------------------------------- releases and rollouts

func TestUploadingAndSendingARelease(t *testing.T) {
	r := newRig(t, 2)
	code, out, e := r.rc("release", "upload", r.zip(), "-name", "kiosk", "-version", "1.0", "-notes", "first")
	if code != 0 || !strings.Contains(out, "kiosk 1.0 for windows/any") {
		t.Fatalf("upload: %d %q %q", code, out, e)
	}
	if code, _, _ := r.rc("release", "upload", r.zip(), "-name", "kiosk", "-version", "1.0"); code == 0 {
		t.Fatal("a version was uploaded twice")
	}
	if code, out, _ := r.rc("release", "list"); code != 0 || !strings.Contains(out, "kiosk") || !strings.Contains(out, "app") {
		t.Fatalf("list: %q", out)
	}
	code, out, e = r.rc("release", "send", "kiosk@1.0", "-all")
	if code != 0 || !strings.Contains(out, "sending kiosk 1.0") || !strings.Contains(out, "rollout ro_") {
		t.Fatalf("send: %d %q %q", code, out, e)
	}
	roID := lastWord(out, "rollout ")
	if code, out, _ := r.rc("rollout", "show", roID); code != 0 || !strings.Contains(out, "canary") || !strings.Contains(out, "waiting") {
		t.Fatalf("show: %q", out)
	}
	if code, out, _ := r.rc("rollout", "list"); code != 0 || !strings.Contains(out, roID) {
		t.Fatalf("list: %q", out)
	}
	if code, _, _ := r.rc("rollout", "halt", roID); code != 0 {
		t.Fatalf("halt: %d", code)
	}
	if code, out, _ := r.rc("rollout", "show", roID); !strings.Contains(out, "halted") || !strings.Contains(out, "halted by") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, _ := r.rc("rollout", "halt", roID); code == 0 {
		t.Fatal("halting a finished rollout succeeded")
	}
	if code, _, e := r.rc("release", "send", "kiosk@9.9", "-all"); code == 0 || !strings.Contains(e, "no release") {
		t.Fatalf("%d %q", code, e)
	}
}

func TestWatchFollowsARolloutToTheEndAndReportsItsOutcomeInTheExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
		want int
	}{{"success", true, 0}, {"canary failure", false, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, 1)
			r.rc("release", "upload", r.zip(), "-name", "kiosk", "-version", "1.0")
			done := make(chan struct{})
			var code int
			var out string
			go func() {
				code, out, _ = r.rc("release", "send", "kiosk@1.0", "-devices", "alpha", "-soak", "0", "-wait")
				close(done)
			}()
			// play the device: wait for the command, then report
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if cmds := r.commandsOf(0); len(cmds) > 0 {
					r.report(0, cmds[0].ID, tc.ok, "installed")
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("watch never returned")
			}
			if code != tc.want {
				t.Fatalf("exit %d, want %d:\n%s", code, tc.want, out)
			}
			if tc.ok && !strings.Contains(out, "done") || !tc.ok && !strings.Contains(out, "halted") {
				t.Fatalf("the output does not say how it ended:\n%s", out)
			}
		})
	}
}
