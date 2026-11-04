//go:build !noscripts && !noselfupdate

package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"remoteconfig/internal/proto"
)

// ---------------------------------------------------------------- helpers

type testScripts struct{ interp, hello, exit3, sleep, noisy string }

func scriptsForThisOS() testScripts {
	if runtime.GOOS == "windows" {
		return testScripts{"cmd", "@echo off\r\necho hello %1\r\n", "@exit /b 3\r\n", "@ping -n 40 127.0.0.1 >nul\r\n",
			"@echo off\r\nfor /l %%i in (1,1,4000) do @echo line %%i padding padding padding padding\r\n"}
	}
	return testScripts{"sh", "echo hello $1\n", "exit 3\n", "sleep 40\n",
		"i=0; while [ $i -lt 4000 ]; do echo line $i padding padding padding padding; i=$((i+1)); done\n"}
}

func (e *env) addScript(name, interp, body string, timeout int) proto.ScriptInfo {
	e.t.Helper()
	var x proto.ScriptInfo
	if code := e.admin("POST", "/scripts", proto.ScriptCreate{Name: name, Interpreter: interp, Content: body, TimeoutS: timeout}, &x); code != 201 {
		e.t.Fatalf("upload script: %d", code)
	}
	return x
}

func (e *env) send(typ string, params map[string]any) string {
	e.t.Helper()
	var c proto.Command
	if code := e.admin("POST", "/devices/"+e.deviceID+"/commands", proto.CommandRequest{Type: typ, Params: params}, &c); code != 201 {
		e.t.Fatalf("queue %s: %d", typ, code)
	}
	return c.ID
}

// outcome waits for a command to finish and returns its status and reported output.
func (e *env) outcome(id string, within time.Duration) (status, output string) {
	e.t.Helper()
	wait(e.t, "command "+id+" to finish", within, func() bool {
		for _, c := range e.detail().Commands {
			if c.ID == id && (c.Status == "succeeded" || c.Status == "failed" || c.Status == "expired") {
				status = c.Status
				output, _ = c.Params["result"].(string)
				return true
			}
		}
		return false
	})
	return
}

func (e *env) addRelease(query string, body []byte) proto.ReleaseInfo {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/admin/projects/demo/releases?"+query, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer adm")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var x proto.ReleaseInfo
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 || json.Unmarshal(b, &x) != nil {
		e.t.Fatalf("upload release: %d %s", resp.StatusCode, b)
	}
	return x
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------- scripts

func TestAScriptRunsExactlyAsUploaded(t *testing.T) {
	ts := scriptsForThisOS()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil)
	e.addScript("hello", ts.interp, ts.hello, 30)
	id := e.send("run_script", map[string]any{"script": "hello", "args": []any{"world"}})
	status, out := e.outcome(id, 30*time.Second)
	if status != "succeeded" || !strings.Contains(out, "hello world") || !strings.Contains(out, "exit code 0") {
		t.Fatalf("%s: %q", status, out)
	}
	wait(t, "the script.ran event", 10*time.Second, func() bool {
		for _, ev := range e.detail().Events {
			if ev.Type == "script.ran" {
				return true
			}
		}
		return false
	})
	if left, _ := filepath.Glob(filepath.Join(e.stateDir, "script-*")); len(left) != 0 {
		t.Fatalf("the script was left on disk: %v", left)
	}
}

func TestAScriptChangedOnTheWireIsNotRun(t *testing.T) {
	ts := scriptsForThisOS()
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, m.link)
	e.addScript("hello", ts.interp, ts.hello, 30)
	evil := "echo pwned\n"
	if runtime.GOOS == "windows" {
		evil = "@echo pwned\r\n"
	}
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if strings.HasPrefix(r.URL.Path, "/v1/scripts/") {
			return status, hdr, []byte(evil)
		}
		return status, hdr, body
	})
	status, out := e.outcome(e.send("run_script", map[string]any{"script": "hello"}), 30*time.Second)
	if status != "failed" || strings.Contains(out, "pwned") || !strings.Contains(out, "does not match") {
		t.Fatalf("a rewritten script was run: %s %q", status, out)
	}
	if e.agent.trust.report().Rejected == 0 {
		t.Fatal("the dashboard would never hear about it")
	}
}

func TestScriptFailuresAndTimeoutsAreReported(t *testing.T) {
	ts := scriptsForThisOS()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil)
	e.addScript("bad", ts.interp, ts.exit3, 30)
	status, out := e.outcome(e.send("run_script", map[string]any{"script": "bad"}), 30*time.Second)
	if status != "failed" || !strings.Contains(out, "exit code 3") {
		t.Fatalf("a failing script: %s %q", status, out)
	}
	e.addScript("slow", ts.interp, ts.sleep, 1)
	start := time.Now()
	status, out = e.outcome(e.send("run_script", map[string]any{"script": "slow"}), 30*time.Second)
	if status != "failed" || !strings.Contains(out, "time limit") {
		t.Fatalf("a script past its limit: %s %q", status, out)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatalf("the script was allowed to run for %s", time.Since(start))
	}
}

func TestLongScriptOutputKeepsBothEnds(t *testing.T) {
	ts := scriptsForThisOS()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil)
	e.addScript("noisy", ts.interp, ts.noisy, 60)
	status, out := e.outcome(e.send("run_script", map[string]any{"script": "noisy"}), 60*time.Second)
	if status != "succeeded" || !strings.Contains(out, "line 1 ") || !strings.Contains(out, "line 3999 ") || !strings.Contains(out, "omitted") {
		t.Fatalf("%s: %d bytes, starts %q, ends %q", status, len(out), out[:min(80, len(out))], out[max(0, len(out)-80):])
	}
	if len(out) > maxScriptOutput+200 {
		t.Fatalf("output not capped: %d bytes", len(out))
	}
}

func TestAnAgentThatCannotVerifyNeverRunsServerCode(t *testing.T) {
	a := New(Options{StateDir: t.TempDir(), Capturer: &fakeCapturer{}}) // no key known: legacy
	for _, run := range []func(context.Context, proto.Command) proto.CommandResult{a.runScript, a.applyRelease} {
		res := run(context.Background(), proto.Command{ID: "c", Params: map[string]any{
			"script_id": "s", "sha256": strings.Repeat("a", 64), "interpreter": "sh",
			"release_id": "r", "kind": "app", "version": "1", "size": 10.0}})
		if res.OK || !strings.Contains(res.Output, "does not verify signatures") {
			t.Fatalf("a legacy agent ran or installed something: %+v", res)
		}
	}
}

func TestACommandStillRunningIsNotReportedTwice(t *testing.T) {
	ts := scriptsForThisOS()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil)
	e.addScript("slow", ts.interp, ts.sleep, 3)
	id := e.send("run_script", map[string]any{"script": "slow"})
	// the command is re-sent at every check-in until it has a result; none of those may
	// complete it early or start the script again
	time.Sleep(1500 * time.Millisecond)
	for _, c := range e.detail().Commands {
		if c.ID == id && (c.Status == "succeeded" || c.Status == "failed") {
			t.Fatalf("reported %s while still running", c.Status)
		}
	}
	status, out := e.outcome(id, 30*time.Second)
	if status != "failed" || !strings.Contains(out, "time limit") {
		t.Fatalf("%s %q", status, out)
	}
}

// ---------------------------------------------------------------- unpacking

func TestUnpackingRefusesPathsThatLeaveTheTarget(t *testing.T) {
	for name, files := range map[string]map[string][]byte{
		"parent":        {"../evil.txt": []byte("x")},
		"nested parent": {"a/../../evil.txt": []byte("x")},
		"absolute":      {"/etc/evil.txt": []byte("x")},
		"backslash":     {`..\evil.txt`: []byte("x")},
		"drive":         {`C:\evil.txt`: []byte("x")},
	} {
		dir := t.TempDir()
		zp := filepath.Join(dir, "r.zip")
		os.WriteFile(zp, zipOf(t, files), 0o600)
		target := filepath.Join(dir, "out")
		os.MkdirAll(target, 0o755)
		if err := extractZip(zp, target); err == nil {
			t.Errorf("%s: unpacked", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "evil.txt")); err == nil {
			t.Errorf("%s: wrote outside the target", name)
		}
	}
}

func TestUnpackingRefusesLinks(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("/etc/passwd"))
	zw.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.zip"), buf.Bytes(), 0o600)
	if err := extractZip(filepath.Join(dir, "r.zip"), dir); err == nil {
		t.Fatal("a symlink in a release was unpacked")
	}
}

func TestUnpackingKeepsNestedFilesAndPermissions(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "r.zip")
	os.WriteFile(zp, zipOf(t, map[string][]byte{"app.exe": []byte("exe"), "Data/level1.bin": []byte("level")}), 0o600)
	out := filepath.Join(dir, "out")
	os.MkdirAll(out, 0o755)
	if err := extractZip(zp, out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "Data", "level1.bin")); string(b) != "level" {
		t.Fatalf("nested file: %q", b)
	}
}

func TestReleasePlaceholderIsExpandedEverywhereTheSupervisorLooks(t *testing.T) {
	a := New(Options{StateDir: t.TempDir()})
	c := proto.SupervisorConfig{Exe: "${release}/app", Args: []string{"-data", "${release}/data"}, Workdir: "${release}", Env: map[string]string{"X": "${release}"}}
	if got := a.expandRelease(c); got.Exe != c.Exe {
		t.Fatalf("with no release installed the config must stay as written: %+v", got)
	}
	a.rel = releaseState{Dir: "/r/1"}
	got := a.expandRelease(c)
	if got.Exe != "/r/1/app" || got.Args[1] != "/r/1/data" || got.Workdir != "/r/1" || got.Env["X"] != "/r/1" {
		t.Fatalf("%+v", got)
	}
	if c.Args[1] != "${release}/data" {
		t.Fatal("the shared config was modified in place")
	}
}

// ---------------------------------------------------------------- downloads

func TestAReleaseDownloadResumesAfterTheLinkDropsAndIsVerified(t *testing.T) {
	var ranged, aborted atomic.Int32
	link := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/file") {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("Range") != "" {
				ranged.Add(1)
			}
			if aborted.Load() < 2 { // the first two attempts die half-way
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				b := rec.Body.Bytes()
				if rec.Code == 200 || rec.Code == 206 {
					for k, v := range rec.Header() {
						w.Header()[k] = v
					}
					w.WriteHeader(rec.Code)
					w.Write(b[:len(b)/2])
					w.(http.Flusher).Flush()
					aborted.Add(1)
					panic(http.ErrAbortHandler)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, link)
	big := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 KB, compresses to little but stored as is
	rel := e.addRelease("kind=app&name=kiosk&version=1.0&os="+runtime.GOOS, zipOf(t, map[string][]byte{"app/data.bin": big, "app/readme.txt": []byte("hi")}))
	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": rel.ID}), 60*time.Second)
	if status != "succeeded" {
		t.Fatalf("%s: %s", status, out)
	}
	if aborted.Load() != 2 || ranged.Load() == 0 {
		t.Fatalf("aborted %d times, resumed with Range %d times: the test did not exercise resuming", aborted.Load(), ranged.Load())
	}
	st := e.agent.releaseSnapshot()
	if st.Version != "1.0" {
		t.Fatalf("release state: %+v", st)
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir, "data.bin")); !bytes.Equal(b, big) { // the single top folder was looked through
		t.Fatalf("the unpacked file differs (%d bytes)", len(b))
	}
	if left, _ := filepath.Glob(filepath.Join(e.stateDir, "releases", "incoming", "*")); len(left) != 0 {
		t.Fatalf("download leftovers: %v", left)
	}
}

func TestADownloadThatDoesNotMatchTheSignedHashIsDiscarded(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, m.link)
	rel := e.addRelease("kind=app&name=kiosk&version=1.0&os="+runtime.GOOS, zipOf(t, map[string][]byte{"app.exe": []byte("real build")}))
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if strings.HasSuffix(r.URL.Path, "/file") && len(body) > 20 {
			body = append([]byte(nil), body...)
			body[len(body)/2] ^= 0xFF // same length, one byte different
		}
		return status, hdr, body
	})
	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": rel.ID}), 60*time.Second)
	if status != "failed" || !strings.Contains(out, "does not match") {
		t.Fatalf("%s: %s", status, out)
	}
	if e.agent.releaseSnapshot().Dir != "" {
		t.Fatal("a release that failed verification was selected")
	}
	if left, _ := filepath.Glob(filepath.Join(e.stateDir, "releases", "app", "*")); len(left) != 0 {
		t.Fatalf("unpacked despite the mismatch: %v", left)
	}
	if e.agent.trust.report().Rejected == 0 {
		t.Fatal("not reported as a rejection")
	}
}

func TestADownloadPausesWhenTheDataBudgetIsUsedUp(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}, Budget: map[string]any{"monthly_mb": 1}}, nil)
	rel := e.addRelease("kind=app&name=kiosk&version=1.0&os="+runtime.GOOS, zipOf(t, map[string][]byte{"app.exe": []byte("x")}))
	wait(t, "the budget policy", 10*time.Second, func() bool { return e.agent.budgetPolicy().MonthlyMB == 1 })
	e.agent.usage.add(2<<20, 0) // 2 MB used of 1 MB
	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": rel.ID}), 30*time.Second)
	if status != "failed" || !strings.Contains(out, "data budget") {
		t.Fatalf("%s: %s", status, out)
	}
}

// ---------------------------------------------------------------- app releases and rollback

func readTestapp(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(testappExe)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnAppReleaseThatDoesNotStayUpIsRolledBack(t *testing.T) {
	sep := string(filepath.Separator)
	sc := &proto.SupervisorConfig{Exe: "${release}" + sep + "app.exe", HeartbeatTimeoutS: 60, QuitTimeoutS: 5, StopAppOnAgentExit: true}
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}, Supervisor: sc}, nil)
	good := e.addRelease("kind=app&name=kiosk&version=1.0&os="+runtime.GOOS, zipOf(t, map[string][]byte{"app.exe": readTestapp(t)}))
	bad := e.addRelease("kind=app&name=kiosk&version=2.0&os="+runtime.GOOS, zipOf(t, map[string][]byte{"app.exe": []byte("this is not a program")}))

	wait(t, "supervision to be configured", 15*time.Second, func() bool { return e.agent.sup.Snapshot().Managing })
	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": good.ID, "health_s": 5.0}), 90*time.Second)
	if status != "succeeded" {
		t.Fatalf("the good release: %s %s", status, out)
	}
	first := e.agent.sup.Snapshot()
	if !first.Running {
		t.Fatalf("the app is not running after a successful release: %+v", first)
	}
	if id, err := identityOf(first.PID); err != nil || !strings.HasPrefix(strings.ToLower(id.Image), strings.ToLower(e.agent.releaseSnapshot().Dir)) {
		t.Fatalf("the app runs from %q (%v), not from the release folder %q", id.Image, err, e.agent.releaseSnapshot().Dir)
	}

	status, out = e.outcome(e.send("apply_release", map[string]any{"release_id": bad.ID, "health_s": 5.0}), 120*time.Second)
	if status != "failed" || !strings.Contains(out, "rolled back to 1.0") {
		t.Fatalf("the broken release: %s %s", status, out)
	}
	if st := e.agent.releaseSnapshot(); st.Version != "1.0" {
		t.Fatalf("still on %+v", st)
	}
	wait(t, "the old build to be running again", 30*time.Second, func() bool { return e.agent.sup.Snapshot().Running })
	wait(t, "the rollback to be reported", 15*time.Second, func() bool {
		for _, ev := range e.detail().Events {
			if ev.Type == "release.rolled_back" {
				return true
			}
		}
		return false
	})
}

// ---------------------------------------------------------------- agent updates

var (
	realAgentOnce sync.Once
	realAgentExe  string
)

// realAgent builds the actual agent binary: the smoke test needs something that answers "version".
func realAgent(t *testing.T) string {
	t.Helper()
	realAgentOnce.Do(func() {
		realAgentExe = filepath.Join(filepath.Dir(testappExe), "realagent.exe")
		if out, err := exec.Command("go", "build", "-o", realAgentExe, "remoteconfig/cmd/agent").CombinedOutput(); err != nil {
			panic("building the agent: " + err.Error() + "\n" + string(out))
		}
	})
	return realAgentExe
}

func agentVersion(t *testing.T, exe string) string {
	t.Helper()
	out, err := exec.Command(exe, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestAnAgentUpdateReplacesTheBinaryAfterASmokeTestAndRestarts(t *testing.T) {
	newBin, _ := os.ReadFile(realAgent(t))
	version := agentVersion(t, realAgent(t))
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	os.WriteFile(exe, []byte("the old agent"), 0o755)
	exited := make(chan int, 1)
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil, func(o *Options) {
		o.ExePath = exe
		o.Exit = func(code int) { exited <- code }
	})
	rel := e.addRelease("kind=agent&name=agent&version="+version+"&os="+runtime.GOOS+"&arch="+runtime.GOARCH, newBin)

	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": rel.ID}), 90*time.Second)
	if status != "succeeded" {
		t.Fatalf("%s: %s", status, out)
	}
	select {
	case code := <-exited:
		if code != exitForUpdate {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent did not restart itself after reporting")
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
		t.Fatal("the binary was not replaced")
	}
	if old, _ := os.ReadFile(exe + ".old"); string(old) != "the old agent" {
		t.Fatalf("the previous binary was not kept: %q", old)
	}
	if _, err := os.Stat(exe + ".new"); err == nil {
		t.Fatal("staging file left behind")
	}
	if _, err := os.Stat(pendingPath(e.stateDir)); err != nil {
		t.Fatal("no pending-update marker: a bad binary could not be rolled back")
	}
}

func TestAnAgentBuildThatFailsItsSmokeTestIsNotInstalled(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	os.WriteFile(exe, []byte("the old agent"), 0o755)
	exited := make(chan int, 1)
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, nil, func(o *Options) {
		o.ExePath = exe
		o.Exit = func(code int) { exited <- code }
	})
	rel := e.addRelease("kind=agent&name=agent&version=9.9.9&os="+runtime.GOOS+"&arch="+runtime.GOARCH, []byte("not an executable"))
	status, out := e.outcome(e.send("apply_release", map[string]any{"release_id": rel.ID}), 60*time.Second)
	if status != "failed" || !strings.Contains(out, "smoke test") {
		t.Fatalf("%s: %s", status, out)
	}
	if got, _ := os.ReadFile(exe); string(got) != "the old agent" {
		t.Fatalf("the running agent was replaced: %q", got)
	}
	for _, p := range []string{exe + ".new", exe + ".old", pendingPath(e.stateDir)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	select {
	case <-exited:
		t.Fatal("the agent restarted although nothing was installed")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestANewBinaryThatKeepsFailingToCheckInIsReplacedByThePreviousOne(t *testing.T) {
	state := t.TempDir()
	exe := filepath.Join(t.TempDir(), "agent.exe")
	os.WriteFile(exe, []byte("broken new agent"), 0o755)
	os.WriteFile(exe+".old", []byte("good old agent"), 0o755)
	b, _ := json.Marshal(pendingUpdate{From: "0.1", To: "0.2", Exe: exe, At: time.Now()})
	os.WriteFile(pendingPath(state), b, 0o600)

	logf := func(string, ...any) {}
	for i := 1; i <= maxTrialBoots; i++ {
		if CheckPendingUpdate(state, logf) {
			t.Fatalf("rolled back on start %d: a new binary gets %d tries", i, maxTrialBoots)
		}
	}
	if !CheckPendingUpdate(state, logf) {
		t.Fatal("a binary that never got to check in stayed")
	}
	if got, _ := os.ReadFile(exe); string(got) != "good old agent" {
		t.Fatalf("the previous binary was not restored: %q", got)
	}
	if _, err := os.Stat(pendingPath(state)); err == nil {
		t.Fatal("the marker survived, so the old binary would be 'rolled back' again")
	}

	// the restored agent tells the dashboard what happened
	a := New(Options{StateDir: state, Version: "0.1"})
	a.confirmUpdate()
	var told bool
	for _, ev := range eventsOf(a) {
		told = told || ev.Type == "agent.update_failed"
	}
	if !told {
		t.Fatal("nobody would know the update failed")
	}
}

func TestACheckInConfirmsTheNewBinary(t *testing.T) {
	state := t.TempDir()
	b, _ := json.Marshal(pendingUpdate{From: "0.1", To: "0.2", Exe: "x", Boots: 2, At: time.Now()})
	os.WriteFile(pendingPath(state), b, 0o600)
	a := New(Options{StateDir: state, Version: "0.2"})
	a.confirmUpdate()
	if _, err := os.Stat(pendingPath(state)); err == nil {
		t.Fatal("a binary that checked in is still on probation")
	}
	var told bool
	for _, ev := range eventsOf(a) {
		told = told || ev.Type == "agent.updated"
	}
	if !told {
		t.Fatal("no agent.updated event")
	}
}

func eventsOf(a *Agent) []proto.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]proto.Event(nil), a.events...)
}
