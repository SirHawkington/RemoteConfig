package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (f *authFixture) raw(method, path, token string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *authFixture) upload(token, query string, body []byte) (int, proto.ReleaseInfo) {
	rec := f.raw("POST", A+"/releases?"+query, token, body, nil)
	var x proto.ReleaseInfo
	json.Unmarshal(rec.Body.Bytes(), &x)
	return rec.Code, x
}

func (f *authFixture) queue(typ string, params map[string]any) (int, map[string]any) {
	code, out, _ := f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", "adm", proto.CommandRequest{Type: typ, Params: params})
	return code, out
}

func TestScriptsAreImmutableVersionsWithTheirHash(t *testing.T) {
	f := newAuthFixture(t)
	body := "echo one"
	code, out, _ := f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: body})
	if code != 201 || out["version"] != 1.0 || out["sha256"] != sum([]byte(body)) {
		t.Fatalf("first upload: %d %v", code, out)
	}
	_, out, _ = f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: "echo two"})
	if out["version"] != 2.0 {
		t.Fatalf("a second upload under the same name is a new version, not an overwrite: %v", out)
	}
	for name, in := range map[string]proto.ScriptCreate{
		"unknown interpreter": {Name: "x", Interpreter: "perl", Content: "print 1"},
		"empty":               {Name: "x", Interpreter: "sh", Content: "  \n"},
		"bad name":            {Name: "../x", Interpreter: "sh", Content: "echo"},
		"too large":           {Name: "x", Interpreter: "sh", Content: strings.Repeat("a", maxScriptBytes+1)},
		"endless":             {Name: "x", Interpreter: "sh", Content: "echo", TimeoutS: 100000},
	} {
		if code, _, _ := f.call("POST", A+"/scripts", "adm", in); code < 400 {
			t.Errorf("%s was accepted (%d)", name, code)
		}
	}
}

func TestTheSignedScriptCommandCarriesTheLibrarysHashNotTheCallers(t *testing.T) {
	f := newAuthFixture(t)
	f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: "echo real"})

	// an admin (or whoever has their token) tries to name a different hash
	code, c := f.queue("run_script", map[string]any{"script": "hello", "sha256": sum([]byte("echo evil")), "interpreter": "powershell", "args": []any{"a", "b"}})
	if code != 201 {
		t.Fatalf("queue: %d %v", code, c)
	}
	rec := f.deviceGet("/v1/commands", nil)
	var cmds []proto.Command
	json.Unmarshal(rec.Body.Bytes(), &cmds)
	if len(cmds) != 1 || cmds[0].Signed == nil {
		t.Fatalf("the command was not delivered signed: %+v", cmds)
	}
	var sc proto.SignedCommand
	if _, err := signing.VerifyJSON(cmds[0].Signed, signing.TypeCommand, f.serverKeys(t), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Params["sha256"] != sum([]byte("echo real")) || sc.Params["interpreter"] != "sh" {
		t.Fatalf("signed parameters came from the request, not the library: %v", sc.Params)
	}
	if a, _ := sc.Params["args"].([]any); len(a) != 2 {
		t.Fatalf("arguments lost: %v", sc.Params["args"])
	}
}

func TestBadScriptCommandsAreRefusedAtTheServer(t *testing.T) {
	f := newAuthFixture(t)
	f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: "echo hi"})
	many := make([]any, maxScriptArgs+1)
	for i := range many {
		many[i] = "x"
	}
	for name, p := range map[string]map[string]any{
		"no script":         {},
		"unknown script":    {"script": "nope"},
		"unknown version":   {"script": "hello", "version": 9.0},
		"too many args":     {"script": "hello", "args": many},
		"non-text argument": {"script": "hello", "args": []any{map[string]any{"a": 1.0}}},
		"huge argument":     {"script": "hello", "args": []any{strings.Repeat("a", maxScriptArgLen+1)}},
	} {
		if code, _ := f.queue("run_script", p); code != 400 {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
}

func TestADeviceFetchesScriptsOfItsOwnProjectOnly(t *testing.T) {
	f := newAuthFixture(t)
	_, out, _ := f.call("POST", A+"/scripts", "adm", proto.ScriptCreate{Name: "hello", Interpreter: "sh", Content: "echo hi"})
	id := out["id"].(string)
	if rec := f.deviceGet("/v1/scripts/"+id, nil); rec.Code != 200 || rec.Body.String() != "echo hi" {
		t.Fatalf("own project: %d %q", rec.Code, rec.Body.String())
	}
	if rec := f.deviceGet("/v1/scripts/scr_nope", nil); rec.Code != 404 {
		t.Fatalf("unknown: %d", rec.Code)
	}
	f.st.Seed("other", "Other", &proto.ConfigDocument{Data: map[string]any{}})
	f.st.db.Exec(`INSERT INTO scripts(id,project,name,version,interpreter,timeout_s,sha256,content,created_at) VALUES('scr_other','other','x',1,'sh',10,'0',x'6563686f',?)`, time.Now().Format(time.RFC3339))
	if rec := f.deviceGet("/v1/scripts/scr_other", nil); rec.Code != 404 {
		t.Fatalf("a device read a script of another project: %d", rec.Code)
	}
	if rec := f.raw("GET", "/v1/scripts/"+id, "not-a-device-token", nil, nil); rec.Code != 401 {
		t.Fatalf("anonymous read of a script: %d", rec.Code)
	}
}

func TestOnlyProjectAdminsUploadAndSend(t *testing.T) {
	f := newAuthFixture(t)
	op := f.user("op", false, map[string]Role{"demo": RoleOperator})
	if code, _, _ := f.call("POST", A+"/scripts", op, proto.ScriptCreate{Name: "x", Interpreter: "sh", Content: "echo"}); code != 403 {
		t.Errorf("operator uploaded a script: %d", code)
	}
	if rec := f.raw("POST", A+"/releases?kind=app&name=a&version=1&os=windows", op, []byte("zip"), nil); rec.Code != 403 {
		t.Errorf("operator uploaded a release: %d", rec.Code)
	}
	for _, typ := range []string{"run_script", "apply_release"} {
		if code, _, _ := f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", op, proto.CommandRequest{Type: typ}); code != 403 {
			t.Errorf("operator sent %s: %d", typ, code)
		}
	}
}

// ---------------------------------------------------------------- releases

func TestReleasesAreHashedByTheServerAndImmutable(t *testing.T) {
	f := newAuthFixture(t)
	file := bytes.Repeat([]byte("build"), 1000)
	code, x := f.upload("adm", "kind=app&name=kiosk&version=1.2.0&os=windows&notes=first", file)
	if code != 201 || x.SHA256 != sum(file) || x.Size != int64(len(file)) || x.Arch != "any" {
		t.Fatalf("upload: %d %+v", code, x)
	}
	if code, _ := f.upload("adm", "kind=app&name=kiosk&version=1.2.0&os=windows", []byte("different")); code != 409 {
		t.Fatalf("a version was overwritten: %d", code)
	}
	for name, q := range map[string]string{
		"bad kind":             "kind=virus&name=a&version=1&os=windows",
		"bad name":             "kind=app&name=../a&version=1&os=windows",
		"missing os":           "kind=app&name=a&version=1",
		"agent without arch":   "kind=agent&name=agent&version=1&os=windows",
		"version with a slash": "kind=app&name=a&version=1/2&os=windows",
	} {
		if code, _ := f.upload("adm", q, []byte("x")); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := f.upload("adm", "kind=app&name=empty&version=1&os=windows", nil); code != 400 {
		t.Errorf("an empty file was accepted: %d", code)
	}
}

func TestADeviceDownloadsAReleaseWithRangeRequests(t *testing.T) {
	f := newAuthFixture(t)
	file := make([]byte, 10000)
	for i := range file {
		file[i] = byte(i * 7)
	}
	_, x := f.upload("adm", "kind=app&name=kiosk&version=1&os=windows", file)
	full := f.deviceGet("/v1/releases/"+x.ID+"/file", nil)
	if full.Code != 200 || !bytes.Equal(full.Body.Bytes(), file) {
		t.Fatalf("download: %d", full.Code)
	}
	part := f.deviceGet("/v1/releases/"+x.ID+"/file", map[string]string{"Range": "bytes=6000-"})
	b, _ := io.ReadAll(part.Body)
	if part.Code != http.StatusPartialContent || !bytes.Equal(b, file[6000:]) {
		t.Fatalf("resume: %d, %d bytes", part.Code, len(b))
	}
	if rec := f.raw("GET", "/v1/releases/"+x.ID+"/file", "wrong", nil, nil); rec.Code != 401 {
		t.Fatalf("anonymous download: %d", rec.Code)
	}
}

func TestApplyReleaseChecksThePlatformAndSignsTheLibrarysHash(t *testing.T) {
	f := newAuthFixture(t)
	f.st.mu.Lock()
	f.st.D.Devices[f.dev.DeviceID].OS, f.st.D.Devices[f.dev.DeviceID].Arch = "windows", "amd64"
	f.st.mu.Unlock()
	file := []byte("agent-binary")
	_, win := f.upload("adm", "kind=agent&name=agent&version=0.2.0&os=windows&arch=amd64", file)
	_, lin := f.upload("adm", "kind=agent&name=agent&version=0.2.0&os=linux&arch=amd64", file)
	_, arm := f.upload("adm", "kind=agent&name=agent&version=0.2.0&os=windows&arch=arm64", file)
	for name, id := range map[string]string{"linux build": lin.ID, "arm build": arm.ID, "unknown": "rel_nope"} {
		if code, _ := f.queue("apply_release", map[string]any{"release_id": id}); code != 400 {
			t.Errorf("%s was sent to a windows/amd64 device: %d", name, code)
		}
	}
	code, _ := f.queue("apply_release", map[string]any{"release_id": win.ID, "sha256": "00", "size": 1.0, "kind": "app"})
	if code != 201 {
		t.Fatalf("matching release: %d", code)
	}
	var cmds []proto.Command
	json.Unmarshal(f.deviceGet("/v1/commands", nil).Body.Bytes(), &cmds)
	var sc proto.SignedCommand
	if _, err := signing.VerifyJSON(cmds[0].Signed, signing.TypeCommand, f.serverKeys(t), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Params["sha256"] != sum(file) || sc.Params["kind"] != "agent" || sc.Params["size"] != float64(len(file)) {
		t.Fatalf("signed parameters came from the request, not the release: %v", sc.Params)
	}
	if sc.ExpiresAt.Sub(sc.IssuedAt) < 3*time.Hour {
		t.Fatalf("a download over 4G needs time: expires %s after issue", sc.ExpiresAt.Sub(sc.IssuedAt))
	}
}
