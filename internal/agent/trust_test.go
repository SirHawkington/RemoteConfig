package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/server"
	"remoteconfig/internal/signing"
)

// ---------------------------------------------------------------- an attacker on the wire

// mitm sits between the agent and the server and may rewrite any response, which is what
// someone controlling a proxy, a captive portal or a hijacked DNS name can do.
type mitm struct {
	mu       sync.Mutex
	rewrite  func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte)
	stripAcc bool              // remove the Accept header from requests (downgrade attempt)
	seen     map[string][]byte // path -> the last 200 body, for replay
	seenHdr  map[string]http.Header
}

func newMITM() *mitm { return &mitm{seen: map[string][]byte{}, seenHdr: map[string]http.Header{}} }

func (m *mitm) set(f func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte)) {
	m.mu.Lock()
	m.rewrite = f
	m.mu.Unlock()
}

func (m *mitm) link(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		rewrite, strip := m.rewrite, m.stripAcc
		m.mu.Unlock()
		if strip && r.URL.Path == "/v1/config" {
			r.Header.Del("Accept")
		}
		if rewrite == nil {
			// still record what passes, for replay attacks
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			m.record(r, rec)
			copyResp(w, rec.Code, rec.Header(), rec.Body.Bytes())
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		m.record(r, rec)
		code, hdr, body := rewrite(r, rec.Code, rec.Header().Clone(), rec.Body.Bytes())
		copyResp(w, code, hdr, body)
	})
}

func (m *mitm) record(r *http.Request, rec *httptest.ResponseRecorder) {
	if rec.Code == 200 {
		m.mu.Lock()
		m.seen[r.URL.Path] = append([]byte(nil), rec.Body.Bytes()...)
		m.seenHdr[r.URL.Path] = rec.Header().Clone()
		m.mu.Unlock()
	}
}

func (m *mitm) lastBody(path string) ([]byte, http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[path], m.seenHdr[path]
}

func copyResp(w http.ResponseWriter, code int, hdr http.Header, body []byte) {
	for k, v := range hdr {
		if k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(code)
	w.Write(body)
}

// ---------------------------------------------------------------- helpers

func (e *env) putConfig(data map[string]any, sup *proto.SupervisorConfig) {
	e.t.Helper()
	if code := e.admin("PUT", "/config/global", proto.ConfigDocument{Data: data, Supervisor: sup}, nil); code != 200 {
		e.t.Fatalf("put config: %d", code)
	}
}

func (e *env) agentCfg() *proto.EffectiveConfig { return e.agent.currentConfig() }

func (e *env) serverKey() proto.KeyInfo {
	sg, _ := e.st.Signer()
	return sg.Current()
}

func (e *env) eventTypes() []string {
	var out []string
	for _, ev := range e.detail().Events {
		out = append(out, ev.Type)
	}
	return out
}

func waitForConfig(t *testing.T, e *env, what string, cond func(*proto.EffectiveConfig) bool) {
	t.Helper()
	wait(t, what, 15*time.Second, func() bool { c := e.agentCfg(); return c != nil && cond(c) })
}

func dataVal(c *proto.EffectiveConfig, k string) any { return c.Data[k] }

// ---------------------------------------------------------------- the normal, secure path

func TestAgentBecomesStrictAndRunsOnSignedConfig(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, nil)
	waitForConfig(t, e, "first config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	if !e.agent.trust.strict() {
		t.Fatal("the agent did not trust the server's key on first use over loopback")
	}
	b, err := os.ReadFile(filepath.Join(e.stateDir, "signed-config.json"))
	if err != nil {
		t.Fatalf("the signed copy was not saved: %v", err)
	}
	var env signing.Envelope
	json.Unmarshal(b, &env)
	if _, _, err := signing.Verify(&env, signing.TypeConfig, e.agent.trust.pubkeys()); err != nil {
		t.Fatalf("the saved copy does not verify: %v", err)
	}
	wait(t, "the server to learn which key verified the config", 10*time.Second, func() bool {
		d := e.detail()
		return d.SignatureState == "strict" && d.Trust != nil && d.Trust.KeyID == e.serverKey().KeyID
	})
	if d := e.detail(); d.Trust.Rejected != 0 || d.Trust.Pinned {
		t.Fatalf("trust report: %+v", d.Trust)
	}
}

func TestAPinnedKeyIsTrustedWithoutAskingTheNetwork(t *testing.T) {
	// the operator copies the key from the dashboard into the install command
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, nil)
	pin := e.serverKey().Public

	e2 := newEnvWithServer(t, e, func(o *Options) { o.ServerKey = pin })
	waitForConfig(t, e2, "config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })
	rep := e2.agent.trust.report()
	if rep.State != "strict" || !rep.Pinned {
		t.Fatalf("pinned agent report: %+v", rep)
	}
}

func TestEnrollmentWithTheWrongPinnedKeyIsRefusedAndKeepsNoIdentity(t *testing.T) {
	otherPub, _ := signing.GenerateKey() // some other server's key
	st, _ := server.OpenStore("", "adm")
	defer st.Close()
	st.Seed("demo", "Demo", &proto.ConfigDocument{Data: map[string]any{}})
	tok := st.NewEnrollToken("demo", nil, time.Hour)
	srv := httptest.NewServer(server.New(st, server.Options{CheckinInterval: time.Second}).Handler())
	defer srv.Close()

	dir := t.TempDir()
	a := New(Options{Server: srv.URL, EnrollToken: tok, StateDir: dir, Interval: 100 * time.Millisecond, Version: "t",
		ServerKey: base64.StdEncoding.EncodeToString(otherPub), Capturer: &fakeCapturer{}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := a.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "refusing to enrol") {
		t.Fatalf("an agent pinned to a different key enrolled with this server: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err == nil {
		t.Fatal("an identity was saved for a server that failed the pin")
	}
	// the pin was checked first, so the one-time token is still good for the right agent
	body, _ := json.Marshal(proto.EnrollRequest{Token: tok, Hostname: "h", OS: "windows"})
	resp, err := http.Post(srv.URL+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the enrollment token was spent on a server that failed the pin (status %d)", resp.StatusCode)
	}
}

func TestAMalformedPinnedKeyIsAnErrorNotSilentlyIgnored(t *testing.T) {
	a := New(Options{StateDir: t.TempDir(), ServerKey: "not-a-key", Capturer: &fakeCapturer{}})
	if err := a.trust.load(); err == nil {
		t.Fatal("a garbage -server-key was accepted: the agent would run unprotected")
	}
}

// ---------------------------------------------------------------- attacks on config

func TestATamperedConfigIsRefusedReportedAndTheOldOneKeepsRunning(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "first config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	// from now on the attacker rewrites every signed config: it swaps in a different program
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path != "/v1/config" || status != 200 {
			return status, hdr, body
		}
		var env signing.Envelope
		json.Unmarshal(body, &env)
		env.Payload = bytes.Replace(env.Payload, []byte(`"v":2`), []byte(`"v":666`), 1)
		out, _ := json.Marshal(env)
		return status, hdr, out
	})
	e.putConfig(map[string]any{"v": 2.0}, nil)

	wait(t, "the agent to refuse the tampered config", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	time.Sleep(600 * time.Millisecond)
	if v := dataVal(e.agentCfg(), "v"); v != 1.0 {
		t.Fatalf("the agent is running %v: it applied (or half-applied) a tampered config", v)
	}
	if b, _ := os.ReadFile(filepath.Join(e.stateDir, "effective-config.json")); bytes.Contains(b, []byte("666")) {
		t.Fatal("the tampered value reached the file the app reads")
	}
	wait(t, "the dashboard to be told", 10*time.Second, func() bool { return e.detail().SignatureState == "rejecting" })
	var told bool
	for _, ev := range e.detail().Events {
		told = told || ev.Type == "signature.rejected" && ev.Level == "error" && strings.Contains(ev.Message, "signature")
	}
	if !told {
		t.Fatalf("no signature.rejected event on the server: %v", e.eventTypes())
	}

	// once the attacker is gone the agent recovers by itself
	m.set(nil)
	waitForConfig(t, e, "recovery", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 2.0 })
	wait(t, "the dashboard to show the device recovered", 10*time.Second, func() bool { return e.detail().SignatureState == "strict" })
}

func TestStrippingTheSignatureDoesNotDowngradeAStrictAgent(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "first config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	m.mu.Lock()
	m.stripAcc = true // the attacker removes "Accept: signed", so the server answers with the plain config
	m.mu.Unlock()
	e.putConfig(map[string]any{"v": 2.0, "evil": true}, nil)

	wait(t, "the unsigned config to be refused", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	if _, bad := e.agentCfg().Data["evil"]; bad || dataVal(e.agentCfg(), "v") != 1.0 {
		t.Fatalf("an unsigned config was applied: %v", e.agentCfg().Data)
	}
	if !strings.Contains(e.agent.trust.report().LastRejected, "not signed") {
		t.Fatalf("reason: %q", e.agent.trust.report().LastRejected)
	}
}

func TestAConfigSignedByTheAttackersOwnKeyIsRefused(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "first config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	_, attacker := signing.GenerateKey()
	cur := e.agentCfg()
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path != "/v1/config" || status != 200 {
			return status, hdr, body
		}
		evil := *cur
		evil.Revision, evil.Etag, evil.Data = cur.Revision+10, "evil-etag", map[string]any{"v": 666.0}
		env, _ := signing.SignJSON(attacker, signing.TypeConfig, proto.SignedConfig{
			DeviceID: e.deviceID, Project: "demo", IssuedAt: time.Now().Add(time.Hour), Config: evil, // perfectly formed, newer, for this device
		})
		out, _ := json.Marshal(env)
		return 200, hdr, out
	})
	e.putConfig(map[string]any{"v": 2.0}, nil)

	wait(t, "refusal", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	if dataVal(e.agentCfg(), "v") != 1.0 {
		t.Fatal("a config signed by an unknown key was applied")
	}
	if !strings.Contains(e.agent.trust.report().LastRejected, "does not trust") {
		t.Fatalf("reason: %q", e.agent.trust.report().LastRejected)
	}
}

func TestACapturedOldConfigCannotBeReplayed(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "v1", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })
	oldBody, oldHdr := m.lastBody("/v1/config") // the attacker keeps a genuine, validly signed copy

	e.putConfig(map[string]any{"v": 2.0}, nil)
	waitForConfig(t, e, "v2", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 2.0 })

	// now the attacker serves the old one back, in answer to the next fetch
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path == "/v1/config" && status == 200 {
			return 200, oldHdr, oldBody
		}
		return status, hdr, body
	})
	e.putConfig(map[string]any{"v": 3.0}, nil)

	wait(t, "the replay to be refused", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	if v := dataVal(e.agentCfg(), "v"); v != 2.0 {
		t.Fatalf("running v=%v: the agent was rolled back by a replayed config (or missed the real update)", v)
	}
	if !strings.Contains(e.agent.trust.report().LastRejected, "replayed") {
		t.Fatalf("reason: %q", e.agent.trust.report().LastRejected)
	}
}

func TestAnotherDevicesSignedConfigIsRefused(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "first config", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	// a second machine in the same project, which the attacker can legitimately talk to
	tok := e.st.NewEnrollToken("demo", []string{"lobby"}, time.Hour)
	var other proto.EnrollResponse
	{
		b, _ := json.Marshal(proto.EnrollRequest{Token: tok, Hostname: "other"})
		resp, err := http.Post(e.srv.URL+"/v1/enroll", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		json.NewDecoder(resp.Body).Decode(&other)
		resp.Body.Close()
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+other.DeviceToken)
	req.Header.Set("Accept", signing.ContentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var theirs bytes.Buffer
	theirs.ReadFrom(resp.Body)
	resp.Body.Close()

	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path == "/v1/config" && status == 200 {
			h := hdr.Clone()
			h.Set("Content-Type", signing.ContentType)
			return 200, h, theirs.Bytes() // genuinely signed by the server, but for someone else
		}
		return status, hdr, body
	})
	e.putConfig(map[string]any{"v": 2.0}, nil)

	wait(t, "refusal", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	if !strings.Contains(e.agent.trust.report().LastRejected, "not this one") {
		t.Fatalf("reason: %q", e.agent.trust.report().LastRejected)
	}
	if dataVal(e.agentCfg(), "v") != 1.0 {
		t.Fatal("another device's config was applied")
	}
}

// ---------------------------------------------------------------- attacks on commands

func TestACommandIsExecutedAsSignedNotAsTheAttackerEditedIt(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, m.link)
	e.cap.set(noiseShot(0, 64, 36, 1))
	wait(t, "enrolled and strict", 10*time.Second, func() bool { return e.agent.trust.strict() })

	// The attacker changes the plain fields of every delivered command to "capture_screenshot"
	// (which this agent would carry out), but cannot touch what the server signed.
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path != "/v1/checkin" || status != 200 {
			return status, hdr, body
		}
		var resp proto.CheckinResponse
		json.Unmarshal(body, &resp)
		for i := range resp.Commands {
			resp.Commands[i].Type = "capture_screenshot"
		}
		out, _ := json.Marshal(resp)
		return status, hdr, out
	})
	e.command("restart_app") // there is no supervised app, so a real restart_app fails with a recognisable message

	wait(t, "the command's result", 15*time.Second, func() bool {
		d := e.detail()
		return len(d.Commands) > 0 && d.Commands[0].Status == "failed"
	})
	out := e.detail().Commands[0].Params["result"]
	if out != "app is not supervised on this device" {
		t.Fatalf("result %q: the agent acted on the attacker's edited type instead of the signed one", out)
	}
	if e.cap.count() != 0 {
		t.Fatal("a screenshot was taken: the unsigned command type was obeyed")
	}
}

func TestAnUnsignedOrForgedCommandIsIgnoredBySAStrictAgent(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, m.link)
	e.cap.set(noiseShot(0, 64, 36, 1))
	wait(t, "strict", 10*time.Second, func() bool { return e.agent.trust.strict() })

	_, attacker := signing.GenerateKey()
	var mode string
	var mu sync.Mutex
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path != "/v1/checkin" || status != 200 {
			return status, hdr, body
		}
		mu.Lock()
		defer mu.Unlock()
		var resp proto.CheckinResponse
		json.Unmarshal(body, &resp)
		forged := proto.Command{ID: "cmd_forged", Type: "capture_screenshot", Status: "queued", ExpiresAt: time.Now().Add(time.Hour)}
		switch mode {
		case "unsigned":
		case "attacker-signed":
			forged.Signed, _ = signing.SignJSON(attacker, signing.TypeCommand, proto.SignedCommand{DeviceID: e.deviceID, ID: "cmd_forged", Type: "capture_screenshot", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now()})
		case "wrong-kind":
			// a genuine, server-signed CONFIG presented as a command
			sg, _ := e.st.Signer()
			forged.Signed, _ = sg.SignConfig(e.deviceID, "demo", proto.EffectiveConfig{})
		case "other-device":
			sg, _ := e.st.Signer()
			forged.Signed, _ = sg.SignCommand("dev_somebody_else", forged)
		default:
			return status, hdr, body
		}
		resp.Commands = append(resp.Commands, forged)
		out, _ := json.Marshal(resp)
		return status, hdr, out
	})

	for _, kind := range []string{"unsigned", "attacker-signed", "wrong-kind", "other-device"} {
		mu.Lock()
		mode = kind
		mu.Unlock()
		before := e.agent.trust.report().Rejected
		wait(t, kind+" to be refused", 10*time.Second, func() bool { return e.agent.trust.report().Rejected > before })
	}
	if e.cap.count() != 0 {
		t.Fatalf("a forged command was executed (%d screenshots taken)", e.cap.count())
	}
}

func TestACommandReplayedAfterARestartDoesNotRunTwice(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{}}, m.link)
	e.cap.set(noiseShot(0, 64, 36, 1))
	wait(t, "strict", 10*time.Second, func() bool { return e.agent.trust.strict() })

	var captured proto.Command
	var mu sync.Mutex
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		if r.URL.Path == "/v1/checkin" && status == 200 {
			var resp proto.CheckinResponse
			json.Unmarshal(body, &resp)
			mu.Lock()
			if len(resp.Commands) > 0 && captured.ID == "" {
				captured = resp.Commands[0]
			}
			mu.Unlock()
		}
		return status, hdr, body
	})
	e.command("capture_screenshot")
	wait(t, "the command to run once", 15*time.Second, func() bool { return e.cap.count() == 1 })
	mu.Lock()
	cmd := captured
	mu.Unlock()
	if cmd.Signed == nil {
		t.Fatal("did not capture a signed command")
	}

	// the agent restarts (new process, same state directory) and the attacker replays the capture
	e.stop()
	e2 := restartAgent(t, e)
	e2.cap.set(noiseShot(0, 64, 36, 1))
	e2.agent.runCommand(context.Background(), cmd)
	if e2.cap.count() != 0 {
		t.Fatal("a signed command that had already run was executed again after a restart")
	}
}

// ---------------------------------------------------------------- key rotation

func TestAnAgentFollowsARotationThroughTheEndorsementChain(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, nil)
	waitForConfig(t, e, "v1", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })
	oldKey := e.serverKey().KeyID

	if code := e.adminTop("POST", "/signing/rotate", nil); code != 200 {
		t.Fatalf("rotate: %d", code)
	}
	if e.serverKey().KeyID == oldKey {
		t.Fatal("the server did not rotate")
	}
	e.putConfig(map[string]any{"v": 2.0}, nil) // now signed by the NEW key

	waitForConfig(t, e, "a config signed by the new key", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 2.0 })
	rep := e.agent.trust.report()
	if rep.KeyID != e.serverKey().KeyID || rep.KeysTrusted != 2 || rep.Rejected != 0 {
		t.Fatalf("after rotation: %+v", rep)
	}
	// and the new trust survives a restart
	e.stop()
	e2 := restartAgent(t, e)
	if k := e2.agent.trust.pubkeys(); len(k) != 2 {
		t.Fatalf("the learned key was not persisted: %d keys", len(k))
	}
}

func TestAFakeRotationOfferedByAnAttackerIsNotFollowed(t *testing.T) {
	m := newMITM()
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, m.link)
	waitForConfig(t, e, "v1", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })

	atkPub, atkPriv := signing.GenerateKey()
	// the attacker answers key-list requests with its own key, endorsed by itself, and signs configs with it
	m.set(func(r *http.Request, status int, hdr http.Header, body []byte) (int, http.Header, []byte) {
		switch r.URL.Path {
		case "/v1/keys":
			ks := proto.KeySet{Current: signing.KeyID(atkPub), Keys: []proto.KeyInfo{{
				KeyID: signing.KeyID(atkPub), Public: base64.StdEncoding.EncodeToString(atkPub), Endorsement: signing.Endorse(atkPriv, atkPub)}}}
			out, _ := json.Marshal(ks)
			return 200, hdr, out
		case "/v1/config":
			if status != 200 {
				break
			}
			cur := e.agentCfg()
			evil := *cur
			evil.Revision, evil.Etag, evil.Data = cur.Revision+5, "x", map[string]any{"v": 666.0}
			env, _ := signing.SignJSON(atkPriv, signing.TypeConfig, proto.SignedConfig{DeviceID: e.deviceID, Project: "demo", IssuedAt: time.Now().Add(time.Hour), Config: evil})
			out, _ := json.Marshal(env)
			return 200, hdr, out
		}
		return status, hdr, body
	})
	e.putConfig(map[string]any{"v": 2.0}, nil)

	wait(t, "refusal", 15*time.Second, func() bool { return e.agent.trust.report().Rejected > 0 })
	time.Sleep(500 * time.Millisecond)
	if dataVal(e.agentCfg(), "v") != 1.0 {
		t.Fatal("an attacker's key took over via a fake rotation")
	}
	if n := len(e.agent.trust.pubkeys()); n != 1 {
		t.Fatalf("the agent now trusts %d keys; the attacker's must not be among them", n)
	}
}

// ---------------------------------------------------------------- offline starts and upgrades

func TestAStrictAgentStartsOfflineFromItsVerifiedCacheAndIgnoresTampering(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, nil)
	waitForConfig(t, e, "v1", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })
	e.stop() // the server is gone too: this is a reboot with no signal

	// someone edits the plain file the app reads
	plain := filepath.Join(e.stateDir, "effective-config.json")
	os.WriteFile(plain, []byte(`{"revision":99,"etag":"x","data":{"v":666}}`), 0o600)

	a := New(Options{Server: "http://127.0.0.1:1", StateDir: e.stateDir, Version: "t", Capturer: &fakeCapturer{}})
	a.trust.load()
	a.loadIdentityFile()
	a.loadCachedConfig()
	if c := a.currentConfig(); c == nil || dataVal(c, "v") != 1.0 {
		t.Fatalf("offline start: %+v", c)
	}
	if b, _ := os.ReadFile(plain); bytes.Contains(b, []byte("666")) {
		t.Fatal("the tampered plain file was left for the app to read")
	}

	// tamper with the SIGNED copy instead: it must not be used at all
	signedPath := filepath.Join(e.stateDir, "signed-config.json")
	raw, _ := os.ReadFile(signedPath)
	var env signing.Envelope
	json.Unmarshal(raw, &env)
	env.Payload = bytes.Replace(env.Payload, []byte(`"v":1`), []byte(`"v":9`), 1)
	bad, _ := json.Marshal(env)
	os.WriteFile(signedPath, bad, 0o600)

	b := New(Options{Server: "http://127.0.0.1:1", StateDir: e.stateDir, Version: "t", Capturer: &fakeCapturer{}})
	b.trust.load()
	b.loadIdentityFile()
	b.loadCachedConfig()
	if b.currentConfig() != nil {
		t.Fatal("a tampered signed cache was loaded")
	}
	if b.trust.report().Rejected != 1 {
		t.Fatalf("the tampering was not reported: %+v", b.trust.report())
	}
}

func TestAnAgentUpgradedFromBeforeSigningBecomesStrictWithoutReapplyingItsConfig(t *testing.T) {
	e := newEnv(t, proto.ConfigDocument{Data: map[string]any{"v": 1.0}}, nil)
	waitForConfig(t, e, "v1", func(c *proto.EffectiveConfig) bool { return dataVal(c, "v") == 1.0 })
	e.stopAgent() // the server stays up: the upgraded agent will need it
	// make the state look like it did before signing existed: an identity and a plain cache only
	for _, f := range []string{"trusted-keys.json", "signed-config.json"} {
		os.Remove(filepath.Join(e.stateDir, f))
	}

	e2 := restartAgent(t, e)
	wait(t, "the plain cache to be loaded", 10*time.Second, func() bool { return e2.agent.currentConfig() != nil })
	before := e2.agent.currentConfig()

	wait(t, "the agent to learn the key and fetch a signed copy", 15*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(e.stateDir, "signed-config.json"))
		return err == nil && e2.agent.trust.strict()
	})
	if r := e2.agent.trust.report(); r.Rejected != 0 || r.State != "strict" {
		t.Fatalf("after the upgrade: %+v", r)
	}
	if e2.agent.currentConfig() != before {
		t.Fatal("learning the key re-applied an unchanged config, which restarts or reloads the app for nothing")
	}
}

func TestFirstUseTrustIsOnlyAllowedWhereTheChannelIsAuthenticated(t *testing.T) {
	cases := []struct {
		url      string
		insecure bool
		want     bool
	}{
		{"https://rc.example.com", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://localhost:8080", false, true},
		{"http://[::1]:8080", false, true},
		{"http://192.168.1.20:8080", false, false},
		{"http://rc.example.com", false, false},
		{"http://rc.example.com", true, true},
		{"::not a url::", false, false},
	}
	for _, c := range cases {
		a := New(Options{Server: c.url, StateDir: t.TempDir(), InsecureTOFU: c.insecure, Capturer: &fakeCapturer{}})
		if got := a.trust.tofuAllowed(); got != c.want {
			t.Errorf("tofuAllowed(%q, insecure=%v) = %v, want %v", c.url, c.insecure, got, c.want)
		}
	}
}

// ---------------------------------------------------------------- more helpers

// adminTop calls an admin endpoint that is not project scoped.
func (e *env) adminTop(method, path string, body any) int {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/v1/admin"+path, rd)
	req.Header.Set("Authorization", "Bearer adm")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// newEnvWithServer starts a second agent against the first environment's server.
func newEnvWithServer(t *testing.T, base *env, tweak ...func(*Options)) *env {
	t.Helper()
	tok := base.st.NewEnrollToken("demo", nil, time.Hour)
	cap := &fakeCapturer{}
	opts := Options{Server: base.srv.URL, EnrollToken: tok, StateDir: t.TempDir(), Interval: 150 * time.Millisecond, Version: "test", Capturer: cap}
	for _, f := range tweak {
		f(&opts)
	}
	a := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	e := &env{t: t, st: base.st, srv: base.srv, agent: a, cap: cap, stateDir: opts.StateDir}
	e.stop = func() { cancel(); <-done }
	t.Cleanup(e.stop)
	wait(t, "enrollment", 10*time.Second, func() bool { e.deviceID = a.DeviceID(); return e.deviceID != "" })
	return e
}

// restartAgent starts a new agent process's worth of agent on the same state directory and
// server (the previous agent must have been stopped).
func restartAgent(t *testing.T, prev *env, tweak ...func(*Options)) *env {
	t.Helper()
	cap := &fakeCapturer{}
	opts := Options{Server: prev.srv.URL, StateDir: prev.stateDir, Interval: 150 * time.Millisecond, Version: "test", Capturer: cap}
	for _, f := range tweak {
		f(&opts)
	}
	a := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	e := &env{t: t, st: prev.st, srv: prev.srv, agent: a, cap: cap, stateDir: opts.StateDir, deviceID: prev.deviceID}
	e.stop = func() { cancel(); <-done }
	t.Cleanup(e.stop)
	wait(t, "the restarted agent to load its identity", 10*time.Second, func() bool { return a.DeviceID() == prev.deviceID })
	return e
}

var _ ed25519.PublicKey
