package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

func (f *authFixture) deviceGet(path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+f.dev.DeviceToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *authFixture) serverKeys(t *testing.T) map[string]ed25519.PublicKey {
	t.Helper()
	sg, _ := f.st.Signer()
	keys := map[string]ed25519.PublicKey{}
	for _, k := range sg.KeySet().Keys {
		pub, _ := base64.StdEncoding.DecodeString(k.Public)
		keys[k.KeyID] = pub
	}
	return keys
}

func TestConfigIsSignedForAgentsThatAskAndBoundToTheirDevice(t *testing.T) {
	f := newAuthFixture(t)
	rec := f.deviceGet("/v1/config", map[string]string{"Accept": signing.ContentType})
	if rec.Code != 200 || rec.Header().Get("Content-Type") != signing.ContentType {
		t.Fatalf("signed config: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var env signing.Envelope
	json.Unmarshal(rec.Body.Bytes(), &env)
	var sc proto.SignedConfig
	kid, err := signing.VerifyJSON(&env, signing.TypeConfig, f.serverKeys(t), &sc)
	if err != nil {
		t.Fatalf("does not verify: %v", err)
	}
	sg, _ := f.st.Signer()
	if kid != sg.Current().KeyID {
		t.Fatal("signed by the wrong key")
	}
	if sc.DeviceID != f.dev.DeviceID || sc.Project != "demo" {
		t.Fatalf("not bound to this device and project: %+v", sc)
	}
	if sc.Config.Revision < 1 || sc.Config.Etag == "" || sc.Config.Data["a"] != 1.0 {
		t.Fatalf("the signed config content is wrong: %+v", sc.Config)
	}
	if sc.IssuedAt.IsZero() {
		t.Fatal("no issued_at: agents could not refuse a replayed old config")
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("ETag header lost")
	}
}

func TestPlainConfigIsStillServedToAgentsThatDoNotAsk(t *testing.T) {
	f := newAuthFixture(t)
	rec := f.deviceGet("/v1/config", nil)
	var cfg proto.EffectiveConfig
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &cfg) != nil || cfg.Data["a"] != 1.0 {
		t.Fatalf("older agents must keep working: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSignedConfigStillHonoursETags(t *testing.T) {
	f := newAuthFixture(t)
	first := f.deviceGet("/v1/config", map[string]string{"Accept": signing.ContentType})
	etag := first.Header().Get("ETag")
	again := f.deviceGet("/v1/config", map[string]string{"Accept": signing.ContentType, "If-None-Match": etag})
	if again.Code != 304 {
		t.Fatalf("unchanged config should be 304, got %d", again.Code)
	}
}

func TestIssuedAtNeverGoesBackwardsEvenIfTheClockDoes(t *testing.T) {
	f := newAuthFixture(t)
	sg, _ := f.st.Signer()
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sg.now = func() time.Time { return clock }

	issue := func() time.Time {
		env, _ := sg.SignConfig(f.dev.DeviceID, "demo", proto.EffectiveConfig{})
		var sc proto.SignedConfig
		json.Unmarshal(env.Payload, &sc)
		return sc.IssuedAt
	}
	a := issue()
	clock = clock.Add(-48 * time.Hour) // the server's clock is stepped back (NTP fix, VM restore)
	b := issue()
	c := issue() // and the same instant twice
	if !b.After(a) || !c.After(b) {
		t.Fatalf("issued_at went backwards: %s, %s, %s: agents would refuse every update", a, b, c)
	}
}

func TestIssuedAtSurvivesARestartThatLosesTheClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, err := OpenSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	sg.now = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	var last time.Time
	for i := 0; i < 5; i++ {
		env, _ := sg.SignConfig("d", "p", proto.EffectiveConfig{})
		var sc proto.SignedConfig
		json.Unmarshal(env.Payload, &sc)
		last = sc.IssuedAt
	}
	sg.Close()

	sg2, err := OpenSigner(path) // restarted on a machine whose clock is a year behind
	if err != nil {
		t.Fatal(err)
	}
	sg2.now = func() time.Time { return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) }
	env, _ := sg2.SignConfig("d", "p", proto.EffectiveConfig{})
	var sc proto.SignedConfig
	json.Unmarshal(env.Payload, &sc)
	if !sc.IssuedAt.After(last) {
		t.Fatalf("after a restart issued_at (%s) is not after the last one before it (%s)", sc.IssuedAt, last)
	}
}

func TestCommandsAreSignedBoundToTheDeviceAndSignedOnce(t *testing.T) {
	f := newAuthFixture(t)
	f.call("POST", A+"/devices/"+f.dev.DeviceID+"/commands", "adm", proto.CommandRequest{Type: "restart_app", Params: map[string]any{"why": "test"}})

	var first, second []proto.Command
	for i, into := range []*[]proto.Command{&first, &second} {
		_ = i
		rec := f.deviceGet("/v1/commands", nil)
		if rec.Code != 200 {
			t.Fatalf("commands: %d", rec.Code)
		}
		json.Unmarshal(rec.Body.Bytes(), into)
	}
	if len(first) != 1 || first[0].Signed == nil {
		t.Fatalf("the command is not signed: %+v", first)
	}
	var sc proto.SignedCommand
	if _, err := signing.VerifyJSON(first[0].Signed, signing.TypeCommand, f.serverKeys(t), &sc); err != nil {
		t.Fatalf("does not verify: %v", err)
	}
	if sc.DeviceID != f.dev.DeviceID || sc.ID != first[0].ID || sc.Type != "restart_app" || sc.Params["why"] != "test" || sc.ExpiresAt.IsZero() {
		t.Fatalf("signed command content wrong: %+v", sc)
	}
	// re-sent until acknowledged, but with the same signature (so a replay check by id/issued_at is stable)
	if !bytes.Equal(first[0].Signed.Signatures[0].Sig, second[0].Signed.Signatures[0].Sig) {
		t.Fatal("the command was re-signed on re-delivery")
	}
}

func TestKeyEndpointsAndEnrollmentExposeOnlyPublicKeys(t *testing.T) {
	f := newAuthFixture(t)
	rec := f.deviceGet("/v1/keys", nil)
	var ks proto.KeySet
	json.Unmarshal(rec.Body.Bytes(), &ks)
	if rec.Code != 200 || len(ks.Keys) != 1 || ks.Current != ks.Keys[0].KeyID {
		t.Fatalf("key set: %d %+v", rec.Code, ks)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("private")) {
		t.Fatal("the key endpoint mentions a private key")
	}
	// devices only
	req := httptest.NewRequest("GET", "/v1/keys", nil)
	if w := httptest.NewRecorder(); func() int { f.h.ServeHTTP(w, req); return w.Code }() != 401 {
		t.Fatal("/v1/keys is open to anyone")
	}
	// enrollment hands out the same key
	tok := f.st.NewEnrollToken("demo", nil, time.Hour)
	var er proto.EnrollResponse
	do(t, f.h, "POST", "/v1/enroll", "", proto.EnrollRequest{Token: tok, Hostname: "k2"}, &er)
	if er.Signing == nil || er.Signing.KeyID != ks.Current {
		t.Fatalf("enrollment did not return the signing key: %+v", er.Signing)
	}
}

func TestRotationKeepsOldAgentsAbleToFollowAndErasesTheOldPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSigner(path)
	first := sg.Current()
	pub1, _ := base64.StdEncoding.DecodeString(first.Public)

	second, err := sg.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	// an agent that only ever pinned key 1 can follow the chain to key 2
	trusted := map[string]ed25519.PublicKey{first.KeyID: pub1}
	var entries []signing.KeyEntry
	for _, k := range sg.KeySet().Keys {
		pub, _ := base64.StdEncoding.DecodeString(k.Public)
		entries = append(entries, signing.KeyEntry{KeyID: k.KeyID, Public: pub, Endorsement: k.Endorsement})
	}
	signing.FollowChain(trusted, entries)
	env, _ := sg.SignConfig("d", "p", proto.EffectiveConfig{})
	if _, kid, err := signing.Verify(env, signing.TypeConfig, trusted); err != nil || kid != second {
		t.Fatalf("content signed after the rotation does not verify for an old agent: %v", err)
	}
	// the old private key is gone from the file: stealing it later cannot sign as key 1
	raw, _ := readFileIfExists(path)
	var f signerFile
	json.Unmarshal(raw, &f)
	for _, k := range f.Keys {
		if k.KeyID == first.KeyID && len(k.Private) != 0 {
			t.Fatal("the retired key's private half is still on disk")
		}
		if k.KeyID == second && len(k.Private) == 0 {
			t.Fatal("the current key lost its private half")
		}
	}
	// and it survives a restart
	sg2, err := OpenSigner(path)
	if err != nil || sg2.Current().KeyID != second || len(sg2.KeySet().Keys) != 2 {
		t.Fatalf("reload after rotation: %v", err)
	}
}

func TestOnlyServerAdminsSeeOrRotateTheSigningKeys(t *testing.T) {
	f := newAuthFixture(t)
	pa := f.user("pa", false, map[string]Role{"demo": RoleAdmin})
	for _, rt := range [][2]string{{"GET", "/v1/admin/signing"}, {"POST", "/v1/admin/signing/rotate"}} {
		if code, _, _ := f.call(rt[0], rt[1], pa, nil); code != 403 {
			t.Errorf("a project admin could %s %s: %d", rt[0], rt[1], code)
		}
	}
	before, _ := f.st.Signer()
	was := before.Current().KeyID
	if code, _, _ := f.call("POST", "/v1/admin/signing/rotate", "adm", nil); code != 200 {
		t.Fatalf("rotate: %d", code)
	}
	if before.Current().KeyID == was {
		t.Fatal("the key did not change")
	}
	var saw bool
	for _, e := range f.st.listAudit("", 20) {
		saw = saw || e.Action == "signing.rotated"
	}
	if !saw {
		t.Fatal("a key rotation is not in the audit log")
	}
}

func TestEnrollmentTokenResponseIncludesTheKeyToPin(t *testing.T) {
	f := newAuthFixture(t)
	code, out, _ := f.call("POST", A+"/enrollment-tokens", "adm", nil)
	sg, _ := f.st.Signer()
	if code != 201 || out["server_key"] != sg.Current().Public || out["key_id"] != sg.Current().KeyID {
		t.Fatalf("the install command cannot pin the key: %d %v", code, out)
	}
}

func TestAgentTrustReportsAreRecordedAndSummarised(t *testing.T) {
	f := newAuthFixture(t)
	post := func(tr *proto.TrustReport, seq int64) {
		do(t, f.h, "POST", "/v1/checkin", f.dev.DeviceToken, proto.CheckinRequest{Session: "s", Seq: seq, Trust: tr}, nil)
	}
	state := func() string {
		var d proto.DeviceDetail
		do(t, f.h, "GET", A+"/devices/"+f.dev.DeviceID+"/detail", "adm", nil, &d)
		return d.SignatureState
	}
	if state() != "unknown" {
		t.Fatalf("before any report: %q", state())
	}
	post(&proto.TrustReport{State: "legacy"}, 1)
	if state() != "legacy" {
		t.Fatalf("legacy: %q", state())
	}
	post(&proto.TrustReport{State: "strict", KeyID: "abc"}, 2)
	if state() != "strict" {
		t.Fatalf("strict: %q", state())
	}
	post(&proto.TrustReport{State: "strict", Rejected: 1, LastRejected: "bad signature", LastRejectedAt: time.Now()}, 3)
	if state() != "rejecting" {
		t.Fatalf("a recent rejection must stand out: %q", state())
	}
	post(&proto.TrustReport{State: "strict", Rejected: 1, LastRejectedAt: time.Now().Add(-time.Minute), LastAcceptedAt: time.Now()}, 4)
	if state() != "strict" {
		t.Fatalf("a device that has since accepted a good config has recovered: %q", state())
	}
	post(&proto.TrustReport{State: "strict", Rejected: 1, LastRejectedAt: time.Now().Add(-48 * time.Hour)}, 5)
	if state() != "strict" {
		t.Fatalf("an old rejection should fade: %q", state())
	}
}

var _ = http.StatusOK
