package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

const goodPass = "correct horse battery staple"

func keyMap(sg *Signer) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, k := range sg.KeySet().Keys {
		pub, _ := base64.StdEncoding.DecodeString(k.Public)
		m[k.KeyID] = pub
	}
	return m
}

// privateOf digs the private key out of an unprotected key file, to know what must not leak.
func privateOf(t *testing.T, path string) []byte {
	t.Helper()
	var f signerFile
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, k := range f.Keys {
		if k.KeyID == f.Current {
			return k.Private
		}
	}
	t.Fatal("no current key")
	return nil
}

func mustSign(t *testing.T, sg *Signer) {
	t.Helper()
	env, err := sg.SignConfig("dev1", "demo", proto.EffectiveConfig{Revision: 1, Etag: "e", Data: map[string]any{"a": 1.0}})
	if err != nil {
		t.Fatal(err)
	}
	var sc proto.SignedConfig
	if _, err := signing.VerifyJSON(env, signing.TypeConfig, keyMap(sg), &sc); err != nil {
		t.Fatalf("what the unlocked signer produced does not verify: %v", err)
	}
}

func TestANewKeyWithAPassphraseNeverHitsTheDiskInTheClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, err := OpenSignerWith(path, goodPass)
	if err != nil {
		t.Fatal(err)
	}
	kid := sg.Current().KeyID
	priv := append([]byte(nil), sg.priv...)
	mustSign(t, sg)
	sg.Close()

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, priv) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(priv))) ||
		bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(priv[:32]))) {
		t.Fatal("the private key is in the file in the clear")
	}
	if strings.Contains(string(raw), `"private"`) {
		t.Fatal("a private field is still written")
	}
	if !strings.Contains(string(raw), `"protection"`) || !strings.Contains(string(raw), kid) {
		t.Fatal("no protection block")
	}

	again, err := OpenSignerWith(path, goodPass)
	if err != nil {
		t.Fatal(err)
	}
	if again.Current().KeyID != kid || !again.Protected() {
		t.Fatal("reopening changed the key")
	}
	mustSign(t, again)
	again.Close()
}

func TestTheWrongOrMissingPassphraseOpensNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSignerWith(path, goodPass)
	sg.Close()
	if _, err := OpenSignerWith(path, ""); !errors.Is(err, ErrPassphraseNeeded) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := OpenSignerWith(path, "correct horse battery stapl3"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a near miss: %v", err)
	}
	if _, err := OpenSigner(path); err == nil {
		t.Fatal("the old entry point opened a sealed file")
	}
}

func TestAnAlteredKeyFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSignerWith(path, goodPass)
	sg.Close()
	orig, _ := os.ReadFile(path)

	edit := func(f func(*signerFile)) string {
		var s signerFile
		json.Unmarshal(orig, &s)
		f(&s)
		b, _ := json.Marshal(&s)
		p := filepath.Join(t.TempDir(), "signing.json")
		os.WriteFile(p, b, 0o600)
		return p
	}
	for name, p := range map[string]string{
		"a flipped bit in the sealed key": edit(func(s *signerFile) { s.Protection.Sealed[3] ^= 1 }),
		"another key id in the AAD":       edit(func(s *signerFile) { s.Protection.KeyID = "0000000000000000"; s.Current = "0000000000000000" }),
		"a weakened iteration count":      edit(func(s *signerFile) { s.Protection.Iter = 1 }),
		"a swapped public key": edit(func(s *signerFile) { // the attacker wants agents to be told their own key
			pub, _ := signing.GenerateKey()
			s.Keys[0].Public = pub
		}),
	} {
		if _, err := OpenSignerWith(p, goodPass); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAPlainKeyIsSealedWhenAPassphraseAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	plain, _ := OpenSigner(path)
	plain.Close()
	priv := privateOf(t, path)
	kid := plain.Current().KeyID

	sg, err := OpenSignerWith(path, goodPass)
	if err != nil {
		t.Fatal(err)
	}
	if !sg.Migrated() || !sg.Protected() || sg.Current().KeyID != kid {
		t.Fatalf("migrated=%v protected=%v same key=%v", sg.Migrated(), sg.Protected(), sg.Current().KeyID == kid)
	}
	sg.Close()
	if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(priv))) {
		t.Fatal("the unencrypted key is still in the file")
	}
	if _, err := OpenSigner(path); err == nil {
		t.Fatal("it still opens without the passphrase")
	}
}

func TestRotationAndTheIssueClockSurviveInASealedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSignerWith(path, goodPass)
	first := sg.Current().KeyID
	newKid, err := sg.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	mustSign(t, sg)
	env1, _ := sg.SignConfig("d", "demo", proto.EffectiveConfig{Data: map[string]any{}})
	var a proto.SignedConfig
	signing.VerifyJSON(env1, signing.TypeConfig, keyMap(sg), &a)
	sg.Close()

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), `"private"`) {
		t.Fatal("a private key reached the disk")
	}
	again, err := OpenSignerWith(path, goodPass)
	if err != nil {
		t.Fatal(err)
	}
	if again.Current().KeyID != newKid || len(again.KeySet().Keys) != 2 {
		t.Fatalf("chain after reopen: %+v", again.KeySet())
	}
	// an agent that only knows the first key can follow the chain to the new one
	ks := again.KeySet()
	pub0, _ := base64.StdEncoding.DecodeString(ks.Keys[0].Public)
	if ks.Keys[0].KeyID != first || ks.Keys[1].Endorsement == nil {
		t.Fatalf("the endorsement chain was lost: %+v", ks)
	}
	pub1, _ := base64.StdEncoding.DecodeString(ks.Keys[1].Public)
	trusted := map[string]ed25519.PublicKey{first: pub0}
	signing.FollowChain(trusted, []signing.KeyEntry{{KeyID: ks.Keys[1].KeyID, Public: pub1, Endorsement: ks.Keys[1].Endorsement}})
	if _, ok := trusted[newKid]; !ok {
		t.Fatal("the old key does not vouch for the new one any more")
	}
	env2, _ := again.SignConfig("d", "demo", proto.EffectiveConfig{Data: map[string]any{}})
	var b proto.SignedConfig
	signing.VerifyJSON(env2, signing.TypeConfig, keyMap(again), &b)
	if !b.IssuedAt.After(a.IssuedAt) {
		t.Fatalf("issued_at went backwards across a restart: %s then %s", a.IssuedAt, b.IssuedAt)
	}
	again.Close()
}

func TestProtectUnprotectAndTheMinimumLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSigner(path)
	before, _ := os.ReadFile(path)
	if err := sg.Protect("short"); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("a short passphrase: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("a refused passphrase changed the file")
	}
	if err := sg.Protect(goodPass); err != nil || !sg.Protected() {
		t.Fatal(err)
	}
	if err := sg.Protect("a completely different passphrase"); err != nil { // changing it
		t.Fatal(err)
	}
	sg.Close()
	if _, err := OpenSignerWith(path, goodPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("the old passphrase still works: %v", err)
	}
	back, err := OpenSignerWith(path, "a completely different passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Unprotect(); err != nil || back.Protected() {
		t.Fatal(err)
	}
	back.Close()
	if _, err := OpenSigner(path); err != nil {
		t.Fatalf("not usable without a passphrase after unprotect: %v", err)
	}
}

func TestEverySaveUsesAFreshNonceButTheSameSalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.json")
	sg, _ := OpenSignerWith(path, goodPass)
	read := func() keyProtection {
		var f signerFile
		b, _ := os.ReadFile(path)
		json.Unmarshal(b, &f)
		return *f.Protection
	}
	a := read()
	sg.mu.Lock()
	sg.save()
	sg.mu.Unlock()
	b := read()
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatal("a nonce was reused with the same AES-GCM key")
	}
	if !bytes.Equal(a.Salt, b.Salt) {
		t.Fatal("the salt changed, so the cached key would not open the file")
	}
	sg.Close()
}

func TestTheStoreNeedsTheRightPassphraseToStartSigning(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "rc.db")
	st, err := OpenStore(db, "")
	if err != nil {
		t.Fatal(err)
	}
	st.SetSigningPassphrase(goodPass)
	sg, err := st.Signer()
	if err != nil || !sg.Protected() {
		t.Fatalf("%v", err)
	}
	st.Close()

	st2, _ := OpenStore(db, "")
	if _, err := st2.Signer(); !errors.Is(err, ErrPassphraseNeeded) {
		t.Fatalf("no passphrase: %v", err)
	}
	st2.Close()
	st3, _ := OpenStore(db, "")
	st3.SetSigningPassphrase("not the passphrase at all")
	if _, err := st3.Signer(); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	st3.Close()
}
