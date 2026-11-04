package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

func trust(pubs ...ed25519.PublicKey) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, p := range pubs {
		m[KeyID(p)] = p
	}
	return m
}

func TestSignedContentVerifiesAndReturnsTheSignersKeyID(t *testing.T) {
	pub, priv := GenerateKey()
	env := Sign(priv, TypeConfig, []byte(`{"volume":0.5}`))
	payload, kid, err := Verify(env, TypeConfig, trust(pub))
	if err != nil || string(payload) != `{"volume":0.5}` || kid != KeyID(pub) {
		t.Fatalf("verify: %q %s %v", payload, kid, err)
	}
}

func TestAnyChangeToTheContentBreaksTheSignature(t *testing.T) {
	pub, priv := GenerateKey()
	env := Sign(priv, TypeConfig, []byte(`{"exe":"C:\\Kiosk\\app.exe"}`))
	keys := trust(pub)

	for name, tamper := range map[string]func(*Envelope){
		"payload byte flipped": func(e *Envelope) { e.Payload[3] ^= 1 },
		"payload replaced":     func(e *Envelope) { e.Payload = []byte(`{"exe":"C:\\Evil\\app.exe"}`) },
		"payload extended":     func(e *Envelope) { e.Payload = append(e.Payload, ' ') },
		"signature flipped":    func(e *Envelope) { e.Signatures[0].Sig[0] ^= 1 },
		"signature truncated":  func(e *Envelope) { e.Signatures[0].Sig = e.Signatures[0].Sig[:10] },
	} {
		c := cloneEnv(env)
		tamper(c)
		if _, _, err := Verify(c, TypeConfig, keys); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
}

func cloneEnv(e *Envelope) *Envelope {
	b, _ := json.Marshal(e)
	var c Envelope
	json.Unmarshal(b, &c)
	return &c
}

// A signature over one kind of content must not be accepted as another kind.
func TestSignedContentCannotBePassedOffAsADifferentKind(t *testing.T) {
	pub, priv := GenerateKey()
	cfg := Sign(priv, TypeConfig, []byte(`{"anything":1}`))
	if _, _, err := Verify(cfg, TypeCommand, trust(pub)); !errors.Is(err, ErrWrongType) {
		t.Fatalf("a signed config accepted as a command: %v", err)
	}
	// even if the type label is rewritten, the signature covered the old label
	relabelled := cloneEnv(cfg)
	relabelled.PayloadType = TypeCommand
	if _, _, err := Verify(relabelled, TypeCommand, trust(pub)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a relabelled envelope verified: %v", err)
	}
}

func TestOnlyTrustedKeysCount(t *testing.T) {
	pub, _ := GenerateKey()
	_, attackerPriv := GenerateKey()
	forged := Sign(attackerPriv, TypeConfig, []byte(`{}`))
	if _, _, err := Verify(forged, TypeConfig, trust(pub)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an unknown key's signature: %v", err)
	}
	// claiming to be the trusted key (copying its id) still fails: that is a bad signature
	claimed := cloneEnv(forged)
	claimed.Signatures[0].KeyID = KeyID(pub)
	if _, _, err := Verify(claimed, TypeConfig, trust(pub)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an impersonated key id: %v", err)
	}
	if _, _, err := Verify(forged, TypeConfig, nil); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("with no trusted keys: %v", err)
	}
}

func TestMalformedEnvelopesAreRejectedNotCrashed(t *testing.T) {
	pub, _ := GenerateKey()
	for name, e := range map[string]*Envelope{
		"nil":            nil,
		"no signatures":  {PayloadType: TypeConfig, Payload: []byte("{}")},
		"empty":          {},
		"junk key bytes": {PayloadType: TypeConfig, Payload: []byte("{}"), Signatures: []Signature{{KeyID: KeyID(pub), Sig: nil}}},
	} {
		if _, _, err := Verify(e, TypeConfig, trust(pub)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a trusted key with a corrupt length must not panic ed25519.Verify
	bad := map[string]ed25519.PublicKey{"abc": []byte{1, 2, 3}}
	if _, _, err := Verify(&Envelope{PayloadType: TypeConfig, Signatures: []Signature{{KeyID: "abc", Sig: []byte{1}}}}, TypeConfig, bad); err == nil {
		t.Error("a corrupt trusted key verified something")
	}
}

func TestEnvelopesSurviveAJSONRoundTrip(t *testing.T) {
	pub, priv := GenerateKey()
	env := Sign(priv, TypeCommand, []byte("\x00\xff binary \n and {json}"))
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if p, _, err := Verify(&got, TypeCommand, trust(pub)); err != nil || !bytes.Equal(p, env.Payload) {
		t.Fatalf("after the wire: %v", err)
	}
}

func TestTheFormatIsUnambiguous(t *testing.T) {
	// ("ab","c") and ("a","bc") must not produce the same signed bytes
	if bytes.Equal(pae("ab", []byte("c")), pae("a", []byte("bc"))) {
		t.Fatal("type/payload boundary is ambiguous")
	}
	pub, priv := GenerateKey()
	e := Sign(priv, "ab", []byte("c"))
	e.PayloadType, e.Payload = "a", []byte("bc")
	if _, _, err := Verify(e, "a", trust(pub)); err == nil {
		t.Fatal("moving the boundary between type and payload kept the signature valid")
	}
}

// ---------------------------------------------------------------- rotation

func TestAnAgentFollowsAnEndorsementChainToANewKey(t *testing.T) {
	pub1, priv1 := GenerateKey()
	pub2, priv2 := GenerateKey()
	pub3, _ := GenerateKey()
	entries := []KeyEntry{
		{KeyID: KeyID(pub1), Public: pub1},
		{KeyID: KeyID(pub2), Public: pub2, Endorsement: Endorse(priv1, pub2)},
		{KeyID: KeyID(pub3), Public: pub3, Endorsement: Endorse(priv2, pub3)}, // endorsed by key 2, which only key 1 vouches for
	}
	trusted := trust(pub1) // the agent only ever pinned key 1
	added := FollowChain(trusted, entries)
	if len(added) != 2 || trusted[KeyID(pub3)] == nil {
		t.Fatalf("chain not followed: added %d", len(added))
	}
	// the order the server lists them in must not matter
	trusted2 := trust(pub1)
	FollowChain(trusted2, []KeyEntry{entries[2], entries[1], entries[0]})
	if trusted2[KeyID(pub3)] == nil {
		t.Fatal("a reversed list was not followed")
	}
	// and new content signed by the newest key now verifies
	env := Sign(priv2, TypeConfig, []byte(`{}`))
	if _, _, err := Verify(env, TypeConfig, trusted); err != nil {
		t.Fatalf("content signed by key 2: %v", err)
	}
	_ = pub3
}

func TestAnAttackerCannotSmuggleInTheirOwnKey(t *testing.T) {
	pub1, _ := GenerateKey()
	attackerPub, attackerPriv := GenerateKey()
	otherPub, otherPriv := GenerateKey()
	victim := trust(pub1)

	for name, entries := range map[string][]KeyEntry{
		"self-endorsed":                         {{KeyID: KeyID(attackerPub), Public: attackerPub, Endorsement: Endorse(attackerPriv, attackerPub)}},
		"no endorsement":                        {{KeyID: KeyID(attackerPub), Public: attackerPub}},
		"endorsed by an unknown key":            {{KeyID: KeyID(attackerPub), Public: attackerPub, Endorsement: Endorse(otherPriv, attackerPub)}},
		"endorsement of a different key reused": {{KeyID: KeyID(attackerPub), Public: attackerPub, Endorsement: Endorse(otherPriv, otherPub)}},
		"wrong key id label":                    {{KeyID: KeyID(pub1), Public: attackerPub, Endorsement: Endorse(attackerPriv, attackerPub)}},
	} {
		trusted := trust(pub1)
		if added := FollowChain(trusted, entries); len(added) != 0 || len(trusted) != len(victim) {
			t.Errorf("%s: an untrusted key was accepted", name)
		}
	}
}

func TestAnEndorsementCannotBeReusedForAnotherKey(t *testing.T) {
	pub1, priv1 := GenerateKey()
	pub2, _ := GenerateKey()
	attackerPub, _ := GenerateKey()
	// the genuine endorsement of pub2, replayed alongside the attacker's key
	real := Endorse(priv1, pub2)
	trusted := trust(pub1)
	FollowChain(trusted, []KeyEntry{{KeyID: KeyID(attackerPub), Public: attackerPub, Endorsement: real}})
	if trusted[KeyID(attackerPub)] != nil {
		t.Fatal("a real endorsement of key 2 made the attacker's key trusted")
	}
}
