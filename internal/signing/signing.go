// Package signing is how the server proves to an agent that a piece of configuration or a
// command really came from it, and how the agent checks that before acting on it.
//
// Design, in short:
//
//   - Ed25519 signatures (stdlib), key id = first 8 bytes of SHA-256(public key).
//   - An Envelope signs the exact bytes that are sent (a DSSE-style "payload" plus a type),
//     so there is no JSON canonicalisation to get subtly wrong across versions or languages:
//     the verifier checks the signature over the bytes, and only then parses those same bytes.
//   - The payload type is part of what is signed, so a signed config can never be passed
//     off as a signed command, a script or a key endorsement (domain separation).
//   - Keys can be rotated without re-installing every machine: the old key signs an
//     endorsement of the new one, and an agent that trusts the old key follows the chain.
//
// What this does NOT do: it cannot protect against someone who holds the server's private
// key. It protects against everything between the server and the agent (a network attacker,
// a bad proxy, a spoofed server address), and against agents acting on anything the server
// did not sign.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Payload types. Each kind of signed thing has its own; they are part of the signed bytes.
// Scripts and releases will get theirs here when those features exist.
const (
	TypeConfig         = "application/vnd.remoteconfig.config+json"
	TypeCommand        = "application/vnd.remoteconfig.command+json"
	TypeKeyEndorsement = "application/vnd.remoteconfig.key-endorsement+json"
)

// ContentType is the media type of a signed envelope on the wire.
const ContentType = "application/vnd.remoteconfig.signed+json"

var (
	ErrUnknownKey   = errors.New("signed by a key this agent does not trust")
	ErrBadSignature = errors.New("the signature does not match the content")
	ErrWrongType    = errors.New("this is signed content of a different kind")
	ErrMalformed    = errors.New("malformed signed envelope")
)

type Signature struct {
	KeyID string `json:"kid"`
	Sig   []byte `json:"sig"` // base64 in JSON
}

// Envelope is signed content: Payload is opaque bytes, authenticated together with PayloadType.
type Envelope struct {
	PayloadType string      `json:"payload_type"`
	Payload     []byte      `json:"payload"` // base64 in JSON
	Signatures  []Signature `json:"signatures"`
}

// KeyID names a public key compactly.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // the system's randomness is broken; nothing sensible can continue
	}
	return pub, priv
}

// pae is the exact byte string that is signed: an unambiguous encoding of (type, payload),
// with a version prefix so the format can change later without old signatures being reusable.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("RCSIG1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// Sign signs payload (the exact bytes) as payloadType.
func Sign(priv ed25519.PrivateKey, payloadType string, payload []byte) *Envelope {
	pub := priv.Public().(ed25519.PublicKey)
	return &Envelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures:  []Signature{{KeyID: KeyID(pub), Sig: ed25519.Sign(priv, pae(payloadType, payload))}},
	}
}

// SignJSON marshals v and signs the resulting bytes.
func SignJSON(priv ed25519.PrivateKey, payloadType string, v any) (*Envelope, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Sign(priv, payloadType, b), nil
}

// Verify checks that e is of type want and carries a valid signature by one of keys (key id
// -> public key). On success it returns the payload bytes and the id of the key that signed.
//
// ErrUnknownKey means no signature was made by a trusted key (the caller may know how to
// learn the key); ErrBadSignature means a trusted key's signature is wrong: tampering.
func Verify(e *Envelope, want string, keys map[string]ed25519.PublicKey) (payload []byte, signedBy string, err error) {
	if e == nil || len(e.Signatures) == 0 {
		return nil, "", ErrMalformed
	}
	if e.PayloadType != want {
		return nil, "", ErrWrongType
	}
	msg := pae(e.PayloadType, e.Payload)
	sawKnown := false
	for _, s := range e.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sawKnown = true
		if ed25519.Verify(pub, msg, s.Sig) {
			return e.Payload, s.KeyID, nil
		}
	}
	if sawKnown {
		return nil, "", ErrBadSignature
	}
	return nil, "", ErrUnknownKey
}

// VerifyJSON is Verify followed by unmarshalling the verified payload into v.
func VerifyJSON(e *Envelope, want string, keys map[string]ed25519.PublicKey, v any) (signedBy string, err error) {
	payload, kid, err := Verify(e, want, keys)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return kid, nil
}

// ---------------------------------------------------------------- key rotation

// KeyEntry is a public key the server has used, with the statement by which the previous
// key vouched for it (nil for the very first key).
type KeyEntry struct {
	KeyID       string            `json:"kid"`
	Public      ed25519.PublicKey `json:"public"` // base64 in JSON
	Endorsement *Envelope         `json:"endorsement,omitempty"`
}

type endorsementPayload struct {
	NewKeyID string `json:"new_kid"`
	NewKey   string `json:"new_public"` // base64
}

// Endorse makes the statement "the holder of old vouches for newPub".
func Endorse(old ed25519.PrivateKey, newPub ed25519.PublicKey) *Envelope {
	env, _ := SignJSON(old, TypeKeyEndorsement, endorsementPayload{NewKeyID: KeyID(newPub), NewKey: base64.StdEncoding.EncodeToString(newPub)})
	return env
}

// FollowChain extends trusted with every entry that is vouched for, directly or through
// other entries, by a key already in trusted. It returns the entries it added. An entry whose
// endorsement is missing, invalid, signed by an untrusted key, or about a different key is
// ignored, so an attacker offering their own key gains nothing.
func FollowChain(trusted map[string]ed25519.PublicKey, entries []KeyEntry) []KeyEntry {
	var added []KeyEntry
	for progress := true; progress; {
		progress = false
		for _, e := range entries {
			if _, have := trusted[e.KeyID]; have || e.Endorsement == nil {
				continue
			}
			var p endorsementPayload
			if _, err := VerifyJSON(e.Endorsement, TypeKeyEndorsement, trusted, &p); err != nil {
				continue
			}
			if p.NewKeyID != e.KeyID || p.NewKey != base64.StdEncoding.EncodeToString(e.Public) || KeyID(e.Public) != e.KeyID {
				continue // vouches for some other key than the one offered
			}
			trusted[e.KeyID] = e.Public
			added = append(added, e)
			progress = true
		}
	}
	return added
}
