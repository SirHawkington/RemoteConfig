package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

// trustStore decides what the agent will act on. The rules:
//
//   - With a trusted server key the agent is STRICT: config and commands are applied only if
//     they carry a valid signature from a trusted key, are for this device, and are not older
//     than what is already in force. Unsigned content is refused, so stripping the signature
//     (a downgrade attack) gains an attacker nothing.
//   - Without any key the agent is in LEGACY mode and accepts unsigned content, exactly as
//     before signing existed. It becomes strict the moment it learns a key.
//   - A key reaches the agent in one of three ways: pinned at install (-server-key, the safe
//     way: it does not depend on the network), trusted on first use (accepted from the server
//     the first time, only over HTTPS or loopback, because that channel is authenticated), or
//     through a rotation (an already-trusted key vouches for it).
//   - A refused item never replaces the config in force, and is reported to the server as an
//     event and in the check-in, so tampering shows up on the dashboard.
type trustStore struct {
	a    *Agent
	path string

	mu             sync.Mutex
	keys           map[string]trustedKey
	lastKeyID      string
	lastIssued     time.Time // issued_at of the config in force: nothing older is accepted
	rejected       int
	lastRejected   string
	lastRejectedAt time.Time
	lastAcceptedAt time.Time
	lastRefresh    time.Time
	lastUnknown    time.Time            // last time an unknown signing key made us re-fetch the key list
	said           map[string]time.Time // event de-duplication
}

type trustedKey struct {
	KeyID  string    `json:"kid"`
	Public []byte    `json:"public"`
	Source string    `json:"source"` // pinned | first-use | rotation
	Added  time.Time `json:"added"`
}

func newTrustStore(a *Agent) *trustStore {
	return &trustStore{a: a, path: filepath.Join(a.o.StateDir, "trusted-keys.json"), keys: map[string]trustedKey{}, said: map[string]time.Time{}}
}

// load reads the saved keys and adds the key pinned in the options, if any.
func (t *trustStore) load() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b, err := os.ReadFile(t.path); err == nil {
		var list []trustedKey
		if json.Unmarshal(b, &list) == nil {
			for _, k := range list {
				if len(k.Public) == ed25519.PublicKeySize && signing.KeyID(k.Public) == k.KeyID {
					t.keys[k.KeyID] = k
				}
			}
		}
	}
	if pin := strings.TrimSpace(t.a.o.ServerKey); pin != "" {
		pub, err := base64.StdEncoding.DecodeString(pin)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("the pinned server key is not a valid public key (expected %d bytes of base64)", ed25519.PublicKeySize)
		}
		kid := signing.KeyID(pub)
		if _, have := t.keys[kid]; !have {
			t.keys[kid] = trustedKey{KeyID: kid, Public: pub, Source: "pinned", Added: time.Now().UTC()}
			return t.saveLocked()
		}
	}
	return nil
}

func (t *trustStore) saveLocked() error {
	list := make([]trustedKey, 0, len(t.keys))
	for _, k := range t.keys {
		list = append(list, k)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	return writeFileAtomic(t.path, b)
}

func (t *trustStore) strict() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys) > 0 || t.a.o.RequireSignatures
}

func (t *trustStore) pubkeys() map[string]ed25519.PublicKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := make(map[string]ed25519.PublicKey, len(t.keys))
	for id, k := range t.keys {
		m[id] = k.Public
	}
	return m
}

// report is the trust section of the check-in.
func (t *trustStore) report() *proto.TrustReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := &proto.TrustReport{State: "legacy", KeyID: t.lastKeyID, KeysTrusted: len(t.keys), Rejected: t.rejected,
		LastRejected: t.lastRejected, LastRejectedAt: t.lastRejectedAt, LastAcceptedAt: t.lastAcceptedAt}
	if len(t.keys) > 0 || t.a.o.RequireSignatures {
		r.State = "strict"
	}
	for _, k := range t.keys {
		r.Pinned = r.Pinned || k.Source == "pinned"
	}
	return r
}

// accepted notes a config fresh from the server that verified, so the dashboard can tell a
// device that recovered from one that is still being fed bad data.
func (t *trustStore) accepted() {
	t.mu.Lock()
	t.lastAcceptedAt = time.Now().UTC()
	t.mu.Unlock()
}

// reject records something that failed verification: log, counter, and (at most once per
// ten minutes per reason) an event the dashboard shows.
func (t *trustStore) reject(what, why string) {
	msg := what + " refused: " + why
	t.mu.Lock()
	t.rejected++
	t.lastRejected, t.lastRejectedAt = msg, time.Now().UTC()
	quiet := time.Since(t.said[msg]) < 10*time.Minute
	t.said[msg] = time.Now()
	t.mu.Unlock()
	t.a.logf("signature check: %s", msg)
	if !quiet {
		t.a.QueueEvent(proto.Event{Type: "signature.rejected", Level: "error", Message: msg})
	}
}

// ---------------------------------------------------------------- learning keys

// tofuAllowed: trusting a key on first use is only as safe as the channel that carried it, so
// it is allowed over HTTPS (the certificate authenticates the server) and over loopback, and
// not over plain HTTP to another machine unless the operator explicitly says so.
func (t *trustStore) tofuAllowed() bool {
	if t.a.o.InsecureTOFU {
		return true
	}
	u, err := url.Parse(t.a.serverURL())
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func decodeKeyInfo(k proto.KeyInfo) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil || len(pub) != ed25519.PublicKeySize || signing.KeyID(pub) != k.KeyID {
		return nil, errors.New("the server sent a malformed signing key")
	}
	return pub, nil
}

// consider takes the server's key set (current key, plus endorsements of any newer ones) and
// extends trust as the rules allow. It returns an error only if it found a conflict: the
// agent trusts keys, and the server's key is neither one of them nor vouched for by one.
func (t *trustStore) consider(ks proto.KeySet, source string) error {
	entries := make([]signing.KeyEntry, 0, len(ks.Keys))
	var current *proto.KeyInfo
	for i := range ks.Keys {
		pub, err := decodeKeyInfo(ks.Keys[i])
		if err != nil {
			return err
		}
		entries = append(entries, signing.KeyEntry{KeyID: ks.Keys[i].KeyID, Public: pub, Endorsement: ks.Keys[i].Endorsement})
		if ks.Keys[i].KeyID == ks.Current {
			current = &ks.Keys[i]
		}
	}
	if current == nil {
		return errors.New("the server's key list does not include its current key")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	trusted := make(map[string]ed25519.PublicKey, len(t.keys))
	for id, k := range t.keys {
		trusted[id] = k.Public
	}
	if len(trusted) == 0 { // nothing pinned or learned yet: first use
		if !t.tofuAllowed() {
			return errors.New("not trusting a key learned over plain HTTP from another machine: install with -server-key (or use https)")
		}
		pub, _ := decodeKeyInfo(*current)
		t.keys[current.KeyID] = trustedKey{KeyID: current.KeyID, Public: pub, Source: "first-use", Added: time.Now().UTC()}
		t.a.logf("trusting the server's signing key %s on first use. Pin it to avoid depending on this: -server-key %s", current.KeyID, current.Public)
		return t.saveLocked()
	}
	for _, e := range signing.FollowChain(trusted, entries) {
		t.keys[e.KeyID] = trustedKey{KeyID: e.KeyID, Public: e.Public, Source: "rotation", Added: time.Now().UTC()}
		t.a.logf("following the server's key rotation to %s", e.KeyID)
	}
	if _, ok := trusted[current.KeyID]; !ok {
		return fmt.Errorf("the server's current key %s is not trusted and no trusted key vouches for it", current.KeyID)
	}
	return t.saveLocked()
}

// fetchKeys asks the server for its keys and applies consider. Rate limited, so a server
// (or attacker) that keeps presenting unknown keys cannot make the agent hammer it.
func (t *trustStore) fetchKeys(ctx context.Context, force bool) error {
	t.mu.Lock()
	if !force && time.Since(t.lastRefresh) < 5*time.Minute {
		t.mu.Unlock()
		return errors.New("key list fetched recently")
	}
	t.lastRefresh = time.Now()
	t.mu.Unlock()

	var ks proto.KeySet
	status, err := t.a.server(ctx, http.MethodGet, "/v1/keys", nil, &ks, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /v1/keys: HTTP %d", status)
	}
	return t.consider(ks, "")
}

// ---------------------------------------------------------------- verifying

// verify checks an envelope of the wanted type against the trusted keys. If it was signed by a
// key the agent does not know, it asks the server for its key chain once (a rotation may have
// happened) and tries again.
func (t *trustStore) verify(ctx context.Context, env *signing.Envelope, want string, into any) (kid string, err error) {
	kid, err = signing.VerifyJSON(env, want, t.pubkeys(), into)
	if errors.Is(err, signing.ErrUnknownKey) && ctx != nil && t.mayRefetchForUnknownKey() {
		if t.fetchKeys(ctx, true) == nil {
			kid, err = signing.VerifyJSON(env, want, t.pubkeys(), into)
		}
	}
	return kid, err
}

// mayRefetchForUnknownKey allows one key-list fetch per 30 s when something arrives signed by
// an unknown key (normally a rotation). The limit keeps content signed by junk keys from making
// the agent hammer the server.
func (t *trustStore) mayRefetchForUnknownKey() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.lastUnknown) < 30*time.Second {
		return false
	}
	t.lastUnknown = time.Now()
	return true
}

// checkConfig verifies a signed config for this device and decides whether it may replace the
// one in force.
func (t *trustStore) checkConfig(ctx context.Context, env *signing.Envelope) (*proto.SignedConfig, error) {
	var sc proto.SignedConfig
	kid, err := t.verify(ctx, env, signing.TypeConfig, &sc)
	if err != nil {
		return nil, err
	}
	id := t.a.identitySnapshot()
	if sc.DeviceID != id.DeviceID || sc.Project != id.Project {
		return nil, fmt.Errorf("this config is for device %q in project %q, not this one", sc.DeviceID, sc.Project)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if sc.IssuedAt.Before(t.lastIssued) {
		return nil, fmt.Errorf("issued %s, before the config already in force (%s): a replayed old config", sc.IssuedAt.Format(time.RFC3339), t.lastIssued.Format(time.RFC3339))
	}
	t.lastKeyID = kid
	return &sc, nil
}

// checkCommand returns the command the agent should act on. In strict mode that is built
// from the verified signed payload only: the plain fields beside the envelope are ignored.
func (t *trustStore) checkCommand(ctx context.Context, c proto.Command) (proto.Command, error) {
	if !t.strict() {
		return c, nil
	}
	if c.Signed == nil {
		return c, errors.New("the command is not signed")
	}
	var sc proto.SignedCommand
	if _, err := t.verify(ctx, c.Signed, signing.TypeCommand, &sc); err != nil {
		return c, err
	}
	if sc.DeviceID != t.a.identitySnapshot().DeviceID {
		return c, fmt.Errorf("the command is for device %q, not this one", sc.DeviceID)
	}
	if !sc.ExpiresAt.IsZero() && time.Since(sc.ExpiresAt) > 24*time.Hour {
		// Not a strict expiry (kiosk clocks are unreliable), but old enough that it is almost
		// certainly a captured command being replayed.
		return c, fmt.Errorf("the command expired on %s", sc.ExpiresAt.Format(time.RFC3339))
	}
	return proto.Command{ID: sc.ID, Type: sc.Type, Params: sc.Params, ExpiresAt: sc.ExpiresAt, Status: c.Status, Signed: c.Signed}, nil
}
