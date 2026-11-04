package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"remoteconfig/internal/proto"
	"remoteconfig/internal/signing"
)

// Signer holds the server's signing keys. It signs what agents will act on (config, commands);
// agents verify before applying. The key file is separate from the database on purpose, so
// backing up or replicating the database does not copy the key.
//
// Only the current key keeps its private half. A retired key survives as a public key plus
// the endorsement that let the next key take over, which is all an agent needs to follow
// the chain.
type Signer struct {
	mu   sync.Mutex
	path string // "" = in memory (tests)
	f    signerFile
	priv ed25519.PrivateKey
	now  func() time.Time

	last      time.Time // last issued_at handed out
	persisted time.Time // last value written to disk

	dk       []byte // derived key when the private key is sealed on disk, else nil
	salt     []byte
	iter     int
	migrated bool
}

type keyRecord struct {
	KeyID       string            `json:"kid"`
	Public      []byte            `json:"public"`
	Private     []byte            `json:"private,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Endorsement *signing.Envelope `json:"endorsement,omitempty"`
}

type signerFile struct {
	Current    string      `json:"current"`
	Keys       []keyRecord `json:"keys"`
	LastIssued time.Time   `json:"last_issued"`

	// Protection holds the sealed private key of the current key when a passphrase is set; the
	// key record then carries no private bytes.
	Protection *keyProtection `json:"protection,omitempty"`
}

// OpenSigner loads the key file, creating it (with a fresh key) if it does not exist.
func OpenSigner(path string) (*Signer, error) { return OpenSignerWith(path, "") }

// OpenSignerWith is OpenSigner for a key that may be sealed with a passphrase. A sealed file
// needs the passphrase; a plain file given a passphrase is sealed on the spot (see Migrated);
// a new file is created sealed.
func OpenSignerWith(path, pass string) (*Signer, error) {
	s := &Signer{path: path, now: time.Now}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &s.f); err != nil {
				return nil, errors.New("signing key file " + path + " is unreadable: " + err.Error())
			}
			cur := s.record(s.f.Current)
			if cur == nil {
				return nil, errors.New("signing key file " + path + " has no usable current key")
			}
			if p := s.f.Protection; p != nil {
				if pass == "" {
					return nil, ErrPassphraseNeeded
				}
				if p.KeyID != s.f.Current {
					return nil, errors.New("signing key file " + path + " does not match its protection block")
				}
				priv, dk, err := unseal(p, pass)
				if err != nil {
					return nil, err
				}
				if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(cur.Public)) {
					return nil, errors.New("signing key file " + path + ": the unsealed key does not match the public key")
				}
				cur.Private = priv
				s.dk, s.salt, s.iter = dk, p.Salt, p.Iter
				s.f.Protection = nil // rebuilt on every save
			}
			if len(cur.Private) != ed25519.PrivateKeySize {
				return nil, errors.New("signing key file " + path + " has no usable current key")
			}
			s.priv = ed25519.PrivateKey(cur.Private)
			if pass != "" && s.dk == nil { // a plain key and a passphrase: seal it now
				if err := s.setPassphrase(pass); err != nil {
					return nil, err
				}
				s.migrated = true
				defer func() { s.save() }()
			}
			// Every issued_at must exceed all earlier ones even if the wall clock went backwards
			// while the server was down (or the machine was restored). The persisted value can lag
			// by up to 30 s, so start a minute past it.
			s.last = s.f.LastIssued.Add(time.Minute)
			s.persisted = s.f.LastIssued
			return s, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	pub, priv := signing.GenerateKey()
	s.priv = priv
	s.f = signerFile{Current: signing.KeyID(pub), Keys: []keyRecord{{KeyID: signing.KeyID(pub), Public: pub, Private: priv, CreatedAt: s.now().UTC()}}}
	if pass != "" && path != "" {
		if err := s.setPassphrase(pass); err != nil {
			return nil, err
		}
	}
	return s, s.save()
}

func (s *Signer) record(kid string) *keyRecord {
	for i := range s.f.Keys {
		if s.f.Keys[i].KeyID == kid {
			return &s.f.Keys[i]
		}
	}
	return nil
}

// save writes the key file atomically with owner-only permissions. Caller holds s.mu (or is constructing).
func (s *Signer) save() error {
	if s.path == "" {
		return nil
	}
	s.f.LastIssued = s.last
	out := s.f
	if s.dk != nil { // sealed: write the key sealed, and no private bytes anywhere else
		out.Keys = append([]keyRecord(nil), s.f.Keys...)
		for i := range out.Keys {
			out.Keys[i].Private = nil
		}
		p, err := s.seal()
		if err != nil {
			return err
		}
		out.Protection = p
	}
	b, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	s.persisted = s.last
	return os.Rename(tmp, s.path)
}

// Close persists the issue clock.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// issued returns a timestamp strictly later than every one it returned before, even across
// restarts and a wall clock that steps backwards. Agents refuse content older than what they
// already applied, which is what stops a captured old config being replayed. Caller holds s.mu.
func (s *Signer) issued() time.Time {
	t := s.now().UTC()
	if !t.After(s.last) {
		t = s.last.Add(time.Microsecond)
	}
	s.last = t
	if t.Sub(s.persisted) > 30*time.Second {
		s.save()
	}
	return t
}

func info(r *keyRecord) proto.KeyInfo {
	return proto.KeyInfo{KeyID: r.KeyID, Public: base64.StdEncoding.EncodeToString(r.Public), Endorsement: r.Endorsement}
}

// Current is the key content is signed with now.
func (s *Signer) Current() proto.KeyInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return info(s.record(s.f.Current))
}

// KeySet is every key, oldest first, with the endorsement chain.
func (s *Signer) KeySet() proto.KeySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	ks := proto.KeySet{Current: s.f.Current}
	for i := range s.f.Keys {
		ks.Keys = append(ks.Keys, info(&s.f.Keys[i]))
	}
	return ks
}

// Rotate makes a new key current. The old key endorses it first, so agents that only know
// the old key accept the new one, and then the old private key is erased. After a rotation
// the server cannot sign as the old key any more, so a later theft of this file does not
// reach back to it. (If the old key was already stolen, rotation does not help: agents must
// be re-pinned. See the README.)
func (s *Signer) Rotate() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newPub, newPriv := signing.GenerateKey()
	endorsement := signing.Endorse(s.priv, newPub)
	old := s.record(s.f.Current)
	old.Private = nil
	s.f.Keys = append(s.f.Keys, keyRecord{KeyID: signing.KeyID(newPub), Public: newPub, Private: newPriv, CreatedAt: s.now().UTC(), Endorsement: endorsement})
	s.f.Current = signing.KeyID(newPub)
	s.priv = newPriv
	return s.f.Current, s.save()
}

// SignConfig signs a device's effective config, bound to that device and project.
func (s *Signer) SignConfig(deviceID, project string, cfg proto.EffectiveConfig) (*signing.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return signing.SignJSON(s.priv, signing.TypeConfig, proto.SignedConfig{DeviceID: deviceID, Project: project, IssuedAt: s.issued(), Config: cfg})
}

// SignCommand signs a command, bound to the device it is for.
func (s *Signer) SignCommand(deviceID string, c proto.Command) (*signing.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return signing.SignJSON(s.priv, signing.TypeCommand, proto.SignedCommand{
		DeviceID: deviceID, ID: c.ID, Type: c.Type, Params: c.Params, ExpiresAt: c.ExpiresAt, IssuedAt: s.issued(),
	})
}
