package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Protecting the signing key at rest.
//
// The private half of the current signing key can be sealed with a passphrase: PBKDF2-SHA256
// (600,000 rounds, the same cost as passwords) derives an AES-256 key and AES-GCM seals the key
// bytes, bound to the key id. The public parts, the rotation chain and the issue clock stay
// readable. A copy of the key file (a backup, a stolen disk image, a repository by mistake) is then
// useless without the passphrase. It does not help against someone who can run code as the
// server while it is running: the key is in memory then, as it must be to sign.

const (
	protectionKDF  = "pbkdf2-sha256"
	protectionIter = 600_000
	minPassphrase  = 12
)

var (
	// ErrPassphraseNeeded: the key file is sealed and no passphrase was given.
	ErrPassphraseNeeded = errors.New("the signing key is encrypted: give its passphrase (RC_SIGNING_PASSPHRASE, or -signing-passphrase-file)")
	// ErrWrongPassphrase: the passphrase does not open the key file (or the file was altered).
	ErrWrongPassphrase = errors.New("the signing key passphrase is wrong, or the key file has been altered")
	// ErrWeakPassphrase: too short to protect anything.
	ErrWeakPassphrase = fmt.Errorf("a signing key passphrase needs at least %d characters", minPassphrase)
)

type keyProtection struct {
	KDF    string `json:"kdf"`
	Iter   int    `json:"iter"`
	Salt   []byte `json:"salt"`
	Nonce  []byte `json:"nonce"`
	Sealed []byte `json:"sealed"` // the private key, AES-256-GCM, additional data = key id
	KeyID  string `json:"kid"`
}

func derive(pass string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, iter, 32)
}

func gcmFor(dk []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// unseal opens a protected key file's private key.
func unseal(p *keyProtection, pass string) (ed25519.PrivateKey, []byte, error) {
	if p.KDF != protectionKDF || p.Iter < 100_000 || len(p.Salt) < 16 {
		return nil, nil, errors.New("the key file uses a protection scheme this server does not know")
	}
	dk, err := derive(pass, p.Salt, p.Iter)
	if err != nil {
		return nil, nil, err
	}
	g, err := gcmFor(dk)
	if err != nil {
		return nil, nil, err
	}
	if len(p.Nonce) != g.NonceSize() {
		return nil, nil, ErrWrongPassphrase
	}
	priv, err := g.Open(nil, p.Nonce, p.Sealed, []byte(p.KeyID))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, nil, ErrWrongPassphrase
	}
	return ed25519.PrivateKey(priv), dk, nil
}

// seal produces the protection block for the current private key. Salt and derived key are
// reused across saves (deriving costs a third of a second); every save gets a fresh nonce.
func (s *Signer) seal() (*keyProtection, error) {
	g, err := gcmFor(s.dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &keyProtection{KDF: protectionKDF, Iter: s.iter, Salt: s.salt, Nonce: nonce, KeyID: s.f.Current,
		Sealed: g.Seal(nil, nonce, s.priv, []byte(s.f.Current))}, nil
}

func (s *Signer) setPassphrase(pass string) error {
	if len(pass) < minPassphrase {
		return ErrWeakPassphrase
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk, err := derive(pass, salt, protectionIter)
	if err != nil {
		return err
	}
	s.dk, s.salt, s.iter = dk, salt, protectionIter
	return nil
}

// Protected reports whether the private key is sealed on disk.
func (s *Signer) Protected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dk != nil
}

// Migrated reports that this run sealed a key file that was stored in the clear.
func (s *Signer) Migrated() bool { return s.migrated }

// Protect seals the private key with a (new) passphrase, replacing any earlier one.
func (s *Signer) Protect(pass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return errors.New("this key is not stored in a file")
	}
	if err := s.setPassphrase(pass); err != nil {
		return err
	}
	return s.save()
}

// Unprotect stores the private key in the clear again.
func (s *Signer) Unprotect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dk, s.salt = nil, nil
	return s.save()
}
