// Package ticket implements egress tickets: short-lived, Ed25519-signed capabilities that allow exactly one
// destination (host:port) through the egress proxy. The broker issues them only for an authorised login to a
// catalog tool; the egress verifies them offline with the broker's public key, so no shared state is needed and
// both sides scale horizontally.
//
// Format: base64url(payload JSON) "." base64url(signature), signature over the payload bytes.
package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims are the signed contents of a ticket.
type Claims struct {
	KeyID     string `json:"kid"`
	ID        string `json:"jti"`
	Audience  string `json:"aud"`  // egress pool name
	Target    string `json:"dst"`  // host:port the bearer may connect to
	ConnectTo string `json:"via"`  // optional address the egress dials instead (Host/SNI stay the target's)
	Subject   string `json:"sub"`  // user the login is for (audit only)
	Tool      string `json:"tool"` // catalog tool id (audit only)
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var (
	ErrMalformed  = errors.New("ticket: malformed")
	ErrSignature  = errors.New("ticket: bad signature")
	ErrExpired    = errors.New("ticket: expired")
	ErrAudience   = errors.New("ticket: wrong audience")
	ErrTarget     = errors.New("ticket: target not allowed")
	ErrUnknownKey = errors.New("ticket: unknown key id")
)

var b64 = base64.RawURLEncoding

// Signer issues tickets.
type Signer struct {
	keyID string
	key   ed25519.PrivateKey
	now   func() time.Time
}

// NewSigner returns a signer. The key id lets verifiers hold several public keys during rotation.
func NewSigner(keyID string, key ed25519.PrivateKey) *Signer {
	return &Signer{keyID: keyID, key: key, now: time.Now}
}

// Issue signs a ticket valid for ttl.
func (s *Signer) Issue(c Claims, ttl time.Duration) (string, error) {
	if c.Target == "" || c.Audience == "" {
		return "", errors.New("ticket: target and audience required")
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := s.now()
	c.KeyID, c.ID = s.keyID, hex.EncodeToString(id)
	c.IssuedAt, c.ExpiresAt = now.Unix(), now.Add(ttl).Unix()
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.key, payload)
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// Verifier checks tickets against a set of public keys.
type Verifier struct {
	keys     map[string]ed25519.PublicKey
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// NewVerifier accepts tickets for audience signed by any of keys (kid -> key).
func NewVerifier(audience string, keys map[string]ed25519.PublicKey) *Verifier {
	return &Verifier{keys: keys, audience: audience, leeway: 5 * time.Second, now: time.Now}
}

// Verify checks signature, expiry, audience and that target equals the ticket's destination.
func (v *Verifier) Verify(tok, target string) (Claims, error) {
	var c Claims
	p, s, ok := strings.Cut(tok, ".")
	if !ok || strings.Contains(s, ".") {
		return c, ErrMalformed
	}
	payload, err1 := b64.DecodeString(p)
	sig, err2 := b64.DecodeString(s)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, ErrMalformed
	}
	key, ok := v.keys[c.KeyID]
	if !ok {
		return c, ErrUnknownKey
	}
	if !ed25519.Verify(key, payload, sig) {
		return c, ErrSignature
	}
	now := v.now()
	if now.After(time.Unix(c.ExpiresAt, 0).Add(v.leeway)) || now.Add(v.leeway).Before(time.Unix(c.IssuedAt, 0)) {
		return c, ErrExpired
	}
	if c.Audience != v.audience {
		return c, ErrAudience
	}
	if !strings.EqualFold(c.Target, target) {
		return c, fmt.Errorf("%w: %s", ErrTarget, target)
	}
	return c, nil
}
