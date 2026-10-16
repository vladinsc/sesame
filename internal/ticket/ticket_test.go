package ticket

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestIssueVerify(t *testing.T) {
	pub, priv := keys(t)
	s := NewSigner("k1", priv)
	v := NewVerifier("pool-a", map[string]ed25519.PublicKey{"k1": pub})

	tok, err := s.Issue(Claims{Audience: "pool-a", Target: "grafana.internal:443", Subject: "u1", Tool: "g"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok, "grafana.internal:443")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "u1" || c.ID == "" {
		t.Fatalf("claims: %+v", c)
	}
}

func TestRejections(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	_ = otherPub
	s := NewSigner("k1", priv)
	v := NewVerifier("pool-a", map[string]ed25519.PublicKey{"k1": pub})
	tok, _ := s.Issue(Claims{Audience: "pool-a", Target: "a:443"}, 30*time.Second)

	cases := map[string]struct {
		tok, target string
		want        error
	}{
		"other target":   {tok, "b:443", ErrTarget},
		"tampered":       {tamper(tok), "b:443", ErrSignature},
		"garbage":        {"abc", "a:443", ErrMalformed},
		"forged key":     {mustIssue(t, NewSigner("k1", otherPriv), "pool-a", "a:443", time.Minute), "a:443", ErrSignature},
		"unknown kid":    {mustIssue(t, NewSigner("k9", priv), "pool-a", "a:443", time.Minute), "a:443", ErrUnknownKey},
		"other audience": {mustIssue(t, s, "pool-b", "a:443", time.Minute), "a:443", ErrAudience},
		"expired":        {mustIssue(t, s, "pool-a", "a:443", -time.Minute), "a:443", ErrExpired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(tc.tok, tc.target); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func mustIssue(t *testing.T, s *Signer, aud, target string, ttl time.Duration) string {
	t.Helper()
	tok, err := s.Issue(Claims{Audience: aud, Target: target}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// tamper rewrites the payload (valid JSON, different target) but keeps the original signature.
func tamper(tok string) string {
	p, s, _ := strings.Cut(tok, ".")
	raw, _ := b64.DecodeString(p)
	raw = []byte(strings.Replace(string(raw), `"dst":"a:443"`, `"dst":"b:443"`, 1))
	return b64.EncodeToString(raw) + "." + s
}
