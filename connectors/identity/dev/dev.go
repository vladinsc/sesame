// Package dev is an identity connector for local development and tests. It verifies compact HMAC-SHA256 tokens
// of the form base64url(json).base64url(hmac). NEVER use it in production; use the oidc connector with a real
// identity provider. The token carries sub, email, name, groups and exp.
package dev

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vladinsc/sesame/pkg/connector"
)

var b64 = base64.RawURLEncoding

// Token is the claim set of a dev token.
type Token struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Exp    int64    `json:"exp"`
}

// Identity verifies dev tokens with a shared secret.
type Identity struct {
	secret   []byte
	issuer   string
	clientID string
	now      func() time.Time
}

// New returns a dev identity connector. issuer/clientID are only echoed in ClientConfig.
func New(secret []byte, issuer, clientID string) *Identity {
	return &Identity{secret: secret, issuer: issuer, clientID: clientID, now: time.Now}
}

// Mint creates a token (used by tests and the local demo CLI).
func (i *Identity) Mint(t Token) string {
	payload, _ := json.Marshal(t)
	mac := hmac.New(sha256.New, i.secret)
	enc := b64.EncodeToString(payload)
	mac.Write([]byte(enc))
	return enc + "." + b64.EncodeToString(mac.Sum(nil))
}

func (i *Identity) Verify(_ context.Context, bearer string) (connector.Subject, error) {
	p, sig, ok := strings.Cut(bearer, ".")
	if !ok {
		return connector.Subject{}, errors.New("dev token: malformed")
	}
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(p))
	want := mac.Sum(nil)
	got, err := b64.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return connector.Subject{}, errors.New("dev token: bad signature")
	}
	raw, err := b64.DecodeString(p)
	if err != nil {
		return connector.Subject{}, errors.New("dev token: bad payload")
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return connector.Subject{}, err
	}
	if i.now().After(time.Unix(t.Exp, 0)) {
		return connector.Subject{}, errors.New("dev token: expired")
	}
	return connector.Subject{ID: t.Sub, Email: t.Email, Name: t.Name, Claims: t.Groups}, nil
}

func (i *Identity) ClientConfig() connector.OIDCClientConfig {
	return connector.OIDCClientConfig{Issuer: i.issuer, ClientID: i.clientID, Scopes: []string{"openid", "profile", "email"}}
}
