// Package oidc is the production identity connector. It verifies OIDC ID/access tokens (RS256) against the
// provider's JWKS, checking signature, issuer, audience and expiry. Groups are taken from a configurable claim
// so the oidc-claims roles connector can use them. Dependency-free: JWKS fetch and RSA verification use only the
// standard library, keeping the supply-chain surface small.
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vladinsc/sesame/pkg/connector"
)

var b64 = base64.RawURLEncoding

// Config configures the connector.
type Config struct {
	Issuer      string // public issuer (the `iss` claim; what the extension uses). e.g. https://idp/realms/acme
	InternalURL string // optional base to fetch discovery/JWKS from, when the broker reaches the provider
	// at a different address than the browser (e.g. keycloak:8088 vs localhost:8088)
	ClientID    string        // audience the token must contain
	Audience    string        // explicit audience override (defaults to ClientID)
	GroupsClaim string        // claim holding group paths (default "groups")
	Scopes      []string      // advertised to the extension
	JWKSTTL     time.Duration // how long to cache JWKS
	HTTP        *http.Client
	now         func() time.Time
}

// Identity verifies tokens.
type Identity struct {
	cfg     Config
	jwksURI string
	authEP  string
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	keysExp time.Time
}

// New discovers the provider's endpoints and returns the connector.
func New(cfg Config) (*Identity, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.ClientID
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.JWKSTTL == 0 {
		cfg.JWKSTTL = time.Hour
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	id := &Identity{cfg: cfg, keys: map[string]*rsa.PublicKey{}}
	if err := id.discover(); err != nil {
		return nil, err
	}
	return id, nil
}

func (i *Identity) discover() error {
	base := i.cfg.Issuer
	if i.cfg.InternalURL != "" {
		base = i.cfg.InternalURL
	}
	url := strings.TrimRight(base, "/") + "/.well-known/openid-configuration"
	resp, err := i.cfg.HTTP.Get(url)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
		AuthEP  string `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return err
	}
	if meta.Issuer != i.cfg.Issuer {
		return fmt.Errorf("oidc issuer mismatch: %q vs %q", meta.Issuer, i.cfg.Issuer)
	}
	i.jwksURI, i.authEP = meta.JWKSURI, meta.AuthEP
	return nil
}

type claims struct {
	Iss   string                     `json:"iss"`
	Sub   string                     `json:"sub"`
	Aud   json.RawMessage            `json:"aud"`
	Exp   int64                      `json:"exp"`
	Nbf   int64                      `json:"nbf"`
	Email string                     `json:"email"`
	Name  string                     `json:"name"`
	Raw   map[string]json.RawMessage `json:"-"`
}

func (i *Identity) Verify(ctx context.Context, bearer string) (connector.Subject, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return connector.Subject{}, errors.New("oidc: not a JWT")
	}
	header, err := b64.DecodeString(parts[0])
	if err != nil {
		return connector.Subject{}, errors.New("oidc: bad header")
	}
	var h struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(header, &h); err != nil {
		return connector.Subject{}, err
	}
	if h.Alg != "RS256" {
		return connector.Subject{}, fmt.Errorf("oidc: unsupported alg %q", h.Alg)
	}
	key, err := i.key(ctx, h.Kid)
	if err != nil {
		return connector.Subject{}, err
	}
	signed := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return connector.Subject{}, errors.New("oidc: bad signature encoding")
	}
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return connector.Subject{}, errors.New("oidc: signature invalid")
	}

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return connector.Subject{}, errors.New("oidc: bad payload")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return connector.Subject{}, err
	}
	_ = json.Unmarshal(payload, &c.Raw)
	now := i.cfg.now()
	if c.Iss != i.cfg.Issuer {
		return connector.Subject{}, errors.New("oidc: wrong issuer")
	}
	if now.After(time.Unix(c.Exp, 0)) {
		return connector.Subject{}, errors.New("oidc: token expired")
	}
	if c.Nbf != 0 && now.Add(30*time.Second).Before(time.Unix(c.Nbf, 0)) {
		return connector.Subject{}, errors.New("oidc: token not yet valid")
	}
	if !audienceOK(c.Aud, i.cfg.Audience) {
		return connector.Subject{}, errors.New("oidc: wrong audience")
	}
	return connector.Subject{ID: c.Sub, Email: c.Email, Name: c.Name, Claims: groupsFrom(c.Raw, i.cfg.GroupsClaim)}, nil
}

func (i *Identity) ClientConfig() connector.OIDCClientConfig {
	scopes := i.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return connector.OIDCClientConfig{Issuer: i.cfg.Issuer, ClientID: i.cfg.ClientID, Scopes: scopes}
}

func (i *Identity) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	i.mu.Lock()
	if k, ok := i.keys[kid]; ok && i.cfg.now().Before(i.keysExp) {
		i.mu.Unlock()
		return k, nil
	}
	i.mu.Unlock()
	if err := i.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	k, ok := i.keys[kid]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown key id %q", kid)
	}
	return k, nil
}

func (i *Identity) refreshJWKS(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.jwksURI, nil)
	resp, err := i.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc jwks: status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Alg, Use, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err1 := b64.DecodeString(k.N)
		eBytes, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return errors.New("oidc jwks: no RSA keys")
	}
	i.mu.Lock()
	i.keys = keys
	i.keysExp = i.cfg.now().Add(i.cfg.JWKSTTL)
	i.mu.Unlock()
	return nil
}

func audienceOK(aud json.RawMessage, want string) bool {
	if len(aud) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(aud, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func groupsFrom(raw map[string]json.RawMessage, claim string) []string {
	v, ok := raw[claim]
	if !ok {
		return nil
	}
	var groups []string
	_ = json.Unmarshal(v, &groups)
	return groups
}
