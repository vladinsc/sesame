package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	catalogfile "github.com/vladinsc/sesame/connectors/catalog/file"
	"github.com/vladinsc/sesame/connectors/credentials/bitwarden"
	credstatic "github.com/vladinsc/sesame/connectors/credentials/static"
	"github.com/vladinsc/sesame/connectors/identity/dev"
	"github.com/vladinsc/sesame/connectors/identity/oidc"
	"github.com/vladinsc/sesame/connectors/roles/keycloak"
	"github.com/vladinsc/sesame/connectors/roles/oidcclaims"
	rolestatic "github.com/vladinsc/sesame/connectors/roles/static"
	"github.com/vladinsc/sesame/internal/agent"
	"github.com/vladinsc/sesame/internal/audit"
	"github.com/vladinsc/sesame/internal/broker"
	"github.com/vladinsc/sesame/internal/metrics"
	"github.com/vladinsc/sesame/internal/policy"
	"github.com/vladinsc/sesame/internal/ticket"
	"github.com/vladinsc/sesame/pkg/connector"
)

// BuildBroker assembles broker.Deps from a validated config.
func (c *Broker) BuildBroker(reg *metrics.Registry, aud connector.Audit) (broker.Deps, error) {
	id, err := c.identity()
	if err != nil {
		return broker.Deps{}, err
	}
	roles, err := c.roles(id)
	if err != nil {
		return broker.Deps{}, err
	}
	creds, err := c.creds()
	if err != nil {
		return broker.Deps{}, err
	}
	cat, err := c.catalog()
	if err != nil {
		return broker.Deps{}, err
	}
	pools, err := c.pools()
	if err != nil {
		return broker.Deps{}, err
	}
	return broker.Deps{
		Identity: id, Roles: roles, Credentials: creds, Catalog: cat,
		Policy:  policy.New(c.Policy.Rules),
		Audit:   aud,
		Metrics: reg,
		Runner:  agent.NewRunner(c.Timeout),
		Pools:   pools, DefaultPool: c.Default,
		RateMax: c.Rate.Max, RateWindow: c.Rate.Window,
	}, nil
}

func (c *Broker) identity() (connector.Identity, error) {
	switch c.Identity.Type {
	case "dev":
		secret, err := os.ReadFile(c.Identity.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("dev identity secret: %w", err)
		}
		return dev.New([]byte(strings.TrimSpace(string(secret))), c.Identity.Issuer, c.Identity.ClientID), nil
	case "oidc":
		return oidc.New(oidc.Config{
			Issuer: c.Identity.Issuer, InternalURL: c.Identity.InternalURL, ClientID: c.Identity.ClientID,
			Audience: c.Identity.Audience, Scopes: c.Identity.Scopes,
		})
	default:
		return nil, fmt.Errorf("unknown identity type %q", c.Identity.Type)
	}
}

func (c *Broker) roles(id connector.Identity) (connector.Roles, error) {
	switch c.Roles.Type {
	case "static":
		return rolestatic.New(c.Roles.Extra), nil
	case "oidc-claims":
		return oidcclaims.New(), nil
	case "keycloak":
		ttl := c.Roles.CacheTTL
		if ttl == 0 {
			ttl = 30 * time.Second
		}
		return keycloak.New(keycloak.Config{URL: c.Roles.URL, Realm: c.Roles.Realm, CacheTTL: ttl}), nil
	default:
		return nil, fmt.Errorf("unknown roles type %q", c.Roles.Type)
	}
}

func (c *Broker) creds() (connector.Credentials, error) {
	switch c.Creds.Type {
	case "static":
		return credstatic.New(c.Creds.Items), nil
	case "bitwarden":
		return bitwarden.New(bitwarden.Config{
			ServeURL: c.Creds.ServeURL, OrgID: c.Creds.OrgID, CacheTTL: c.Creds.CacheTTL,
		}), nil
	default:
		return nil, fmt.Errorf("unknown credentials type %q", c.Creds.Type)
	}
}

func (c *Broker) catalog() (connector.Catalog, error) {
	switch c.Catalog.Type {
	case "file":
		return catalogfile.New(c.Catalog.Path), nil
	default:
		return nil, fmt.Errorf("unknown catalog type %q", c.Catalog.Type)
	}
}

func (c *Broker) pools() (map[string]broker.Pool, error) {
	out := map[string]broker.Pool{}
	for _, p := range c.Pools {
		key, err := loadEd25519Private(p.SignKeyFile)
		if err != nil {
			return nil, fmt.Errorf("pool %s: %w", p.Name, err)
		}
		ttl := p.TicketTTL
		if ttl == 0 {
			ttl = 30 * time.Second
		}
		out[p.Name] = broker.Pool{
			Name: p.Name, EgressAddr: p.EgressAddr,
			Signer: ticket.NewSigner(p.KeyID, key), TicketTTL: ttl,
		}
	}
	return out, nil
}

// Verifier builds a ticket verifier for the egress from its config.
func (e *Egress) Verifier() (*ticket.Verifier, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, k := range e.PubKeys {
		raw, err := hex.DecodeString(strings.TrimSpace(k.Hex))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("egress public key %s: invalid", k.KeyID)
		}
		keys[k.KeyID] = ed25519.PublicKey(raw)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("egress: no public keys configured")
	}
	return ticket.NewVerifier(e.Pool, keys), nil
}

// loadEd25519Private reads a 32-byte hex seed and returns the private key.
func loadEd25519Private(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("want 32-byte hex ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

var _ = audit.NewStdout // keep audit import available to callers wiring Multi sinks
