// Package config loads broker, agent and egress configuration from YAML. Secrets (signing keys, client secrets)
// are referenced by file path, never inlined, so they can come from Kubernetes secrets mounted into the pod.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	credstatic "github.com/vladinsc/sesame/connectors/credentials/static"
	"github.com/vladinsc/sesame/internal/policy"
)

// Broker is the broker's configuration.
type Broker struct {
	Listen   string        `yaml:"listen"`
	Identity Identity      `yaml:"identity"`
	Roles    Roles         `yaml:"roles"`
	Creds    Credentials   `yaml:"credentials"`
	Catalog  Catalog       `yaml:"catalog"`
	Policy   PolicyConfig  `yaml:"policy"`
	Pools    []PoolConfig  `yaml:"pools"`
	Default  string        `yaml:"default_pool"`
	Rate     RateConfig    `yaml:"rate_limit"`
	Timeout  time.Duration `yaml:"login_timeout"`
}

// Identity selects and configures an identity connector.
type Identity struct {
	Type        string   `yaml:"type"` // "dev" | "oidc"
	Issuer      string   `yaml:"issuer"`
	InternalURL string   `yaml:"internal_url"` // oidc: broker-side provider URL if different from issuer
	ClientID    string   `yaml:"client_id"`
	Audience    string   `yaml:"audience"`
	SecretFile  string   `yaml:"secret_file"` // dev only (HMAC secret)
	Scopes      []string `yaml:"scopes"`
}

// Roles selects a roles connector.
type Roles struct {
	Type     string              `yaml:"type"` // "static" | "oidc-claims" | "keycloak"
	Extra    map[string][]string `yaml:"extra"`
	URL      string              `yaml:"url"`
	Realm    string              `yaml:"realm"`
	CacheTTL time.Duration       `yaml:"cache_ttl"`
}

// Credentials selects a credentials connector.
type Credentials struct {
	Type     string            `yaml:"type"` // "static" | "bitwarden"
	Items    []credstatic.Item `yaml:"items"`
	ServeURL string            `yaml:"serve_url"`       // bitwarden: base URL of `bw serve`
	OrgID    string            `yaml:"organization_id"` // bitwarden: org whose collections are scopes
	CacheTTL time.Duration     `yaml:"cache_ttl"`       // bitwarden
}

// Catalog selects a catalog connector.
type Catalog struct {
	Type string `yaml:"type"` // "file"
	Path string `yaml:"path"`
}

// PolicyConfig holds the access rules.
type PolicyConfig struct {
	Rules []policy.Rule `yaml:"rules"`
}

// PoolConfig configures one egress pool.
type PoolConfig struct {
	Name        string        `yaml:"name"`
	EgressAddr  string        `yaml:"egress_addr"`
	SignKeyFile string        `yaml:"sign_key_file"` // ed25519 private key seed (hex), 32 bytes
	KeyID       string        `yaml:"key_id"`
	TicketTTL   time.Duration `yaml:"ticket_ttl"`
}

// RateConfig limits logins per subject.
type RateConfig struct {
	Max    int           `yaml:"max"`
	Window time.Duration `yaml:"window"`
}

// Egress is the egress proxy's configuration.
type Egress struct {
	Listen  string   `yaml:"listen"`
	Pool    string   `yaml:"pool"`        // audience this egress serves
	PubKeys []PubKey `yaml:"public_keys"` // broker signing public keys (hex)
}

// PubKey is a broker signing public key.
type PubKey struct {
	KeyID string `yaml:"key_id"`
	Hex   string `yaml:"hex"`
}

// LoadBroker reads and validates a broker config file.
func LoadBroker(path string) (*Broker, error) {
	var c Broker
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	return &c, nil
}

// LoadEgress reads an egress config file.
func LoadEgress(path string) (*Egress, error) {
	var c Egress
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8081"
	}
	return &c, nil
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}
