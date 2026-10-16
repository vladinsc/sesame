// Package connector defines the pluggable interfaces of sesame. Everything that talks to a specific product
// (identity provider, role source, credential store, catalog, login form of a tool, audit sink) is a connector.
//
// The core (broker, agent, egress) only depends on these interfaces. This package is the project's public API;
// breaking changes require a major version bump.
package connector

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrNotFound is returned by connectors when the requested object does not exist.
var ErrNotFound = errors.New("not found")

// Subject is a verified user.
type Subject struct {
	ID     string   `json:"id"`
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Claims []string `json:"-"` // raw group claims, used by claim-based role connectors
}

// OIDCClientConfig is what the browser extension needs to sign a user in.
type OIDCClientConfig struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// Identity verifies bearer tokens.
type Identity interface {
	Verify(ctx context.Context, bearer string) (Subject, error)
	ClientConfig() OIDCClientConfig
}

// Roles returns the current groups/roles of a subject. Implementations must reflect removals quickly
// (live lookup or a short cache), because revocation speed depends on it.
type Roles interface {
	Groups(ctx context.Context, s Subject) ([]string, error)
}

// Ref points at a credential inside a credential store, e.g. "bitwarden://<item-id>".
type Ref string

// Credential is a decrypted secret. It must only live in memory and never be logged.
type Credential struct {
	Username string
	Password string
	TOTPSeed string
	Extra    map[string]string
}

// Credentials reads credentials and the access scopes they belong to.
type Credentials interface {
	Get(ctx context.Context, ref Ref) (Credential, error)
	Scopes(ctx context.Context, ref Ref) ([]string, error)
}

// Account is one credential usable for a tool.
type Account struct {
	Label string `json:"label" yaml:"label"`
	Ref   Ref    `json:"-" yaml:"ref"`
}

// Tool is one tool instance users open in their browser.
type Tool struct {
	ID        string    `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
	URL       string    `json:"url" yaml:"url"`      // as users open it; cookies are set for this origin
	Login     string    `json:"login" yaml:"login"`  // login connector type, e.g. "grafana"
	Pool      string    `json:"-" yaml:"pool"`       // which agent pool / egress can reach it
	ConnectTo string    `json:"-" yaml:"connect_to"` // optional host:port the egress dials instead
	PinSHA256 string    `json:"-" yaml:"pin_sha256"` // optional SPKI pin (base64) for TLS tools
	Accounts  []Account `json:"accounts" yaml:"accounts"`
}

// Catalog lists the tools sesame can log users in to.
type Catalog interface {
	Tools(ctx context.Context) ([]Tool, error)
}

// Artifact is one piece of session state handed to the browser.
type Artifact struct {
	Origin   string `json:"origin"`
	Type     string `json:"type"` // "cookie" | "localStorage" | "sessionStorage"
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	SameSite string `json:"sameSite,omitempty"`
	MaxAge   int    `json:"maxAge,omitempty"` // seconds; relative so clock skew doesn't matter
}

// LoginMeta describes a login connector to the extension and the agent.
type LoginMeta struct {
	Type      string   `json:"type"`
	LoggedOut []string `json:"logged_out"` // URL paths that mean "not logged in"
	Check     string   `json:"check"`      // path of an authenticated "who am I" request
	Cookies   []string `json:"cookies"`    // cookie names that make up the session (prefix match with '*')
}

// LoginJob is the input of a login connector.
type LoginJob struct {
	UserURL        string
	Credential     Credential
	UserAgent      string
	AcceptLanguage string
}

// LoginResult is what a login connector returns.
type LoginResult struct {
	Artifacts []Artifact
	Landing   string
}

// Login logs in to one tool type. The HTTP client is prepared by the agent: it routes through the egress,
// enforces TLS verification and records Set-Cookie headers.
type Login interface {
	Meta() LoginMeta
	Login(ctx context.Context, c *http.Client, job LoginJob) (LoginResult, error)
	Check(ctx context.Context, c *http.Client, job LoginJob) error
}

// Event is one audit record. It must never contain credentials or cookie values.
type Event struct {
	Time     time.Time `json:"ts"`
	Action   string    `json:"action"`
	Decision string    `json:"decision"` // allow | deny | error
	Reason   string    `json:"reason,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	Account  string    `json:"account,omitempty"`
	Pool     string    `json:"pool,omitempty"`
	Duration int64     `json:"duration_ms,omitempty"`
	RemoteIP string    `json:"remote_ip,omitempty"`
	Request  string    `json:"request_id,omitempty"`
}

// Audit records decisions.
type Audit interface {
	Write(ctx context.Context, e Event) error
}

// Login errors with a meaning for the user.
var (
	ErrBadCredentials     = errors.New("bad_credentials")
	ErrUnexpectedResponse = errors.New("unexpected_response")
	ErrNeedsInteraction   = errors.New("needs_interaction")
)
