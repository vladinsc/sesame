// Package keycloak is a roles connector that looks up a user's groups live via the Keycloak admin REST API,
// with a short cache. Live lookup means removing a user from a group takes effect within CacheTTL, independent
// of their token lifetime. It authenticates with a service-account client (client_credentials).
package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Config configures the connector.
type Config struct {
	URL        string        // base Keycloak URL, e.g. http://keycloak:8080
	Realm      string        // realm name
	ClientID   string        // service-account client id
	Secret     string        // client secret (prefer SecretFile)
	SecretFile string        // path to a file with the client secret
	CacheTTL   time.Duration // how long group lookups are cached
	HTTP       *http.Client
}

// Roles implements connector.Roles against Keycloak.
type Roles struct {
	cfg    Config
	http   *http.Client
	mu     sync.Mutex
	tok    string
	tokExp time.Time
	cache  map[string]cacheEntry
}

type cacheEntry struct {
	groups []string
	exp    time.Time
}

// New returns the connector. The client secret is read from SecretFile at first use if set.
func New(cfg Config) *Roles {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	return &Roles{cfg: cfg, http: cfg.HTTP, cache: map[string]cacheEntry{}}
}

func (r *Roles) Groups(ctx context.Context, s connector.Subject) ([]string, error) {
	r.mu.Lock()
	if e, ok := r.cache[s.ID]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.groups, nil
	}
	r.mu.Unlock()

	tok, err := r.token(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := r.fetchGroups(ctx, tok, s.ID)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[s.ID] = cacheEntry{groups: groups, exp: time.Now().Add(r.cfg.CacheTTL)}
	r.mu.Unlock()
	return groups, nil
}

func (r *Roles) token(ctx context.Context) (string, error) {
	r.mu.Lock()
	if r.tok != "" && time.Now().Before(r.tokExp) {
		t := r.tok
		r.mu.Unlock()
		return t, nil
	}
	r.mu.Unlock()

	secret := r.cfg.Secret
	if secret == "" && r.cfg.SecretFile != "" {
		b, err := os.ReadFile(r.cfg.SecretFile)
		if err != nil {
			return "", fmt.Errorf("keycloak secret: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.cfg.ClientID}, "client_secret": {secret}}
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", strings.TrimRight(r.cfg.URL, "/"), r.cfg.Realm)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak token: status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	r.mu.Lock()
	r.tok = out.AccessToken
	r.tokExp = time.Now().Add(time.Duration(out.ExpiresIn-30) * time.Second)
	r.mu.Unlock()
	return out.AccessToken, nil
}

func (r *Roles) fetchGroups(ctx context.Context, tok, userID string) ([]string, error) {
	endpoint := fmt.Sprintf("%s/admin/realms/%s/users/%s/groups?briefRepresentation=true&max=500",
		strings.TrimRight(r.cfg.URL, "/"), r.cfg.Realm, url.PathEscape(userID))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak groups: status %d", resp.StatusCode)
	}
	var groups []struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.Path)
	}
	return out, nil
}
