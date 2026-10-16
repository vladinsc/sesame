// Package bitwarden is a credentials connector for Bitwarden / Vaultwarden. It reads items through a local
// `bw serve` instance (the Bitwarden CLI running unlocked as a read-only bot), so the broker never handles the
// master password and item contents stay in memory. Refs are "bitwarden://<item-id>". An item's scopes are the
// names of the collections it belongs to, so the same policy (groups -> scopes) governs the wiki and the Vault.
package bitwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Config configures the connector.
type Config struct {
	ServeURL string        // base URL of `bw serve`, e.g. http://127.0.0.1:8087
	OrgID    string        // organisation whose collections define scopes
	CacheTTL time.Duration // how long to cache the collection id->name map
	HTTP     *http.Client
}

// Store implements connector.Credentials over `bw serve`.
type Store struct {
	cfg  Config
	http *http.Client

	mu          sync.Mutex
	collections map[string]string // id -> name
	collExp     time.Time
}

// New returns the connector.
func New(cfg Config) *Store {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Minute
	}
	return &Store{cfg: cfg, http: cfg.HTTP}
}

type bwItem struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	CollectionIDs []string `json:"collectionIds"`
	Login         struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	} `json:"login"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields"`
}

func itemID(ref connector.Ref) string {
	return strings.TrimPrefix(string(ref), "bitwarden://")
}

func (s *Store) item(ctx context.Context, ref connector.Ref) (*bwItem, error) {
	id := itemID(ref)
	if id == "" {
		return nil, connector.ErrNotFound
	}
	var out struct {
		Success bool   `json:"success"`
		Data    bwItem `json:"data"`
	}
	if err := s.get(ctx, "/object/item/"+url.PathEscape(id), &out); err != nil {
		return nil, err
	}
	if !out.Success {
		return nil, connector.ErrNotFound
	}
	return &out.Data, nil
}

func (s *Store) Get(ctx context.Context, ref connector.Ref) (connector.Credential, error) {
	it, err := s.item(ctx, ref)
	if err != nil {
		return connector.Credential{}, err
	}
	cred := connector.Credential{Username: it.Login.Username, Password: it.Login.Password, TOTPSeed: it.Login.TOTP}
	if len(it.Fields) > 0 {
		cred.Extra = make(map[string]string, len(it.Fields))
		for _, f := range it.Fields {
			cred.Extra[f.Name] = f.Value
		}
	}
	return cred, nil
}

// ScopeField, when present on an item as a custom field, overrides collection-derived scopes. This lets items in
// a personal vault carry a scope (handy for demos); in an org, scopes come from the item's collection names.
const ScopeField = "sesame-scope"

func (s *Store) Scopes(ctx context.Context, ref connector.Ref) ([]string, error) {
	it, err := s.item(ctx, ref)
	if err != nil {
		return nil, err
	}
	for _, f := range it.Fields {
		if f.Name == ScopeField && strings.TrimSpace(f.Value) != "" {
			return splitScopes(f.Value), nil
		}
	}
	if s.cfg.OrgID == "" {
		return nil, nil // personal vault, no scope field: grants nothing
	}
	names, err := s.collectionNames(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(it.CollectionIDs))
	for _, id := range it.CollectionIDs {
		if n, ok := names[id]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func splitScopes(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// collectionNames returns the org's collection id->name map, cached.
func (s *Store) collectionNames(ctx context.Context) (map[string]string, error) {
	s.mu.Lock()
	if s.collections != nil && time.Now().Before(s.collExp) {
		m := s.collections
		s.mu.Unlock()
		return m, nil
	}
	s.mu.Unlock()

	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		} `json:"data"`
	}
	path := "/list/object/org-collections?organizationId=" + url.QueryEscape(s.cfg.OrgID)
	if err := s.get(ctx, path, &out); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(out.Data.Data))
	for _, c := range out.Data.Data {
		m[c.ID] = c.Name
	}
	s.mu.Lock()
	s.collections, s.collExp = m, time.Now().Add(s.cfg.CacheTTL)
	s.mu.Unlock()
	return m, nil
}

func (s *Store) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.ServeURL, "/")+path, nil)
	if err != nil {
		return err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("bw serve: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return connector.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bw serve: status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
