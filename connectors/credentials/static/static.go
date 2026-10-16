// Package static is a credentials connector backed by a config map. It exists for local development and tests;
// production uses the bitwarden connector. Refs look like "static://<id>".
package static

import (
	"context"
	"strings"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Item is one stored credential.
type Item struct {
	ID       string   `yaml:"id"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	TOTPSeed string   `yaml:"totp_seed"`
	Scopes   []string `yaml:"scopes"`
}

// Store implements connector.Credentials over a fixed set of items.
type Store struct{ items map[string]Item }

// New indexes items by id.
func New(items []Item) *Store {
	m := make(map[string]Item, len(items))
	for _, it := range items {
		m[it.ID] = it
	}
	return &Store{items: m}
}

func (s *Store) lookup(ref connector.Ref) (Item, bool) {
	id := strings.TrimPrefix(string(ref), "static://")
	it, ok := s.items[id]
	return it, ok
}

func (s *Store) Get(_ context.Context, ref connector.Ref) (connector.Credential, error) {
	it, ok := s.lookup(ref)
	if !ok {
		return connector.Credential{}, connector.ErrNotFound
	}
	return connector.Credential{Username: it.Username, Password: it.Password, TOTPSeed: it.TOTPSeed}, nil
}

func (s *Store) Scopes(_ context.Context, ref connector.Ref) ([]string, error) {
	it, ok := s.lookup(ref)
	if !ok {
		return nil, connector.ErrNotFound
	}
	return it.Scopes, nil
}
