// Package static is a roles connector that returns groups from the subject's own token claims, optionally
// extended by a per-subject map from config. Used for local development with the dev identity connector.
package static

import (
	"context"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Roles returns the subject's claim groups plus any extra groups configured for its id.
type Roles struct{ extra map[string][]string }

// New builds a roles connector. extra maps subject id -> additional groups.
func New(extra map[string][]string) *Roles { return &Roles{extra: extra} }

func (r *Roles) Groups(_ context.Context, s connector.Subject) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(g string) {
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, g := range s.Claims {
		add(g)
	}
	for _, g := range r.extra[s.ID] {
		add(g)
	}
	return out, nil
}
