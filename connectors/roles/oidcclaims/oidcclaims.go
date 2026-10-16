// Package oidcclaims is a roles connector that returns the groups carried in the user's own token claims.
// Simplest to operate, but revocation only takes effect when the access token is refreshed; use the keycloak
// connector (live lookup) where faster revocation matters.
package oidcclaims

import (
	"context"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Roles returns the subject's claim groups.
type Roles struct{}

// New returns the connector.
func New() *Roles { return &Roles{} }

func (Roles) Groups(_ context.Context, s connector.Subject) ([]string, error) {
	return s.Claims, nil
}
