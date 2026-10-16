// Package login holds the built-in login connectors and a registry. A login connector knows one tool type's
// login: where credentials are posted, which cookies form the session, how to tell logged-out from logged-in,
// and a cheap authenticated "check" request. Connectors are stateless and must never log credentials.
package login

import (
	"fmt"
	"sort"

	"github.com/vladinsc/sesame/pkg/connector"
)

var registry = map[string]connector.Login{}

// Register adds a login connector under its Meta().Type. Called from each connector's init.
func Register(l connector.Login) {
	registry[l.Meta().Type] = l
}

// Get returns the connector for a tool type.
func Get(typ string) (connector.Login, error) {
	l, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("login connector %q not registered", typ)
	}
	return l, nil
}

// Types lists the registered connector names, sorted.
func Types() []string {
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
