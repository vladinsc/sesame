// Package policy decides whether a user's groups grant a credential's scopes. Rules are plain configuration:
// an exact group, or a pattern with {placeholders} shared between the group path and the scope. This keeps the
// access model out of code and identical for every connector.
package policy

import (
	"regexp"
	"strings"
)

// Rule maps groups to scopes. Exactly one of Groups or GroupPattern is set.
type Rule struct {
	Groups       []string `yaml:"groups"`
	GroupPattern string   `yaml:"group_pattern"`
	Scopes       []string `yaml:"scopes"`
}

// Engine evaluates rules.
type Engine struct {
	rules    []Rule
	compiled []*regexp.Regexp // for pattern rules, nil for exact rules
	vars     [][]string       // placeholder names per pattern rule
}

var placeholder = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// New compiles the rules.
func New(rules []Rule) *Engine {
	e := &Engine{rules: rules, compiled: make([]*regexp.Regexp, len(rules)), vars: make([][]string, len(rules))}
	for i, r := range rules {
		if r.GroupPattern == "" {
			continue
		}
		var names []string
		expr := placeholder.ReplaceAllStringFunc(regexpEscapeKeepingBraces(r.GroupPattern), func(m string) string {
			names = append(names, m[1:len(m)-1])
			return `([^/]+)`
		})
		e.compiled[i] = regexp.MustCompile("^" + expr + "$")
		e.vars[i] = names
	}
	return e
}

// regexpEscapeKeepingBraces escapes regex metacharacters but leaves {name} placeholders intact.
func regexpEscapeKeepingBraces(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '{', '}':
			b.WriteRune(r)
		case '.', '+', '*', '?', '(', ')', '|', '[', ']', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Allows reports whether any of the user's groups grants any of the wanted scopes.
func (e *Engine) Allows(groups, scopes []string) bool {
	for _, g := range groups {
		for i, r := range e.rules {
			granted, ok := e.scopesFor(i, r, g)
			if !ok {
				continue
			}
			for _, want := range scopes {
				for _, have := range granted {
					if scopeMatch(have, want) {
						return true
					}
				}
			}
		}
	}
	return false
}

// scopesFor returns the scopes a single group grants under rule i, and whether the rule matched the group.
func (e *Engine) scopesFor(i int, r Rule, group string) ([]string, bool) {
	if e.compiled[i] == nil { // exact rule
		for _, rg := range r.Groups {
			if rg == group {
				return r.Scopes, true
			}
		}
		return nil, false
	}
	m := e.compiled[i].FindStringSubmatch(group)
	if m == nil {
		return nil, false
	}
	repl := make([]string, 0, len(e.vars[i])*2)
	for j, name := range e.vars[i] {
		repl = append(repl, "{"+name+"}", m[j+1])
	}
	rep := strings.NewReplacer(repl...)
	out := make([]string, len(r.Scopes))
	for k, s := range r.Scopes {
		out[k] = rep.Replace(s)
	}
	return out, true
}

// scopeMatch supports a trailing "/*" wildcard and a bare "*" meaning all scopes.
func scopeMatch(have, want string) bool {
	if have == "*" || have == want {
		return true
	}
	if strings.HasSuffix(have, "/*") {
		prefix := strings.TrimSuffix(have, "*") // keep the slash
		return strings.HasPrefix(want, prefix)
	}
	return false
}
