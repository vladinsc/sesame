package login

import (
	"net/http"
	"strings"

	"github.com/vladinsc/sesame/pkg/connector"
)

// collectCookies turns the cookies the HTTP client recorded for the tool's origin into artifacts the browser
// can replay. Only cookies whose name matches one of want (exact, or "prefix*") are kept.
func collectCookies(origin string, jarCookies []*http.Cookie, want []string) []connector.Artifact {
	var out []connector.Artifact
	for _, c := range jarCookies {
		if !nameWanted(c.Name, want) {
			continue
		}
		out = append(out, connector.Artifact{
			Origin: origin, Type: "cookie", Name: c.Name, Value: c.Value,
			Path: orDefault(c.Path, "/"), HTTPOnly: c.HttpOnly, Secure: c.Secure,
			SameSite: sameSite(c.SameSite), MaxAge: maxAge(c),
		})
	}
	return out
}

func nameWanted(name string, want []string) bool {
	for _, w := range want {
		if w == name || (strings.HasSuffix(w, "*") && strings.HasPrefix(name, strings.TrimSuffix(w, "*"))) {
			return true
		}
	}
	return false
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return ""
	}
}

// maxAge prefers an explicit Max-Age, else derives seconds-from-now from Expires, else 0 (session cookie).
func maxAge(c *http.Cookie) int {
	if c.MaxAge > 0 {
		return c.MaxAge
	}
	return 0
}
