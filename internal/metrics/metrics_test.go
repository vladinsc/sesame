package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExport(t *testing.T) {
	r := New()
	r.Describe("sesame_logins_total", "logins")
	r.Inc("sesame_logins_total", "tool", "grafana", "decision", "allow")
	r.Inc("sesame_logins_total", "tool", "grafana", "decision", "allow")
	r.ObserveDuration("sesame_login", 250*time.Millisecond, "tool", "grafana")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	body := w.Body.String()

	for _, want := range []string{
		`# HELP sesame_logins_total logins`,
		`sesame_logins_total{tool="grafana",decision="allow"} 2`,
		`sesame_login_seconds_count{tool="grafana"} 1`,
		`sesame_login_seconds_sum{tool="grafana"} 0.25`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestLabelEscaping(t *testing.T) {
	r := New()
	r.Inc("x", "reason", `a"b\c`)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), `reason="a\"b\\c"`) {
		t.Errorf("bad escaping:\n%s", w.Body.String())
	}
}
