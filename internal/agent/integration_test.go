package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vladinsc/sesame/internal/agent"
	"github.com/vladinsc/sesame/internal/egress"
	"github.com/vladinsc/sesame/internal/ticket"
	"github.com/vladinsc/sesame/pkg/connector"

	_ "github.com/vladinsc/sesame/connectors/login" // register grafana, argocd, ...
)

// End to end: agent -> egress (ticket-gated) -> TLS tool. Proves the tunnel, TLS verification against the tool's
// cert, the login connector, the session check, and that a wrong/forged ticket is refused.
func TestLoginThroughEgress(t *testing.T) {
	tool := fakeGrafanaTLS(t, "admin", "s3cret")
	defer tool.Close()
	toolHostPort := tool.Listener.Addr().String()

	// Trust the httptest server's self-signed cert via a CA bundle.
	pool := x509.NewCertPool()
	pool.AddCert(tool.Certificate())

	// Egress proxy with a verifier for pool "test".
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := ticket.NewSigner("k1", priv)
	verifier := ticket.NewVerifier("test", map[string]ed25519.PublicKey{"k1": pub})
	proxy := egress.New(verifier, &net.Dialer{Timeout: 5 * time.Second}, nil)
	egSrv := httptest.NewServer(proxy)
	defer egSrv.Close()
	egAddr := egSrv.Listener.Addr().String()

	runner := agent.NewRunner(10 * time.Second)
	toolCfg := connector.Tool{ID: "g", Name: "Grafana", URL: "https://" + toolHostPort, Login: "grafana"}

	tkt, err := signer.Issue(ticket.Claims{Audience: "test", Target: toolHostPort, Subject: "u1", Tool: "g"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	job := agent.Job{
		Tool:       toolCfg,
		Credential: connector.Credential{Username: "admin", Password: "s3cret"},
		Ticket:     tkt,
		EgressAddr: egAddr,
		CABundle:   pool,
	}
	res, err := runner.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Name != "grafana_session" {
		t.Fatalf("artifacts: %+v", res.Artifacts)
	}

	// A ticket for a different target must not let the agent reach this tool.
	badTkt, _ := signer.Issue(ticket.Claims{Audience: "test", Target: "other.host:443"}, time.Minute)
	job.Ticket = badTkt
	if _, err := runner.Run(context.Background(), job); err == nil {
		t.Fatal("expected refusal with a ticket for a different target")
	}
}

func fakeGrafanaTLS(t *testing.T, user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ User, Password string }
		_ = decodeJSON(r, &b)
		if b.User != user || b.Password != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "grafana_session", Value: "sess-xyz", Path: "/", HttpOnly: true, Secure: true})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("grafana_session"); err != nil || c.Value != "sess-xyz" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	return srv
}
