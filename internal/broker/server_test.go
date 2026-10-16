package broker_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/vladinsc/sesame/connectors/login"

	credstatic "github.com/vladinsc/sesame/connectors/credentials/static"
	"github.com/vladinsc/sesame/connectors/identity/dev"
	rolestatic "github.com/vladinsc/sesame/connectors/roles/static"
	"github.com/vladinsc/sesame/internal/agent"
	"github.com/vladinsc/sesame/internal/audit"
	"github.com/vladinsc/sesame/internal/broker"
	"github.com/vladinsc/sesame/internal/egress"
	"github.com/vladinsc/sesame/internal/metrics"
	"github.com/vladinsc/sesame/internal/policy"
	"github.com/vladinsc/sesame/internal/ticket"
	"github.com/vladinsc/sesame/pkg/connector"
)

// fakeCatalog serves one Grafana tool with one account.
type fakeCatalog struct{ tools []connector.Tool }

func (f fakeCatalog) Tools(context.Context) ([]connector.Tool, error) { return f.tools, nil }

func TestBrokerLoginFlow(t *testing.T) {
	// Fake HTTP (not TLS) Grafana for simplicity; egress tunnels plain HTTP.
	tool := fakeGrafana(t, "admin", "s3cret")
	defer tool.Close()
	toolAddr := tool.Listener.Addr().String()

	// egress
	pub, priv, _ := ed25519.GenerateKey(nil)
	verifier := ticket.NewVerifier("local", map[string]ed25519.PublicKey{"k1": pub})
	egSrv := httptest.NewServer(egress.New(verifier, &net.Dialer{}, nil))
	defer egSrv.Close()

	idp := dev.New([]byte("test-secret"), "https://idp.example", "sesame")
	deps := broker.Deps{
		Identity: idp,
		Roles:    rolestatic.New(nil),
		Credentials: credstatic.New([]credstatic.Item{
			{ID: "grafana-admin", Username: "admin", Password: "s3cret", Scopes: []string{"projects/demo/dev"}},
		}),
		Catalog: fakeCatalog{tools: []connector.Tool{{
			ID: "grafana", Name: "Grafana", URL: "http://" + toolAddr, Login: "grafana",
			Accounts: []connector.Account{{Label: "admin", Ref: "static://grafana-admin"}},
		}}},
		Policy:  policy.New([]policy.Rule{{GroupPattern: "/projects/{p}/{env}", Scopes: []string{"projects/{p}/{env}"}}}),
		Audit:   audit.NewStdout(discard{}),
		Metrics: metrics.New(),
		Runner:  agent.NewRunner(5 * time.Second),
		Pools: map[string]broker.Pool{"local": {
			Name: "local", EgressAddr: egSrv.Listener.Addr().String(),
			Signer: ticket.NewSigner("k1", priv), TicketTTL: 30 * time.Second,
		}},
		DefaultPool: "local",
	}
	srv := httptest.NewServer(broker.New(deps).Handler())
	defer srv.Close()

	token := idp.Mint(dev.Token{Sub: "u1", Email: "u1@example", Groups: []string{"/projects/demo/dev"}, Exp: time.Now().Add(time.Hour).Unix()})

	// catalog shows the tool
	var cat struct {
		Tools []struct {
			ID       string `json:"id"`
			Accounts []struct {
				Label string `json:"label"`
			} `json:"accounts"`
		} `json:"tools"`
	}
	do(t, srv.URL+"/v1/catalog", token, nil, &cat)
	if len(cat.Tools) != 1 || cat.Tools[0].ID != "grafana" || len(cat.Tools[0].Accounts) != 1 {
		t.Fatalf("catalog: %+v", cat)
	}

	// login returns artifacts, never a password
	body, _ := json.Marshal(map[string]string{"tool": "grafana", "account": "admin"})
	var out struct {
		Artifacts []connector.Artifact `json:"artifacts"`
		Landing   string               `json:"landing"`
	}
	code := do(t, srv.URL+"/v1/login", token, body, &out)
	if code != 200 {
		t.Fatalf("login status %d", code)
	}
	if len(out.Artifacts) != 1 || out.Artifacts[0].Name != "grafana_session" {
		t.Fatalf("artifacts: %+v", out.Artifacts)
	}
}

func TestBrokerDeniesWrongGroup(t *testing.T) {
	idp := dev.New([]byte("s"), "", "")
	deps := minimalDeps(idp)
	srv := httptest.NewServer(broker.New(deps).Handler())
	defer srv.Close()
	token := idp.Mint(dev.Token{Sub: "u2", Groups: []string{"/projects/other/dev"}, Exp: time.Now().Add(time.Hour).Unix()})
	body, _ := json.Marshal(map[string]string{"tool": "grafana", "account": "admin"})
	if code := do(t, srv.URL+"/v1/login", token, body, &struct{}{}); code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

func TestBrokerRejectsNoToken(t *testing.T) {
	idp := dev.New([]byte("s"), "", "")
	srv := httptest.NewServer(broker.New(minimalDeps(idp)).Handler())
	defer srv.Close()
	if code := do(t, srv.URL+"/v1/catalog", "", nil, &struct{}{}); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

func minimalDeps(idp *dev.Identity) broker.Deps {
	return broker.Deps{
		Identity:    idp,
		Roles:       rolestatic.New(nil),
		Credentials: credstatic.New([]credstatic.Item{{ID: "a", Scopes: []string{"projects/demo/dev"}}}),
		Catalog: fakeCatalog{tools: []connector.Tool{{
			ID: "grafana", URL: "http://127.0.0.1:1", Login: "grafana",
			Accounts: []connector.Account{{Label: "admin", Ref: "static://a"}},
		}}},
		Policy:      policy.New([]policy.Rule{{GroupPattern: "/projects/{p}/{env}", Scopes: []string{"projects/{p}/{env}"}}}),
		Audit:       audit.NewStdout(discard{}),
		Metrics:     metrics.New(),
		Runner:      agent.NewRunner(time.Second),
		Pools:       map[string]broker.Pool{},
		DefaultPool: "local",
	}
}

func do(t *testing.T, url, token string, body []byte, out any) int {
	t.Helper()
	var r *http.Request
	if body != nil {
		r, _ = http.NewRequest("POST", url, bytes.NewReader(body))
	} else {
		r, _ = http.NewRequest("GET", url, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(out)
	return resp.StatusCode
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func fakeGrafana(t *testing.T, user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ User, Password string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.User != user || b.Password != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "grafana_session", Value: "ok", Path: "/", HttpOnly: true})
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("grafana_session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	return httptest.NewServer(mux)
}
