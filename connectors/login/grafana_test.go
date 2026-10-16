package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/vladinsc/sesame/pkg/connector"
)

// fakeGrafana serves /login (sets grafana_session on correct creds) and /api/user (200 if the cookie is present).
func fakeGrafana(user, pass string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ User, Password string }
		_ = jsonDecode(r, &body)
		if body.User != user || body.Password != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "grafana_session", Value: "sess-123", Path: "/", HttpOnly: true})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("grafana_session"); err != nil || c.Value != "sess-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func TestGrafanaLogin(t *testing.T) {
	srv := fakeGrafana("admin", "s3cret")
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	job := connector.LoginJob{UserURL: srv.URL, Credential: connector.Credential{Username: "admin", Password: "s3cret"}}

	g := grafana{}
	res, err := g.Login(context.Background(), client, job)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Name != "grafana_session" || res.Artifacts[0].Value != "sess-123" {
		t.Fatalf("artifacts: %+v", res.Artifacts)
	}
	if !res.Artifacts[0].HTTPOnly {
		t.Error("httpOnly should be carried over")
	}
	if err := g.Check(context.Background(), client, job); err != nil {
		t.Fatalf("check: %v", err)
	}
}

func TestGrafanaBadPassword(t *testing.T) {
	srv := fakeGrafana("admin", "s3cret")
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	job := connector.LoginJob{UserURL: srv.URL, Credential: connector.Credential{Username: "admin", Password: "wrong"}}
	g := grafana{}
	_, err := g.Login(context.Background(), &http.Client{Jar: jar}, job)
	if !errors.Is(err, connector.ErrBadCredentials) {
		t.Fatalf("got %v, want ErrBadCredentials", err)
	}
}
