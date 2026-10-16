package bitwarden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vladinsc/sesame/pkg/connector"
)

// fakeServe mimics the two `bw serve` endpoints the connector uses.
func fakeServe() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/object/item/item-1", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"success":true,"data":{"id":"item-1","name":"Grafana",
			"collectionIds":["col-dev"],"login":{"username":"admin","password":"s3cret"}}}`))
	})
	mux.HandleFunc("/list/object/org-collections", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"success":true,"data":{"data":[
			{"id":"col-dev","name":"projects/demo/dev"},
			{"id":"col-prod","name":"projects/demo/prod"}]}}`))
	})
	return httptest.NewServer(mux)
}

func TestGetAndScopes(t *testing.T) {
	srv := fakeServe()
	defer srv.Close()
	s := New(Config{ServeURL: srv.URL, OrgID: "org-1"})

	cred, err := s.Get(context.Background(), "bitwarden://item-1")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "admin" || cred.Password != "s3cret" {
		t.Fatalf("cred: %+v", cred)
	}
	scopes, err := s.Scopes(context.Background(), "bitwarden://item-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 || scopes[0] != "projects/demo/dev" {
		t.Fatalf("scopes: %v", scopes)
	}
}

func TestMissingItem(t *testing.T) {
	srv := fakeServe()
	defer srv.Close()
	s := New(Config{ServeURL: srv.URL, OrgID: "org-1"})
	if _, err := s.Get(context.Background(), "bitwarden://nope"); err != connector.ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
