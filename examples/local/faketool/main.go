// Command faketool is a tiny stand-in tool for the local demo. It mimics a Grafana-style login: POST /login with
// {user,password} sets a session cookie; GET /api/user returns 200 only with that cookie. Not part of sesame.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	user := flag.String("user", "admin", "accepted username")
	pass := flag.String("pass", "s3cret", "accepted password")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ User, Password string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.User != *user || b.Password != *pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "grafana_session", Value: "demo-session", Path: "/", HttpOnly: true})
		log.Printf("login ok for %s", b.User)
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("grafana_session"); err != nil || c.Value != "demo-session" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"login": *user})
	})
	log.Printf("faketool (grafana-like) on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
