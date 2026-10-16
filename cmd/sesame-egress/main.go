// Command sesame-egress runs the ticket-gated CONNECT proxy. It is the only component with network access to the
// tools. It forwards a TCP stream only when given a valid, unexpired, audience-matching ticket whose target
// equals the requested host:port, and never terminates TLS. See docs/ARCHITECTURE.md §6.000.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vladinsc/sesame/internal/audit"
	"github.com/vladinsc/sesame/internal/config"
	"github.com/vladinsc/sesame/internal/egress"
)

func main() {
	cfgPath := flag.String("config", "sesame-egress.yaml", "path to egress config")
	flag.Parse()

	cfg, err := config.LoadEgress(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	verifier, err := cfg.Verifier()
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}
	proxy := egress.New(verifier, nil, audit.NewStdout(os.Stdout))

	srv := &http.Server{Addr: cfg.Listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("sesame-egress (pool %q) listening on %s", cfg.Pool, cfg.Listen)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Print("sesame-egress stopped")
}
