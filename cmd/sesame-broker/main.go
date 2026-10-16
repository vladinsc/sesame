// Command sesame-broker runs the sesame broker: the public API that authenticates users, authorises logins and
// returns session artifacts (never credentials). See docs/ARCHITECTURE.md.
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
	"github.com/vladinsc/sesame/internal/broker"
	"github.com/vladinsc/sesame/internal/config"
	"github.com/vladinsc/sesame/internal/metrics"

	_ "github.com/vladinsc/sesame/connectors/login" // register built-in login connectors
)

func main() {
	cfgPath := flag.String("config", "sesame-broker.yaml", "path to broker config")
	flag.Parse()

	cfg, err := config.LoadBroker(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	reg := metrics.New()
	aud := audit.NewStdout(os.Stdout)
	deps, err := cfg.BuildBroker(reg, aud)
	if err != nil {
		log.Fatalf("wire: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           broker.New(deps).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("sesame-broker listening on %s", cfg.Listen)
	run(srv)
}

func run(srv *http.Server) {
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
	log.Print("sesame-broker stopped")
}
