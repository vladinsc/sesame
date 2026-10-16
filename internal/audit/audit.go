// Package audit provides audit sinks. The default writes one JSON object per line to stdout, which container log
// pipelines (Loki, Elasticsearch) pick up. Events never contain credentials or cookie values; that invariant is
// the caller's, but Scrub() is a defence in depth for the free-text Reason field.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"github.com/vladinsc/sesame/pkg/connector"
)

// Stdout writes newline-delimited JSON. Safe for concurrent use.
type Stdout struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewStdout writes to w (typically os.Stdout).
func NewStdout(w io.Writer) *Stdout {
	return &Stdout{enc: json.NewEncoder(w)}
}

// Write emits one event.
func (s *Stdout) Write(_ context.Context, e connector.Event) error {
	e.Reason = Scrub(e.Reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(e)
}

// Scrub trims the reason and caps its length, so an upstream error body can't smuggle a secret into the log.
func Scrub(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Multi fans out to several sinks; the first error is returned but all are attempted.
type Multi []connector.Audit

func (m Multi) Write(ctx context.Context, e connector.Event) error {
	var first error
	for _, a := range m {
		if err := a.Write(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}
