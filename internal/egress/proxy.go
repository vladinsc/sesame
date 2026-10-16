// Package egress implements the ticket-gated CONNECT proxy. It is the only component with network access to the
// tools. It forwards a TCP stream to a destination only when presented a valid, unexpired, audience-matching
// ticket whose target equals the requested host:port. It never terminates TLS, so credentials and sessions stay
// end-to-end encrypted between the agent and the tool. Stateless: tickets are verified offline with the broker's
// public key, so many egress replicas can run behind one service.
package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/vladinsc/sesame/internal/ticket"
	"github.com/vladinsc/sesame/pkg/connector"
)

// TicketHeader carries the egress ticket on CONNECT requests.
const TicketHeader = "X-Sesame-Ticket"

// Dialer opens a raw connection to an upstream address. The default dials directly; a network connector (e.g. a
// VPN sidecar) can supply a different one.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Proxy is the CONNECT proxy.
type Proxy struct {
	verifier *ticket.Verifier
	dialer   Dialer
	audit    connector.Audit
	dialTO   time.Duration
}

// New returns a proxy. If dialer is nil, a direct dialer with a 10s timeout is used.
func New(v *ticket.Verifier, dialer Dialer, aud connector.Audit) *Proxy {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	return &Proxy{verifier: v, dialer: dialer, audit: aud, dialTO: 10 * time.Second}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	target := r.Host // authority form host:port for CONNECT
	tok := r.Header.Get(TicketHeader)
	claims, err := p.verifier.Verify(tok, target)
	if err != nil {
		p.log("deny", "", target, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	dialTarget := target
	if claims.ConnectTo != "" {
		dialTarget = claims.ConnectTo
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.dialTO)
	defer cancel()
	upstream, err := p.dialer.DialContext(ctx, "tcp", dialTarget)
	if err != nil {
		p.log("error", claims.Subject, target, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		p.log("error", claims.Subject, target, err)
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.log("allow", claims.Subject, target, nil)
	pipe(client, upstream)
}

// pipe copies in both directions until either side closes, then unblocks the other.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = dst.SetDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func (p *Proxy) log(decision, sub, target string, err error) {
	if p.audit == nil {
		return
	}
	e := connector.Event{Time: time.Now().UTC(), Action: "egress", Decision: decision, Subject: sub, Tool: target}
	if err != nil {
		e.Reason = err.Error()
	}
	_ = p.audit.Write(context.Background(), e)
}

// ErrClosed is returned by a wrapped dialer that has been shut down.
var ErrClosed = errors.New("egress: closed")
