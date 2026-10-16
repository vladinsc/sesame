// Package agent runs login jobs: it builds an HTTP client that reaches a tool only through the ticket-gated
// egress proxy, runs the tool's login connector, verifies the resulting session, and returns the session
// artifacts. Credentials live only in memory for the duration of a job.
package agent

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"

	"github.com/vladinsc/sesame/internal/egress"
)

// egressDialer dials the tool's host:port through the egress CONNECT proxy, presenting a ticket.
type egressDialer struct {
	egressAddr string // host:port of the egress proxy
	ticket     string
	target     string // host:port the ticket authorises (and the CONNECT authority)
	base       net.Dialer
}

// DialContext ignores the address http asks for (it may be the tool host) and always CONNECTs to the ticketed
// target through the egress. This guarantees the connection can only reach what the ticket allows.
func (d *egressDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	conn, err := d.base.DialContext(ctx, "tcp", d.egressAddr)
	if err != nil {
		return nil, fmt.Errorf("dial egress: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n",
		d.target, d.target, egress.TicketHeader, d.ticket)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	// Consume headers up to the blank line.
	tp := textproto.NewReader(br)
	if _, err := tp.ReadMIMEHeader(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT headers: %w", err)
	}
	if !containsStatus(status, "200") {
		conn.Close()
		return nil, fmt.Errorf("egress refused CONNECT: %s", status)
	}
	_ = conn.SetDeadline(zeroTime)
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func containsStatus(line, code string) bool {
	// line like "HTTP/1.1 200 Connection Established"
	for i := 0; i+len(code) <= len(line); i++ {
		if line[i:i+len(code)] == code {
			return true
		}
	}
	return false
}

// bufferedConn preserves bytes buffered by bufio.Reader ahead of the tunnel.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
