package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/vladinsc/sesame/connectors/login"
	"github.com/vladinsc/sesame/pkg/connector"
)

var zeroTime time.Time

// Job is one login the agent must perform.
type Job struct {
	Tool       connector.Tool
	Credential connector.Credential
	Ticket     string // egress ticket authorising the tool's host:port
	EgressAddr string // host:port of the egress proxy
	UserAgent  string
	Language   string
	CABundle   *x509.CertPool // extra roots for the tool's TLS, nil = system roots
}

// Runner performs login jobs.
type Runner struct {
	timeout time.Duration
}

// NewRunner returns a runner with a per-job timeout.
func NewRunner(timeout time.Duration) *Runner {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &Runner{timeout: timeout}
}

// Run logs in and verifies the session, returning artifacts for the browser.
func (r *Runner) Run(ctx context.Context, job Job) (connector.LoginResult, error) {
	lc, err := login.Get(job.Tool.Login)
	if err != nil {
		return connector.LoginResult{}, err
	}
	u, err := url.Parse(job.Tool.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return connector.LoginResult{}, fmt.Errorf("invalid tool url %q", job.Tool.URL)
	}
	target := hostPort(u)

	client, err := r.client(u, target, job)
	if err != nil {
		return connector.LoginResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	lj := connector.LoginJob{
		UserURL:        strings.TrimRight(job.Tool.URL, "/"),
		Credential:     job.Credential,
		UserAgent:      job.UserAgent,
		AcceptLanguage: job.Language,
	}
	res, err := lc.Login(ctx, client, lj)
	if err != nil {
		return connector.LoginResult{}, err
	}
	// Prove the session works before handing it over.
	if err := lc.Check(ctx, client, lj); err != nil {
		return connector.LoginResult{}, fmt.Errorf("session check failed: %w", err)
	}
	return res, nil
}

// client builds an HTTP client that reaches the tool only through the egress, with TLS verification/pinning.
func (r *Runner) client(u *url.URL, target string, job Job) (*http.Client, error) {
	dialer := &egressDialer{
		egressAddr: job.EgressAddr,
		ticket:     job.Ticket,
		target:     target,
		base:       net.Dialer{Timeout: 10 * time.Second},
	}
	tlsConf := &tls.Config{
		ServerName: u.Hostname(), // verify against the user-facing host even if ConnectTo differs
		MinVersion: tls.VersionTLS12,
		RootCAs:    job.CABundle,
	}
	if job.Tool.PinSHA256 != "" {
		pin, err := base64.StdEncoding.DecodeString(job.Tool.PinSHA256)
		if err != nil {
			return nil, fmt.Errorf("bad pin: %w", err)
		}
		tlsConf.InsecureSkipVerify = true // we verify the pin ourselves below
		tlsConf.VerifyPeerCertificate = pinVerifier(pin)
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: r.timeout,
		Transport: &http.Transport{
			DialContext:     dialer.DialContext, // http path: raw tunnel
			DialTLSContext:  dialTLS(dialer, tlsConf),
			TLSClientConfig: tlsConf,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
			}
			return nil
		},
	}, nil
}

// dialTLS tunnels through the egress and then performs the TLS handshake over that tunnel.
func dialTLS(d *egressDialer, conf *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tconn := tls.Client(raw, conf)
		if err := tconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tconn, nil
	}
}

// pinVerifier accepts the chain only if the leaf's SHA-256 SPKI pin matches.
func pinVerifier(pin []byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificate presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtleEqual(sum[:], pin) {
			return nil
		}
		return errors.New("certificate pin mismatch")
	}
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
