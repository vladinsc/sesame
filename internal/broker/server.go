// Package broker is the public API of sesame. It verifies the user (identity), looks up their current groups
// (roles), filters the catalog and authorises a login against the policy, reads the credential, issues a
// short-lived egress ticket, and asks the agent runner to perform the login. It never returns credentials, only
// the session artifacts the browser replays.
package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vladinsc/sesame/internal/agent"
	"github.com/vladinsc/sesame/internal/metrics"
	"github.com/vladinsc/sesame/internal/policy"
	"github.com/vladinsc/sesame/internal/ratelimit"
	"github.com/vladinsc/sesame/internal/ticket"
	"github.com/vladinsc/sesame/pkg/connector"
)

// Pool is an egress pool the broker can dispatch logins to.
type Pool struct {
	Name       string
	EgressAddr string         // host:port the agent CONNECTs to
	Signer     *ticket.Signer // signs tickets for this pool
	TicketTTL  time.Duration
}

// Deps are the broker's wired connectors and settings.
type Deps struct {
	Identity    connector.Identity
	Roles       connector.Roles
	Credentials connector.Credentials
	Catalog     connector.Catalog
	Policy      *policy.Engine
	Audit       connector.Audit
	Metrics     *metrics.Registry
	Runner      *agent.Runner
	Pools       map[string]Pool
	DefaultPool string
	RateMax     int
	RateWindow  time.Duration
}

// Server implements the broker HTTP API.
type Server struct {
	d     Deps
	limit *ratelimit.Limiter
}

// New returns a broker server.
func New(d Deps) *Server {
	if d.RateMax == 0 {
		d.RateMax = 30
	}
	if d.RateWindow == 0 {
		d.RateWindow = time.Minute
	}
	d.Metrics.Describe("sesame_logins_total", "login attempts by decision")
	return &Server{d: d, limit: ratelimit.New(d.RateMax, d.RateWindow)}
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("GET /metrics", s.d.Metrics.Handler())
	mux.HandleFunc("GET /v1/auth/config", s.authConfig)
	mux.HandleFunc("GET /v1/catalog", s.catalog)
	mux.HandleFunc("POST /v1/login", s.login)
	return securityHeaders(mux)
}

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.d.Identity.ClientConfig())
}

// authed verifies the bearer token and returns the subject and its live groups.
func (s *Server) authed(r *http.Request) (connector.Subject, []string, error) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" || bearer == r.Header.Get("Authorization") {
		return connector.Subject{}, nil, errUnauthorized
	}
	sub, err := s.d.Identity.Verify(r.Context(), bearer)
	if err != nil {
		return connector.Subject{}, nil, errUnauthorized
	}
	groups, err := s.d.Roles.Groups(r.Context(), sub)
	if err != nil {
		return sub, nil, errRolesUnavailable
	}
	return sub, groups, nil
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	sub, groups, err := s.authed(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	tools, err := s.d.Catalog.Tools(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiErr{"catalog unavailable"})
		return
	}
	out := make([]connector.Tool, 0, len(tools))
	for _, t := range tools {
		allowed := t
		allowed.Accounts = s.allowedAccounts(r.Context(), groups, t)
		if len(allowed.Accounts) > 0 {
			out = append(out, allowed)
		}
	}
	_ = sub
	writeJSON(w, http.StatusOK, map[string]any{"tools": out})
}

// allowedAccounts returns the accounts of t whose scopes the groups grant (labels only, refs stripped).
func (s *Server) allowedAccounts(ctx context.Context, groups []string, t connector.Tool) []connector.Account {
	var out []connector.Account
	for _, a := range t.Accounts {
		scopes, err := s.d.Credentials.Scopes(ctx, a.Ref)
		if err != nil {
			continue
		}
		if s.d.Policy.Allows(groups, scopes) {
			out = append(out, connector.Account{Label: a.Label})
		}
	}
	return out
}

type loginReq struct {
	Tool      string `json:"tool"`
	Account   string `json:"account"`
	UserAgent string `json:"user_agent"`
	Language  string `json:"language"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sub, groups, err := s.authed(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.limit.Allow(sub.ID) {
		s.audit(sub, "", "", "deny", "rate limit")
		writeJSON(w, http.StatusTooManyRequests, apiErr{"slow down"})
		return
	}
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiErr{"bad request"})
		return
	}

	tool, account, ok := s.findToolAccount(r.Context(), req.Tool, req.Account)
	if !ok {
		s.audit(sub, req.Tool, req.Account, "deny", "unknown tool/account")
		writeJSON(w, http.StatusNotFound, apiErr{"not found"})
		return
	}

	scopes, err := s.d.Credentials.Scopes(r.Context(), account.Ref)
	if err != nil || !s.d.Policy.Allows(groups, scopes) {
		s.metricInc("deny")
		s.audit(sub, tool.ID, account.Label, "deny", "no group grants the scope")
		writeJSON(w, http.StatusForbidden, apiErr{"no access"})
		return
	}

	pool, ok := s.poolFor(tool)
	if !ok {
		s.audit(sub, tool.ID, account.Label, "error", "no pool")
		writeJSON(w, http.StatusBadGateway, apiErr{"no egress pool for tool"})
		return
	}

	cred, err := s.d.Credentials.Get(r.Context(), account.Ref)
	if err != nil {
		s.audit(sub, tool.ID, account.Label, "error", "credential unavailable")
		writeJSON(w, http.StatusBadGateway, apiErr{"credential unavailable"})
		return
	}

	target := toolTarget(tool)
	tkt, err := pool.Signer.Issue(ticket.Claims{
		Audience: pool.Name, Target: target, ConnectTo: tool.ConnectTo, Subject: sub.ID, Tool: tool.ID,
	}, pool.TicketTTL)
	if err != nil {
		s.audit(sub, tool.ID, account.Label, "error", "ticket")
		writeJSON(w, http.StatusInternalServerError, apiErr{"internal error"})
		return
	}

	res, err := s.d.Runner.Run(r.Context(), agent.Job{
		Tool: tool, Credential: cred, Ticket: tkt, EgressAddr: pool.EgressAddr,
		UserAgent: req.UserAgent, Language: req.Language,
	})
	if err != nil {
		s.metricInc("error")
		s.audit(sub, tool.ID, account.Label, "error", err.Error())
		writeJSON(w, http.StatusBadGateway, apiErr{loginErrMessage(err)})
		return
	}

	s.metricInc("allow")
	ev := connector.Event{
		Time: time.Now().UTC(), Action: "login", Decision: "allow", Subject: sub.ID,
		Tool: tool.ID, Account: account.Label, Pool: pool.Name, Duration: time.Since(start).Milliseconds(),
	}
	_ = s.d.Audit.Write(r.Context(), ev)
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": res.Artifacts, "landing": res.Landing})
}

func (s *Server) findToolAccount(ctx context.Context, toolID, label string) (connector.Tool, connector.Account, bool) {
	tools, err := s.d.Catalog.Tools(ctx)
	if err != nil {
		return connector.Tool{}, connector.Account{}, false
	}
	for _, t := range tools {
		if t.ID != toolID {
			continue
		}
		for _, a := range t.Accounts {
			if a.Label == label || (label == "" && len(t.Accounts) == 1) {
				return t, a, true
			}
		}
	}
	return connector.Tool{}, connector.Account{}, false
}

func (s *Server) poolFor(t connector.Tool) (Pool, bool) {
	name := t.Pool
	if name == "" {
		name = s.d.DefaultPool
	}
	p, ok := s.d.Pools[name]
	return p, ok
}

func (s *Server) audit(sub connector.Subject, tool, account, decision, reason string) {
	_ = s.d.Audit.Write(context.Background(), connector.Event{
		Time: time.Now().UTC(), Action: "login", Decision: decision, Reason: reason,
		Subject: sub.ID, Tool: tool, Account: account,
	})
}

func (s *Server) metricInc(decision string) {
	s.d.Metrics.Inc("sesame_logins_total", "decision", decision)
}

var (
	errUnauthorized     = errors.New("unauthorized")
	errRolesUnavailable = errors.New("roles unavailable")
)

func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		writeJSON(w, http.StatusUnauthorized, apiErr{"sign in"})
	case errors.Is(err, errRolesUnavailable):
		writeJSON(w, http.StatusBadGateway, apiErr{"identity provider unavailable"})
	default:
		writeJSON(w, http.StatusInternalServerError, apiErr{"internal error"})
	}
}

func loginErrMessage(err error) string {
	switch {
	case errors.Is(err, connector.ErrBadCredentials):
		return "the stored credential was rejected by the tool"
	case errors.Is(err, connector.ErrNeedsInteraction):
		return "this tool needs manual login"
	default:
		return "login failed"
	}
}

type apiErr struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func toolTarget(t connector.Tool) string {
	// mirrors agent.hostPort without importing it; tool.URL is validated there too.
	u := t.URL
	u = strings.TrimPrefix(u, "https://")
	if u != t.URL { // had https
		return withPort(u, "443")
	}
	u = strings.TrimPrefix(t.URL, "http://")
	return withPort(u, "80")
}

func withPort(hostpath, def string) string {
	host := hostpath
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + def
}
