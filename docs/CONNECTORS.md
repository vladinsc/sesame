# Connectors

Everything that touches a specific product is a **connector**. The core (broker, agent, extension, policy, job
protocol) only knows the interfaces below. Swapping Keycloak for Authentik, Vaultwarden for HashiCorp Vault, or
NetBird for Tailscale means configuring a different connector, not changing the core.

Proposed implementation: Go. Each connector is a package under `connectors/<kind>/<name>/` that registers itself in
`pkg/connector` (`connector.Register(kind, name, factory)`). A connector is selected by `type:` in the configuration
and receives the rest of its configuration block. Build tags allow slim builds with only the connectors you need.
Out-of-process connectors (gRPC, for third parties who don't want to fork) can come later behind the same interfaces.

The interfaces in `pkg/connector` are the project's public API and are versioned; breaking changes bump the major
version.

## Kinds

| Kind | Runs in | Interface (sketch) | First implementations |
|---|---|---|---|
| identity | broker | `Verify(ctx, token) (Subject, error)` · `ClientConfig() OIDCClientConfig` | `oidc` |
| roles | broker | `Groups(ctx, Subject) ([]string, error)` | `keycloak`, `oidc-claims` |
| credentials | broker | `Get(ctx, Ref) (Credential, error)` · `Scopes(ctx, Ref) ([]string, error)` · optional `List`, `Changes` | `bitwarden` |
| catalog | broker | `Tools(ctx) ([]Tool, error)` | `file`, `credential-store` |
| network | agent | `Up(ctx) error` · `Ready(ctx) error` · `Probe(ctx, hostPort) error` | `none`, `netbird` |
| login | agent (and extension, for in-browser mode) | `Meta() Meta` · `Login(ctx, Job) (Result, error)` · optional `Logout` | `argocd`, `grafana`, `kibana`, `jenkins` |
| audit | broker | `Write(ctx, Event) error` | `stdout` |

```go
// pkg/connector (sketch)
type Subject struct{ ID, Name, Email string }

type Identity interface {
    Verify(ctx context.Context, bearer string) (Subject, error)
    ClientConfig() OIDCClientConfig // what the extension needs to sign in
}

type Roles interface {
    Groups(ctx context.Context, s Subject) ([]string, error)
}

type Ref string // e.g. "bitwarden://<item-id>", "vault://kv/data/grafana#password"

type Credential struct {
    Username, Password string
    TOTPSeed           string            // optional
    Extra              map[string]string // custom fields some login connectors need
}

type Credentials interface {
    Get(ctx context.Context, ref Ref) (Credential, error)
    Scopes(ctx context.Context, ref Ref) ([]string, error) // e.g. Bitwarden collection names
}

type Tool struct {
    ID, Name, URL, Login, Pool string
    Accounts                   []Account
}
type Account struct{ Label string; Ref Ref }

type Catalog interface {
    Tools(ctx context.Context) ([]Tool, error)
}

type Network interface {
    Up(ctx context.Context) error    // bring the VPN up, or no-op
    Ready(ctx context.Context) error // reported in agent heartbeats
    Probe(ctx context.Context, hostPort string) error
    // Explain says how traffic to host would leave: interface, VPN router chosen, whether that router is up,
    // and (when the VPN's API is configured) whether a policy allows this host:port. Used to label failures.
    Explain(ctx context.Context, host string) (RouteInfo, error)
    KeepWarm(ctx context.Context) // keep tunnels to the pool's routers open (lazy/on-demand VPNs)
    // Optional: make the VPN's rules match the catalog (one host resource + one agent → host:port rule per tool).
    // Only touches objects it created (name prefix "sesame-"). Runs on catalog change and periodically.
    Reconcile(ctx context.Context, tools []Tool) (ReconcileReport, error)
    // Optional: just-in-time access. Enables the pre-created rule for this tool only, for the duration of one
    // login (ARCHITECTURE.md §6.0). Returns ErrNotSupported for VPNs without an API (standing rules then).
    Open(ctx context.Context, tool Tool) (release func(), err error)
    // Optional: would this user's own VPN access reach the tool's host:port? (read-only, from the VPN's policies and
    // the user's groups). Open is only called when this is true, so sesame never extends a user's network reach.
    UserCanReach(ctx context.Context, s Subject, groups []string, tool Tool) (bool, error)
}

type Login interface {
    Meta() LoginMeta // logged-out signal, check endpoint, cookie names, logout support, TOTP support
    Identify(ctx context.Context, loginPage *http.Response) bool // "is this really a <tool>?" (no credentials)
    Login(ctx context.Context, job Job) (Result, error)
}

type Audit interface {
    Write(ctx context.Context, e Event) error
}
```

## Configuration

Broker (`sesame-broker.yaml`), reference setup with Keycloak, Vaultwarden and NetBird:

```yaml
listen: :8080
identity:
  type: oidc
  issuer: https://idp.example.com/realms/acme
  client_id: sesame-extension
  audience: sesame
roles:
  type: keycloak                      # live lookup: removals apply within cache_ttl
  url: http://keycloak.auth.svc:8080
  realm: acme
  client_id: sesame-roles
  client_secret_file: /secrets/roles-client-secret
  cache_ttl: 30s
credentials:
  type: bitwarden                     # Vaultwarden or Bitwarden, through a local `bw serve`
  serve_url: http://127.0.0.1:8087
  organization_id: 00000000-0000-0000-0000-000000000000
  sync_interval: 60s
catalog:
  type: credential-store              # tools defined by metadata on the credential items
  fields: {login: "sesame:login", url: "sesame:url", pool: "sesame:pool"}
policy:
  use_store_scopes: true              # scope = the item's collections
  rules:
    - groups: ["/admins"]
      scopes: ["*"]
    - group_pattern: "/projects/{p}/{env}"
      scopes: ["projects/{p}/{env}"]
agents:
  pools: [hq, client-a]
audit:
  - type: stdout
```

Agent (`sesame-agent.yaml`):

```yaml
broker: wss://sesame.example.com/v1/agents
pool: client-a
credential_file: /secrets/agent-token
network:
  type: netbird                       # or: none, tailscale, wireguard, …
login: [argocd, grafana, kibana, jenkins]
```

Alternative catalog without credential-store metadata (`catalog.type: file`):

```yaml
tools:
  - id: client-a-grafana
    name: Grafana (client A, prod)
    url: https://grafana.client-a.example
    login: grafana
    pool: client-a
    accounts:
      - {label: viewer, ref: "bitwarden://3f0c…"}
      - {label: admin,  ref: "bitwarden://9a1d…"}
```

## Writing a login connector

A login connector knows one tool type's login:

- where the login is sent and in what format (HTML form or JSON)
- any extra step first (CSRF token, required header, pre-login request)
- which cookies mean "logged in"
- how to recognise "logged out", so the extension can log in again
- optionally: how to log out, and how to answer an in-tool TOTP prompt

One login connector serves every instance of that tool type; the URL and account come from the catalog.

**Job (input)**

| Field | Notes |
|---|---|
| `user_url` | how the **user** opens it. The agent always uses this host for the Host header and TLS server name, so tools that check their own public URL accept the login |
| `connect_to` | optional address the agent actually dials instead of `user_url`'s host (like `curl --connect-to`) |
| `tls` | CA bundle for the pool, optional certificate pin for the tool; verification can't be turned off |
| `credential` | username, password, optional TOTP seed and extra fields; memory only |
| `user_agent`, `accept_language` | the user's browser values, sent on every request |
| `timeout` | default 10 s |

**Result (output)**

A list of **session artifacts**, each bound to an origin. Most tools need one cookie; tools behind their own IdP need
cookies on two origins; single-page apps that keep a token in the browser need web-storage entries.

```json
{
  "artifacts": [
    {"origin": "https://grafana.example", "type": "cookie", "name": "grafana_session", "value": "…",
     "path": "/", "httpOnly": true, "secure": true, "sameSite": "lax", "maxAge": 2592000},
    {"origin": "https://app.example", "type": "localStorage", "key": "jwt", "value": "…"}
  ],
  "landing": "/",
  "revoke": "opaque, only kept if the session registry is enabled"
}
```

Expiry is relative (`maxAge`), so clock differences between agent and browser don't matter.

Errors are typed: `bad_credentials`, `unreachable`, `unexpected_response` (the tool changed), `needs_interaction`
(CAPTCHA or unsupported 2FA), `timeout`.

**Rules for login connectors:** stateless; never log credentials or cookie values; return only the cookies declared in
`Meta()`; follow redirects only within the tool's origin; no external dependencies beyond the standard HTTP client.

**Tests:** recorded responses of the real tool (no credentials in fixtures) for unit tests, plus an optional daily
synthetic login per connector type with a dedicated read-only account, to catch login changes before users do.

Every login connector also declares a **check**: a cheap authenticated request ("who am I") used twice. The agent
calls it right after login, and the extension calls it from the user's browser after writing the artifacts. That's
how sesame knows the handed-over session really works on the user's device
([ARCHITECTURE.md F3](ARCHITECTURE.md#f3-log-in-to-a-tool-the-main-flow)).

## First login connectors (to verify against real versions in the PoC)

**argocd**
```
POST {base}/api/v1/session          JSON {"username": u, "password": p}
← 200 {"token": "<jwt>"}
cookie  argocd.token = <jwt>   path /
logged out: path /login
check: GET /api/v1/session/userinfo  → loggedIn: true
```

**grafana**
```
POST {base}/login                   JSON {"user": u, "password": p}
← 200, Set-Cookie: grafana_session (+ grafana_session_expiry)
logged out: path /login
check: GET /api/user → 200
```

**kibana** (basic auth provider)
```
POST {base}/internal/security/login header kbn-xsrf: true
     JSON {"providerType": "basic", "providerName": "basic", "currentURL": "{user_url}/login",
           "params": {"username": u, "password": p}}
← 200, Set-Cookie: sid
logged out: path /login
check: GET /internal/security/me (header kbn-xsrf) → 200
```

**jenkins** (form login)
```
POST {base}/j_spring_security_check form j_username=u&j_password=p&from=/&Submit=Sign+in
← 302, Set-Cookie: JSESSIONID.<node-id>
logged out: path /login
check: GET /whoAmI/api/json → authenticated: true
```

Next, after researching each login: `rancher`, `harbor`, `bonita`, `jasper`, `keycloak-admin` (an OIDC flow performed
by the agent, handing over the Keycloak session cookies: the most involved one), and a generic **`oidc-form`** for
tools that redirect to their own identity provider (authorization-code flow through the IdP's login form, with
configurable field names; returns cookies for both the IdP and the tool).

Login connectors that create server-side tokens or sessions should implement `Revoke(ctx, revokeHandle)`, so the
optional session registry can end sessions at offboarding ([RISKS.md B1](RISKS.md)).

## Writing other connectors

- **identity:** anything that can verify a bearer token and describe an OIDC client for the extension. Non-OIDC
  providers (SAML-only) would need an OIDC bridge in front (e.g. Keycloak or Dex as a broker).
- **roles:** must answer for the **current** state (live lookup or short cache). Token claims alone (`oidc-claims`)
  are fine but delay revocation until the access token expires.
- **credentials:** must never write credentials to disk or logs; caches stay in memory with a short TTL.
  `Scopes()` returns whatever the store uses for access grouping (collections, path prefixes, vaults). A connector
  should support **several store accounts**, each limited to some scopes, so one broker compromise doesn't expose
  every credential. Don't link SDKs with non-OSI licences (e.g. the Bitwarden Secrets Manager SDK); separate GPL
  helpers like the `bw` CLI run as their own process.
- **network:** ship a deployment template (sidecar or init) in `deploy/helm` plus the small `Up/Ready/Probe/Explain/
  KeepWarm` code. `Explain` should use the VPN client's local view (e.g. `netbird status -d`: routes, selected router,
  peer state), not only the management API, whose peer status can lag. Optionally, with read access to the VPN's
  management API, it also checks that a policy allows the agent → host:port, so a missing rule shows up as
  `route: no policy` rather than a timeout. Document how to give the agent the same egress router as the users.
- **audit:** must not block logins for long; buffer and drop with a counter if the sink is down.
