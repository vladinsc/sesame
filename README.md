<div align="center">

# 🔓 sesame

**Password-less login to internal web consoles — without the password ever touching the user's machine.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8)](https://go.dev) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![status](https://img.shields.io/badge/status-working%20prototype-brightgreen)]()

</div>

Teams share a lot of logins to tools they don't control — Grafana, ArgoCD, Kibana, Jenkins, Rancher, Harbor,
Bonita, internal consoles. Password managers autofill those credentials **into the user's browser**, where anyone
with a few minutes and the dev tools can read them. sesame removes the credential from the user's machine entirely:
a server component performs the login and hands the browser only the resulting **session cookie**. The user opens a
tool and is simply logged in. They never see, copy, or hold the password.

No changes to the tools — no SSO plugins, no reconfiguration. Everything product-specific — identity provider,
role source, credential store, catalog, per-tool login, network path, audit sink — is a **pluggable connector**.

> **Status:** working prototype. A one-command Docker stack brings up the whole thing — **Keycloak** (identity),
> **Vaultwarden** (credential store), **Grafana** (a target tool), the sesame services, and a **Chrome/Edge/Brave
> extension** — and logs you into Grafana from the browser without the Grafana password ever leaving the server.

---

## How it works

```
  ┌─────────────────────────── user's device ───────────────────────────┐
  │  Browser + sesame extension                                          │
  │   1. sign in once (OIDC + PKCE)         5. receives a session cookie │
  │   2. open https://grafana.internal         and is logged in          │
  └───────────┬──────────────────────────────────────────▲──────────────┘
              │ 3. POST /v1/login (access token)          │ artifacts (never a password)
              ▼                                            │
  ┌──────────────────── sesame-broker ────────────────────┴──────────────┐
  │  identity.Verify → roles.Groups → policy(groups→scopes)               │
  │  → credentials.Get → issue a signed, 30s, single-destination ticket   │
  │  → ask the agent to log in                                            │
  └───────────┬───────────────────────────────────────────────────────────┘
              │ 4. login job + ticket                 credential stays server-side
              ▼
  ┌──────── agent ────────┐   CONNECT (ticket-gated)   ┌──── sesame-egress ────┐
  │ runs the tool's login │ ─────────────────────────► │ verifies the ticket,  │ ──► tool
  │ connector; TLS is     │   end-to-end TLS, egress   │ forwards ONE host:port│     login
  │ end-to-end to the tool│   never sees plaintext     │ never terminates TLS  │     API
  └───────────────────────┘                            └───────────────────────┘
```

The **egress** is the only component with network reach to the tools. It forwards a TCP stream **only** when
presented a valid, unexpired, Ed25519-signed ticket whose destination equals the requested `host:port`. Because it
never terminates TLS, credentials and sessions stay encrypted end-to-end between the agent and the tool.

### Why these boundaries

| Property | How it's achieved |
|---|---|
| User never holds the password | the login runs on the agent; the browser gets only session artifacts (cookies / web-storage) |
| Session actually works on the user's device | the agent leaves through the same network path as the users (same source IP); the login is verified with a "who am I" check before hand-off |
| A compromised broker can't roam the network | it has no network path to tools; it can only ask the egress, and only via single-destination tickets |
| A compromised agent process can't roam either | it reaches a tool only with a broker-signed ticket for that exact `host:port` |
| Removing a user takes effect fast | access is the user's **live** groups vs the credential's scope, re-checked every login |
| Horizontal scale | broker and egress are stateless (tickets verified offline with a public key) — run N replicas behind a Service |

Full design, threat model and the alternatives that were rejected:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/RISKS.md](docs/RISKS.md), [docs/PRIOR-ART.md](docs/PRIOR-ART.md).

---

## Live demo — the full stack (Keycloak + Vaultwarden + Grafana)

Requires Docker and Go 1.26+.

```bash
bash examples/stack/bootstrap.sh
```

This brings up Keycloak, Vaultwarden (seeded with the Grafana admin password), Grafana, and the sesame
broker/egress, all wired together. When it prints **"sesame demo is up"**:

| Service | URL | Login |
|---|---|---|
| Grafana (target tool) | http://localhost:3000 | opened for you by sesame |
| Keycloak | http://localhost:8088 | `admin` / `admin`, realm `demo` |
| Vaultwarden | http://localhost:8089 | holds the Grafana credential |
| Broker API | http://localhost:8080 | what the extension talks to |

**Load the extension** (Brave/Chrome/Edge): open `brave://extensions` (or `chrome://extensions`), enable
**Developer mode**, **Load unpacked** → `extension/`. The ID is pinned to
`eienbohlonipiffgdmandlbnchingemp` so it matches the redirect already registered in Keycloak.

**Try it:** click the sesame icon → **Sign in** as **alice / alice** → click **Open** on *Grafana*. A Grafana tab
opens **already logged in as admin** — you never saw the password. (User **bob / bob** is in `/admins` and also has
access; a user in another group sees no tools.)

**Verify it from the shell** (no browser; the demo realm enables the direct-grant shortcut):

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=sesame-extension \
  -d username=alice -d password=alice -d scope=openid \
  http://localhost:8088/realms/demo/protocol/openid-connect/token | jq -r .access_token)

# the login returns a Grafana session cookie — and that cookie alone logs you in:
COOKIE=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"tool":"grafana","account":"admin"}' http://localhost:8080/v1/login | jq -r '.artifacts[0].value')
curl -s -H "Cookie: grafana_session=$COOKIE" http://localhost:3000/api/user | jq '.login, .isGrafanaAdmin'
# -> "admin"  true     (and the Grafana password appears in no sesame log)
```

Tear down: `docker compose -f examples/stack/docker-compose.yml down -v`. More detail:
[examples/stack/README.md](examples/stack/README.md).

### Minimal demo (no Docker)

`bash examples/local/demo.sh` runs the broker + egress + a fake tool with a dev identity and a static credential
store — the full login flow end to end in a few seconds, nothing to pull.

---

## Components

| Path | What it is |
|---|---|
| `cmd/sesame-broker` | the public API: authenticate, authorise, issue tickets, return session artifacts |
| `cmd/sesame-egress` | the ticket-gated CONNECT proxy — the only component with network reach to tools |
| `cmd/sesame-keygen` | generate ticket keypairs; mint dev tokens for local testing |
| `pkg/connector` | the public, versioned connector interfaces |
| `internal/ticket` | Ed25519 single-destination egress tickets (offline-verifiable) |
| `internal/policy` | groups → scopes rules with `{placeholder}` patterns |
| `internal/agent` | login runner: dial-through-egress HTTP client, TLS pinning, session check |
| `connectors/…` | identity (`oidc`, `dev`), roles (`keycloak`, `oidc-claims`, `static`), credentials (`bitwarden`, `static`), catalog (`file`), login (`grafana`, `argocd`), audit (`stdout`) |
| `extension/` | MV3 browser extension (OIDC+PKCE sign-in, catalog, cookie hand-off) |
| `deploy/k8s/` | example hardened manifests (distroless, non-root, read-only FS, NetworkPolicy) |
| `examples/stack/` | the full Keycloak + Vaultwarden + Grafana demo |

### Connector model

The core depends only on interfaces in `pkg/connector`, so Keycloak / Vaultwarden / NetBird are just the first
implementations:

```go
type Identity    interface { Verify(ctx, bearer) (Subject, error); ClientConfig() OIDCClientConfig }
type Roles       interface { Groups(ctx, Subject) ([]string, error) }
type Credentials interface { Get(ctx, Ref) (Credential, error); Scopes(ctx, Ref) ([]string, error) }
type Catalog     interface { Tools(ctx) ([]Tool, error) }
type Login       interface { Meta() LoginMeta; Login(ctx, *http.Client, LoginJob) (LoginResult, error); Check(...) error }
type Audit       interface { Write(ctx, Event) error }
```

A login connector for a new tool type is ~40 lines: where credentials are posted, which cookies make up the
session, how to recognise logged-out, and a "who am I" check. See [docs/CONNECTORS.md](docs/CONNECTORS.md).

---

## Security notes

- **Tickets** are Ed25519-signed, carry one destination, expire in seconds, and are verified offline by the egress
  — no shared state, so both tiers scale horizontally.
- **TLS** between agent and tool is verified against a configurable CA bundle, with optional per-tool SPKI pinning;
  verification can never be disabled.
- **Credentials** live only in memory for the duration of a login and are never logged (audit scrubbing + a
  no-secrets invariant on `Event`). The demo asserts this: the Grafana password appears in no sesame log.
- **Residual risk** (documented, by design): the user ends up with a working session cookie for a tool they're
  allowed to use. It expires, dies on logout, and can't be turned back into the password. Plain-HTTP and
  Basic/NTLM-auth tools have specific limits — see [docs/RISKS.md](docs/RISKS.md).

## Development

```bash
make test     # unit + integration tests (httptest tools, real TLS, ticket-gated tunnel)
make vet
make build    # binaries into ./bin
make images   # distroless container images (needs Docker)
```

## License

[Apache-2.0](LICENSE).
