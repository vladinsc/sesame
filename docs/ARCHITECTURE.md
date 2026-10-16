# sesame: architecture

Status: **design**, 2026-10-14. Nothing here is implemented yet.

## 1. Goal and principles

Users open a tool's web console and are logged in, without typing anything and without ever being able to see the
tool's password.

| Constraint | Consequence |
|---|---|
| Don't touch the tools (no SSO plugins, no config changes) | sesame logs in **as a normal client** through each tool's own login, using a **login connector** per tool type |
| Users must never hold the password | The login happens on a **login agent**; the browser only receives the **session cookie** |
| Tools sit in restricted networks | Agents run wherever they can reach the tool (inside that network, or joined to it over a VPN) and only ever dial **out** to the broker |
| As fast as typing a password | One identity-provider login (with its MFA) per session, e.g. 7 days; each tool login after that takes ~1 s |
| Same access rules as the rest of the organisation | Access = the user's **live groups/roles** from the identity side vs the credential's **scope** in the credential store |
| Open source, no lock-in | Identity, roles, credentials, catalog, network, audit and per-tool login are all **connectors** behind versioned interfaces ([CONNECTORS.md](CONNECTORS.md)) |

Non-goals: replacing the tools' own users and roles; proxying tool traffic (after login the browser talks to the tool
directly, exactly as before).

## 2. Topology

```
 USER DEVICE                          sesame BROKER (one per organisation)           IDENTITY / CREDENTIALS
┌──────────────────────────┐  HTTPS  ┌───────────────────────────────────────┐      ┌──────────────────────────┐
│ Browser                  │────────►│ API: catalog, login, audit            │◄────►│ identity connector (OIDC)│
│  └ sesame extension      │         │ policy: groups → credential scopes    │◄────►│ roles connector          │
│    (OIDC token, catalog) │         │ job dispatcher                        │◄────►│ credentials connector    │
│                          │         └───────────▲───────────────▲───────────┘      │ catalog connector        │
│  tabs: tool UIs ─────────┼──┐                  │ outbound      │ outbound         └──────────────────────────┘
│  (traffic unchanged)     │  │                  │ job channel   │ job channel
│ VPN client (if any)      │  │      ┌───────────┴─────────┐ ┌───┴──────────────────────┐
└──────────────────────────┘  │      │ AGENT pool "hq"     │ │ AGENT pool "client-a"    │
                              │      │ network: none       │ │ network: netbird /       │
                              │      │ (runs next to tools)│ │ tailscale / wireguard …  │
                              │      │ login connectors    │ │ login connectors         │
                              │      └──────────┬──────────┘ └───────────┬──────────────┘
                              │                 │ login                  │ login (through the VPN's
                              │                 ▼                        ▼  router, same as users)
                              │        ┌─────────────────┐    ┌──────────────────────────────┐
                              └───────►│ tools in HQ net │    │ tools in client-a network    │
                                       └─────────────────┘    └──────────────────────────────┘
```

Network paths:

| From → to | Carries | Notes |
|---|---|---|
| Extension → broker | identity token, login requests, **session cookies** (never passwords) | the only public endpoint besides the identity provider |
| Extension → identity provider | one interactive login per session, then silent token refresh | standard OIDC + PKCE |
| Broker → identity / roles / credentials / catalog | token verification, group lookup, credential reads | through the configured connectors |
| Agent → broker | **outbound** job channel (agent registers, receives jobs, returns results) | agents need no inbound port, so they can run inside closed networks |
| Agent → tool | the tool's login request | directly, or through the network connector's VPN |
| Browser → tool | normal tool traffic | unchanged; however users reach the tool today |

## 3. Components

| Component | Responsibility | Holds | Exposed |
|---|---|---|---|
| **Extension** | sign-in (generic OIDC), match tabs to catalog tools, request logins, set cookies, re-login on expiry | the user's refresh token, the catalog of tools the user may use | n/a |
| **Broker** | verify identity, look up roles, apply policy, read credentials, dispatch jobs to agents, audit | credential-connector session; short-lived cache of catalog and credentials | yes (HTTPS API) |
| **Agent** | run login connectors, inside or joined to the tool's network | nothing persistent; a credential lives in memory only during one job | no (outbound only) |
| **Connectors** | the pluggable parts: identity, roles, credentials, catalog, network, login, audit | per kind, see [CONNECTORS.md](CONNECTORS.md) | n/a |

Why broker and agents are separate processes: the broker is internet-facing and can read credentials; agents can reach
private networks. Keeping them apart means compromising one doesn't give both "all passwords" and "reach to every
network".

## 4. Data model

| Concept | Meaning | Comes from |
|---|---|---|
| **Subject** | the verified user (id, name, email) | identity connector |
| **Groups** | the user's current groups/roles | roles connector (live lookup, short cache, so removals apply in seconds) |
| **Tool** | one tool instance users open: `id`, `name`, `url` (as users open it), `login` (connector type), `pool` (which agents can reach it), plus optional flags: `ip_bound` (sessions tied to client IP: only pools with the users' egress), `session_policy` (`per_user` default / `shared` / `exclusive`), `connect_to` (address the agent dials instead, Host stays the user's), `ca` / `pin` (TLS trust) | catalog connector |
| **Account** | a credential for a tool: `ref` (e.g. `bitwarden://<item-id>`), `label` (e.g. "admin", "viewer"), `scope` | catalog + credentials connectors |
| **Scope** | the credential store's access unit (a Bitwarden collection, a Vault path prefix, …) | credentials connector |
| **Policy** | rules mapping groups to scopes | broker configuration (see below) |

Policy rules are plain configuration, for example:

```yaml
policy:
  rules:
    - groups: ["/admins"]                    # exact group
      scopes: ["*"]
    - group_pattern: "/projects/{p}/{env}"   # placeholders shared between group and scope
      scopes: ["projects/{p}/{env}"]
    - group_pattern: "/projects/{p}"         # a project's root group sees all its environments
      scopes: ["projects/{p}/*"]
```

A credential store that already maps groups to scopes itself (e.g. Bitwarden groups → collections) can expose that
mapping through its connector; the policy then just says "use the store's mapping".

## 5. Flows

### F1. Sign in to the extension (once per session)

```
User          Extension                   Identity provider (OIDC)          Broker
 │ "Sign in" │                                  │                              │
 │──────────►│ GET /v1/auth/config ────────────────────────────────────────────►│ issuer, client id, scopes
 │           │◄─────────────────────────────────────────────────────────────────│
 │           │ authorization code + PKCE ──────►│                              │
 │ login + MFA on the provider's own page ─────►│                              │
 │           │◄── tokens (short access, rotating refresh) ─│                     │
 │           │ GET /v1/catalog (Bearer) ───────────────────────────────────────►│ identity.Verify → roles.Groups
 │           │◄──────── tools this user may use (names, URLs, account labels) ──│ → policy filters the catalog
 │ "Signed in, 23 tools"                                                         │
```

The extension is identity-provider-agnostic: it only speaks OIDC and gets the provider details from the broker.

### F1b. How the extension knows which tool a tab is

The extension never guesses from page content. It only acts on tabs whose URL matches the catalog it got from the
broker (which already contains only tools this user may use):

1. **Match** the tab's URL against each tool's `url`: same scheme, host and port, and the tool's path as a prefix.
   Longest prefix wins (`https://host/grafana` beats `https://host/`).
2. **Trigger** only when the tool's login connector says the page is a logged-out page (its `logged_out` signal, e.g.
   path `/login`), or when the user clicks the toolbar button. A tab that is already logged in is left alone.
3. **Ambiguity:** if several tools or accounts match (two accounts for one tool, or the **same private IP:port used
   in two different networks**), the extension shows a picker instead of choosing. Overlapping private address
   ranges between networks are common, so catalogs should prefer hostnames; the broker warns about duplicate URLs.
4. Unknown URLs: nothing happens. The extension never sends a URL that isn't in the catalog to the broker.

### F2. Agent registration (on agent start)

```
Agent                                         Broker
 │ connect wss://broker/v1/agents (agent credential: mTLS cert or token)  │
 │──────────────────────────────────────────────────────────────────────►│ verify agent identity
 │ hello {pool: "client-a", version, login connectors: [argocd, grafana]} │
 │──────────────────────────────────────────────────────────────────────►│ register in pool
 │◄──────────────────────────────────────────── ok, heartbeat every 15 s │
 │ network.Ready() reported in heartbeats (VPN up, probes OK)            │
```

### F2b. Reachability: knowing an agent can reach each tool

sesame never assumes reachability from configuration. Every agent continuously **tests** the tools assigned to its
pool and reports results; the broker only dispatches a login to an agent that reached that tool recently.

```
Broker                                   Agent (pool "client-a")                       Tool
 │ catalog change / every 60 s:            │                                            │
 │ "your tools: grafana-a, kibana-a, …" ──►│ for each tool, probe ladder:               │
 │                                         │  1 DNS     resolve the tool's host (VPN DNS)│
 │                                         │  2 route   network.Explain(host): which     │
 │                                         │            interface / VPN router, router up?│
 │                                         │  3 TCP     connect host:port ──────────────►│
 │                                         │  4 TLS     handshake, cert valid for the    │
 │                                         │            pool's CA bundle / pin           │
 │                                         │  5 HTTP    GET the login page, no credentials│
 │                                         │            → login connector's Identify():   │
 │                                         │            "is this really a Grafana?"       │
 │◄── heartbeat: per tool {ok | failed_at: dns|route|tcp|tls|http, router, latency, ts} ─│
 │ reachability table → admin view, metrics, alerts; the extension greys out tools        │
 │ no agent can reach ("can't reach right now") instead of failing on click               │
```

The step that fails tells you **who has to act**:

| Fails at | Usually means | Who fixes it |
|---|---|---|
| dns | the agent isn't in the VPN's DNS distribution for that domain | VPN/DNS admin |
| route | no VPN policy from the agent to this host/port, or the router is down | VPN admin |
| tcp | the tool or its host is down, or a firewall behind the router blocks it | tool owner / client network |
| tls | private CA missing from the pool's bundle, expired or wrong certificate | sesame admin / tool owner |
| http | something else answers on that address (wrong URL or port, or the tool changed) | catalog owner |

When a tool is added to the catalog, the broker asks its pool to probe it immediately, so the admin sees "no agent can
reach X (fails at: route)" **before** any user clicks it. Probes never send credentials. A real login is only tested by
the optional daily synthetic login ([CONNECTORS.md](CONNECTORS.md)).

Agents also expose the table as metrics (`sesame_tool_reachable{tool,pool,stage}`,
`sesame_tool_probe_seconds`) for the organisation's existing monitoring and alerting.

### F3. Log in to a tool (the main flow)

```
Browser             Extension               Broker                               Agent (pool of the tool)       Tool
 │ open tool URL ─►│ matches catalog tool; tool's login page shown → auto-login     │                            │
 │                 │ POST /v1/login {tool, account, url, userAgent, lang}           │                            │
 │                 │────────────────────►│ 1 identity.Verify(token); rate limit     │                            │
 │                 │                     │ 2 roles.Groups(subject) (short cache)    │                            │
 │                 │                     │ 3 policy: groups → account.scope? else 403 + audit                  │
 │                 │                     │ 4 credentials.Get(account.ref)            │                            │
 │                 │                     │ 5 job ───────────────────────────────────►│ 6 login connector          │
 │                 │                     │                                          │   (user's UA + language) ─►│
 │                 │                     │                                          │◄── session cookie ─────────│
 │                 │                     │◄──── {artifacts, landing} (credential dropped)                        │
 │                 │                     │ 7 audit.Write(allow …), never cookie values or passwords             │
 │                 │◄─── artifacts ──────│                                          │                            │
 │                 │ 8 write session artifacts (cookies per origin, web-storage entries); reload / landing          │
 │◄── tool UI, logged in ─────────────────────────────────────────────────────────────────────────────────────►│
```

Target: under 1–2 s end to end. The password exists only in the credential store, in broker memory for the request,
in the job in flight, and in the agent's memory while the connector runs.

**Proving the session works on the user's device.** A login only counts as successful after two checks:

1. **Agent side:** after logging in, the connector calls the tool's "who am I" endpoint with the new session (e.g.
   Grafana `GET /api/user`, ArgoCD `GET /api/v1/session/userinfo`, Kibana `GET /internal/security/me`). A failure
   here is a connector problem, reported as `error`.
2. **Device side:** after writing the artifacts, the extension calls the **same** endpoint from the user's browser,
   so it goes through the user's own network path. `200` → done. `401/403` → the extension removes what it wrote and
   reports "session handover rejected". The usual causes are the session being tied to the client IP (the agent and
   the user leave through different NAT/routers) or to the device. The broker records `handover_failed` for that
   tool and pool, so a systematic problem shows up after the first failure, not after user complaints.

The check endpoint is part of each login connector's metadata ([CONNECTORS.md](CONNECTORS.md)).

### F4. Several accounts for one tool

If several accounts match, the extension shows a picker with their **labels** (never values) and remembers the
choice per tool. Users only see accounts the policy allows them.

### F5. Session expired or logged out

Each login connector declares a "logged-out" signal (login page path, or a 401 on a known endpoint). When the
extension sees it, it repeats F3, at most once per tool per minute so a broken connector can't loop. "Log out of all"
deletes the catalog tools' cookies and, where the connector supports it, ends the session in the tool.

### F6. Access removed

```
Admin removes the user from a group (or disables the user) in the identity provider
  → the next roles lookup (short cache) no longer grants the scope → new logins denied
  → disabled user: token refresh fails → extension signs out
Sessions already in the browser live until the tool expires them (Grafana's default allows up to 30 days)
  → optional session registry: the broker remembers, per user and tool, what's needed to end each session it handed
    out (encrypted, deleted at the tool's max lifetime) and calls the login connector's Revoke for all of them
  → without the registry: shorten tool session lifetimes where possible; rotating the shared password ends sessions
    only in tools that tie them to it
```

There is no password to take back: the user never had it. See [RISKS.md B1](RISKS.md#b1-logged-in-sessions-outlive-offboarding--h--design-change).

### F7. Password rotation

Change the credential in the store (by hand, or by a rotation job). The broker's credential cache expires within a
minute; the next login uses the new value. Since nobody knows these passwords, rotating them is free; a later phase
can add **rotation connectors** that change the password in the tool and the store in one step.

### F8. Adding a tool

1. The credential exists in the store, in the right scope.
2. Add the tool to the catalog (YAML entry, or metadata on the credential item: see the `credential-store` catalog
   connector).
3. Make sure an agent pool can reach it (an agent inside that network, or the pool's VPN allows that host and port).
4. New tool type → write a login connector ([CONNECTORS.md](CONNECTORS.md#writing-a-login-connector)).

### F9. When no agent can reach the tool

Default: not supported; the extension says so. Optional, per scope: **in-browser mode**, where the extension runs the
login connector itself (compiled to the extension). The password then reaches the user's device, so this is opt-in
for low-risk scopes only, and audited as `mode: in-browser`.

Tools that authenticate every request (HTTP Basic, Digest, NTLM, Kerberos) have no session to hand over at all. They
are out of scope for cookie handover; a later, opt-in **proxy mode** (the agent reverse-proxies that one tool and adds
the header server-side) can cover them. See [RISKS.md A2](RISKS.md#a2-tools-protected-by-http-basic-digest-ntlm-or-kerberos-auth--h--design-change).

All known issues and their mitigations: [RISKS.md](RISKS.md).

## 6. Networks

sesame doesn't depend on any VPN. An agent pool is just "a set of agents that can reach these tools":

| Network connector | How the agent reaches the tools | Typical use |
|---|---|---|
| `none` | the agent runs **inside** the tools' network | client clusters or hosts where you may deploy a container |
| `netbird` | the agent is its own NetBird peer (sidecar or embedded client) in a dedicated group whose policies allow only the tools' ports | tools reached by users over NetBird |
| `tailscale`, `wireguard`, `openvpn` (later) | same idea with that VPN's client | |

A network connector is small: it brings the VPN up for the agent (or checks it is up), reports `Ready()` and probes
tool ports in heartbeats, and ships deployment templates (e.g. a sidecar) in `deploy/helm`.

Rules that hold for every VPN:

- **Same source IP as the users.** If users reach a tool through a VPN router that NATs/masquerades, the agent must
  leave through the **same router**, so the tool sees the same source IP for both and IP-bound sessions survive the
  handover. With HA routers, prefer one deterministically (metrics) for users and agents alike.
- **MAC addresses never matter.** They don't cross routers, and browsers don't expose them.
- **Least privilege.** The agent's VPN identity is allowed only the tools' ports, never whole networks.

What breaks a cookie handover regardless of network: sessions tied to TLS client certificates, device-bound cookies,
CAPTCHAs. Sessions tied to the User-Agent work, because the agent sends the user's User-Agent and language. In-tool
TOTP works when the TOTP seed is stored with the credential.

### 6.000 Recommended: coarse VPN access, fine control inside sesame

Keeping VPN rules in step with the catalog is operational overhead (reviews, propagation, one rule per tool). The
pragmatic split: **the VPN grants the agent pool coarse reach once** (per network, TCP only), and **sesame enforces
the fine-grained limit itself**, where it changes instantly with the catalog.

```
                   ┌──────────────── agent pod ─────────────┐     ┌──────── egress pod ───────────┐
broker ── job ───► │ login connectors (no VPN, no NET_ADMIN) │──►  │ allowlist proxy  +  VPN client │ ──► tools
                   └─────────────────────────────────────────┘ CONNECT host:port          (coarse VPN access)
                                                                │ allowed only if host:port is in the
                                                                │ broker-signed catalog
```

- **VPN side (set once):** one rule `agent-group → each project network`, TCP only, optionally limited to web ports.
  New networks are added once per network, not per tool.
- **sesame side (instant):** the VPN client runs in a separate **egress pod** whose only job is a CONNECT proxy with
  an allowlist of catalog `host:port` pairs (signed by the broker, refreshed on every catalog change). The agent pod
  has no VPN and can reach tools only through that proxy. A compromised agent process therefore can't reach anything
  outside the catalog. Only a compromise of the egress pod itself gives the full coarse reach.
- The `UserCanReach` check (§6.0) and the per-request filter for each login connector still apply.
- The trade-off is explicit: the egress pod holds VPN reach comparable to an administrator's laptop. It has no
  inbound exposure, runs nothing but the proxy, and its configuration is signed.

### 6.00 Alternative: catalog-driven VPN rules

The simplest setup that keeps credentials off user devices without installing anything in the tools' networks: **one
central agent pool that is an ordinary peer of the VPN users already use, whose access is generated from the
catalog.**

```
catalog (tools: host, port, network)                   VPN control plane
        │  network connector Reconcile() ─────────────► for each tool: host resource in that tool's existing network
        │  (owns only objects it created, prefix sesame-)  + rule  agent-group → host:port (TCP)
        │                                                  remove tool → rule removed
        ▼                                                         │ pushed like any other rule
agent (central, one VPN peer) ── same routing peer and NAT as users ──► tool login endpoint
```

- **No new paths:** the agent reaches tools through the same VPN routers users use, so the tools see the same
  source IP and IP-bound sessions keep working.
- **Access equals the catalog, exactly:** one `host:port` per tool, created and removed automatically. No subnets,
  no manual rule work, no drift.
- **Never more than the user:** before a login the broker checks `UserCanReach` (the user's own VPN access covers
  that tool), so sesame can't be used to get somewhere the user's VPN wouldn't take them.
- **Defence in depth:** inside the agent pod, an egress filter only lets through the requests each login connector
  declares.
- **Hardening, optional:** the same rules can be kept disabled and switched on per login (§6.0) if standing
  endpoint access isn't acceptable, at the cost of extra login latency.

### 6.0 Just-in-time network access (no standing access)

A pool agent doesn't need permanent access to the tools' networks. With a VPN whose access rules can be switched
through an API, the agent's access can exist **only for the seconds of a login**:

```
Broker                     Access gate (holds the VPN API token)        VPN control plane        Agent
 │ login for tool T approved   │                                          │                        │
 │ open(T, 30 s) — signed ────►│ T in the allowlist? → enable the         │                        │
 │                             │ pre-created rule "agent → T host:port" ─►│ push to agent's peer ─►│ route to T only
 │ job ──────────────────────────────────────────────────────────────────────────────────────────►│ connector runs
 │◄─────────────────────────────────────────────────────────────────────────────── artifacts ────│
 │ close(T) ──────────────────►│ disable the rule (also auto after 30 s) ►│ route removed ───────►│
```

- **At rest the agent can reach nothing.** During a login it can reach exactly one `host:port`, the tool's login
  endpoint. Even then, an egress filter in the agent pod only allows the HTTP requests that tool's login connector
  declares (e.g. `POST /login`, `GET /api/user`).
- **The agent never gets more network access than the requesting user has.** Before opening tool T for user U, the
  gate checks with the network connector that **U's own VPN permissions cover T's host:port**. Where the VPN takes
  its groups from the same identity provider (e.g. NetBird groups synced from Keycloak), the connector computes this
  from U's groups and the VPN's policies, read-only. The extension adds that U's tab actually loaded T's login page.
  The agent's access is thus **the user's access, narrowed to one login endpoint, for one login**. Copying the user's
  whole VPN group membership onto the agent is deliberately not done:
  - it would give the agent the user's full reach (often whole subnets, all ports) instead of one endpoint;
  - a shared agent serving several users at once would hold the union of their access;
  - changing identity-synced groups on every login pushes network updates to every member peer and can be
    overwritten by the next group sync.
- **Rules are pre-created, disabled, by a network admin**, one per catalog tool. The gate can only **toggle those
  rules**, never create or edit others. It's a separate small service, so a compromised broker can't open arbitrary
  paths with the VPN token.
- **Cost:** login latency now includes the VPN's rule propagation and tunnel set-up (to be measured; the target is
  still a few seconds). It also depends on the VPN's management API being up; when it's down, logins fail closed.
- The network connector interface gets an optional `Open(ctx, tool) (release func(), error)`. VPNs without an API
  fall back to standing per-tool rules.

### 6.1 Relay path: borrowing the user's own network access

Agents normally need their own way into each tool's network (pools, §6). But the user opening the tool **already** has
a working path to it. The relay path uses that path without exposing the credential to the user's device:

```
Agent (anywhere, no VPN)          Broker                 User's device                         Tool
 │ TLS ClientHello (SNI = tool) ───►│── relay stream ──────►│ sesame-relay helper: raw TCP ──────►│
 │◄═══════════════ end-to-end TLS between agent and tool; device sees only ciphertext ═════════►│
 │ verifies the tool's certificate (pool CA bundle or catalog pin) BEFORE sending the login      │
 │ POST /login {user, password} ── encrypted ── forwarded ── forwarded ────────────────────────►│
 │◄────────────── Set-Cookie (encrypted) ◄────────────────────────────────────────────────────────│
```

- The **agent** does the TLS handshake with the tool itself, over a byte stream the user's device forwards. The
  device never holds TLS keys, so it can't read the login or the response.
- The tool sees the login coming from the **user's own network path**, so sessions tied to the client IP always
  match. This removes the "same router" problem entirely.
- Agents need **no access to client networks**, and a central agent pool can serve every network any user can reach,
  including a client's own VPN and public URLs.

Conditions and limits:

| Condition | Why |
|---|---|
| **Tool must use HTTPS** | Over plain HTTP the device would see the password. HTTP tools use the pool path or are out of scope. |
| **Agent must authenticate the tool's certificate** (public CA, the pool's private CA bundle, or a per-tool pin) | The device controls the path and could send the connection to its own server. Only certificate verification stops it from collecting the password. Self-signed tools need a pin in the catalog; "skip verify" is never allowed on this path. |
| **Native helper on the device** | Browser extensions can't open raw TCP connections. A small signed helper (`sesame-relay`, talks to the extension via native messaging, per-user install, no admin rights) does only this. |
| **Helper only connects where a live login needs it** | Otherwise a compromised broker could use every user's device as a way into every network they can reach. The helper only opens `host:port` from a ticket that is signed by the broker, bound to a login the user just started in this browser, valid for seconds, and limited in bytes. It never accepts other targets. |

Per tool, the catalog chooses `path: relay` (HTTPS with a verifiable certificate), `path: pool` (agent's own network
access), or `path: auto` (relay when possible, else pool).

Making certificate verification practical: internal tools usually share **one private CA per network or client**
(e.g. a wildcard certificate for an internal domain issued by the client's CA). The catalog pins that **CA per
network**, not each tool's certificate, so all HTTPS tools of that network are verifiable with one entry. The CA is
recorded by an administrator or a pool agent, never through the relay itself. Tools that are plain HTTP behind an
existing HTTPS ingress or reverse proxy (common in Kubernetes) should be catalogued under their HTTPS name; that
brings them onto the relay path without changing the tool. The relay path is **optional**; deployments that want a
browser-extension-only footprint use the pool path for everything.

Why the relay can't do more (checked, not assumptions):

- **Plain-HTTP tools can't be relayed safely, whatever encryption we add.** Encryption needs a party at the tool's
  end that decrypts. A plain-HTTP tool only understands plaintext, so the bytes must be plaintext from the last
  encrypting hop onwards, and on the relay path that hop is the user's device. A tool can be protected without TLS
  only by putting something of ours in its network to decrypt (a WireGuard/Noise endpoint with pre-shared keys, so
  no certificates). That is just an agent in that network, i.e. the pool path.
- **No certificate authority is needed for HTTPS tools; trusting the right key is.** Self-signed certificates are
  fine if the catalog **pins** their fingerprint. The pin can be recorded automatically on first use, but only over a
  path the user doesn't control (a pool agent or an admin), never over the relay itself. Otherwise the first user
  could plant their own key.
- **The user's VPN permissions can't be borrowed without the user's device seeing the traffic.** In a WireGuard-based
  mesh, access belongs to a key: the router only forwards packets encrypted with a key its rules allow. To use the
  user's access, the agent's traffic must be encrypted with the **user's** key, and only the user's device has it, so
  that device sees the traffic before encrypting it. Forwarding the agent's own encrypted packets through the device
  (as the VPN's relay servers do) keeps the content secret, but the router then sees the **agent's** key, so the agent
  still needs its own permission.
- **The relay needs a native helper.** Browser extensions can't open raw TCP connections. `chrome.sockets` was for
  the retired Chrome Apps, and the Direct Sockets API is limited to Isolated Web Apps. WebSocket, WebTransport and
  WebRTC only talk to servers that speak those protocols. Relaying the HTTP request through the browser's `fetch()`
  instead would let the browser read the password, since the browser itself would be the TLS endpoint.

## 7. Security model

| Secret | Lives in | Never in |
|---|---|---|
| Tool passwords | credential store; broker memory per request; agent memory during a job | extension, user's device, logs, catalog files, git |
| Tool session cookies | the tool; in flight agent → broker → extension; the user's browser | logs (audit records cookie names and expiry only) |
| User refresh token | the extension's storage | broker (only short-lived access tokens reach it) |
| Agent credential | the agent's secret (mTLS key or token), one per agent | anything else |

| Compromised | Gets | Doesn't get |
|---|---|---|
| a user's device | that user's tool sessions, and new logins **as that user** until revoked (same as any SSO) | any password |
| broker | credentials the credential connector can read | network reach into tool networks |
| one agent | reach to its pool's tools; credentials of jobs sent to it | the credential store; other pools; inbound access |
| broker **and** an agent | everything in that pool's scope | (mitigate: separate hosts/accounts, pinned images, audit alerts) |

Residual risk, accepted by design: a user can read **their own session cookie** for a tool they may use. It expires,
dies on logout and can't be turned back into the password.

Not prevented: a user logged in with an admin account creating new credentials inside the tool. Least-privilege
accounts (viewer vs admin, as separate catalog accounts with separate scopes) limit that.

Agent ↔ broker: every agent has its own credential, is pinned to one pool, and only receives jobs for that pool's
tools. Jobs carry a short expiry and a one-time id.

Audit event, one per decision: `ts, subject, tool, account, scope, pool, agent, login_connector, decision
(allow|deny|error), reason, duration_ms, mode (agent|in-browser)`.

## 8. Failure behaviour

| Failure | User sees |
|---|---|
| identity provider down | "Sign in unavailable"; existing tool sessions keep working |
| broker down | toolbar error; already-logged-in tools keep working |
| credential store down | nothing, within the broker's short credential cache |
| no agent online in the tool's pool | "Can't reach <tool> right now" (and an alert if sustained) |
| login connector fails (tool changed its login) | "Login failed for <tool>"; a daily synthetic login per connector type catches it early |
| rate limit | "Slow down" |

## 9. Reference deployment

The first deployment uses Keycloak (identity + roles), Vaultwarden (credentials + catalog metadata) and NetBird
(network) on Kubernetes:

- Broker: a Deployment with a `bw serve` sidecar (credentials connector `bitwarden`), behind a reverse proxy that
  preserves client IPs (for rate limits).
- Agents: one pool per reachable network. In-cluster pool with `network: none`; pools for VPN-reached networks with
  a NetBird sidecar and a NetBird group whose policies allow only the catalog tools' ports.
- Keycloak: a public client for the extension (PKCE, redirect `https://<extension-id>.chromiumapp.org/`), and a
  service client with read access to users and groups for the `keycloak` roles connector.

Organisation-specific values (hostnames, groups, NetBird setup keys) live in the deploying organisation's own repo,
not here.

## 10. Decisions to make

1. Implementation language for broker and agent. Proposed: **Go** (single static binaries, clear interfaces,
   connectors compiled in through a registry; out-of-process plugins via gRPC later if third parties need them).
   The extension is TypeScript.
2. License. Proposed: **Apache-2.0** (patent grant, permissive, common for infra tools).
3. Project name: check that "sesame" is free enough on GitHub/npm/Chrome Web Store before publishing.
4. Session length for the extension (proposed 7 days idle, 30 days max) and whether in-browser mode (F9) exists at all.
5. Firefox from day one or later.

## 11. Proof of concept

1. Broker with connectors `oidc` + `keycloak` (identity/roles), `bitwarden` (credentials), `credential-store` catalog,
   `stdout` audit.
2. One agent pool `network: none` (next to the tools) and one with `network: netbird` (behind a VPN router).
3. Login connectors `argocd` and `grafana`.
4. Chrome extension: sign in, match, login, set cookies, reload.
5. Measure: login time, cookie handover, the same-source-IP assumption, in a real browser.
