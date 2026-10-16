# Known issues and risks

Review of the design (2026-10-14) for problems not covered in [ARCHITECTURE.md](ARCHITECTURE.md). Each item says
what goes wrong, how likely it is, and what the design does about it. "Design change" means the architecture or the
connector contract was updated because of it.

Severity: **H** = breaks the core promise or a common case; **M** = breaks some tools or setups; **L** = edge case.

## A. Cookie handover

### A1. Tools that don't use cookies for the session — **H** — design change

Some tools keep the session token in `localStorage`/`sessionStorage` (single-page apps that store a JWT in the
browser), or need cookies on **two origins** (tool + its own identity provider). A cookie-only result can't log
these in.

**Mitigation:** the login result carries a list of **session artifacts**, each with an origin: cookies (any number of
origins) and web-storage entries. The extension writes storage entries with a script injected only into that tool's
origin, before reloading. See CONNECTORS.md "Result".

### A2. Tools protected by HTTP Basic, Digest, NTLM or Kerberos auth — **H** — design change

With these, the browser must send the credential (`Authorization` header) on **every request**; there is no session
cookie to hand over. Typical cases: Elasticsearch on `:9200`, Prometheus/Alertmanager behind an nginx basic-auth,
some Windows tools. Injecting the header from the extension would put the password back in the browser.

**Mitigation:** cookie handover is not possible here. Options: (a) leave such tools out of sesame; (b) a later
**proxy mode** where the agent acts as a reverse proxy for that one tool and adds the header server-side. That's the
gateway pattern, so it's opt-in per tool, not the default. In a typical ops inventory Elasticsearch entries are common, so
expect this to matter.

### A3. Cookies are shared by every port of a host — **M**

Cookies are isolated by host, **not by port** ([RFC 6265 §8.5](https://kb.cert.org/vuls/id/804060)). Two tools on
`10.0.0.5:30080` and `10.0.0.5:30090`:

- **Collide:** two Grafanas both use `grafana_session`, so logging in to one logs you out of the other, and
  auto-login could bounce between them.
- **Leak:** the session cookie of one tool is also **sent to every other service on that host**, which can then use it.

This is already true without sesame, but sesame makes logins automatic.

**Mitigation:** prefer distinct hostnames per tool (a DNS name per service, even internal). The catalog flags tools
that share a host; the extension refuses to auto-login twice on the same host within a minute and tells the user why.

### A4. Sessions tied to the client's IP: the `none` network is different — **M** — design change

The "same source IP" argument only holds when the agent leaves through the **same NAT/router as the users**. An agent
placed **inside** the tool network (`network: none`) uses its own IP, while users arrive from the VPN router's IP. Any
tool that ties sessions to the client IP then rejects the handed-over cookie.

Example to verify: Jenkins documents its default CSRF crumb as session-based in current versions
([javadoc](https://javadoc.jenkins-ci.org/hudson/security/csrf/DefaultCrumbIssuer.html)). CloudBees support still
describes a strict IP check behind proxies
([kb](https://docs.cloudbees.com/d/kb-360039598171)), so it depends on version.

**Mitigation:** the catalog records per tool whether it is `ip_bound`. The broker only sends such tools to a pool whose
egress matches the users' path, and the PoC tests each connector both ways.

### A5. Secure cookies on plain-HTTP tools, cookie prefixes, partitioned cookies — **L**

A tool on `http://` can't receive cookies marked `Secure`. `__Host-` cookies need `Secure`, `path=/` and no domain.
Partitioned cookies need a partition key.

**Mitigation:** the extension adapts the attributes to the user's URL scheme, and connectors declare cookie prefixes.
Covered by tests.

### A6. The tool checks the hostname it was reached by — **M** — design change

Tools often have a configured public URL (Grafana `root_url`, Jenkins URL, Keycloak hostname) and redirect or reject
logins coming in under another name. If the agent reaches the tool by a different address than users do, the login
can fail or produce cookies for the wrong name.

**Mitigation:** the agent always sends the **user's host** (Host header, TLS server name) and only overrides the
address it connects to ("connect-to"), like `curl --connect-to`. One catalog URL; an optional per-pool address
override.

## B. Shared accounts in the tools

### B1. Logged-in sessions outlive offboarding — **H** — design change

Removing a user stops **new** logins, but sessions already in their browser live as long as the tool allows. Grafana's
defaults are 7 days of inactivity and up to **30 days** in total, rotated every 10 minutes while in use
([Grafana docs](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/)).
Without changing the tools, a leaver can keep a Grafana session for weeks.

**Mitigation:** an optional **session registry** in the broker. It keeps, per user and tool, what's needed to end the
session (encrypted at rest, deleted at the tool's maximum lifetime). Offboarding then calls each login connector's
`Revoke`, which logs out that session. Where a tool's session lifetime can be shortened, document it as recommended
configuration. A password rotation ends sessions only in tools that tie sessions to the password.

### B2. Tools that allow only one session per account, or cap sessions — **M**

When many people share one account, a tool that allows **one active session per user** kicks the previous person out
on every new login, and auto-login can make two users bounce each other. Tools that cap sessions or create a token per
login (session tables or API tokens piling up) degrade over time.

**Mitigation:** per-tool `session_policy` in the catalog: `per_user` (default), `shared` (the broker hands the same
session to everyone and refreshes it centrally), or `exclusive` (one user at a time, others get "in use by X").
Connectors that create server-side tokens must implement `Revoke`, and the broker logs out sessions it no longer needs.

### B3. Inside the tool, everyone is the same shared user — **M** (organisational)

The tool's own audit shows the shared account, not the person. sesame's audit records who obtained which session and
when, so actions can be correlated by time, but not proven.

**Mitigation:** where a tool supports named local users, a future **provisioning connector** can create a per-person
account and store its credential, giving a real identity in the tool without SSO. Until then, document the limitation.

### B4. Login throttling, lockouts, "new device" alerts — **M**

Shared accounts logging in many times from the same router IP can trip a tool's brute-force protection. Typically
that's after failed attempts (e.g. a wrong password after a rotation), but some tools count all logins. Some products
email "new login from unknown device".

**Mitigation:** the broker caps logins per tool account per minute, and stops after the first `bad_credentials` until
the credential changes (no retry storms). Reusing a recent session for the same user (B2) also cuts the volume.

### B5. Tools behind their own SSO — **M** — design change

Some tools redirect to the client's identity provider (often Keycloak) for login. The connector must then follow a
whole login flow across two origins and hand over cookies for both.

**Mitigation:** a generic `oidc-form` login connector (authorization-code flow with the IdP's login form, configurable
field names), plus A1's multi-origin result.

## C. Identity provider and sessions

### C1. A 7-day sign-in may not be possible per client in Keycloak — **M**

In Keycloak the realm's SSO session limits cap normal sessions; client-level settings mainly control refresh-token
lifetimes ([one guide](https://uds.defenseunicorns.com/reference/configuration/single-sign-on/keycloak-session-timeouts)).
Making the extension last 7 days by raising the realm SSO idle time would lengthen sessions for **every** app in the
realm. Offline tokens (`offline_access`) have their own idle/max timers and are the usual answer for long-lived clients
([Keycloak offline tokens](https://skycloak.io/blog/keycloak-offline-tokens-explained/)). Older versions had a bug
where offline tokens still died with the SSO session
([forum](https://forum.keycloak.org/t/refresh-token-offline-access-scope-affected-by-session-idle-session-max/12735)).

**Mitigation:** the identity connector requests `offline_access` when configured, and documents the realm settings
needed. Verify against the deployed Keycloak version in the PoC. Other IdPs differ; the identity connector declares
what it supports.

### C2. Revocation delay with claim-based roles — **L**

The `oidc-claims` roles connector only sees changes when the access token is refreshed (minutes). Live-lookup
connectors (`keycloak`) apply removals within their cache TTL.

**Mitigation:** documented trade-off; recommend live lookup where the IdP has an API.

## D. Browser extension

### D1. Permissions and store review — **M**

Setting cookies on arbitrary internal hosts needs the `cookies` permission and host access to every tool. Asking for
`<all_urls>` at install looks alarming and draws extra store review.

**Mitigation:** use **optional host permissions** and request each tool's origin at first use (one click per tool).
Content scripts run only on catalog origins, the extension accepts no messages from web pages
(no `externally_connectable`), and the catalog comes only from the broker.

### D2. Browser support — **M**

`launchWebAuthFlow` and its `chromiumapp.org` redirect are Chrome APIs. Edge is Chromium-based but I found no Edge
documentation confirming them, so test it. Firefox uses a different redirect host. Extensions are off in
incognito/private windows unless the user allows them.

**Mitigation:** an auth module per browser; Chrome and Edge tested in the PoC; Firefox later.

### D3. The extension's update channel is a high-value target — **H**

An extension that holds session cookies for all internal tools and updates itself automatically is the best
supply-chain target in the system. A malicious update could exfiltrate every session.

**Mitigation:**
- release signing, protected store-publisher accounts with 2FA, two-person release approval
- reproducible builds of the extension
- signed container images for broker and agent (e.g. cosign)
- pinned dependencies and minimal third-party code in the extension

### D4. Concurrency and user choice — **L**

- **Concurrency:** two tabs opening the same tool would trigger two logins.
- **User choice:** some users want to log in with a personal account instead.

**Mitigation:** one in-flight login per tool in the extension; per-tool auto-login toggle; a "don't log me in here"
action.

### D5. Ending a session in the tool — **L** — design change

The broker never stores cookies (unless the session registry in B1 is enabled), so "Log out of all" can't be done
server-side by default.

**Mitigation:** the extension calls each tool's logout URL from the browser (where the cookie already is), then deletes
the cookies. Server-side revocation is part of the optional session registry.

## E. Credential store

### E1. `bw serve` is an unauthenticated local API, slow when cold, single process — **M**

Anyone who can reach `bw serve`'s port gets everything the bot can read. Measured on a Vaultwarden instance with ~1000 items: 0.4–0.9 s for the
first read after a few seconds of idle. It's one Node.js process.

**Mitigation:**
- bind it to `127.0.0.1` inside the broker pod only
- the connector keeps an in-memory copy, reloaded after each sync (already done in the wiki broker)
- one broker replica per bot session

### E2. Licences of what we ship — **M** (open-source)

The Bitwarden CLI is GPL-3.0. Shipping it inside our container image means meeting GPL obligations for that image (the
source offer for the CLI); calling it over HTTP doesn't make our code GPL. The Bitwarden **Secrets Manager SDK** keeps
the proprietary "Bitwarden SDK License"; only the client-facing `sdk-internal` was moved to GPL
([report](https://alternativeto.net/news/2024/10/bitwarden-cto-clarifies-sdk-license-concerns-reaffirming-open-source-commitment)).

**Mitigation:** never link the Secrets Manager SDK. Keep the `bw` CLI as a separate process in a separate image layer
with its licence and source reference. Vaultwarden is AGPL-3.0, but sesame only talks to it over its API.

### E3. One bot that can read every credential — **M**

The broker's store account sees all scopes. A broker compromise exposes them all.

**Mitigation:** the credentials connector supports **several store accounts**, each limited to some scopes (e.g. one
per project or per environment), and the broker picks the account by the credential's scope.

## F. Agents and network

### F1. Internal CAs and self-signed certificates — **M**

Tools on internal HTTPS often use private CAs or self-signed certificates. A global "skip TLS verification" would let
anyone on the path capture passwords.

**Mitigation:** per-pool CA bundles and per-tool certificate pinning (fingerprint in the catalog). Verification can't be
turned off globally.

### F2. Long-lived job channel through proxies — **L**

WebSockets through reverse proxies and NATs get cut by idle timeouts.

**Mitigation:**
- heartbeats every 15 s, reconnect with backoff
- jobs carry a one-time id and expire after a few seconds (no replay)
- the broker only sends jobs to agents with a fresh heartbeat

### F2b. Idle VPN tunnels make the first login slow or fail — **M**

Mesh VPNs with lazy or on-demand connections (e.g. NetBird's lazy connections) only open a tunnel to a router when
traffic arrives. The first request after idle can time out. That's exactly the login request.

**Mitigation:** network connectors keep the tunnels to their pool's routers warm (a cheap probe per router every
~30 s) and report per-router state in heartbeats. Agent health comes from these probes, not from the VPN's management
API, whose "connected" status can lag.

### F2c. Several routers with equal priority — **M**

If a network has two VPN routers with the same priority, each client (user or agent) may pick a different one. With
NAT on the routers, the tool then sees different source IPs for the user and the agent, and `ip_bound` sessions fail.

**Mitigation:** give routers distinct priorities so everyone uses the same primary. The device-side check (F3)
catches the remaining cases.

### F3. Login storms — **L**

Everyone opens the same tool at 09:00 with the same shared account.

**Mitigation:** per-tool concurrency limit in the agent; session reuse per user (B2).

### F4. Relay path: the user's device sits on the login connection — **H** — design change

On the relay path ([ARCHITECTURE.md §6.1](ARCHITECTURE.md#61-relay-path-borrowing-the-users-own-network-access)),
the user's device forwards the agent's connection to the tool. Three ways it could go wrong:

- **Fake tool:** the device sends the connection to a server of its own and captures the password. Prevented only by
  the agent strictly verifying the tool's certificate (CA bundle or pin). A tool without a verifiable certificate must
  not use the relay path.
- **Plain HTTP tools:** nothing to verify and nothing encrypted, so the password would cross the device in clear.
  These tools use the pool path only.
- **The helper as a way into networks:** a compromised broker could ask helpers to connect to arbitrary internal
  hosts. Prevented by tickets bound to a user-started login, catalog-only targets, short lifetime and byte limits.

### F5. The VPN API token behind Reconcile is account-wide — **H**

VPN roles usually apply to the whole account. For example, a NetBird "Network Admin" can edit every policy, network,
route and DNS setting, not just sesame's. "Only touch `sesame-*` objects" is sesame's own restraint, not something the
VPN enforces. A bug or a compromised reconciler could open any path or break every user's routing.

**Mitigation:**
- Run the reconciler as its own component (never inside the internet-facing broker), with its own token.
- Default to **plan mode**: produce the list of VPN changes for a human to approve or apply, as GitOps would. Only
  apply automatically once trusted.
- Alert on any change by the sesame user to objects without the prefix (from the VPN's activity log).
- Rotate the token.

### F6. VPN-provided DNS for agents — **M**

Internal names often resolve only through VPN-distributed nameservers that sit inside the tools' networks. An agent
then needs both the nameserver distribution and network access to the nameserver's port 53. Per-tool rules alone
don't give that. Sidecar VPN clients also rewrite the pod's DNS configuration.

**Mitigation:** the catalog stores the tool's address, and the agent connects with `connect_to` while keeping the
tool's hostname for Host/SNI. That way agents don't need VPN DNS at all. It doesn't work for names that load-balance
or fail over by DNS (GSLB): for those, add a DNS rule for the agent instead.

## G. Organisational and legal

### G1. Client policies — **M**

Some clients forbid shared accounts, automated logins, or storing their credentials outside their premises. sesame
doesn't change who uses a shared account; it changes how. That still needs to be cleared per client before their tools
go into the catalog.

### G2. Personal data in the audit trail — **L**

Audit events contain user identifiers and timestamps (GDPR). They need a retention period and access control in the
log store.

## What this changes in the design

| Change | Where |
|---|---|
| Login result = session artifacts for several origins: cookies **and** web-storage entries | CONNECTORS.md (Result), ARCHITECTURE F3 |
| Per-tool catalog flags: `ip_bound`, `session_policy` (per_user / shared / exclusive), `ca` / `pin`, connect-to address | ARCHITECTURE §4 |
| Optional session registry + `Revoke` on login connectors, used at offboarding | ARCHITECTURE F6, CONNECTORS.md |
| Agent keeps the user's Host and TLS server name and only overrides the connect address | CONNECTORS.md (Job) |
| `oidc-form` generic login connector for tools behind their own IdP | CONNECTORS.md |
| Proxy mode (later, opt-in) for Basic/NTLM tools | ARCHITECTURE F9 |
| Several store accounts per credentials connector, chosen by scope | CONNECTORS.md |
