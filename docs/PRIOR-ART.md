# Prior art: how other tools solve the same problems

Researched 2026-10-14. Product claims come from vendor documentation (linked) and were not independently tested.

## Four families

| Family | Examples | Where the login happens | Credential reaches the user's device? | How it reaches private networks |
|---|---|---|---|---|
| **Autofill** | Bitwarden/1Password (incl. "hidden passwords"), Okta SWA | user's browser | **yes** (only hidden from the UI) | the user's own network access |
| **Identity-aware proxy** | Pomerium, Teleport App Access, Cloudflare Access | the tool trusts the proxy, or the proxy **adds headers** to every request | no, for header-based auth | a connector/agent **in each network**, connecting outbound |
| **Remote browser isolation (RBI)** | Keeper Connection Manager RBI, CyberArk PSM for web | a **browser running next to the tool**; the user only sees a video-like projection | **no**, and the page's code never runs on the device | the gateway/connector **in each network** |
| **Session handover** (sesame) | uncommon | an agent logs in; only the **session** goes to the user's browser | no (the session cookie does) | an agent with network reach |

Sources:
- Keeper RBI: "inject credentials, submit forms … without ever sending the credentials to the user's device", and the
  site's code and DOM "never execute locally" ([Keeper docs](https://docs.keeper.io/keeper-connection-manager/supported-protocols/remote-browser-isolation),
  [autofill](https://docs.keeper.io/keeperpam/privileged-access-manager/remote-browser-isolation/setting-up-rbi/browser-autofill)).
- CyberArk PSM is described as a proxy that injects credentials into RDP, SSH and web sessions without revealing
  them ([summary](https://decryptiondigest.com/blog/how-to-implement-privileged-access-management-cyberark-beyond-trust)).
- Pomerium can add a fixed `Authorization: Basic …` header to upstream requests
  ([docs](https://pomerium.com/docs/reference/routes/headers)).
- Teleport can add configured headers per app ([docs](https://goteleport.com/docs/enroll-resources/application-access/reference/)).

## How they handle the problems we hit

| Problem | What others do | What sesame takes from it |
|---|---|---|
| **Reaching private networks** | Everyone runs a small component **inside each network** that connects **outbound**: Twingate Connectors (one per isolated subnet) ([Twingate](https://twingate.com/docs/resources-and-access-nodes)), Teleport agents, Cloudflare tunnels, PAM gateways. Nobody reaches all networks from one place without something in each. | A mesh VPN's **routing peers** already are that component. A sesame agent that is a peer of the same VPN reuses them, so nothing new is installed per network. |
| **DNS of private names** | Resolved **at the connector**, inside the remote network; the client gets a placeholder address ([Twingate DNS](https://www.twingate.com/docs/how-twingate-forwards-dns)). | Prefer VPN features that resolve on the routing peer (NetBird domain resources may do this: to verify). Otherwise the agent connects to the IP and keeps the hostname for Host/SNI (RISKS F6). |
| **Managing access rules programmatically** | Through the vendor's control plane or **infrastructure-as-code**: Teleport, Twingate and NetBird have Terraform providers ([NetBird provider](https://github.com/netbirdio/terraform-provider-netbird)). Changes go through plan → review → apply. | Instead of the reconciler holding an account-wide API token, the network connector can **emit IaC** (e.g. Terraform for NetBird). Review and apply stay in the organisation's normal pipeline (RISKS F5). |
| **Tools with Basic/header auth** | Proxies add the header server-side (Pomerium, Teleport). RBI types the credentials into the remote browser. | Proxy mode for those tools (RISKS A2) is the established pattern. |
| **Session tied to client IP** | Not an issue for proxies and RBI: the tool always sees the proxy/gateway. | sesame's handover needs the same egress (§6). The device-side check (F3) catches failures. |
| **Who did what in a shared account** | PAM and RBI **record the whole session**; proxies log every request with the user's identity. | sesame only sees the login, not what happens after. Proxy mode (and an RBI tier) would give per-request or per-session attribution where it's required. |

## Second round (2026-10-14): non-invasive options

| Product | Hides credentials for **form logins**? | How it reaches private networks |
|---|---|---|
| StrongDM (web resources) | **No.** Web resources support "no authentication, basic HTTP authentication, or header-based authentication"; "interactive logins and websites secured with SSO are not supported". Credentials are injected on the last hop for those ([docs](https://docs.strongdm.com/admin/resources/websites), [credentials](https://docs.strongdm.com/concepts/security/credentials-and-secrets-management)) | gateways/relays in or into the network |
| Envoy credential injector | header/Basic only; meant for workload auth, not end users ([docs](https://www.envoyproxy.io/docs/envoy/v1.30.4/configuration/http/http_filters/credential_injector_filter)) | wherever Envoy runs |
| HashiCorp Boundary | brokers/injects for SSH/RDP/DB via workers; not web form logins ([docs](https://developer.hashicorp.com/boundary/docs/credentials)) | workers in the network |
| Microsoft Entra App Proxy, password SSO | **No.** The "My Apps" browser extension fills the stored password ([docs](https://learn.microsoft.com/entra/architecture/auth-password-based-sso)) | connectors in the network |
| **NetBird reverse proxy** (beta, v0.65+) | **No.** It publishes internal services with SSO, group gating or "NetBird-only" access and passes the caller's identity/groups as headers. Its docs describe **no upstream credential injection** ([docs](https://docs.netbird.io/manage/reverse-proxy), [v0.72](https://netbird.io/knowledge-hub/netbird-only-private-services)) | its embedded NetBird client acts like a routing peer |
| Neko / Kasm (open-source virtual browsers) | could, if the login is automated inside the remote browser (not built in) ([neko](https://github.com/O-clock-Dev/neko)) | the browser container needs network reach |
| Keeper RBI, CyberArk PSM | **Yes** (remote browser fills the form) | gateway with network reach |

Conclusion: **no product hides form-login credentials without a component that has network reach to the tool.** The
non-invasive products (autofill extensions) expose the credential to the user's browser. Those that hide it (RBI,
last-hop injection) all run a gateway that can reach the tool, and proxies only handle header/Basic auth.

## What sesame is, compared to these

- **Lighter and faster than proxies and RBI.** After login the browser talks to the tool directly. There's no
  per-request hop and no remote browser to run (RBI needs a Chromium instance per session).
- **Weaker than RBI in one respect:** the user holds a working session cookie. Proxies and RBI never give the user
  anything reusable outside their system.
- **Same constraint as everyone:** something must sit in or route into each network. sesame's choice is to reuse the
  VPN's routing peers instead of deploying its own connectors.

Possible later tiers built from this:
1. **Proxy mode** for header-auth tools and tools needing per-request attribution.
2. An **RBI tier** for the most sensitive tools. This is a large project: an open-source RBI would need a Chromium
   per session and pixel streaming, e.g. building on Apache Guacamole or Kasm.
