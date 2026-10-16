# sesame demo stack (Keycloak + Vaultwarden + Grafana)

A full, self-contained demo: sign in with Keycloak, and sesame logs you into Grafana using a password stored in
Vaultwarden — which you never see or type.

```
Brave + sesame extension ──(1) sign in──▶ Keycloak (OIDC)
        │                                      
        │ (2) Open "Grafana"                   
        ▼                                      
   sesame-broker ──(3) read credential──▶ Vaultwarden (via bw serve)
        │ (4) ticket + login job
        ▼
   sesame-egress ──(5) log in──▶ Grafana
        │ (6) session cookie
        ▼
   Brave gets the cookie and lands in Grafana, logged in
```

## 1. Start it

Requires Docker Desktop running and Go (for the one keygen step).

```bash
bash examples/stack/bootstrap.sh
```

First run pulls images and builds the Go services (a few minutes). When it prints **"sesame demo is up"**:

| Service | URL | Notes |
|---|---|---|
| Keycloak | http://localhost:8088 | admin / admin, realm `demo` |
| Vaultwarden | http://localhost:8089 | holds the Grafana credential |
| Grafana | http://localhost:3000 | the target tool |
| Broker API | http://localhost:8080 | what the extension talks to |

Demo users: **alice / alice** (group `/projects/demo/dev`) and **bob / bob** (group `/admins`). Both may open
Grafana.

## 2. Load the extension in Brave

1. Open `brave://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select `C:\Soft31\sesame\extension`.
4. The extension ID will be **eienbohlonipiffgdmandlbnchingemp** (pinned via the manifest key, so it matches the
   redirect URL already registered in Keycloak).

## 3. Use it

1. Click the **sesame** icon → **Sign in**. A Keycloak window opens; log in as **alice / alice**.
2. The popup lists **Grafana**. Click **Open**.
3. A Grafana tab opens **already logged in as admin** — you never saw the password.

Behind the scenes: the broker verified alice's Keycloak token, checked her group grants the credential's scope,
read the Grafana password from Vaultwarden, issued a 30-second single-destination ticket, and the egress logged
into Grafana and returned only the session cookie.

## Verify from the command line (no browser)

`bob` is in `/admins` (scope `*`); here we get a Keycloak token via direct grant for a quick check:

```bash
TOKEN=$(curl -s -d grant_type=password -d client_id=sesame-extension \
  -d username=alice -d password=alice -d scope=openid \
  http://localhost:8088/realms/demo/protocol/openid-connect/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/catalog        # shows Grafana
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"tool":"grafana","account":"admin"}' http://localhost:8080/v1/login     # returns a session cookie
```

(Direct grant is disabled on the client by default; enable `directAccessGrantsEnabled` in the realm for this
shortcut, or just use the extension.)

## Tear down

```bash
docker compose -f examples/stack/docker-compose.yml down -v
```

Generated secrets live in `examples/stack/.secrets/` (git-ignored). Delete that folder yourself if you want it gone.

## Notes & limitations

- Vaultwarden runs with in-memory storage (`I_REALLY_WANT_VOLATILE_STORAGE`) — the demo re-seeds on each bootstrap.
- The Grafana credential is stored in the bot's **personal** vault with a `sesame-scope` custom field. In a real
  deployment, scopes come from Vaultwarden **collections** (organisations), mapped from Keycloak groups.
- This stack grants the egress direct docker-network reach to Grafana (via `connect_to: grafana:3000`). In
  production the egress reaches tools through a VPN; see [docs/RISKS.md](../../docs/RISKS.md).
