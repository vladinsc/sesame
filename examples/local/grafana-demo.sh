#!/usr/bin/env bash
# Test sesame against a REAL Grafana running locally. Proves that the session cookie sesame hands back actually
# logs you in — without the Grafana admin password ever reaching the "browser" (here, curl).
#
#   1. start Grafana:   docker run -d --name sesame-grafana -p 3000:3000 \
#                         -e GF_SECURITY_ADMIN_PASSWORD=s3cret-admin grafana/grafana:11.3.0
#   2. run this:        bash examples/local/grafana-demo.sh
#   3. cleanup:         docker rm -f sesame-grafana
set -euo pipefail
cd "$(dirname "$0")/../.."
RUN=examples/local/.run-grafana
GRAFANA=${GRAFANA:-http://127.0.0.1:3000}
GF_USER=${GF_USER:-admin}
GF_PASS=${GF_PASS:-s3cret-admin}
mkdir -p "$RUN"

echo "==> checking Grafana at $GRAFANA"
curl -fsS "$GRAFANA/api/health" >/dev/null || { echo "Grafana not reachable — start it first (see header)"; exit 1; }

echo "==> generating keys + configs"
go run ./cmd/sesame-keygen > "$RUN/keys.txt"
SEED=$(grep 'seed'      "$RUN/keys.txt" | awk '{print $NF}')
PUB=$(grep 'public key' "$RUN/keys.txt" | awk '{print $NF}')
printf '%s' "$SEED" > "$RUN/ticket-seed.hex"
printf 'dev-secret-%s' "$RANDOM" > "$RUN/dev-secret"

cat > "$RUN/catalog.yaml" <<EOF
tools:
  - id: grafana
    name: Local Grafana
    url: $GRAFANA
    login: grafana
    pool: local
    accounts:
      - label: admin
        ref: static://grafana-admin
EOF

cat > "$RUN/sesame-egress.yaml" <<EOF
listen: "127.0.0.1:8081"
pool: local
public_keys:
  - { key_id: k1, hex: "$PUB" }
EOF

cat > "$RUN/sesame-broker.yaml" <<EOF
listen: "127.0.0.1:8080"
login_timeout: 15s
identity: { type: dev, issuer: "https://idp.local/realms/demo", client_id: sesame-extension, secret_file: $RUN/dev-secret }
roles: { type: static }
credentials:
  type: static
  items:
    - { id: grafana-admin, username: "$GF_USER", password: "$GF_PASS", scopes: ["projects/demo/dev"] }
catalog: { type: file, path: $RUN/catalog.yaml }
policy:
  rules:
    - { group_pattern: "/projects/{p}/{env}", scopes: ["projects/{p}/{env}"] }
pools:
  - { name: local, egress_addr: "127.0.0.1:8081", sign_key_file: $RUN/ticket-seed.hex, key_id: k1, ticket_ttl: 30s }
default_pool: local
rate_limit: { max: 30, window: 1m }
EOF

echo "==> starting egress + broker"
go build -o "$RUN/sesame-egress" ./cmd/sesame-egress
go build -o "$RUN/sesame-broker" ./cmd/sesame-broker
"$RUN/sesame-egress" -config "$RUN/sesame-egress.yaml" >"$RUN/egress.log" 2>&1 & EG=$!
"$RUN/sesame-broker" -config "$RUN/sesame-broker.yaml" >"$RUN/broker.log" 2>&1 & BR=$!
trap 'kill $EG $BR 2>/dev/null || true' EXIT
sleep 2

TOKEN=$(go run ./cmd/sesame-keygen --dev-token "alice,$RUN/dev-secret,/projects/demo/dev" --ttl 1h)

echo "==> POST /v1/login — sesame logs into Grafana on alice's behalf"
RESP=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
            -d '{"tool":"grafana","account":"admin"}' http://127.0.0.1:8080/v1/login)
echo "$RESP"
COOKIE=$(printf '%s' "$RESP" | sed -n 's/.*"name":"grafana_session","value":"\([^"]*\)".*/\1/p')
[ -n "$COOKIE" ] || { echo "no session cookie returned"; exit 1; }

echo "==> using ONLY that cookie against Grafana (no password) -> who am I?"
curl -s -H "Cookie: grafana_session=$COOKIE" "$GRAFANA/api/user" | sed 's/.*/   &/'

echo
echo "==> proof: the Grafana admin password is NOT in sesame's logs:"
if grep -q "$GF_PASS" "$RUN"/*.log; then echo "   LEAK!"; else echo "   clean (no password in broker/egress logs)"; fi
echo "==> done."
