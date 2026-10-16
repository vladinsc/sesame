#!/usr/bin/env bash
# Self-contained local demo of sesame. Generates fresh keys into examples/local/.run/ (gitignored), starts a
# fake Grafana-like tool + the egress proxy + the broker, then performs an allowed and a denied login.
# No cluster, no real credentials. Requires Go. Run from the repo root: bash examples/local/demo.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
RUN=examples/local/.run
mkdir -p "$RUN"

echo "==> generating ed25519 ticket keypair and a dev HMAC secret"
go run ./cmd/sesame-keygen > "$RUN/keys.txt"
SEED=$(grep 'seed'       "$RUN/keys.txt" | awk '{print $NF}')
PUB=$(grep 'public key'  "$RUN/keys.txt" | awk '{print $NF}')
printf '%s' "$SEED" > "$RUN/ticket-seed.hex"
printf 'dev-hmac-secret-%s' "$RANDOM" > "$RUN/dev-secret"

echo "==> rendering configs"
cp examples/local/catalog.yaml "$RUN/catalog.yaml"
cat > "$RUN/sesame-egress.yaml" <<EOF
listen: "127.0.0.1:8081"
pool: local
public_keys:
  - key_id: k1
    hex: "$PUB"
EOF
sed -e "s#examples/local/dev-secret#$RUN/dev-secret#" \
    -e "s#examples/local/catalog.yaml#$RUN/catalog.yaml#" \
    -e "s#examples/local/ticket-seed.hex#$RUN/ticket-seed.hex#" \
    examples/local/sesame-broker.yaml > "$RUN/sesame-broker.yaml"

echo "==> building binaries"
go build -o "$RUN/faketool"       ./examples/local/faketool
go build -o "$RUN/sesame-egress"  ./cmd/sesame-egress
go build -o "$RUN/sesame-broker"  ./cmd/sesame-broker

echo "==> starting servers"
"$RUN/faketool" -addr 127.0.0.1:3000           >"$RUN/faketool.log" 2>&1 &  FT=$!
"$RUN/sesame-egress" -config "$RUN/sesame-egress.yaml" >"$RUN/egress.log" 2>&1 & EG=$!
"$RUN/sesame-broker" -config "$RUN/sesame-broker.yaml" >"$RUN/broker.log" 2>&1 & BR=$!
trap 'kill $FT $EG $BR 2>/dev/null || true' EXIT
sleep 2

echo "==> minting a dev token for user u1 in group /projects/demo/dev"
TOKEN=$(go run ./cmd/sesame-keygen --dev-token "u1,$RUN/dev-secret,/projects/demo/dev" --ttl 1h)

echo "==> GET /v1/catalog"
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/catalog; echo
echo "==> POST /v1/login (admin, allowed) -> returns a session cookie, never the password"
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"tool":"demo-grafana","account":"admin"}' http://127.0.0.1:8080/v1/login; echo
echo "==> POST /v1/login (viewer, prod scope the user lacks) -> 403"
curl -s -o /dev/null -w 'status %{http_code}\n' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"tool":"demo-grafana","account":"viewer"}' http://127.0.0.1:8080/v1/login

echo "==> done. logs in $RUN/*.log"
