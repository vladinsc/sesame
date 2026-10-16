#!/usr/bin/env bash
# Bring up and seed the full sesame demo stack. Idempotent-ish: safe to re-run.
#   Keycloak (OIDC) + Vaultwarden (credential store) + Grafana (target) + sesame broker/egress.
# Usage (from repo root):  bash examples/stack/bootstrap.sh
set -euo pipefail
cd "$(dirname "$0")"              # examples/stack
export MSYS_NO_PATHCONV=1
COMPOSE="docker compose -f docker-compose.yml"

mkdir -p .secrets
: > .secrets/bw.env               # ensure the env_file exists before compose reads it

echo "==> generating the ticket signing keypair"
( cd ../.. && go run ./cmd/sesame-keygen ) > .secrets/keys.txt
SEED=$(grep 'seed'       .secrets/keys.txt | awk '{print $NF}')
PUB=$(grep 'public key'  .secrets/keys.txt | awk '{print $NF}')
printf '%s' "$SEED" > sesame/ticket-seed.hex
cat > sesame/egress.yaml <<EOF
listen: ":8081"
pool: local
public_keys:
  - key_id: k1
    hex: "$PUB"
EOF

echo "==> starting Keycloak, Vaultwarden, Grafana (first run pulls images — be patient)"
$COMPOSE up -d keycloak vaultwarden grafana

echo "==> waiting for Vaultwarden to be healthy"
until [ "$($COMPOSE ps vaultwarden --format '{{.Health}}' 2>/dev/null)" = "healthy" ]; do sleep 2; done

echo "==> seeding Vaultwarden with the Grafana credential"
$COMPOSE run --rm seed

ITEM_ID=$(cat .secrets/item-id.txt)
echo "==> rendering catalog with item id ${ITEM_ID:0:8}…"
cat > sesame/catalog.yaml <<EOF
# Rendered by bootstrap.sh. url = what the browser opens; connect_to = where the egress dials in docker.
tools:
  - id: grafana
    name: Grafana
    url: http://localhost:3000
    connect_to: grafana:3000
    login: grafana
    pool: local
    accounts:
      - label: admin
        ref: "bitwarden://$ITEM_ID"
EOF

echo "==> building and starting bw-serve, egress, broker"
$COMPOSE up -d --build bw-serve egress broker

echo "==> waiting for the broker"
until curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; do sleep 2; done

cat <<EOF

================  sesame demo is up  ================
 Keycloak    http://localhost:8088/   (admin / admin)   realm: demo
 Vaultwarden http://localhost:8089/
 Grafana     http://localhost:3000/   (the target tool)
 Broker API  http://localhost:8080/

 Demo users (Keycloak):  alice / alice   (group /projects/demo/dev -> may open Grafana)
                         bob   / bob     (group /admins            -> may open Grafana)

 Next: load the extension in Brave (see examples/stack/README.md), click the sesame
 icon, Sign in as alice, then Open "Grafana" — you land logged in, no password typed.
=====================================================
EOF
