#!/bin/bash
# The auth standby on Unraid (GRYT-2038). `check` runs nightly: it builds the standby from the newest pulled snapshot,
# checks it answers, and throws it away. `up` does the same and leaves it running, for when the VPS is gone.
set -euo pipefail

MODE="${1:-check}"
REPO="${REPO:-/mnt/user/appdata/gryt-auth-monitoring/auth}"
ENV_FILE="${ENV_FILE:-$REPO/.env.standby}"
SNAPSHOTS="${SNAPSHOTS:-/mnt/user/gryt-backups/auth-vps}"
AM="${AM:-http://127.0.0.1:19093}"
MIN_USERS="${MIN_USERS:-300}"
P=auth-standby
LIVE="$REPO/.standby-live"

dc() { docker compose -f "$REPO/docker-compose.keycloak.yml" --env-file "$ENV_FILE" -p "$P" "$@"; }
pg() { docker exec -i gryt-auth-postgres psql -q -v ON_ERROR_STOP=1 -U keycloak -d keycloak "$@"; }
throw_away() {
  dc down --remove-orphans >/dev/null 2>&1 || true
  docker volume rm -f "${P}_gryt-auth-postgres-data" "${P}_gryt-identity-data" >/dev/null 2>&1 || true
}
alert() {
  echo "standby $MODE failed: $1" >&2
  [[ "$MODE" == check ]] || return 0
  curl -fsS -m 5 -X POST -H 'Content-Type: application/json' "$AM/api/v2/alerts" -d "[{
    \"labels\": {\"alertname\": \"AuthStandbyRestoreFailed\", \"severity\": \"warning\"},
    \"annotations\": {\"summary\": \"The nightly auth restore on Unraid failed: $1\"},
    \"endsAt\": \"$(date -u -d '+12 hours' +%FT%TZ)\"}]" >/dev/null || true
}
trap 'alert "line $LINENO"' ERR

[[ "$MODE" == check || "$MODE" == up ]] || { echo "usage: $0 check|up" >&2; exit 2; }
# A realm import here would wipe the standby's copy, and in `up` mode that copy is the only live one.
grep -qx 'GRYT_IMPORT_REALM=0' "$ENV_FILE" || { alert "GRYT_IMPORT_REALM isn't 0 in $ENV_FILE"; exit 1; }

# Once `up` has run, the standby may hold the only copy of new sign-ups, so nothing here touches it again.
[[ -e "$LIVE" ]] && { echo "standby is live since $(cat "$LIVE"); remove $LIVE once it's retired" >&2; exit 0; }

snap="$(ls -1d "$SNAPSHOTS"/keycloak-* | sort | tail -n 1)"
echo "restoring $(basename "$snap")"
throw_away
if [[ "$MODE" == check ]]; then
  trap 'throw_away' EXIT
else
  # The tunnel connectors reach it from other boxes on the LAN; shell env wins over --env-file.
  export GRYT_KEYCLOAK_BIND=0.0.0.0 GRYT_IDENTITY_BIND=0.0.0.0
  date -u +%FT%TZ > "$LIVE"
fi

dc up -d --wait --no-deps postgres
gzip -dc "$snap/$(basename "$snap").sql.gz" | pg >/dev/null
docker run --rm -v "${P}_gryt-identity-data:/d" -v "$snap/identity:/s:ro" alpine \
  sh -c 'cp -a /s/. /d/ && chown -R 1001:1001 /d && chmod 600 /d/ca-key.pem'
dc up -d --wait --no-deps keycloak identity

users="$(pg -tA -c 'select count(*) from user_entity')"
(( users >= MIN_USERS )) || { alert "only $users users restored"; exit 1; }
curl -fsS -m 10 -H 'Host: auth.gryt.chat' -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:18080/realms/gryt/.well-known/openid-configuration | grep -q '"issuer":"https://auth.gryt.chat/realms/gryt"' \
  || { alert "keycloak didn't serve the realm"; exit 1; }
curl -fsS -m 10 http://127.0.0.1:18081/health | grep -q '"ok"' || { alert "identity isn't healthy"; exit 1; }

echo "standby $MODE ok: $(basename "$snap"), $users users"
