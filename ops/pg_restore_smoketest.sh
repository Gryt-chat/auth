#!/usr/bin/env bash
set -euo pipefail

backup="${1:-}"
if [[ -z "${backup}" || ! -f "${backup}" ]]; then
  echo "Usage: $0 path/to/keycloak-<timestamp>.sql.gz" >&2
  exit 2
fi

name="gryt-auth-restore-pg"
port="${PG_RESTORE_PORT:-55432}"
pass="${PG_RESTORE_PASSWORD:-restore_test_password}"
db="${PG_RESTORE_DB:-keycloak}"
user="${PG_RESTORE_USER:-keycloak}"

cleanup() {
  docker rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
docker run -d --name "${name}" -e POSTGRES_DB="${db}" -e POSTGRES_USER="${user}" -e POSTGRES_PASSWORD="${pass}" -p "127.0.0.1:${port}:5432" postgres:16-alpine >/dev/null

echo "[pg_restore_smoketest] Waiting for Postgres..."
for _ in $(seq 1 60); do
  if docker exec "${name}" pg_isready -U "${user}" -d "${db}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[pg_restore_smoketest] Restoring ${backup}..."
gzip -dc "${backup}" | docker exec -i "${name}" psql -U "${user}" -d "${db}" >/dev/null

# Simple sanity check: Keycloak should have a `realm` table.
echo "[pg_restore_smoketest] Verifying schema..."
docker exec "${name}" psql -U "${user}" -d "${db}" -c "select count(*) from realm;" >/dev/null

echo "[pg_restore_smoketest] OK"

