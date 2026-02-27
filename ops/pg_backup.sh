#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUTH_DIR="${ROOT_DIR}/auth"

mkdir -p "${AUTH_DIR}/backups"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="${AUTH_DIR}/backups/keycloak-${ts}.sql.gz"

compose=(docker compose -f "${AUTH_DIR}/docker-compose.keycloak.yml")
if [[ -f "${AUTH_DIR}/.env" ]]; then
  compose+=(--env-file "${AUTH_DIR}/.env")
fi

db="${GRYT_AUTH_POSTGRES_DB:-keycloak}"
user="${GRYT_AUTH_POSTGRES_USER:-keycloak}"
retain_days="${GRYT_BACKUP_RETAIN_DAYS:-30}"

echo "[pg_backup] Writing ${out}"
"${compose[@]}" exec -T postgres sh -lc "pg_dump -U \"${user}\" -d \"${db}\"" | gzip -c > "${out}"
echo "[pg_backup] Done ($(du -h "${out}" | cut -f1))"

pruned=0
while IFS= read -r -d '' f; do
  rm -f "${f}"
  echo "[pg_backup] Pruned ${f}"
  ((pruned++)) || true
done < <(find "${AUTH_DIR}/backups" -name 'keycloak-*.sql.gz' -mtime +"${retain_days}" -print0)

if (( pruned > 0 )); then
  echo "[pg_backup] Pruned ${pruned} backup(s) older than ${retain_days} days"
fi
