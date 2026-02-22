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

echo "[pg_backup] Writing ${out}"
 "${compose[@]}" exec -T postgres sh -lc "pg_dump -U \"${user}\" -d \"${db}\"" | gzip -c > "${out}"
echo "[pg_backup] Done"

