#!/usr/bin/env bash
set -euo pipefail

# Helper to start Keycloak with local, non-committed secrets.
#
# Usage:
#   cp auth/.env.example auth/.env
#   # edit auth/.env to add Postmark token
#   ./auth/up.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_DIR="${ROOT_DIR}/auth"

if [[ -f "${AUTH_DIR}/.env" ]]; then
  # Use compose's dotenv parsing (doesn't require shell-quoting)
  exec docker compose --env-file "${AUTH_DIR}/.env" -f "${AUTH_DIR}/docker-compose.keycloak.yml" up -d
fi

echo "[auth/up.sh] Missing auth/.env. Copy auth/.env.example -> auth/.env and set GRYT_SMTP_USER/GRYT_SMTP_PASS." >&2
exec docker compose -f "${AUTH_DIR}/docker-compose.keycloak.yml" up -d

