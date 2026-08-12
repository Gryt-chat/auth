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

# The login theme is a jar built by Keycloakify, and compose mounts it as a
# file. If it is missing Docker creates a directory at that path instead, and
# Keycloak starts with no login theme and no obvious reason why — so build it
# here rather than let that happen.
THEME_JAR="${AUTH_DIR}/login-theme/dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar"
if [[ ! -f "${THEME_JAR}" ]]; then
  echo "[auth/up.sh] Login theme jar missing — building it (this needs Docker only)."
  "${AUTH_DIR}/login-theme/build.sh"
fi

compose() {
  if [[ -f "${AUTH_DIR}/.env" ]]; then
    # Use compose's dotenv parsing (doesn't require shell-quoting)
    docker compose --env-file "${AUTH_DIR}/.env" -f "${AUTH_DIR}/docker-compose.keycloak.yml" "$@"
  else
    docker compose -f "${AUTH_DIR}/docker-compose.keycloak.yml" "$@"
  fi
}

if [[ ! -f "${AUTH_DIR}/.env" ]]; then
  echo "[auth/up.sh] Missing auth/.env. Copy auth/.env.example -> auth/.env and set GRYT_SMTP_USER/GRYT_SMTP_PASS." >&2
fi

compose up -d

# `up` leaves an already-exited one-shot alone, so the profile would not be
# re-applied after a realm import wiped it. Recreating it explicitly is cheap —
# the container runs for about a second — and it is the only thing standing
# between a re-imported realm and registration failing again (GRYT-180).
compose up -d --force-recreate --no-deps keycloak-user-profile
