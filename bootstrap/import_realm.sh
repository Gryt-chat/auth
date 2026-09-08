#!/usr/bin/env bash
set -euo pipefail

if [[ "${GRYT_IMPORT_REALM:-0}" != "1" ]]; then
  echo "[keycloak-import] GRYT_IMPORT_REALM!=1, skipping realm import."
  exit 0
fi

# Refuse to import into a database a running Keycloak is holding open: `--override true`
# deletes the realm and every user in it, and the running server then 500s until restarted.

# The probe runs in a subshell so the descriptor goes away with it: `exec 3>&-` in a shell
# that never opened it is a failed redirection, which ends the script on the spot.
if (exec 3<>/dev/tcp/keycloak/8080) 2>/dev/null; then
  echo "[keycloak-import] ERROR: Keycloak is running. Refusing to import." >&2
  echo "[keycloak-import]" >&2
  echo "[keycloak-import] The import deletes the realm and recreates it, which a running" >&2
  echo "[keycloak-import] server cannot survive — it serves 500s until restarted, and every" >&2
  echo "[keycloak-import] user in the realm is lost." >&2
  echo "[keycloak-import]" >&2
  echo "[keycloak-import] Stop it first, then bring the stack up again:" >&2
  echo "[keycloak-import]   docker compose -f docker-compose.keycloak.yml stop keycloak" >&2
  echo "[keycloak-import]   docker compose -f docker-compose.keycloak.yml up -d" >&2
  echo "[keycloak-import]" >&2
  echo "[keycloak-import] Set GRYT_IMPORT_REALM=0 if you did not mean to import at all." >&2
  exit 1
fi

# Warn rather than refuse. A realm without working SMTP cannot send a verification email,
# which matters in production and not locally; the placeholders still get substituted.
if [[ -z "${GRYT_SMTP_USER:-}" || -z "${GRYT_SMTP_PASS:-}" ]]; then
  echo "[keycloak-import] WARNING: GRYT_SMTP_USER / GRYT_SMTP_PASS not set."
  echo "[keycloak-import] Importing without working SMTP — this realm cannot send email."
  echo "[keycloak-import] For a deployment that needs it, set both in auth/.env."
fi

tmp="/tmp/gryt-import"
rm -rf "${tmp}"
mkdir -p "${tmp}"
cp -a /opt/keycloak/data/import-src/. "${tmp}/"

# Escape values for sed replacement (handles &, | and backslashes).
esc() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

sed -i \
  -e "s|__GRYT_SMTP_HOST__|$(esc "${GRYT_SMTP_HOST:-}")|g" \
  -e "s|__GRYT_SMTP_PORT__|$(esc "${GRYT_SMTP_PORT:-}")|g" \
  -e "s|__GRYT_SMTP_FROM__|$(esc "${GRYT_SMTP_FROM:-}")|g" \
  -e "s|__GRYT_SMTP_FROM_NAME__|$(esc "${GRYT_SMTP_FROM_NAME:-}")|g" \
  -e "s|__GRYT_SMTP_REPLY_TO__|$(esc "${GRYT_SMTP_REPLY_TO:-}")|g" \
  -e "s|__GRYT_SMTP_REPLY_TO_NAME__|$(esc "${GRYT_SMTP_REPLY_TO_NAME:-}")|g" \
  -e "s|__GRYT_SMTP_USER__|$(esc "${GRYT_SMTP_USER:-}")|g" \
  -e "s|__GRYT_SMTP_PASS__|$(esc "${GRYT_SMTP_PASS:-}")|g" \
  "${tmp}/gryt-realm.json"

if grep -q "__GRYT_SMTP_" "${tmp}/gryt-realm.json"; then
  echo "[keycloak-import] ERROR: SMTP placeholders were not fully replaced."
  exit 1
fi

exec /opt/keycloak/bin/kc.sh import --dir "${tmp}" --override true

