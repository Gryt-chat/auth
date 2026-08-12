#!/usr/bin/env bash
set -euo pipefail

if [[ "${GRYT_IMPORT_REALM:-0}" != "1" ]]; then
  echo "[keycloak-import] GRYT_IMPORT_REALM!=1, skipping realm import."
  exit 0
fi

# Refuse to import into a database a running Keycloak is holding open.
#
# `kc.sh import --override true` deletes the realm and recreates it. That is the
# documented behaviour and there is a backup taken first, but it is an *offline*
# operation: the running server keeps the old realm id in memory, so every
# request against the realm it was serving fails with
#
#   NullPointerException: Cannot invoke RealmModel.getAttribute ... realm is null
#
# and stays that way until the container is restarted. Every user in the realm is
# gone by then too.
#
# It is easy to hit by accident, because `docker compose up -d` re-runs this
# one-shot whenever its config changed while leaving `keycloak` running — the
# service's own definition did not change, so compose sees no reason to restart
# it. Measured: a user created a minute earlier was gone, the registration
# endpoint returned 500, and `.well-known/openid-configuration` still returned
# 200, so a readiness probe pointed at it reported the server healthy.
#
# Refusing rather than stopping Keycloak here: a container that takes auth down
# for the whole box as a side effect of an env var is worse than an error
# message, and the two-step is one command.
# The probe runs in a subshell so the descriptor goes away with it. Closing it
# here instead would be `exec 3>&-` in a shell that never opened it, and a failed
# redirection on a special builtin ends the script on the spot — which produced
# exactly the silent exit 1 this guard exists to replace.
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

# Warn rather than refuse.
#
# A realm without working SMTP cannot send a verification or reset email, which
# matters in production and does not matter at all locally — and requiring a
# Postmark token to bring a development realm up meant the only way to try this
# stack was to hold a production credential. The placeholders below still get
# substituted, just with empty values.
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

