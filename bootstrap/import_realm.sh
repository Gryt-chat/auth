#!/usr/bin/env bash
set -euo pipefail

if [[ "${GRYT_IMPORT_REALM:-0}" != "1" ]]; then
  echo "[keycloak-import] GRYT_IMPORT_REALM!=1, skipping realm import."
  exit 0
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

