#!/bin/sh
# Sign in with Google and Apple, through the admin API. Safe to re-run, and it must: a realm import deletes them.
# A provider whose client id isn't set is left as it is, so nothing turns on until the keys exist.
set -eu

KC_URL="${KC_URL:-http://keycloak:8080}"
REALM="${GRYT_REALM:-gryt}"
ADMIN_USER="${GRYT_KEYCLOAK_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${GRYT_KEYCLOAK_ADMIN_PASSWORD:-admin}"
GOOGLE_ID="${GRYT_GOOGLE_CLIENT_ID:-}"
GOOGLE_SECRET="${GRYT_GOOGLE_CLIENT_SECRET:-}"
APPLE_ID="${GRYT_APPLE_SERVICES_ID:-}"
APPLE_TEAM="${GRYT_APPLE_TEAM_ID:-}"
APPLE_KEY_ID="${GRYT_APPLE_KEY_ID:-}"
APPLE_KEY="${GRYT_APPLE_PRIVATE_KEY:-}"

log() { echo "[identity-providers] $*"; }

if [ -z "${GOOGLE_ID}" ] && [ -z "${APPLE_ID}" ]; then
  log "Neither GRYT_GOOGLE_CLIENT_ID nor GRYT_APPLE_SERVICES_ID is set, nothing to configure."
  exit 0
fi
if [ -n "${GOOGLE_ID}" ] && [ -z "${GOOGLE_SECRET}" ]; then
  log "ERROR: GRYT_GOOGLE_CLIENT_ID is set but GRYT_GOOGLE_CLIENT_SECRET is not."
  exit 1
fi
if [ -n "${APPLE_ID}" ] && { [ -z "${APPLE_TEAM}" ] || [ -z "${APPLE_KEY_ID}" ] || [ -z "${APPLE_KEY}" ]; }; then
  log "ERROR: GRYT_APPLE_SERVICES_ID is set but GRYT_APPLE_TEAM_ID, GRYT_APPLE_KEY_ID or GRYT_APPLE_PRIVATE_KEY is not."
  exit 1
fi

token=""
n=0
while [ "${n}" -lt 10 ]; do
  n=$((n + 1))
  body=$(curl -sS -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d grant_type=password \
    --data-urlencode "username=${ADMIN_USER}" \
    --data-urlencode "password=${ADMIN_PASS}" 2>&1) || body=""
  token=$(printf '%s' "${body}" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  [ -n "${token}" ] && break
  reason=$(printf '%s' "${body}" | sed -n 's/.*"error_description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  log "no admin token yet (attempt ${n}/10)${reason:+ -- ${reason}}"
  sleep 3
done
if [ -z "${token}" ]; then
  log "ERROR: could not get an admin token as '${ADMIN_USER}'. The README's security-policy section covers why."
  exit 1
fi

base="${KC_URL}/admin/realms/${REALM}"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" "${base}")
if [ "${code}" = "404" ]; then
  log "realm '${REALM}' does not exist, nothing to configure."
  exit 0
fi

# Creates or updates one provider from /tmp/<alias>.json, then reads it back.
# A provider that silently trusts every email is the failure that matters here.
apply_provider() {
  alias="$1"
  exists=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" "${base}/identity-provider/instances/${alias}")
  if [ "${exists}" = "200" ]; then
    method=PUT
    url="${base}/identity-provider/instances/${alias}"
  else
    method=POST
    url="${base}/identity-provider/instances"
  fi
  code=$(curl -sS -o /tmp/idp.out -w '%{http_code}' -X "${method}" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    --data-binary "@/tmp/${alias}.json" "${url}")
  rm -f "/tmp/${alias}.json"
  case "${code}" in
    200 | 201 | 204) ;;
    *)
      log "ERROR: ${method} ${alias} returned ${code}."
      cat /tmp/idp.out
      exit 1
      ;;
  esac
  current=$(curl -sS -H "Authorization: Bearer ${token}" "${base}/identity-provider/instances/${alias}" | tr -d ' \n\t')
  case "${current}" in
    *'"trustEmail":false'*) ;;
    *)
      log "ERROR: ${alias} came back without trustEmail=false."
      exit 1
      ;;
  esac
  case "${current}" in
    *'"enabled":true'*) ;;
    *)
      log "ERROR: ${alias} came back disabled."
      exit 1
      ;;
  esac
  log "Sign in with ${alias} is on."
}

# trustEmail off, so a Google or Apple address still gets Gryt's own verification mail. The default first-login
# flow never links an existing account on email alone: it asks for that account's password or a mail link.
if [ -n "${GOOGLE_ID}" ]; then
  cat > /tmp/google.json <<JSON
{
  "alias": "google",
  "providerId": "google",
  "displayName": "Google",
  "enabled": true,
  "trustEmail": false,
  "storeToken": false,
  "linkOnly": false,
  "firstBrokerLoginFlowAlias": "first broker login",
  "config": {
    "clientId": "${GOOGLE_ID}",
    "clientSecret": "${GOOGLE_SECRET}",
    "defaultScope": "openid email profile",
    "syncMode": "IMPORT",
    "guiOrder": "1"
  }
}
JSON
  apply_provider google
fi

# The .p8 key is multi-line, so its newlines become \n to sit inside a JSON string.
if [ -n "${APPLE_ID}" ]; then
  apple_key=$(printf '%s' "${APPLE_KEY}" | awk 'BEGIN{ORS="\\n"} {print}')
  cat > /tmp/apple.json <<JSON
{
  "alias": "apple",
  "providerId": "apple",
  "displayName": "Apple",
  "enabled": true,
  "trustEmail": false,
  "storeToken": false,
  "linkOnly": false,
  "firstBrokerLoginFlowAlias": "first broker login",
  "config": {
    "clientId": "${APPLE_ID}",
    "clientSecret": "${apple_key}",
    "teamId": "${APPLE_TEAM}",
    "keyId": "${APPLE_KEY_ID}",
    "defaultScope": "openid email",
    "syncMode": "IMPORT",
    "guiOrder": "2"
  }
}
JSON
  apply_provider apple
fi
