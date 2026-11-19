#!/bin/sh
# Sign in with Google, through the admin API. Safe to re-run, and it must: a realm import deletes it.
# A provider whose client id isn't set is left as it is, so nothing turns on until the keys exist.
set -eu

KC_URL="${KC_URL:-http://keycloak:8080}"
REALM="${GRYT_REALM:-gryt}"
ADMIN_USER="${GRYT_KEYCLOAK_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${GRYT_KEYCLOAK_ADMIN_PASSWORD:-admin}"
GOOGLE_ID="${GRYT_GOOGLE_CLIENT_ID:-}"
GOOGLE_SECRET="${GRYT_GOOGLE_CLIENT_SECRET:-}"

log() { echo "[identity-providers] $*"; }

if [ -z "${GOOGLE_ID}" ]; then
  log "GRYT_GOOGLE_CLIENT_ID is not set, nothing to configure."
  exit 0
fi
if [ -z "${GOOGLE_SECRET}" ]; then
  log "ERROR: GRYT_GOOGLE_CLIENT_ID is set but GRYT_GOOGLE_CLIENT_SECRET is not."
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

# trustEmail off, so a Google address still gets Gryt's own verification mail. The default first-login
# flow never links an existing account on email alone: it asks for that account's password or a mail link.
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

exists=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" "${base}/identity-provider/instances/google")
if [ "${exists}" = "200" ]; then
  method=PUT
  url="${base}/identity-provider/instances/google"
else
  method=POST
  url="${base}/identity-provider/instances"
fi
code=$(curl -sS -o /tmp/idp.out -w '%{http_code}' -X "${method}" \
  -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
  --data-binary @/tmp/google.json "${url}")
rm -f /tmp/google.json
case "${code}" in
  200 | 201 | 204) ;;
  *)
    log "ERROR: ${method} google returned ${code}."
    cat /tmp/idp.out
    exit 1
    ;;
esac

# Read it back: a provider that silently trusts every email is the failure that matters here.
current=$(curl -sS -H "Authorization: Bearer ${token}" "${base}/identity-provider/instances/google" | tr -d ' \n\t')
case "${current}" in
  *'"trustEmail":false'*) ;;
  *)
    log "ERROR: google came back without trustEmail=false."
    exit 1
    ;;
esac
case "${current}" in
  *'"enabled":true'*) ;;
  *)
    log "ERROR: google came back disabled."
    exit 1
    ;;
esac
log "Sign in with Google is on."
