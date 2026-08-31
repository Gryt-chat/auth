#!/bin/sh
# Turns on brute-force protection and a password policy for the realm.
#
# Neither is in gryt-realm.json, and the omission is not a decision anybody
# made: the realm export simply never had them. Grepping it for
# bruteForceProtected, failureFactor, passwordPolicy or any recaptcha setting
# returns nothing, so out of the box a Gryt auth stack accepts unlimited login
# attempts against any account and any password a user cares to pick.
#
# That matters most on a deployment with open registration, where the only gate
# on joining is owning an email address (GRYT-743).
#
# A separate one-shot for the same reason apply_user_profile.sh is one: the
# settings have to be written through the admin API against a running server,
# and the last time realm-level configuration was put in the import file
# directly it stopped the whole stack from coming up (GRYT-136).
#
# Safe to re-run. The PUT is a partial update of the realm representation, so
# it leaves everything it does not name alone, and it has to run after every
# realm import because `--override true` deletes the realm and its settings
# with it.
set -eu

KC_URL="${KC_URL:-http://keycloak:8080}"
REALM="${GRYT_REALM:-gryt}"
ADMIN_USER="${GRYT_KEYCLOAK_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${GRYT_KEYCLOAK_ADMIN_PASSWORD:-admin}"

# Eight wrong passwords before a lockout starts, doubling from a minute and
# capped at fifteen. Temporary rather than permanent on purpose: a permanent
# lockout hands anybody who knows an email address a way to lock its owner out,
# which trades a brute-force problem for a denial-of-service one.
FAILURE_FACTOR="${GRYT_KC_FAILURE_FACTOR:-8}"
WAIT_INCREMENT="${GRYT_KC_WAIT_INCREMENT_SECONDS:-60}"
MAX_WAIT="${GRYT_KC_MAX_WAIT_SECONDS:-900}"
# How long a quiet account takes to forget its failures.
MAX_DELTA="${GRYT_KC_MAX_DELTA_SECONDS:-43200}"

# Length over composition, which is what NIST settled on: a long passphrase
# beats a short one with a symbol bolted onto the end, and composition rules
# mostly teach people to write Password1!. notUsername and notEmail stop the
# two guesses anybody would try first.
#
# This is checked when a password is set, not when one is used, so nobody is
# locked out by turning it on -- existing passwords keep working until they are
# next changed.
PASSWORD_POLICY="${GRYT_KC_PASSWORD_POLICY:-length(12) and notUsername and notEmail}"

log() { echo "[security-policy] $*"; }

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
  log "no admin token yet (attempt ${n}/10), retrying in 3s"
  sleep 3
done

if [ -z "${token}" ]; then
  log "ERROR: could not get an admin token as '${ADMIN_USER}' after 10 attempts."
  log "       Last response: ${body}"
  exit 1
fi

code=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${token}" "${KC_URL}/admin/realms/${REALM}")
if [ "${code}" = "404" ]; then
  log "realm '${REALM}' does not exist, nothing to configure."
  exit 0
fi
if [ "${code}" != "200" ]; then
  log "ERROR: GET /admin/realms/${REALM} returned ${code}."
  exit 1
fi

cat > /tmp/policy.json <<JSON
{
  "bruteForceProtected": true,
  "permanentLockout": false,
  "failureFactor": ${FAILURE_FACTOR},
  "waitIncrementSeconds": ${WAIT_INCREMENT},
  "maxFailureWaitSeconds": ${MAX_WAIT},
  "maxDeltaTimeSeconds": ${MAX_DELTA},
  "quickLoginCheckMilliSeconds": 1000,
  "minimumQuickLoginWaitSeconds": 60,
  "passwordPolicy": "${PASSWORD_POLICY}"
}
JSON

code=$(curl -sS -o /tmp/put.out -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/policy.json \
  "${KC_URL}/admin/realms/${REALM}")
if [ "${code}" != "204" ] && [ "${code}" != "200" ]; then
  log "ERROR: PUT /admin/realms/${REALM} returned ${code}."
  cat /tmp/put.out
  exit 1
fi

# Read it back rather than trusting the response code, the same way the user
# profile script does. A realm update that silently drops a field is exactly the
# failure this is meant to prevent.
current=$(curl -sS -H "Authorization: Bearer ${token}" "${KC_URL}/admin/realms/${REALM}")
field() { printf '%s' "${current}" | tr -d ' \n\t' | sed -n "s/.*\"$1\":\([^,}]*\).*/\1/p" | head -1; }

brute=$(field bruteForceProtected)
factor=$(field failureFactor)
if [ "${brute}" != "true" ]; then
  log "ERROR: bruteForceProtected did not take effect (got '${brute}')."
  exit 1
fi
if [ "${factor}" != "${FAILURE_FACTOR}" ]; then
  log "ERROR: failureFactor is '${factor}', wanted '${FAILURE_FACTOR}'."
  exit 1
fi

log "brute-force protection on: ${FAILURE_FACTOR} failures, ${WAIT_INCREMENT}s doubling to ${MAX_WAIT}s, forgotten after ${MAX_DELTA}s"
log "password policy: ${PASSWORD_POLICY}"
log "NOTE: registration has no captcha. That needs keys and an auth-flow change; see the README."
