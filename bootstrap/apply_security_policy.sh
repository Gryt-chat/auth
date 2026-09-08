#!/bin/sh
# Brute-force protection, a password policy and a failed-sign-in log, none of which is in
# gryt-realm.json. Safe to re-run, and it must — `--override true` deletes them.

# Out of the import file on purpose: realm-level config there took the whole stack down
# once (GRYT-136), and these have to go through the admin API against a running server.
set -eu

KC_URL="${KC_URL:-http://keycloak:8080}"
REALM="${GRYT_REALM:-gryt}"
ADMIN_USER="${GRYT_KEYCLOAK_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${GRYT_KEYCLOAK_ADMIN_PASSWORD:-admin}"

# Eight wrong passwords before a lockout, doubling from a minute and capped at fifteen.
# Temporary rather than permanent: a permanent lockout is a denial-of-service handle.
FAILURE_FACTOR="${GRYT_KC_FAILURE_FACTOR:-8}"
WAIT_INCREMENT="${GRYT_KC_WAIT_INCREMENT_SECONDS:-60}"
MAX_WAIT="${GRYT_KC_MAX_WAIT_SECONDS:-900}"
# How long a quiet account takes to forget its failures.
MAX_DELTA="${GRYT_KC_MAX_DELTA_SECONDS:-43200}"

# Four, on purpose: this password only guards the Keycloak login that vouches for the
# keypair. Raise it back if that changes, not because twelve reads safer (GRYT-979).

# Checked when a password is set, not when one is used, so turning it on locks nobody out.
PASSWORD_POLICY="${GRYT_KC_PASSWORD_POLICY:-length(4) and notUsername and notEmail}"

# Failed sign-ins, kept for thirty days (GRYT-1077). Failure types only: successful logins
# are already counted in Prometheus and would add an IP address per user per sign-in.
EVENTS_EXPIRATION="${GRYT_KC_EVENTS_EXPIRATION_SECONDS:-2592000}"
# Set to 0 only if something else already limits the admin realm.
APPLY_TO_MASTER="${GRYT_KC_APPLY_TO_MASTER:-1}"

EVENT_TYPES="${GRYT_KC_EVENT_TYPES:-LOGIN_ERROR REGISTER_ERROR RESET_PASSWORD_ERROR CODE_TO_TOKEN_ERROR REFRESH_TOKEN_ERROR}"

# Admin events stay off. Sivert is the only admin, so they would record one
# person configuring their own realm.

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

  # Say which failure this is instead of retrying ten times and reporting "could not get a
  # token": Keycloak answers invalid_grant for two different problems, both permanent.
  reason=$(printf '%s' "${body}" | sed -n 's/.*"error_description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  case "${reason}" in
    "Account disabled")
      log "ERROR: '${ADMIN_USER}' exists but is disabled. Retrying will not help."
      log "       On gryt.chat that account is disabled on purpose. Make a temporary"
      log "       admin instead -- it needs no restart and leaves '${ADMIN_USER}' alone:"
      log "         docker exec -e PW=... <keycloak container> \\"
      log "           /opt/keycloak/bin/kc.sh bootstrap-admin user \\"
      log "           --username tmpadmin --password:env PW --no-prompt"
      log "       Then re-run this with GRYT_KEYCLOAK_ADMIN_USERNAME=tmpadmin, and"
      log "       delete the user afterwards. See the README."
      exit 1
      ;;
    "Invalid user credentials")
      log "ERROR: '${ADMIN_USER}' exists and is enabled, but the password is wrong."
      log "       Retrying will not help. GRYT_KEYCLOAK_ADMIN_PASSWORD in .env is a"
      log "       placeholder on some deployments, so this is what a stale default"
      log "       looks like. Pass the real one with -e on docker compose run."
      exit 1
      ;;
  esac

  log "no admin token yet (attempt ${n}/10), retrying in 3s${reason:+ -- ${reason}}"
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

# Space-separated in the environment, a JSON array in the request.
event_types_json=$(printf '%s' "${EVENT_TYPES}" | tr -s ' ' '\n' | sed '/^$/d;s/.*/"&"/' | paste -sd, -)

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

# Read it back rather than trusting the response code. A realm update that silently drops a
# field is exactly the failure this is meant to prevent.
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

# Events have their own endpoint. They are part of the realm representation, but a GET does
# not reliably return them, so the read-back below would have nothing to check.
cat > /tmp/events.json <<JSON
{
  "eventsEnabled": true,
  "eventsExpiration": ${EVENTS_EXPIRATION},
  "enabledEventTypes": [${event_types_json}],
  "adminEventsEnabled": false,
  "adminEventsDetailsEnabled": false
}
JSON

code=$(curl -sS -o /tmp/events.out -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/events.json \
  "${KC_URL}/admin/realms/${REALM}/events/config")
if [ "${code}" != "204" ] && [ "${code}" != "200" ]; then
  log "ERROR: PUT /admin/realms/${REALM}/events/config returned ${code}."
  cat /tmp/events.out
  exit 1
fi

current=$(curl -sS -H "Authorization: Bearer ${token}" \
  "${KC_URL}/admin/realms/${REALM}/events/config")
events=$(field eventsEnabled)
expiry=$(field eventsExpiration)
if [ "${events}" != "true" ]; then
  log "ERROR: eventsEnabled did not take effect (got '${events}')."
  exit 1
fi
# Checked because the default is 0, which means keep forever: a silent drop turns a
# thirty-day security log into an unbounded store of IP addresses.
if [ "${expiry}" != "${EVENTS_EXPIRATION}" ]; then
  log "ERROR: eventsExpiration is '${expiry}', wanted '${EVENTS_EXPIRATION}'."
  exit 1
fi

log "brute-force protection on: ${FAILURE_FACTOR} failures, ${WAIT_INCREMENT}s doubling to ${MAX_WAIT}s, forgotten after ${MAX_DELTA}s"
log "password policy: ${PASSWORD_POLICY}"
log "failed-event log on: ${EVENT_TYPES}, kept ${EVENTS_EXPIRATION}s"
# Deliberately does not say "registration has no captcha": GRYT-782 put a Cloudflare Managed
# Challenge in front of the registration path, where this script cannot see it.

# The master realm, which inherits nothing and until GRYT-1080 took unlimited guesses. Same
# numbers as gryt, not stricter: locking this account out locks everybody out of the fix.

# No password policy here: it only applies when a password is set, so it would do nothing
# for the existing one and could block a passphrase you want.
if [ "${APPLY_TO_MASTER}" = "1" ]; then
  cat > /tmp/master-policy.json <<JSON
{
  "bruteForceProtected": true,
  "permanentLockout": false,
  "failureFactor": ${FAILURE_FACTOR},
  "waitIncrementSeconds": ${WAIT_INCREMENT},
  "maxFailureWaitSeconds": ${MAX_WAIT},
  "maxDeltaTimeSeconds": ${MAX_DELTA},
  "quickLoginCheckMilliSeconds": 1000,
  "minimumQuickLoginWaitSeconds": 60
}
JSON

  code=$(curl -sS -o /tmp/master-put.out -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data-binary @/tmp/master-policy.json \
    "${KC_URL}/admin/realms/master")
  if [ "${code}" != "204" ] && [ "${code}" != "200" ]; then
    log "ERROR: PUT /admin/realms/master returned ${code}."
    cat /tmp/master-put.out
    exit 1
  fi

  current=$(curl -sS -H "Authorization: Bearer ${token}" "${KC_URL}/admin/realms/master")
  master_brute=$(field bruteForceProtected)
  if [ "${master_brute}" != "true" ]; then
    log "ERROR: bruteForceProtected did not take effect on master (got '${master_brute}')."
    exit 1
  fi
  log "master realm brute-force protection on: same ${FAILURE_FACTOR}/${WAIT_INCREMENT}s/${MAX_WAIT}s as ${REALM}"
fi

log "note: no captcha in the Keycloak flow. On gryt.chat the challenge is at the edge; see the README before adding one."
