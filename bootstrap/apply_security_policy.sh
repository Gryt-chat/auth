#!/bin/sh
# Turns on brute-force protection, a password policy, and a log of failed
# sign-ins for the realm.
#
# None of them is in gryt-realm.json, and the omission is not a decision anybody
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

# Four, which is short on purpose. A Gryt account is protected by its keypair;
# this password only guards the Keycloak login that vouches for that keypair, so
# the length is traded away for less friction signing up. notUsername and
# notEmail stay -- they are the two guesses anybody tries first and they cost
# nothing.
#
# It was length(12) until GRYT-979, on the NIST argument that a long passphrase
# beats a short one with a symbol bolted onto the end. That argument is sound
# for a password doing the whole job of protecting an account. It is not doing
# that job here. Raise it back if that changes, rather than because twelve reads
# safer than four.
#
# This is checked when a password is set, not when one is used, so nobody is
# locked out by turning it on -- existing passwords keep working until they are
# next changed.
PASSWORD_POLICY="${GRYT_KC_PASSWORD_POLICY:-length(4) and notUsername and notEmail}"

# Failed sign-ins, kept for thirty days.
#
# The realm stored nothing at all until GRYT-1077: events_enabled was false and
# event_entity was empty, so brute-force protection could fire without leaving
# any record that it had. keycloak_user_events_total is scraped and counts the
# same failures, but a counter has no timestamp, client or origin, so it cannot
# separate one misconfigured client from somebody working through a list. Over
# the life of the realm it had logged 133 invalid_redirect_uri rejections and
# there was no way to tell which of the two that was.
#
# Failure types only. Successful logins are the high-volume half and are already
# counted in Prometheus, so storing them would add an IP address per user per
# sign-in and answer nothing the counter does not. REFRESH_TOKEN is worse again:
# 60,543 of those against 58 logins.
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

# Events have their own endpoint. They are part of the realm representation, but
# a GET on the realm does not reliably return them, so setting them in the PUT
# above would leave the read-back below with nothing to check and this script
# would fail on a realm it had configured correctly.
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
# Checked because the default is 0, which means keep forever. A silent drop of
# this field turns a thirty-day security log into an unbounded store of IP
# addresses, which is the one outcome the privacy policy does not allow.
if [ "${expiry}" != "${EVENTS_EXPIRATION}" ]; then
  log "ERROR: eventsExpiration is '${expiry}', wanted '${EVENTS_EXPIRATION}'."
  exit 1
fi

log "brute-force protection on: ${FAILURE_FACTOR} failures, ${WAIT_INCREMENT}s doubling to ${MAX_WAIT}s, forgotten after ${MAX_DELTA}s"
log "password policy: ${PASSWORD_POLICY}"
log "failed-event log on: ${EVENT_TYPES}, kept ${EVENTS_EXPIRATION}s"
# Deliberately does not say "registration has no captcha", which is what this
# line used to say. It is true of the Keycloak flow and false of the deployment:
# GRYT-782 put a Cloudflare Managed Challenge in front of the registration path,
# where this script cannot see it. Read literally, the old wording sent people
# off to buy reCAPTCHA keys for something already partly covered.
# The master realm, which until GRYT-1080 had none of the above.
#
# Everything so far applies to ${REALM}, which is `gryt`. Master is a different
# realm and inherits nothing, so the admin plane -- the one account that can
# reconfigure every other realm -- accepted unlimited password guesses while end
# users were limited to eight.
#
# Cloudflare restricts /admin on auth.gryt.chat to Norway, so this was never open
# to the whole internet. It is not a lockout either: a Norwegian address, or any
# VPN with a Norwegian exit, reaches Keycloak and gets to keep guessing.
#
# Same numbers as the gryt realm rather than stricter ones. Tempting to lock
# harder on the admin realm, but the account is reachable by name, so a short
# lockout somebody can trigger deliberately is the safer trade -- the same
# reasoning as permanentLockout above, and it matters more here, because locking
# this account out locks everybody out of fixing it.
#
# No password policy. It is only checked when a password is set, so it would do
# nothing for the existing one and could block a passphrase Sivert wants.
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
