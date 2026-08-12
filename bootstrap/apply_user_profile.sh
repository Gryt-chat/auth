#!/bin/sh
# Applies the realm's declarative User Profile.
#
# Why this is a separate one-shot container rather than part of the realm import:
#
#   - A "userProfile" block inside gryt-realm.json is not importable. Keycloak
#     rejects the realm and the whole auth stack fails to come up (GRYT-136).
#   - import_realm.sh runs `kc.sh import` *before* Keycloak starts, so it has no
#     admin API to call. The endpoint used here only exists on a running server.
#
# Without it the realm falls back to Keycloak's built-in profile, which marks
# firstName and lastName required. The realm sets registrationEmailAsUsername,
# and the Gryt login theme hides both name fields, so registration is rejected
# on inputs nobody can see and the failure is silent (GRYT-180). Production
# already runs a profile that collects email only; this is what puts every other
# deployment in the same state.
#
# Safe to re-run: the PUT is idempotent, and it has to run after every realm
# import, because `--override true` deletes the realm and takes the profile
# with it. The flip side is that this file is the source of truth — an edit made
# in the admin console is reverted on the next `up`.
set -eu

KC_URL="${KC_URL:-http://keycloak:8080}"
REALM="${GRYT_REALM:-gryt}"
PROFILE_FILE="${PROFILE_FILE:-/bootstrap/gryt-user-profile.json}"
ADMIN_USER="${GRYT_KEYCLOAK_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${GRYT_KEYCLOAK_ADMIN_PASSWORD:-admin}"

log() { echo "[user-profile] $*"; }

if [ "${GRYT_IMPORT_REALM:-0}" = "1" ]; then
  log "realm was just re-imported, so the profile has reverted to Keycloak's default."
fi

if [ ! -f "${PROFILE_FILE}" ]; then
  log "ERROR: ${PROFILE_FILE} not found."
  exit 1
fi

# Keycloak reports ready slightly before the master realm will issue tokens on a
# first-ever start, so a healthy container is necessary but not always enough.
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
  log "       KC_BOOTSTRAP_ADMIN_* only applies on a first start against an empty"
  log "       database; if the admin password was changed since, update"
  log "       GRYT_KEYCLOAK_ADMIN_PASSWORD in auth/.env to match."
  exit 1
fi

# A realm that was never imported has no profile to set, and that is not an
# error — it is a stack brought up with GRYT_IMPORT_REALM unset.
code=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${token}" "${KC_URL}/admin/realms/${REALM}")
if [ "${code}" = "404" ]; then
  log "realm '${REALM}' does not exist, nothing to configure."
  log "Set GRYT_IMPORT_REALM=1 to import it, then bring the stack up again."
  exit 0
fi
if [ "${code}" != "200" ]; then
  log "ERROR: GET /admin/realms/${REALM} returned ${code}."
  exit 1
fi

code=$(curl -sS -o /tmp/put.out -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  --data-binary "@${PROFILE_FILE}" \
  "${KC_URL}/admin/realms/${REALM}/users/profile")
if [ "${code}" != "200" ]; then
  log "ERROR: PUT users/profile returned ${code}."
  cat /tmp/put.out
  exit 1
fi

# Read it back rather than trusting the 200. Comparing the set of names, rather
# than looking for firstName specifically, means this keeps checking the right
# thing if the file changes later.
names() { tr -d ' \n\t' | tr ',' '\n' | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' '; }

want=$(names < "${PROFILE_FILE}")
got=$(curl -sS -H "Authorization: Bearer ${token}" \
  "${KC_URL}/admin/realms/${REALM}/users/profile" | names)

if [ "${want}" != "${got}" ]; then
  log "ERROR: profile did not take effect."
  log "       wanted: ${want}"
  log "       got:    ${got}"
  exit 1
fi

log "applied, realm '${REALM}' now collects: ${want}"
