#!/usr/bin/env bash
# Makes sure the master realm has an administrator.
#
# KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD on the `keycloak` service only creates one
# when `start` finds no master realm. keycloak-import runs `kc.sh import` first,
# and that creates master as a side effect — so on a genuinely fresh database the
# admin is never created and the deployment comes up with no way in, and no way
# for keycloak-user-profile to do its job either. Nothing noticed, because every
# existing deployment predates the import service.
#
# `kc.sh bootstrap-admin user` does the same job as a separate offline step
# against the same database.
#
# It cannot be trusted to report itself: on a second run it exits 0 while logging
# a unique-constraint violation and "KC-SERVICES0010: Failed to add user". So the
# output is what gets read, not the exit code.
#
# Deliberately does not fail the stack on an unrecognised outcome — `keycloak`
# waits for this to complete, and a Keycloak that will not start is worse than an
# admin whose state we are unsure of. keycloak-user-profile needs a working admin
# a few seconds later and does fail loudly, so nothing stays quiet for long.
set -uo pipefail

USER_NAME="${GRYT_KEYCLOAK_ADMIN_USERNAME:-}"
if [[ -z "${USER_NAME}" || -z "${GRYT_KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
  echo "[bootstrap-admin] ERROR: GRYT_KEYCLOAK_ADMIN_USERNAME / _PASSWORD not set."
  exit 1
fi

if [[ "${GRYT_KEYCLOAK_ADMIN_PASSWORD}" == "admin" || "${GRYT_KEYCLOAK_ADMIN_PASSWORD}" == "change_me" ]]; then
  echo "[bootstrap-admin] WARNING: the admin password is still an example value."
  echo "[bootstrap-admin] Set GRYT_KEYCLOAK_ADMIN_PASSWORD in auth/.env before exposing this."
fi

out=$(/opt/keycloak/bin/kc.sh bootstrap-admin user --no-prompt \
  --username:env GRYT_KEYCLOAK_ADMIN_USERNAME \
  --password:env GRYT_KEYCLOAK_ADMIN_PASSWORD 2>&1)
rc=$?

if [[ ${rc} -ne 0 ]]; then
  echo "${out}"
  echo "[bootstrap-admin] ERROR: kc.sh bootstrap-admin exited ${rc}."
  exit "${rc}"
fi

# Every start after the first takes this branch. Keycloak logs the failed insert
# as a Hibernate warning and a stack trace, which is noise, not news.
if grep -qE "KC-SERVICES0010.*user with username exists|user with username exists" <<<"${out}"; then
  echo "[bootstrap-admin] Admin '${USER_NAME}' already exists, nothing to do."
  exit 0
fi

if grep -qE "KC-SERVICES0077|Added user '${USER_NAME}' to realm|Created temporary admin user" <<<"${out}"; then
  echo "[bootstrap-admin] Created admin '${USER_NAME}' in the master realm."
  exit 0
fi

echo "${out}"
echo "[bootstrap-admin] WARNING: could not tell whether admin '${USER_NAME}' was created."
echo "[bootstrap-admin] kc.sh exited 0 but said neither. Keycloak's wording may have"
echo "[bootstrap-admin] changed in an upgrade — check the output above, and check that"
echo "[bootstrap-admin] keycloak-user-profile could get a token."
exit 0
