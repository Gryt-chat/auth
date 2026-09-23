#!/usr/bin/env bash
set -euo pipefail

# Settings, and what each one means: ops/systemd/gryt-offsite-backup.env.example.
AUTH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKUP_DIR="${GRYT_AUTH_BACKUP_DIR:-${AUTH_DIR}/backups}"
HOST="${GRYT_OFFSITE_HOST:-}"
RECIPIENT="${GRYT_OFFSITE_RECIPIENT:-}"
SSH_KEY="${GRYT_OFFSITE_SSH_KEY:-}"
STALE_HOURS="${GRYT_OFFSITE_STALE_HOURS:-26}"
MIN_BYTES="${GRYT_OFFSITE_MIN_BYTES:-10000}"
WEBHOOK="${GRYT_OFFSITE_ALERT_WEBHOOK:-}"

read -r -a SSH_CMD <<<"${GRYT_OFFSITE_SSH:-ssh}"

log() { printf '%s  [offsite] %s\n' "$(date -Is)" "$*"; }

# Non-zero is the reporting channel that always works: systemd marks the unit
# failed and the reason is in the journal. The webhook is the one that pings.
fail() {
  local msg="$*" json
  log "FAILED: ${msg}"

  if [[ -n "${WEBHOOK}" ]]; then
    json="${msg//\\/\\\\}"
    json="${json//\"/\\\"}"
    curl -fsS -m 20 -H 'Content-Type: application/json' \
      -d "$(printf '{"content":"Keycloak off-site backup failed on %s: %s"}' "$(hostname)" "${json}")" \
      "${WEBHOOK}" >/dev/null || log "the alert webhook did not take the failure notice"
  fi

  exit 1
}

remote() {
  "${SSH_CMD[@]}" -i "${SSH_KEY}" -o BatchMode=yes -o ConnectTimeout=20 "${HOST}" "$@"
}

# GNU date on the deployment, BSD date so this is testable on a Mac.
dump_epoch() {
  local iso="${1:0:4}-${1:4:2}-${1:6:2}T${1:9:2}:${1:11:2}:${1:13:2}Z"
  date -u -d "${iso}" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "${iso}" +%s
}

[[ -n "${HOST}" ]] || fail "GRYT_OFFSITE_HOST is not set"
[[ -n "${RECIPIENT}" ]] || fail "GRYT_OFFSITE_RECIPIENT is not set"
[[ -n "${SSH_KEY}" ]] || fail "GRYT_OFFSITE_SSH_KEY is not set"
[[ -r "${SSH_KEY}" ]] || fail "cannot read the ssh key at ${SSH_KEY}"
[[ -d "${BACKUP_DIR}" ]] || fail "${BACKUP_DIR} is not a directory"
command -v age >/dev/null || fail "age is not installed"

# A recipients file and a bare age1... string take different flags, and the
# setup is easier to get right if both work.
if [[ -r "${RECIPIENT}" ]]; then
  recipient_arg=(-R "${RECIPIENT}")
else
  recipient_arg=(-r "${RECIPIENT}")
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/gryt-offsite.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

log "destination ${HOST}, dumps from ${BACKUP_DIR}"

listing="$(remote list </dev/null)" || fail "cannot list what is already off-site"

uploaded=0
present=0

while IFS= read -r dump; do
  [[ -n "${dump}" ]] || continue
  name="$(basename "${dump}").age"

  if grep -qxF "${name}" <<<"${listing}"; then
    present=$((present + 1))
    continue
  fi

  age "${recipient_arg[@]}" -o "${tmp}" "${dump}" || fail "age would not encrypt ${dump}"

  size="$(wc -c <"${tmp}" | tr -d ' ')"
  (( size >= MIN_BYTES )) || fail "${name} came out ${size} bytes, under the ${MIN_BYTES} floor"

  sum="$(sha256sum "${tmp}" | cut -d' ' -f1)"
  remote put "${name}" "${sum}" <"${tmp}" || fail "the far end would not take ${name}"

  uploaded=$((uploaded + 1))
done < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'keycloak-*.sql.gz' | sort)

remote prune </dev/null || fail "the off-site prune failed"

# Re-read rather than trusting the uploads above, so the staleness check is a
# statement about what is actually on the far end.
listing="$(remote list </dev/null)" || fail "cannot re-list what is off-site"

newest="$(grep -E '^keycloak-[0-9]{8}T[0-9]{6}Z\.sql\.gz\.age$' <<<"${listing}" | sort | tail -1 || true)"
[[ -n "${newest}" ]] || fail "there is nothing off-site at all"

stamp="${newest#keycloak-}"
stamp="${stamp%.sql.gz.age}"
hours=$(( ( $(date -u +%s) - $(dump_epoch "${stamp}") ) / 3600 ))

(( hours <= STALE_HOURS )) || fail "the newest copy off-site is from ${stamp}, ${hours}h ago, past the ${STALE_HOURS}h limit"

log "${uploaded} uploaded, ${present} already there, newest is ${hours}h old"
