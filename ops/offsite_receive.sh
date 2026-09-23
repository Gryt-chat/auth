#!/bin/sh
set -eu

# The forced command for the backup key on the VPS. Install and authorized_keys
# line: README.md, "One copy out of the building".
DIR="${GRYT_OFFSITE_DIR:-${HOME}/keycloak}"

# Longer than the 30 days kept on dev on purpose: the two windows should not be
# able to end on the same day.
RETAIN_DAYS="${GRYT_OFFSITE_RETAIN_DAYS:-90}"

MAX_BYTES="${GRYT_OFFSITE_MAX_BYTES:-52428800}"
MIN_FREE_KB="${GRYT_OFFSITE_MIN_FREE_KB:-1048576}"

mkdir -p "${DIR}"

# Word splitting is the point: nothing here is ever handed to a shell.

# shellcheck disable=SC2086
set -- ${SSH_ORIGINAL_COMMAND:-}

verb="${1:-}"

refuse() {
  echo "[offsite-receive] refused: $1" >&2
  exit "$2"
}

# Both shapes the dumper produces. The pre-import ones are the dumps taken just
# before a realm import deletes every account, so they matter most of all.
valid_name() {
  case "$1" in
    */*|*..*) return 1 ;;
    keycloak-????????T??????Z.sql.gz.age) stamp="${1#keycloak-}" ;;
    keycloak-pre-import-????????T??????Z.sql.gz.age) stamp="${1#keycloak-pre-import-}" ;;
    *) return 1 ;;
  esac

  stamp="${stamp%Z.sql.gz.age}"
  case "${stamp}" in *[!0-9T]*) return 1 ;; esac
}

case "${verb}" in
  list)
    for f in "${DIR}"/keycloak-*.age; do
      [ -e "${f}" ] || continue
      basename "${f}"
    done
    ;;

  put)
    name="${2:-}"
    want="${3:-}"

    valid_name "${name}" || refuse "that is not a Keycloak dump name" 2
    [ "${#want}" -eq 64 ] || refuse "the checksum is not a sha256" 2
    case "${want}" in *[!0-9a-f]*) refuse "the checksum is not a sha256" 2 ;; esac

    free_kb="$(df -Pk "${DIR}" | awk 'NR == 2 { print $4 }')"
    [ "${free_kb}" -ge "${MIN_FREE_KB}" ] || refuse "only ${free_kb}K free here" 3

    # Never overwritten, so a machine that has been taken over can add copies
    # and cannot replace the ones already here with anything.
    if [ -e "${DIR}/${name}" ]; then
      echo "[offsite-receive] ${name} is already here, left alone"
      exit 0
    fi

    part="${DIR}/.${name}.part"
    trap 'rm -f "${part}"' EXIT

    head -c "$((MAX_BYTES + 1))" >"${part}"

    size="$(wc -c <"${part}" | tr -d ' ')"
    [ "${size}" -le "${MAX_BYTES}" ] || refuse "over the ${MAX_BYTES} byte cap" 3

    got="$(sha256sum "${part}" | cut -d' ' -f1)"
    [ "${got}" = "${want}" ] || refuse "${name} arrived with a different sha256" 4

    # Named only once the bytes are known to be the ones that were sent.
    mv "${part}" "${DIR}/${name}"
    echo "[offsite-receive] stored ${name} (${size} bytes)"
    ;;

  prune)
    find "${DIR}" -maxdepth 1 -type f -name 'keycloak-*.age' -mtime +"${RETAIN_DAYS}" -delete -print
    ;;

  *)
    refuse "this key may only run: list, put <name> <sha256>, prune" 2
    ;;
esac
