#!/bin/sh
# The forced command for Unraid's key on the VPS (GRYT-2034): the newest dump and the identity
# volume as one tar on stdout, under a folder named after the dump. Unraid pulls; the VPS never reaches in.
set -eu

BACKUP_DIR="${GRYT_AUTH_BACKUP_DIR:-/opt/gryt-auth/backups}"
VOLUME="${GRYT_IDENTITY_VOLUME:-/var/lib/docker/volumes/auth_gryt-identity-data}"

dump="$(cd "$BACKUP_DIR" && ls -1 keycloak-*.sql.gz 2>/dev/null | sort | tail -n 1)"
[ -n "$dump" ] || { echo "no dumps in $BACKUP_DIR" >&2; exit 1; }
gzip -t "$BACKUP_DIR/$dump" || { echo "$dump does not decompress" >&2; exit 1; }
[ -s "$VOLUME/_data/ca-key.pem" ] || { echo "no ca-key.pem in $VOLUME" >&2; exit 1; }

snap="${dump%.sql.gz}"
tar -cf - \
  --transform "s,^keycloak-,$snap/keycloak-," --transform "s,^_data,$snap/identity," \
  -C "$BACKUP_DIR" "$dump" -C "$VOLUME" _data
