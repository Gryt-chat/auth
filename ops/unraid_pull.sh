#!/bin/bash
# Runs on Unraid as a User Script, hourly at :10, after the VPS dumps on the hour.
# Pulls the newest auth snapshot onto the parity array and keeps KEEP_DAYS of them.
set -euo pipefail

VPS="${VPS:-root@193.200.238.156}"
KEY="${KEY:-/boot/config/gryt-backup/id_ed25519_auth}"
DEST="${DEST:-/mnt/user/gryt-backups/auth-vps}"
KEEP_DAYS="${KEEP_DAYS:-30}"

mkdir -p "$DEST"
tmp="$(mktemp -d "$DEST/.incoming.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# The key only runs vps_backup_export.sh there, whatever is asked. Its own known_hosts,
# because /root/.ssh is on the flash drive.
ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$(dirname "$KEY")/known_hosts" "$VPS" true | tar -C "$tmp" -xf -
snap="$(ls "$tmp")"
[[ -n "$snap" && -s "$tmp/$snap/identity/ca-key.pem" ]] || { echo "pulled nothing usable" >&2; exit 1; }
gzip -t "$tmp/$snap/$snap.sql.gz"

if [[ -e "$DEST/$snap" ]]; then
  echo "$snap already here"
else
  mv "$tmp/$snap" "$DEST/"
  echo "pulled $snap ($(du -sh "$DEST/$snap" | cut -f1))"
fi

find "$DEST" -mindepth 1 -maxdepth 1 -type d -name 'keycloak-*' -mtime "+$KEEP_DAYS" -exec rm -rf {} +
