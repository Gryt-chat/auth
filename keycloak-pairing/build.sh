#!/usr/bin/env bash
# Builds the pairing extension in Docker into a temp directory, then renames it into dist/.
# Same shape as login-theme/build.sh, so a failed build never leaves the mounted jar missing.
set -euo pipefail

cd "$(dirname "$0")"

out="dist"
name="gryt-pairing.jar"
tmp="$(mktemp -d "${out}.tmp.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

docker build --target artifact --output "type=local,dest=$tmp" .

if [ ! -f "$tmp/$name" ]; then
  echo "build.sh: expected $name, got:" >&2
  ls -1 "$tmp" >&2
  echo "build.sh: $out left untouched." >&2
  exit 1
fi

mkdir -p "$out"
# Compose makes an empty directory here if it ran before the jar existed; mv would go inside it.
if [ -d "$out/$name" ]; then rmdir "$out/$name"; fi
mv -f "$tmp/$name" "$out/$name"

echo "built $out/$name ($(du -h "$out/$name" | cut -f1))"
echo "note: Keycloak reads providers at startup, so this needs a restart of the keycloak container."
