#!/usr/bin/env bash
# Builds the login theme JAR inside Docker into a temp directory, then renames it into
# dist_keycloak/. Deleting the mounted jar first left the deployment with none (2026-09-01).
set -euo pipefail

cd "$(dirname "$0")"

out="dist_keycloak"
tmp="$(mktemp -d "${out}.tmp.XXXXXX")"
# Same directory as `out`, so the move is a rename rather than a copy, and a leftover temp
# dir from a killed run is obvious. Removed on any exit, including an interrupt.
trap 'rm -rf "$tmp"' EXIT INT TERM

docker build \
  --target artifact \
  --build-arg "KC_THEME_NAME=${KC_THEME_NAME:-}" \
  --output "type=local,dest=$tmp" .

# Keycloakify emits one jar per Keycloak generation. We run 26.x, which is
# "all-other-versions"; the 22-to-25 jar gives a theme Keycloak will not load properly.
name="keycloak-theme-for-kc-all-other-versions.jar"

if [ ! -f "$tmp/$name" ]; then
  echo "build.sh: expected $name, got:" >&2
  ls -1 "$tmp" >&2
  echo "build.sh: dist_keycloak left untouched." >&2
  exit 1
fi

# Only now. Everything above can fail without the deployment noticing.
mkdir -p "$out"
for jar in "$tmp"/*.jar; do
  mv -f "$jar" "$out/$(basename "$jar")"
done

echo "built $out/$name ($(du -h "$out/$name" | cut -f1))"
echo "note: $out also holds a 22-to-25 jar for older Keycloak; we run 26.x."
echo "note: Keycloak reads providers at startup, so this needs a restart to take effect."
