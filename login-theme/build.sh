#!/usr/bin/env bash
# Builds the login theme JAR inside Docker and drops it in dist_keycloak/.
#
# Nothing is installed on the host: buildx writes the artifact stage straight
# out to the local filesystem.
set -euo pipefail

cd "$(dirname "$0")"

out="dist_keycloak"
rm -rf "$out"
mkdir -p "$out"

docker build \
  --target artifact \
  --build-arg "KC_THEME_NAME=${KC_THEME_NAME:-}" \
  --output "type=local,dest=$out" .

# Keycloakify emits one jar per Keycloak generation. We run 26.x, which falls
# under "all-other-versions" — the 22-to-25 jar is for older servers and picking
# it by accident gives a theme Keycloak will not load properly.
jar="$out/keycloak-theme-for-kc-all-other-versions.jar"

if [ ! -f "$jar" ]; then
  echo "build.sh: expected $jar, got:" >&2
  ls -1 "$out" >&2
  exit 1
fi

echo "built $jar ($(du -h "$jar" | cut -f1))"
echo "note: $out also holds a 22-to-25 jar for older Keycloak; we run 26.x."
