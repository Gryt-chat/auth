#!/usr/bin/env bash
# Builds the login theme JAR inside Docker and drops it in dist_keycloak/.
#
# Nothing is installed on the host: buildx writes the artifact stage straight
# out to the local filesystem.
#
# ## Why this builds somewhere else first
#
# dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar is bind-mounted
# into the running Keycloak (docker-compose.keycloak.yml). This script used to
# `rm -rf` that directory before building, and the build takes about two
# minutes — so a Ctrl-C, a dropped SSH session or a failed apt fetch left the
# deployment with no jar at all.
#
# That failure hides. A running Keycloak holds the deleted file open and keeps
# serving it, so nothing looks wrong until the next restart, which might be a
# reboot weeks later for an unrelated reason. Then Docker has no file to mount
# and every sign-in on auth.gryt.chat loses the theme. It happened on
# 2026-09-01 and was found by chance.
#
# So: build into a temporary directory, check the jar is really there, and only
# then move it into place. A `mv` within one filesystem is a rename, so the
# mount target goes straight from the old jar to the new one and is never
# missing. dist_keycloak is never deleted.
set -euo pipefail

cd "$(dirname "$0")"

out="dist_keycloak"
tmp="$(mktemp -d "${out}.tmp.XXXXXX")"
# Same directory as `out`, so the move below is a rename rather than a copy —
# and so a leftover temp dir from a killed run is obvious rather than hidden in
# /tmp. Removed on any exit, including the interrupt this exists to survive.
trap 'rm -rf "$tmp"' EXIT INT TERM

docker build \
  --target artifact \
  --build-arg "KC_THEME_NAME=${KC_THEME_NAME:-}" \
  --output "type=local,dest=$tmp" .

# Keycloakify emits one jar per Keycloak generation. We run 26.x, which falls
# under "all-other-versions" — the 22-to-25 jar is for older servers and picking
# it by accident gives a theme Keycloak will not load properly.
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
