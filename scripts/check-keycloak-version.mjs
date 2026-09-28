// Fails unless every Keycloak image in the compose file matches keycloak.version in the
// pairing extension's pom.xml, so a Keycloak bump has to rebuild and retest the extension.

import { readFileSync } from "node:fs";

const pom = readFileSync("keycloak-pairing/pom.xml", "utf8");
const compose = readFileSync("docker-compose.keycloak.yml", "utf8");

const built = pom.match(/<keycloak\.version>([^<]+)<\/keycloak\.version>/)?.[1];
const images = [...compose.matchAll(/quay\.io\/keycloak\/keycloak:(\S+)/g)].map((m) => m[1]);

if (!built) {
  console.error("keycloak-pairing/pom.xml has no <keycloak.version>");
  process.exit(1);
}
if (images.length === 0) {
  console.error("docker-compose.keycloak.yml names no quay.io/keycloak/keycloak image");
  process.exit(1);
}

const wrong = images.filter((tag) => tag !== built);
if (wrong.length > 0) {
  console.error(`pom.xml builds against Keycloak ${built}, but the compose file runs ${[...new Set(wrong)].join(", ")}.`);
  console.error("Move both in the same PR, so the extension is compiled and tested against what runs.");
  process.exit(1);
}

console.log(`keycloak: pom.xml and all ${images.length} compose images are ${built}`);
