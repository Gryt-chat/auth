# Builds the Keycloak login theme JAR.
#
# Keycloakify packages its output with Maven, so building the theme needs a JVM
# as well as Node. Doing that here rather than on the machine keeps the JVM out
# of everyone's laptop and out of CI runners — the only requirement either place
# is Docker, which is already needed to run Keycloak at all.
#
# Build and extract the jar with ./build.sh, which uses buildx --output so the
# artifact lands in dist_keycloak/ without anything being installed locally.

# Pinned by digest, not just by tag. `node:22-bookworm` moves, and when Docker
# resolves a digest it has not seen before, every layer below is invalidated —
# including the Maven install, which is 58 seconds of the roughly two minutes
# this takes. That is what makes an occasional build unexpectedly slow, and a
# slow build on a production box is what gets interrupted.
#
# To move to a newer Node: change the tag and the digest together. `docker
# pull node:22-bookworm` prints the digest it resolved.
FROM node:22-bookworm@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d AS builder

# Maven only; the JDK comes with it. --no-install-recommends keeps this from
# pulling a desktop's worth of suggested packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends maven \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
# --ignore-scripts: the postinstall runs `keycloakify sync-extensions`, which
# wants the source tree that has not been copied yet. It runs below instead.
RUN npm ci --ignore-scripts

COPY . .

# Lets build.sh install this beside the existing theme for comparison.
ARG KC_THEME_NAME
ENV KC_THEME_NAME=${KC_THEME_NAME}

RUN npx keycloakify sync-extensions && npm run build-keycloak-theme

# A scratch stage so `--output type=local` writes just the jar, not a filesystem.
FROM scratch AS artifact
COPY --from=builder /app/dist_keycloak/*.jar /
