# Builds the Keycloak login theme JAR.
#
# Keycloakify packages its output with Maven, so building the theme needs a JVM
# as well as Node. Doing that here rather than on the machine keeps the JVM out
# of everyone's laptop and out of CI runners — the only requirement either place
# is Docker, which is already needed to run Keycloak at all.
#
# Build and extract the jar with ./build.sh, which uses buildx --output so the
# artifact lands in dist_keycloak/ without anything being installed locally.

FROM node:22-bookworm AS builder

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
