# Builds gryt-pairing.jar against the Keycloak version in pom.xml, so no JVM is needed on the host.
# Pinned by digest; change the tag and the digest together.
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS builder

WORKDIR /build
COPY pom.xml ./
COPY src ./src

# -DskipTests: the integration tests start Keycloak in Docker, which a build can't. CI runs them.
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -DskipTests package

# A scratch stage so `--output type=local` writes just the jar.
FROM scratch AS artifact
COPY --from=builder /build/target/gryt-pairing.jar /
