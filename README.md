<div align="center">
  <img src="https://raw.githubusercontent.com/Gryt-chat/client/main/public/logo.svg" width="80" alt="Gryt logo" />
  <h1>Gryt Auth</h1>
  <p>Keycloak-based authentication for the <a href="https://github.com/Gryt-chat/gryt">Gryt</a> voice chat platform.<br />Centralized identity management, SSO, and token-based auth.</p>
</div>

<br />

> **This repository is open source for transparency — you are not expected to host this yourself.**

## Why Centralized Auth?

Gryt uses a single auth service at **auth.gryt.chat**. All users authenticate through it regardless of which server they connect to. This ensures identities are consistent and verifiable across the entire network — if anyone could run their own auth service, they could impersonate any user.

- **Server hosts** — Your server validates tokens against `auth.gryt.chat`. No auth setup required.
- **Users** — Sign up once, your identity works on every Gryt server.
- **Contributors** — This repo is open so you can audit and contribute. The dev setup below is only needed for working on auth itself.

## Overview

| Component | Description |
|-----------|-------------|
| **Keycloak** | Identity provider with custom Gryt realm and themes |
| **Identity** | Certificate authority that binds Keycloak identities to client public keys ([details](identity/README.md)) |
| **HAProxy** | Reverse proxy for production TLS termination |
| **Bootstrap** | One-shot containers that bring a fresh Keycloak into a usable state ([details](#bootstrap)) |
| **Ops** | Backup/restore tooling for the Postgres database |

## Development Setup

> Only needed if you're contributing to the auth service itself.

```bash
cp .env.example .env
./up.sh
```

Starts a local Keycloak instance via Docker Compose — completely separate from production.

## Bootstrap

Four one-shot containers run around the Keycloak server, in this order. All of them
exit immediately and are safe to re-run.

| Service | What it does |
|---------|--------------|
| `keycloak-pre-import-backup` | Dumps Postgres to `./backups` before an import can overwrite anything. Only when `GRYT_IMPORT_REALM=1`. |
| `keycloak-import` | Imports `realm/gryt-realm.json`, substituting SMTP settings. Only when `GRYT_IMPORT_REALM=1`. **`--override true` deletes the realm first — every user in it goes too.** |
| `keycloak-bootstrap-admin` | Creates the master-realm admin if there isn't one. |
| `keycloak-user-profile` | Applies `bootstrap/gryt-user-profile.json` through the admin API, once the server is up. |

Two things about this are worth knowing before you change any of it.

**The admin is not created by `KC_BOOTSTRAP_ADMIN_*` alone.** Keycloak only does that
when `start` finds no master realm, and `keycloak-import` creates master as a side
effect of running first. On a genuinely fresh database that left a deployment with no
administrator at all, which is why `keycloak-bootstrap-admin` exists.

**The user profile has to go through the admin API.** A `userProfile` block in the
realm JSON is rejected on import and takes the whole stack down. Without the profile,
the realm falls back to Keycloak's built-in one, which requires `firstName` and
`lastName` — and since the realm sets `registrationEmailAsUsername` and the login theme
hides both fields, registration then fails on inputs nobody can see.

`bootstrap/gryt-user-profile.json` is the source of truth for what registration
collects. Editing the profile in the admin console works until the next time this runs.
Note that `docker compose up -d` will not re-run a one-shot that has already exited, so
after a realm import you need `up.sh`, or:

```bash
docker compose -f docker-compose.keycloak.yml up -d --force-recreate --no-deps keycloak-user-profile
```

## Documentation

See the [architecture overview](https://docs.gryt.chat/docs/guide/architecture) for how auth fits into the Gryt platform.

## Issues

Please report bugs and request features in the [main Gryt repository](https://github.com/Gryt-chat/gryt/issues).

## License

[AGPL-3.0](https://github.com/Gryt-chat/gryt/blob/main/LICENSE) — Part of [Gryt](https://github.com/Gryt-chat/gryt)
