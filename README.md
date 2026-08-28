<div align="center">
  <img src="https://raw.githubusercontent.com/Gryt-chat/client/main/public/logo.svg" width="80" alt="Gryt logo" />
  <h1>Gryt Auth</h1>
  <p>Keycloak-based authentication for <a href="https://github.com/Gryt-chat/gryt">Gryt</a>, the voice, video and text chat platform.<br />One identity across every Gryt server, with token-based auth.</p>
</div>

<br />

> **This repository is open source for transparency — you aren't expected to host this yourself.**

## Why one central auth service

Gryt uses a single auth service at **auth.gryt.chat**, and everyone
authenticates through it whatever server they connect to. If anyone could run
their own, they could mint an identity claiming to be anyone else, so the
identities would stop meaning anything.

For a server host that means no auth setup: your server validates tokens against
`auth.gryt.chat`. For a user it means signing up once and being the same person
on every Gryt server. For a contributor it means this repo is here to be audited,
and the development setup below is only needed if you're working on auth
itself.

## Overview

| Component | Description |
|-----------|-------------|
| **Keycloak** | Identity provider with custom Gryt realm and themes |
| **Identity** | Certificate authority that binds Keycloak identities to client public keys ([details](identity/README.md)) |
| **HAProxy** | Reverse proxy for production TLS termination |
| **Bootstrap** | One-shot containers that bring a fresh Keycloak into a usable state ([details](#bootstrap)) |
| **Ops** | Backup/restore tooling for the Postgres database |

## Development setup

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
| `keycloak-import` | Imports `realm/gryt-realm.json`, substituting SMTP settings. Only when `GRYT_IMPORT_REALM=1`. **`--override true` deletes the realm first — every user in it goes too.** Refuses to run while Keycloak is up; stop it first. |
| `keycloak-bootstrap-admin` | Creates the master-realm admin if there isn't one. |
| `keycloak-user-profile` | Applies `bootstrap/gryt-user-profile.json` through the admin API, once the server is up. |

Two things about this are worth knowing before you change any of it.

**The import is an offline operation.** `kc.sh import` rewrites the database directly, and a
running Keycloak goes on holding the realm id it started with — so importing underneath one
leaves it serving 500s until it's restarted, with every user in the realm already gone. It's
easy to do by accident, because `docker compose up -d` re-runs a one-shot whose config changed
without restarting `keycloak`, whose own definition didn't. `import_realm.sh` checks for a
listening server and refuses. To import deliberately:

```bash
docker compose -f docker-compose.keycloak.yml stop keycloak
docker compose -f docker-compose.keycloak.yml up -d
```

**The admin isn't created by `KC_BOOTSTRAP_ADMIN_*` alone.** Keycloak only does that
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
`docker compose up -d` won't re-run a one-shot that has already exited, so
after a realm import you need `up.sh`, or:

```bash
docker compose -f docker-compose.keycloak.yml up -d --force-recreate --no-deps keycloak-user-profile
```

## Documentation

See the [architecture overview](https://docs.gryt.chat/docs/guide/architecture) for how auth fits into the Gryt platform.

## Issues

Please report bugs and request features in the [main Gryt repository](https://github.com/Gryt-chat/gryt/issues).

## Sponsors

What sponsoring pays for, the tiers, and everyone who has sponsored:
[gryt.chat/sponsors](https://gryt.chat/sponsors). To sponsor:
[GitHub Sponsors](https://github.com/sponsors/Gryt-chat).

The list itself lives in the [Gryt README](https://github.com/Gryt-chat/gryt#sponsors),
in one place rather than ten, so it cannot fall out of step across repositories.

## License

[AGPL-3.0](https://github.com/Gryt-chat/gryt/blob/main/LICENSE) — Part of [Gryt](https://github.com/Gryt-chat/gryt)
