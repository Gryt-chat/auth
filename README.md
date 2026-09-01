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

Five one-shot containers run around the Keycloak server, in this order. All of them
exit immediately and are safe to re-run.

| Service | What it does |
|---------|--------------|
| `keycloak-pre-import-backup` | Dumps Postgres to `./backups` before an import can overwrite anything. Only when `GRYT_IMPORT_REALM=1`. |
| `keycloak-import` | Imports `realm/gryt-realm.json`, substituting SMTP settings. Only when `GRYT_IMPORT_REALM=1`. **`--override true` deletes the realm first — every user in it goes too.** Refuses to run while Keycloak is up; stop it first. |
| `keycloak-bootstrap-admin` | Creates the master-realm admin if there isn't one. |
| `keycloak-user-profile` | Applies `bootstrap/gryt-user-profile.json` through the admin API, once the server is up. |
| `keycloak-security-policy` | Turns on brute-force protection and a password policy, through the admin API. |

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

**Login hardening is not in the realm file either.** `gryt-realm.json` sets no
`bruteForceProtected`, no `failureFactor` and no `passwordPolicy`, so a stack brought up
without `keycloak-security-policy` accepts unlimited login attempts against any account
and whatever password a user picks. It runs through the admin API for the same reason the
user profile does, and it re-runs the same way:

```bash
docker compose -f docker-compose.keycloak.yml up -d --force-recreate --no-deps keycloak-security-policy
```

The password policy is checked when a password is set, never when one is used, so turning
it on locks nobody out — existing passwords keep working until they are next changed.
Lockouts are temporary rather than permanent, because a permanent one hands anybody who
knows an email address a way to lock its owner out.

### What stops a bot registering

Most of it isn't in this repository.

**A Cloudflare Managed Challenge on the registration path** (GRYT-782). It judges the
browser and the address it comes from, so it turns away crude automation. Someone driving a
real browser through a residential proxy gets past it.

**Email verification.** `verifyEmail` is on, so every account needs a mailbox somebody can
read. That forces an attacker onto a throwaway-mail service or a domain they own. It's also
why blocking throwaway domains would help here.

**Brute-force protection** is about guessing a password, not making an account.
`apply_security_policy.sh` turns it on, and it does nothing for registration.

**No captcha inside the Keycloak flow, and that's deliberate.** Keycloak 26.5.3 ships two
captcha authenticators and both are Google's — `RegistrationRecaptcha` has
`/recaptcha/api/siteverify` written into it, with no way to point it somewhere else. So
Turnstile needs a Java authenticator rather than a setting. That's GRYT-790, and we haven't
built it on purpose. Google's would work today, and it would hand Google every registration.

If you do add one, both halves are things you do in the admin console, and a realm import
with `--override true` wipes them. Check them again afterwards.

#### The gap

Nothing rate-limits registration. Brute-force protection only covers logging in, and a
Managed Challenge weighs reputation rather than volume. So nothing stops a slow trickle from
ordinary-looking addresses. Fixing that means a Cloudflare rate-limiting rule on the
registration path, not a change in here.

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
