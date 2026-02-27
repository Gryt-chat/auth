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
| **Bootstrap** | Python scripts for automated Keycloak client configuration |
| **Ops** | Backup/restore tooling for the Postgres database |

## Development Setup

> Only needed if you're contributing to the auth service itself.

```bash
cp .env.example .env
./up.sh
```

Starts a local Keycloak instance via Docker Compose — completely separate from production.

## Documentation

See the [architecture overview](https://docs.gryt.chat/docs/guide/architecture) for how auth fits into the Gryt platform.

## Issues

Please report bugs and request features in the [main Gryt repository](https://github.com/Gryt-chat/gryt/issues).

## License

[AGPL-3.0](https://github.com/Gryt-chat/gryt/blob/main/LICENSE) — Part of [Gryt](https://github.com/Gryt-chat/gryt)
