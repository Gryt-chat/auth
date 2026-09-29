# Gryt Identity Service

Lightweight certificate authority that bridges Keycloak authentication with Gryt's peer-to-peer identity model. When a user authenticates via Keycloak, they can present their access token here along with an EC P-256 public key and receive a signed certificate (JWT) binding their Keycloak `sub` to that key.

Servers and other clients verify these certificates against the public JWKS endpoint — no direct Keycloak access required.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Public JWKS containing the CA signing key |
| `POST` | `/api/v1/certificate` | Issue a certificate for an authenticated user |
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/pairing/sessions` | Open a pairing session (the new device) |
| `POST` | `/api/v1/pairing/sessions/claim` | Claim one by id or code (the approving device) |
| `POST` | `/api/v1/pairing/sessions/:id/messages` | Send the reveal or a sealed message |
| `GET` | `/api/v1/pairing/sessions/:id/messages` | Read the other side's messages, long-polling up to 25 seconds |
| `DELETE` | `/api/v1/pairing/sessions/:id` | Cancel or finish |
| `PUT` | `/api/v1/pairing/sessions/:id/chunks/:n` | Store a sealed history chunk in slot `n` (the approving device) |
| `GET` | `/api/v1/pairing/sessions/:id/chunks/:n` | Fetch one (the new device) |
| `DELETE` | `/api/v1/pairing/sessions/:id/chunks/:n` | Done with it (the new device) |

### Pairing relay

Linking a device goes through here. The relay passes sealed messages between the two devices
and can't open them. Nothing needs a Keycloak token, so guests use it too. The protocol is in
[`docs/pairing-design.md`](https://github.com/Gryt-chat/crypto/blob/main/docs/pairing-design.md)
in Gryt-chat/crypto.

Sessions and messages live in memory, so a restart drops every session and people start again. Keys,
commitments and sealed bodies are unpadded base64url. The logs hold counts and durations, and
never an IP, a code, a session id or a location.

The rate limits go by the client's address. Behind the Cloudflare tunnel that's
`CF-Connecting-IP`, and the relay only believes it from the addresses in
`GRYT_PAIRING_TRUSTED_PROXIES`. Leave that empty and every request counts as the tunnel's own
address, so ten sessions in ten minutes would be the limit for everybody at once. The
`CF-IPCountry` and `CF-IPCity` headers are read from the same trusted addresses, and turned
into "Oslo, Norway" for the approving device.

#### History chunks

Message history is the one thing that goes on disk. The approving device uploads it in sealed
chunks of up to 2 MiB, as `{"body": "<base64url>"}`, and the new device fetches them. The relay
can't open them and never logs them. Each one is saved as it arrived, under
`$GRYT_IDENTITY_DATA_DIR/pairing/<session>/<n>`. In compose that's the `gryt-identity-data`
volume.

A chunk goes when the new device deletes it or fetches it a second time, when its session
closes or expires, or an hour after upload. The folder also gets emptied at startup, because
the sessions didn't survive the restart. Only folders named like a session id get removed, so
the CA key in the same volume is left alone.

That volume sits on the same disk as Keycloak's Postgres, and a full disk takes the auth
database down. So uploads stop with `507` when any of these is hit:

| Limit | Default | Error |
|---|---|---|
| Chunks in one session | 256 MiB | `session_full` |
| Chunks in total, with each file counted as 4 KiB at least | 2 GiB | `full` |
| Free space on the volume after the upload | 5 GiB | `disk_low` |

On top of that, one address can upload 1 GiB a day, then gets `429 rate_limited`. The apps
treat a `507` as the end of what fits, and mark the history as cut short.

### `POST /api/v1/certificate`

**Headers:** `Authorization: Bearer <keycloak-access-token>`

**Body:**

```json
{
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

**Response:** A signed JWT certificate containing the user's `sub`, `preferred_username`, and their public key (`jwk` claim).

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Listen port | `3000` |
| `GRYT_OIDC_ISSUER` | Keycloak realm issuer URL | _(required)_ |
| `GRYT_IDENTITY_ORIGIN` | Issuer (`iss`) in issued certificates | `https://id.gryt.chat` |
| `GRYT_CA_PRIVATE_KEY_FILE` | Path to a PEM-encoded ECDSA P-256 private key | _(auto-generated)_ |
| `GRYT_IDENTITY_DATA_DIR` | Directory for auto-generated CA key storage | `./data` |
| `GRYT_CERT_LIFETIME_DAYS` | Certificate validity period in days | `30` |
| `GRYT_PAIRING_TRUSTED_PROXIES` | Comma-separated addresses or CIDR ranges allowed to set `CF-Connecting-IP` | _(none)_ |
| `GRYT_PAIRING_CHUNKS_SESSION_MIB` | History chunks one pairing can store, in MiB | `256` |
| `GRYT_PAIRING_CHUNKS_TOTAL_MIB` | History chunks stored across every pairing, in MiB | `2048` |
| `GRYT_PAIRING_CHUNKS_MIN_FREE_MIB` | Free space the volume keeps; uploads stop below it | `5120` |
| `GRYT_PAIRING_CHUNKS_PER_IP_MIB` | History chunks one address can upload a day, in MiB | `1024` |

## Stack

- [Node.js](https://nodejs.org) 22+
- [Hono](https://hono.dev) web framework
- [jose](https://github.com/panva/jose) for JWT/JWK operations
