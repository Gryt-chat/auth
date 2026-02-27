# Gryt Identity Service

Lightweight certificate authority that bridges Keycloak authentication with Gryt's peer-to-peer identity model. When a user authenticates via Keycloak, they can present their access token here along with an EC P-256 public key and receive a signed certificate (JWT) binding their Keycloak `sub` to that key.

Servers and other clients verify these certificates against the public JWKS endpoint — no direct Keycloak access required.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Public JWKS containing the CA signing key |
| `POST` | `/api/v1/certificate` | Issue a certificate for an authenticated user |
| `GET` | `/health` | Health check |

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

## Stack

- [Bun](https://bun.sh) runtime
- [Hono](https://hono.dev) web framework
- [jose](https://github.com/panva/jose) for JWT/JWK operations
