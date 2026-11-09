import { join } from "node:path";

import { Hono } from "hono";
import { cors } from "hono/cors";

import { getCAPublicJwk } from "./keys.js";
import { verifyKeycloakToken } from "./keycloak.js";
import { issueCertificate } from "./certificate.js";
import { AccountKeys, gateModeFromEnv, verifyProof } from "./accountKeys.js";
import { Relay } from "./pairing/relay.js";
import { pairingRoutes, trustedProxies } from "./pairing/routes.js";

export const app = new Hono();
export const relay = new Relay();
export const accountKeys = new AccountKeys(join(process.env.GRYT_IDENTITY_DATA_DIR || "./data", "accounts"));
const gateMode = () => gateModeFromEnv(process.env.GRYT_ACCOUNT_KEY_GATE);

app.use("*", cors());
app.route("/api/v1/pairing", pairingRoutes(relay, trustedProxies(process.env.GRYT_PAIRING_TRUSTED_PROXIES)));

app.get("/health", (c) => c.json({ status: "ok" }));

app.get("/.well-known/jwks.json", async (c) => {
  const publicJwk = await getCAPublicJwk();
  return c.json({ keys: [publicJwk] });
});

app.post("/api/v1/certificate", async (c) => {
  const authHeader = c.req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "missing_token", message: "Authorization header with Bearer token required." }, 401);
  }

  const keycloakToken = authHeader.slice(7);

  let user;
  try {
    user = await verifyKeycloakToken(keycloakToken);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return c.json({ error: "invalid_token", message: `Keycloak token validation failed: ${msg}` }, 401);
  }

  let body: { jwk?: JsonWebKey; proof?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid_body", message: "JSON body with jwk field required." }, 400);
  }

  const { jwk } = body;
  if (!jwk || typeof jwk !== "object" || jwk.kty !== "EC" || (jwk as Record<string, string>).crv !== "P-256") {
    return c.json({
      error: "invalid_jwk",
      message: "Body must contain a jwk field with an EC P-256 public key (kty: EC, crv: P-256).",
    }, 400);
  }

  if ((jwk as Record<string, string>).d) {
    return c.json({ error: "invalid_jwk", message: "Do not send private key material. Send the public key only." }, 400);
  }

  const seedKey = await verifyProof(body.proof, user.sub, jwk as Record<string, string>);
  const decision = await accountKeys.decide(user.sub, seedKey, gateMode());
  if (!decision.ok) {
    return c.json({ error: "approval_required", message: "Link this device from one that's already signed in, or use your 24 words.", resetAt: decision.resetAt }, 403);
  }

  try {
    const certificate = await issueCertificate(user, jwk);
    return c.json({ certificate });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("Certificate issuance failed:", msg);
    return c.json({ error: "issuance_failed", message: "Failed to issue certificate." }, 500);
  }
});

/* Reset, cancel and status all take the same { jwk, proof } a certificate request does. */
async function seedKeyFrom(c: { req: { header: (n: string) => string | undefined; json: () => Promise<unknown> } }) {
  const auth = c.req.header("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const user = await verifyKeycloakToken(auth.slice(7)).catch(() => null);
  const body = (await c.req.json().catch(() => null)) as { jwk?: Record<string, string>; proof?: string } | null;
  if (!user || !body?.jwk) return null;
  const thumb = await verifyProof(body.proof, user.sub, body.jwk);
  return thumb ? { sub: user.sub, thumb } : null;
}

app.post("/api/v1/account-key/status", async (c) => {
  const who = await seedKeyFrom(c);
  if (!who) return c.json({ error: "invalid_proof" }, 401);
  // Both apps ask on every sign-in, so learn mode fills in days rather than at the next certificate renewal.
  await accountKeys.decide(who.sub, who.thumb, gateMode());
  return c.json(await accountKeys.status(who.sub, who.thumb));
});

app.post("/api/v1/account-key/reset", async (c) => {
  const who = await seedKeyFrom(c);
  if (!who) return c.json({ error: "invalid_proof" }, 401);
  const at = await accountKeys.requestReset(who.sub, who.thumb);
  return at === null ? c.json({ error: "already_known" }, 409) : c.json({ at });
});

app.post("/api/v1/account-key/reset/cancel", async (c) => {
  const who = await seedKeyFrom(c);
  if (!who) return c.json({ error: "invalid_proof" }, 401);
  return (await accountKeys.cancelReset(who.sub, who.thumb)) ? c.json({ ok: true }) : c.json({ error: "not_yours" }, 403);
});
