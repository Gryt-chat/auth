import { SignJWT } from "jose";

import { getCAPrivateKey, getCAKid, CA_ALG } from "./keys.js";
import type { VerifiedUser } from "./keycloak.js";

const DEFAULT_LIFETIME_DAYS = 30;

function getCertLifetimeSeconds(): number {
  const days = parseInt(process.env.GRYT_CERT_LIFETIME_DAYS || "", 10);
  return (days > 0 ? days : DEFAULT_LIFETIME_DAYS) * 86400;
}

function getIssuer(): string {
  return (
    process.env.GRYT_IDENTITY_ORIGIN?.replace(/\/+$/, "") ||
    "https://id.gryt.chat"
  );
}

export interface CertificatePayload {
  iss: string;
  sub: string;
  preferred_username?: string;
  jwk: JsonWebKey;
  iat: number;
  exp: number;
}

export async function issueCertificate(
  user: VerifiedUser,
  clientPublicJwk: JsonWebKey,
): Promise<string> {
  const privateKey = await getCAPrivateKey();
  const kid = await getCAKid();
  const lifetimeSeconds = getCertLifetimeSeconds();
  const now = Math.floor(Date.now() / 1000);

  const jwt = await new SignJWT({
    jwk: clientPublicJwk,
    preferred_username: user.preferredUsername,
  })
    .setProtectedHeader({ alg: CA_ALG, kid, typ: "JWT" })
    .setIssuer(getIssuer())
    .setSubject(user.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + lifetimeSeconds)
    .sign(privateKey);

  return jwt;
}

/** Ticket lifetime: long enough to reach your other devices, short enough that a replay is stale. */
export const APPROVE_TICKET_SECONDS = 600;

/* Proves to your other devices that this account really has a device waiting, so a server can't fake one.
   Its own typ and no jwk claim, so it can never pass as a certificate. */
export async function issueApproveTicket(sub: string, deviceType: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ purpose: "approve-ask", deviceType })
    .setProtectedHeader({ alg: CA_ALG, kid: await getCAKid(), typ: "gryt-approve+jwt" })
    .setIssuer(getIssuer())
    .setSubject(sub)
    .setIssuedAt(now)
    .setExpirationTime(now + APPROVE_TICKET_SECONDS)
    .setJti(crypto.randomUUID())
    .sign(await getCAPrivateKey());
}
