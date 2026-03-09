import { createRemoteJWKSet, jwtVerify } from "jose";
function getIssuer() {
    const issuer = process.env.GRYT_OIDC_ISSUER;
    if (!issuer) {
        throw new Error("Missing GRYT_OIDC_ISSUER environment variable");
    }
    return issuer.replace(/\/+$/, "");
}
let jwks = null;
function getJwks() {
    if (jwks)
        return jwks;
    const issuer = getIssuer();
    const certsUrl = new URL(`${issuer}/protocol/openid-connect/certs`);
    jwks = createRemoteJWKSet(certsUrl);
    return jwks;
}
function parseStringClaim(payload, key) {
    const v = payload[key];
    return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}
export async function verifyKeycloakToken(token) {
    const issuer = getIssuer();
    const { payload } = await jwtVerify(token, getJwks(), { issuer });
    if (!payload.sub || typeof payload.sub !== "string") {
        throw new Error("Token missing sub claim");
    }
    return {
        sub: payload.sub,
        preferredUsername: parseStringClaim(payload, "preferred_username"),
        email: parseStringClaim(payload, "email"),
    };
}
