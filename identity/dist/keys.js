import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { exportJWK, generateKeyPair, importPKCS8 } from "jose";
const ALG = "ES256";
let cachedPrivateKey = null;
let cachedPublicJwk = null;
let cachedKid = null;
function deriveKid(jwk) {
    const material = `${jwk.crv}:${jwk.x}:${jwk.y}`;
    const hash = createHash("sha256").update(material).digest("hex");
    return hash.slice(0, 16);
}
async function loadOrGenerateKey() {
    if (cachedPrivateKey && cachedPublicJwk && cachedKid) {
        return { privateKey: cachedPrivateKey, publicJwk: cachedPublicJwk, kid: cachedKid };
    }
    const keyPath = process.env.GRYT_CA_PRIVATE_KEY_FILE;
    if (keyPath) {
        try {
            const pem = await readFile(keyPath, "utf-8");
            const privateKey = await importPKCS8(pem, ALG, { extractable: true });
            const jwk = await exportJWK(privateKey);
            const kid = deriveKid(jwk);
            const { d: _, ...publicJwk } = jwk;
            const pub = { ...publicJwk, alg: ALG, use: "sig", kid };
            cachedPrivateKey = privateKey;
            cachedPublicJwk = pub;
            cachedKid = kid;
            return { privateKey, publicJwk: pub, kid };
        }
        catch (e) {
            console.error(`Failed to load CA key from ${keyPath}, generating new keypair:`, e);
        }
    }
    const dataDir = process.env.GRYT_IDENTITY_DATA_DIR || "./data";
    const autoKeyPath = `${dataDir}/ca-key.pem`;
    try {
        const pem = await readFile(autoKeyPath, "utf-8");
        const privateKey = await importPKCS8(pem, ALG, { extractable: true });
        const jwk = await exportJWK(privateKey);
        const kid = deriveKid(jwk);
        const { d: _, ...publicJwk } = jwk;
        const pub = { ...publicJwk, alg: ALG, use: "sig", kid };
        cachedPrivateKey = privateKey;
        cachedPublicJwk = pub;
        cachedKid = kid;
        console.log(`Loaded existing CA key from ${autoKeyPath}`);
        return { privateKey, publicJwk: pub, kid };
    }
    catch (e) {
        console.warn(`Failed to load CA key from ${autoKeyPath}:`, e);
    }
    console.log("Generating new ECDSA P-256 CA keypair...");
    const { privateKey, publicKey } = await generateKeyPair(ALG, {
        extractable: true,
    });
    const privateJwk = await exportJWK(privateKey);
    const pubJwk = await exportJWK(publicKey);
    const kid = deriveKid(pubJwk);
    // Serialize private key to PEM via PKCS8
    const { exportPKCS8 } = await import("jose");
    const pem = await exportPKCS8(privateKey);
    await mkdir(dirname(autoKeyPath), { recursive: true });
    await writeFile(autoKeyPath, pem, { mode: 0o600 });
    console.log(`Saved new CA key to ${autoKeyPath}`);
    const pub = { ...pubJwk, alg: ALG, use: "sig", kid };
    cachedPrivateKey = privateKey;
    cachedPublicJwk = pub;
    cachedKid = kid;
    return { privateKey, publicJwk: pub, kid };
}
export async function getCAPrivateKey() {
    const { privateKey } = await loadOrGenerateKey();
    return privateKey;
}
export async function getCAPublicJwk() {
    const { publicJwk, kid } = await loadOrGenerateKey();
    return { ...publicJwk, kid };
}
export async function getCAKid() {
    const { kid } = await loadOrGenerateKey();
    return kid;
}
export const CA_ALG = ALG;
