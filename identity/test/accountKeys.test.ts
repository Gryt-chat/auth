import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";

import { AccountKeys, RESET_DELAY_MS, verifyProof } from "../src/accountKeys.js";

const dir = mkdtempSync(join(tmpdir(), "gryt-account-keys-"));
after(() => rmSync(dir, { recursive: true, force: true }));

let clock = 1_000_000_000_000;
const keys = new AccountKeys(dir, () => clock);

async function seedKey() {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, thumb: await calculateJwkThumbprint(jwk) };
}

async function proofFor(seed: Awaited<ReturnType<typeof seedKey>>, sub: string, certJwk: object, iat = Math.floor(clock / 1000)) {
  return new SignJWT({ cnf: await calculateJwkThumbprint(certJwk as never) })
    .setProtectedHeader({ alg: "ES256", jwk: seed.jwk })
    .setSubject(sub)
    .setIssuedAt(iat)
    .sign(seed.privateKey);
}

test("a proof only counts for its account, its certificate key and a few minutes", async () => {
  const seed = await seedKey();
  const cert = (await seedKey()).jwk;
  const now = Math.floor(clock / 1000);
  const proof = await proofFor(seed, "alice", cert);
  assert.equal(await verifyProof(proof, "alice", cert, now), seed.thumb);
  assert.equal(await verifyProof(proof, "bob", cert, now), null, "another account");
  assert.equal(await verifyProof(proof, "alice", (await seedKey()).jwk, now), null, "another certificate key");
  assert.equal(await verifyProof(proof, "alice", cert, now + 600), null, "too old");
  assert.equal(await verifyProof(undefined, "alice", cert, now), null);
});

test("learn mode records every seed and refuses nothing", async () => {
  const [a, b] = [await seedKey(), await seedKey()];
  assert.deepEqual(await keys.decide("learner", a.thumb, "learn"), { ok: true });
  assert.deepEqual(await keys.decide("learner", b.thumb, "learn"), { ok: true });
  assert.deepEqual(await keys.decide("learner", null, "learn"), { ok: true }, "an older app sends no proof");
  assert.equal((await keys.read("learner")).keys.length, 2);
});

test("enforce: the first seed is the account's, a known one passes, a new one waits", async () => {
  const [mine, linked, password] = [await seedKey(), await seedKey(), await seedKey()];
  assert.deepEqual(await keys.decide("enf", mine.thumb, "enforce"), { ok: true }, "first device");
  await keys.decide("enf", linked.thumb, "learn");
  assert.deepEqual(await keys.decide("enf", linked.thumb, "enforce"), { ok: true }, "learned before enforcing");
  assert.deepEqual(await keys.decide("enf", password.thumb, "enforce"), { ok: false, resetAt: null });
  assert.deepEqual(await keys.decide("enf", null, "enforce"), { ok: false, resetAt: null });
});

test("a reset waits 30 days, and a device with the key can stop it", async () => {
  const [mine, thief] = [await seedKey(), await seedKey()];
  await keys.decide("reset", mine.thumb, "enforce");
  const at = await keys.requestReset("reset", thief.thumb);
  assert.equal(at, clock + RESET_DELAY_MS);
  assert.equal(await keys.requestReset("reset", thief.thumb), at, "asking again doesn't restart it");
  assert.deepEqual(await keys.decide("reset", thief.thumb, "enforce"), { ok: false, resetAt: at });
  assert.equal(await keys.cancelReset("reset", thief.thumb), false, "only a known key can stop it");
  assert.equal(await keys.cancelReset("reset", mine.thumb), true);
  assert.deepEqual(await keys.decide("reset", thief.thumb, "enforce"), { ok: false, resetAt: null });
});

test("a reset finishes and replaces the key, at once when the known keys are unused for 30 days", async () => {
  const [old, fresh] = [await seedKey(), await seedKey()];
  await keys.decide("lost", old.thumb, "enforce");
  await keys.requestReset("lost", fresh.thumb);
  clock += RESET_DELAY_MS;
  assert.deepEqual(await keys.decide("lost", fresh.thumb, "enforce"), { ok: true });
  assert.deepEqual(await keys.decide("lost", old.thumb, "enforce"), { ok: false, resetAt: null }, "the old seed is out");

  const [gone, phone] = [await seedKey(), await seedKey()];
  await keys.decide("dormant", gone.thumb, "enforce");
  clock += RESET_DELAY_MS + 1;
  const due = await keys.requestReset("dormant", phone.thumb);
  assert.ok(due !== null && due <= clock);
  assert.deepEqual(await keys.decide("dormant", phone.thumb, "enforce"), { ok: true });
});
