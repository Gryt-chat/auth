import assert from "node:assert/strict";
import {
  createCipheriv, createDecipheriv, createHash, createPublicKey, diffieHellman,
  generateKeyPairSync, hkdfSync, randomBytes, type KeyObject,
} from "node:crypto";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, test } from "node:test";

import { serve } from "@hono/node-server";
import { Hono } from "hono";

import { Relay, type Limits } from "../src/pairing/relay.js";
import { pairingRoutes, trustedProxies } from "../src/pairing/routes.js";

let clock = 0;
let logs: string[] = [];
let relay: Relay;
let base = "";
let trustTunnel = true;
const server = serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch: (req, env) => {
    const app = new Hono();
    app.route("/p", pairingRoutes(relay, trustedProxies(trustTunnel ? "127.0.0.1" : "")));
    return app.fetch(req, env);
  },
});

before(async () => {
  if (!server.listening) await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/p`;
});
after(() => { server.close(); });
beforeEach(() => fresh());

function fresh(limits: Partial<Limits> = {}) {
  clock = 1_000_000;
  logs = [];
  trustTunnel = true;
  relay = new Relay({ now: () => clock, log: (line) => logs.push(line), limits });
}

async function call(method: string, path: string, opts: { body?: unknown; token?: string; ip?: string; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json", ...opts.headers };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  headers["cf-connecting-ip"] = opts.ip ?? "203.0.113.1";
  const res = await fetch(base + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

// Each side of the channel, done with node:crypto. The key schedule's own tests are in @gryt/crypto.
function side() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return { pk: Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url"), sk: privateKey };
}
const lp = (b: Buffer) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 255]), b]);
const commitOf = (pkN: Buffer) => createHash("sha256").update("gryt-pair-v1 commit").update(pkN).digest();

function channel(sk: KeyObject, theirs: Buffer, me: "n" | "a", id: string, pkN: Buffer, pkA: Buffer) {
  const th = createHash("sha256")
    .update(Buffer.concat([lp(Buffer.from("gryt-pair-v1")), lp(Buffer.from(id)), lp(commitOf(pkN)), lp(pkN), lp(pkA)]))
    .digest();
  const publicKey = createPublicKey({ key: { kty: "OKP", crv: "X25519", x: theirs.toString("base64url") }, format: "jwk" });
  const dh = diffieHellman({ privateKey: sk, publicKey });
  const key = (info: string, n: number) => Buffer.from(hkdfSync("sha256", dh, th, `gryt-pair-v1 ${info}`, n));
  const [out, inn] = me === "n" ? [key("n to a", 32), key("a to n", 32)] : [key("a to n", 32), key("n to a", 32)];
  const [outDir, inDir] = me === "n" ? [1, 2] : [2, 1];
  const counters = { out: 0, in: 0 };
  const nonce = (n: number) => { const b = Buffer.alloc(12); b.writeUInt32BE(n, 8); return b; };
  const aad = (dir: number, iv: Buffer) => Buffer.concat([th, Buffer.from([dir]), iv]);
  return {
    emoji: key("emoji", 3).toString("hex"),
    seal(plain: Buffer) {
      const iv = nonce(counters.out++);
      const c = createCipheriv("aes-256-gcm", out, iv).setAAD(aad(outDir, iv));
      return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]).toString("base64url");
    },
    open(body: string) {
      const bytes = Buffer.from(body, "base64url");
      const iv = nonce(counters.in++);
      const d = createDecipheriv("aes-256-gcm", inn, iv).setAAD(aad(inDir, iv));
      d.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([d.update(bytes.subarray(0, -16)), d.final()]);
    },
  };
}

async function openSession(ip?: string) {
  const n = side();
  const res = await call("POST", "/sessions", { body: { commit: commitOf(n.pk).toString("base64url") }, ip });
  assert.equal(res.status, 201);
  return { n, ...(res.json as { id: string; code: string; token: string; expiresAt: string }) };
}

async function claimed() {
  const s = await openSession();
  const a = side();
  const claim = await call("POST", "/sessions/claim", { body: { id: s.id, pkA: a.pk.toString("base64url") } });
  assert.equal(claim.status, 200);
  return { ...s, a, aToken: claim.json.token as string };
}

async function revealed() {
  const s = await claimed();
  const res = await call("POST", `/sessions/${s.id}/messages`, { token: s.token, body: { type: "reveal", pkN: s.n.pk.toString("base64url") } });
  assert.equal(res.status, 201);
  return s;
}

const sealed = (bytes: number) => ({ type: "sealed", body: randomBytes(bytes).toString("base64url") });

test("two devices pair through the relay, which only ever holds sealed bytes", async () => {
  const seed = Buffer.from("SEED-THAT-MUST-NEVER-REACH-THE-RELAY");
  const location = { "cf-ipcountry": "NO", "cf-ipcity": "Oslo" };
  const n = side();
  const commit = commitOf(n.pk).toString("base64url");
  const opened = await call("POST", "/sessions", { body: { commit }, ip: "198.51.100.7", headers: location });
  const { id, code, token: nToken } = opened.json;
  assert.match(id, /^[0-9A-Z]{26}$/);

  const nWaiting = call("GET", `/sessions/${id}/messages?after=0&wait=5`, { token: nToken });
  const a = side();
  const typed = `${code.slice(0, 4).toLowerCase()}-${code.slice(4)}`;
  const claim = await call("POST", "/sessions/claim", { body: { code: typed, pkA: a.pk.toString("base64url") }, headers: { "cf-ipcountry": "SE" } });
  assert.equal(claim.status, 200);
  assert.deepEqual([claim.json.id, claim.json.commit, claim.json.location, claim.json.yourLocation], [id, commit, "Oslo, Norway", "Sweden"]);
  const aToken = claim.json.token;

  const [claimMsg] = (await nWaiting).json.messages;
  assert.deepEqual(claimMsg, { seq: 1, type: "claim", pkA: a.pk.toString("base64url") });
  await call("POST", `/sessions/${id}/messages`, { token: nToken, body: { type: "reveal", pkN: n.pk.toString("base64url") } });
  const [reveal] = (await call("GET", `/sessions/${id}/messages`, { token: aToken })).json.messages;
  const pkN = Buffer.from(reveal.pkN, "base64url");
  assert.deepEqual(commitOf(pkN).toString("base64url"), claim.json.commit);

  const nChannel = channel(n.sk, Buffer.from(claimMsg.pkA, "base64url"), "n", id, n.pk, a.pk);
  const aChannel = channel(a.sk, pkN, "a", id, pkN, a.pk);
  assert.equal(nChannel.emoji, aChannel.emoji);

  const hello = nChannel.seal(Buffer.from('{"name":"MacBook Air"}'));
  await call("POST", `/sessions/${id}/messages`, { token: nToken, body: { type: "sealed", body: hello } });
  const fromN = (await call("GET", `/sessions/${id}/messages?after=1`, { token: aToken })).json.messages;
  assert.equal(fromN[0].body, hello);
  assert.equal(aChannel.open(fromN[0].body).toString(), '{"name":"MacBook Air"}');

  const envelope = aChannel.seal(Buffer.concat([seed, randomBytes(150_000)]));
  assert.equal((await call("POST", `/sessions/${id}/messages`, { token: aToken, body: { type: "sealed", body: envelope } })).status, 201);

  const held = [...relay.sessions.values()].flatMap((s) => [...s.sent.n, ...s.sent.a]);
  for (const m of held) assert.ok(!m.body || !Buffer.from(m.body, "base64url").includes(seed));

  const fromA = (await call("GET", `/sessions/${id}/messages?after=1`, { token: nToken })).json.messages;
  assert.equal(fromA[0].body, envelope);
  assert.ok(nChannel.open(fromA[0].body).subarray(0, seed.length).equals(seed));

  const aWaiting = call("GET", `/sessions/${id}/messages?after=2&wait=5`, { token: aToken });
  assert.equal((await call("DELETE", `/sessions/${id}`, { token: nToken })).status, 204);
  assert.deepEqual(await aWaiting, { status: 410, json: { error: "closed" } });
  assert.equal(relay.sessions.size, 0);

  relay.sweep();
  clock += 60_000;
  relay.sweep();
  const logged = logs.join("\n");
  for (const secret of [id, code, nToken, aToken, "198.51.100.7", "Oslo", "Sweden", commit, hello]) {
    assert.ok(!logged.includes(secret), `the log mentions ${secret}`);
  }
  assert.match(logged, /session closed after \d+s, approved/);
});

test("N can only reveal after A claims, and only the key it committed to", async () => {
  const s = await openSession();
  const reveal = { type: "reveal", pkN: s.n.pk.toString("base64url") };
  assert.equal((await call("POST", `/sessions/${s.id}/messages`, { token: s.token, body: reveal })).json.error, "not_claimed");

  const c = await claimed();
  const other = { type: "reveal", pkN: side().pk.toString("base64url") };
  assert.equal((await call("POST", `/sessions/${c.id}/messages`, { token: c.token, body: sealed(10) })).json.error, "not_revealed");
  assert.equal((await call("POST", `/sessions/${c.id}/messages`, { token: c.token, body: other })).json.error, "commit_mismatch");
  const byA = { type: "reveal", pkN: c.n.pk.toString("base64url") };
  assert.equal((await call("POST", `/sessions/${c.id}/messages`, { token: c.aToken, body: byA })).status, 403);
  assert.equal((await call("GET", `/sessions/${c.id}/messages`, { token: "wrong" })).status, 401);
  assert.equal((await call("GET", `/sessions/${c.id}/messages`)).status, 401);
});

test("a second claim is refused, and the code dies with the first", async () => {
  const s = await openSession();
  const pkA = side().pk.toString("base64url");
  assert.equal((await call("POST", "/sessions/claim", { body: { id: s.id, pkA } })).status, 200);
  assert.deepEqual(await call("POST", "/sessions/claim", { body: { id: s.id, pkA } }), { status: 409, json: { error: "already_claimed" } });
  assert.equal((await call("POST", "/sessions/claim", { body: { code: s.code, pkA } })).status, 404);
});

test("lifetimes: 5 minutes open, 2 minutes to approve, an hour from the claim", async () => {
  const open = await openSession();
  clock += 5 * 60_000;
  const pkA = side().pk.toString("base64url");
  assert.equal((await call("POST", "/sessions/claim", { body: { id: open.id, pkA } })).json.error, "expired");

  const unapproved = await revealed();
  clock += 2 * 60_000 - 1;
  assert.equal((await call("POST", `/sessions/${unapproved.id}/messages`, { token: unapproved.token, body: sealed(10) })).status, 201);
  clock += 1;
  relay.sweep();
  assert.equal((await call("GET", `/sessions/${unapproved.id}/messages`, { token: unapproved.token })).json.error, "expired");

  const approved = await revealed();
  await call("POST", `/sessions/${approved.id}/messages`, { token: approved.aToken, body: sealed(10) });
  clock += 60 * 60_000 - 1;
  relay.sweep();
  assert.equal((await call("GET", `/sessions/${approved.id}/messages`, { token: approved.token })).status, 200);
  clock += 1;
  relay.sweep();
  assert.equal((await call("GET", `/sessions/${approved.id}/messages`, { token: approved.token })).status, 410);
  assert.match(logs.join("\n"), /session expired after 3600s, approved/);
});

test("20 wrong codes in ten minutes block that address for an hour", async () => {
  const s = await openSession();
  const pkA = side().pk.toString("base64url");
  for (let i = 0; i < 20; i++) {
    const guess = `ZZZZ${String(i).padStart(4, "0")}`;
    assert.equal((await call("POST", "/sessions/claim", { body: { code: guess, pkA }, ip: "192.0.2.9" })).status, 404);
  }
  assert.equal((await call("POST", "/sessions/claim", { body: { code: s.code, pkA }, ip: "192.0.2.9" })).status, 429);
  clock += 60 * 60_000;
  relay.sweep();
  const later = await openSession();
  assert.equal((await call("POST", "/sessions/claim", { body: { code: later.code, pkA }, ip: "192.0.2.9" })).status, 200);
});

test("the block follows CF-Connecting-IP only when the socket is the tunnel", async () => {
  trustTunnel = false;
  const pkA = side().pk.toString("base64url");
  for (let i = 0; i < 20; i++) await call("POST", "/sessions/claim", { body: { code: "ZZZZZZZZ", pkA }, ip: `192.0.2.${i}` });
  assert.equal((await call("POST", "/sessions/claim", { body: { code: "ZZZZZZZZ", pkA }, ip: "192.0.2.99" })).status, 429);
  const s = await openSession();
  const claim = await call("POST", "/sessions/claim", { body: { id: s.id, pkA }, headers: { "cf-ipcountry": "NO" } });
  assert.equal(claim.json.yourLocation, null);
});

test("ten new sessions per address per ten minutes", async () => {
  for (let i = 0; i < 10; i++) await openSession("192.0.2.1");
  const commit = commitOf(side().pk).toString("base64url");
  assert.equal((await call("POST", "/sessions", { body: { commit }, ip: "192.0.2.1" })).status, 429);
  assert.equal((await call("POST", "/sessions", { body: { commit }, ip: "192.0.2.2" })).status, 201);
});

test("oversize messages are refused: 64 KiB each, one envelope of 256 KiB from A", async () => {
  const s = await revealed();
  const post = (token: string, bytes: number) => call("POST", `/sessions/${s.id}/messages`, { token, body: sealed(bytes) });
  assert.equal((await post(s.token, 64 * 1024)).status, 201);
  assert.equal((await post(s.token, 64 * 1024 + 1)).status, 413);
  assert.equal((await post(s.aToken, 256 * 1024 + 1)).status, 413);
  assert.equal((await post(s.aToken, 256 * 1024)).status, 201);
  assert.equal((await post(s.aToken, 64 * 1024 + 1)).status, 413);
});

test("at most 64 messages a session", async () => {
  const s = await revealed();
  for (let i = 1; i < 64; i++) await call("POST", `/sessions/${s.id}/messages`, { token: s.token, body: sealed(4) });
  const last = await call("POST", `/sessions/${s.id}/messages`, { token: s.token, body: sealed(4) });
  assert.deepEqual(last, { status: 429, json: { error: "too_many_messages" } });
});

test("sealed bodies go through untouched, and acknowledged ones are dropped", async () => {
  const s = await revealed();
  const bodies = [randomBytes(33), randomBytes(1), randomBytes(1000)].map((b) => b.toString("base64url"));
  for (const body of bodies) await call("POST", `/sessions/${s.id}/messages`, { token: s.aToken, body: { type: "sealed", body } });
  const got = (await call("GET", `/sessions/${s.id}/messages?after=1`, { token: s.token })).json.messages;
  assert.deepEqual(got.map((m: { body: string }) => m.body), bodies);
  await call("GET", `/sessions/${s.id}/messages?after=3`, { token: s.token });
  assert.deepEqual(relay.sessions.get(s.id)!.sent.a.map((m) => m.seq), [4]);
  assert.equal((await call("POST", `/sessions/${s.id}/messages`, { token: s.aToken, body: { type: "sealed", body: "not base64!" } })).status, 400);
});

// Last, since the server hangs up on a body it won't read and the next fetch can hit that socket.
test("a request body past the envelope cap is refused before it's parsed", async () => {
  const s = await revealed();
  const huge = await call("POST", `/sessions/${s.id}/messages`, { token: s.aToken, body: { type: "sealed", body: "A".repeat(400_000) } });
  assert.deepEqual(huge, { status: 413, json: { error: "too_large" } });
});
