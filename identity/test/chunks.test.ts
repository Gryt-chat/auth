import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, test } from "node:test";

import { serve } from "@hono/node-server";
import { Hono } from "hono";

import { ChunkStore, chunkLimitsFromEnv, type ChunkLimits } from "../src/pairing/chunks.js";
import { Relay } from "../src/pairing/relay.js";
import { pairingRoutes, trustedProxies } from "../src/pairing/routes.js";

const GiB = 1024 ** 3;
let clock = 0;
let logs: string[] = [];
let free = 100 * GiB;
let dir = "";
let store: ChunkStore;
let relay: Relay;
let base = "";
const server = serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch: (req, env) => {
    const app = new Hono();
    app.route("/p", pairingRoutes(relay, trustedProxies("127.0.0.1")));
    return app.fetch(req, env);
  },
});

before(async () => {
  if (!server.listening) await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/p`;
});
after(async () => {
  server.close();
  if (dir) await rm(dir, { recursive: true, force: true });
});
beforeEach(() => fresh());

async function fresh(limits: Partial<ChunkLimits> = {}) {
  clock = 1_000_000;
  logs = [];
  free = 100 * GiB;
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = join(await mkdtemp(join(tmpdir(), "gryt-chunks-")), "pairing");
  const log = (line: string) => logs.push(line);
  store = new ChunkStore(dir, { limits, now: () => clock, log, freeBytes: async () => free });
  await store.wipe();
  relay = new Relay({ now: () => clock, log, chunks: store });
}

async function call(method: string, path: string, opts: { body?: unknown; token?: string; ip?: string } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  headers["cf-connecting-ip"] = opts.ip ?? "203.0.113.1";
  const res = await fetch(base + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const key = () => randomBytes(32);
const commitOf = (pkN: Buffer) => createHash("sha256").update("gryt-pair-v1 commit").update(pkN).digest();

/** A session past the reveal, with both bearer tokens. */
async function revealed(opts: { approve?: boolean } = {}) {
  const pkN = key();
  const opened = await call("POST", "/sessions", { body: { commit: commitOf(pkN).toString("base64url") }, ip: `198.51.100.${randomBytes(1)[0]}` });
  const { id, token } = opened.json;
  const claim = await call("POST", "/sessions/claim", { body: { id, pkA: key().toString("base64url") } });
  const aToken = claim.json.token as string;
  assert.equal((await call("POST", `/sessions/${id}/messages`, { token, body: { type: "reveal", pkN: pkN.toString("base64url") } })).status, 201);
  if (opts.approve) await call("POST", `/sessions/${id}/messages`, { token: aToken, body: { type: "sealed", body: "AAAA" } });
  return { id: id as string, n: token as string, a: aToken };
}

const put = (s: { id: string; a: string }, slot: number | string, bytes: Buffer, ip?: string) =>
  call("PUT", `/sessions/${s.id}/chunks/${slot}`, { token: s.a, body: { body: bytes.toString("base64url") }, ip });
const get = (s: { id: string; n: string }, slot: number) => call("GET", `/sessions/${s.id}/chunks/${slot}`, { token: s.n });
const del = (s: { id: string; n: string }, slot: number) => call("DELETE", `/sessions/${s.id}/chunks/${slot}`, { token: s.n });
const onDisk = async (id: string) => (existsSync(join(dir, id)) ? (await readdir(join(dir, id))).sort() : []);

test("A uploads, N fetches, and the chunk is gone once N deletes it or fetches it twice", async () => {
  const s = await revealed();
  const first = randomBytes(300_000);
  assert.deepEqual(await put(s, 0, first), { status: 201, json: {} });
  assert.ok((await readFile(join(dir, s.id, "0"))).equals(first), "the file holds the sealed bytes as sent");

  const fetched = await get(s, 0);
  assert.equal(fetched.status, 200);
  assert.ok(Buffer.from(fetched.json.body, "base64url").equals(first));
  assert.equal((await del(s, 0)).status, 204);
  assert.deepEqual(await onDisk(s.id), []);
  assert.deepEqual(await get(s, 0), { status: 404, json: { error: "not_found" } });
  assert.equal((await del(s, 0)).status, 204);

  const second = randomBytes(1000);
  await put(s, 1, second);
  assert.equal((await get(s, 1)).status, 200);
  assert.ok(Buffer.from((await get(s, 1)).json.body, "base64url").equals(second));
  assert.deepEqual(await onDisk(s.id), []);
  assert.equal((await get(s, 1)).status, 404);
  assert.equal(store.totalBytes, 0);

  const logged = logs.join("\n");
  for (const secret of [s.id, s.n, s.a, first.toString("base64url").slice(0, 40)]) assert.ok(!logged.includes(secret));
});

test("a retry with the same bytes is fine, different bytes in a used slot are not", async () => {
  const s = await revealed();
  const bytes = randomBytes(500);
  assert.equal((await put(s, 3, bytes)).status, 201);
  assert.equal((await put(s, 3, bytes)).status, 201);
  assert.deepEqual(await put(s, 3, randomBytes(500)), { status: 409, json: { error: "exists" } });
  assert.equal(store.totalBytes, 4096);
});

test("only A uploads, only N fetches, and only after the reveal", async () => {
  const pkN = key();
  const opened = await call("POST", "/sessions", { body: { commit: commitOf(pkN).toString("base64url") } });
  const claim = await call("POST", "/sessions/claim", { body: { id: opened.json.id, pkA: key().toString("base64url") } });
  const early = { id: opened.json.id, n: opened.json.token, a: claim.json.token };
  assert.deepEqual(await put(early, 0, randomBytes(10)), { status: 409, json: { error: "not_revealed" } });

  const s = await revealed();
  assert.equal((await put({ id: s.id, a: s.n }, 0, randomBytes(10))).json.error, "wrong_side");
  await put(s, 0, randomBytes(10));
  assert.equal((await get({ id: s.id, n: s.a }, 0)).json.error, "wrong_side");
  assert.equal((await del({ id: s.id, n: s.a }, 0)).json.error, "wrong_side");
  assert.equal((await put(s, "01", randomBytes(10))).json.error, "invalid_slot");
  assert.equal((await put(s, 65_536, randomBytes(10))).json.error, "invalid_slot");
  assert.equal((await put(s, -1, randomBytes(10))).json.error, "invalid_slot");
  const padded = await call("PUT", `/sessions/${s.id}/chunks/1`, { token: s.a, body: { body: "AAA=" } });
  assert.equal(padded.json.error, "invalid_body");
  const loose = await call("PUT", `/sessions/${s.id}/chunks/1`, { token: s.a, body: { body: "AB" } });
  assert.equal(loose.json.error, "invalid_body");
  assert.equal((await call("PUT", `/sessions/${s.id}/chunks/1`, { token: s.a, body: {} })).json.error, "invalid_body");
});

test("a token from one session can't touch another session's chunks", async () => {
  const mine = await revealed();
  const theirs = await revealed();
  await put(theirs, 0, randomBytes(100));
  assert.deepEqual(await put({ id: theirs.id, a: mine.a }, 1, randomBytes(100)), { status: 401, json: { error: "unauthorized" } });
  assert.equal((await get({ id: theirs.id, n: mine.n }, 0)).status, 401);
  assert.equal((await del({ id: theirs.id, n: mine.n }, 0)).status, 401);
  assert.equal((await call("GET", `/sessions/${theirs.id}/chunks/0`)).status, 401);
  assert.deepEqual(await onDisk(theirs.id), ["0"]);
});

test("chunks go with their session: closed, or expired an hour after the claim", async () => {
  const closed = await revealed({ approve: true });
  await put(closed, 0, randomBytes(100));
  assert.equal((await call("DELETE", `/sessions/${closed.id}`, { token: closed.a })).status, 204);
  await store.idle();
  assert.ok(!existsSync(join(dir, closed.id)));
  assert.deepEqual(await get(closed, 0), { status: 410, json: { error: "closed" } });

  const s = await revealed({ approve: true });
  await put(s, 0, randomBytes(100));
  await put(s, 1, randomBytes(100));
  clock += 60 * 60_000 - 1;
  await relay.sweep();
  assert.deepEqual(await onDisk(s.id), ["0", "1"]);
  clock += 1;
  await relay.sweep();
  await store.idle();
  assert.ok(!existsSync(join(dir, s.id)));
  assert.deepEqual(await get(s, 0), { status: 410, json: { error: "expired" } });
  assert.equal(store.totalBytes, 0);
  assert.deepEqual(await readdir(dir), []);
});

test("the sweep also drops a chunk an hour after its upload on its own", async () => {
  await fresh({ maxAgeMs: 10 * 60_000 });
  const s = await revealed({ approve: true });
  await put(s, 0, randomBytes(100));
  clock += 5 * 60_000;
  await put(s, 1, randomBytes(100));
  clock += 5 * 60_000;
  await relay.sweep();
  assert.deepEqual(await onDisk(s.id), ["1"]);
  assert.equal((await get(s, 0)).status, 404);
});

test("256 MiB a session, counted in sealed bytes", async () => {
  await fresh({ sessionBytes: 5000, chunkBytes: 4000 });
  const s = await revealed();
  assert.equal((await put(s, 0, randomBytes(3000))).status, 201);
  assert.deepEqual(await put(s, 1, randomBytes(2001)), { status: 507, json: { error: "session_full" } });
  assert.equal((await put(s, 1, randomBytes(2000))).status, 201);
  assert.deepEqual(await put(s, 2, randomBytes(4001)), { status: 413, json: { error: "too_large" } });
  const other = await revealed();
  assert.equal((await put(other, 0, randomBytes(3000))).status, 201);
  assert.equal((await del(s, 0)).status, 204);
  assert.equal((await put(s, 2, randomBytes(3000))).status, 201);
});

test("2 GiB in total, with every file counted at 4 KiB at least", async () => {
  await fresh({ totalBytes: 3 * 4096 });
  const one = await revealed();
  const two = await revealed();
  await put(one, 0, randomBytes(10));
  await put(one, 1, randomBytes(10));
  await put(two, 0, randomBytes(10));
  assert.deepEqual(await put(two, 1, randomBytes(10)), { status: 507, json: { error: "full" } });
  assert.deepEqual(await onDisk(two.id), ["0"]);
  await call("DELETE", `/sessions/${one.id}`, { token: one.n });
  assert.equal((await put(two, 1, randomBytes(10))).status, 201);
});

test("uploads stop while the disk has under 5 GiB free", async () => {
  const s = await revealed();
  free = 5 * GiB + 1000;
  assert.equal((await put(s, 0, randomBytes(1000))).status, 201);
  assert.deepEqual(await put(s, 1, randomBytes(1001)), { status: 507, json: { error: "disk_low" } });
  assert.deepEqual(await onDisk(s.id), ["0"]);
  assert.equal(store.totalBytes, 4096);
  free = 6 * GiB;
  assert.equal((await put(s, 1, randomBytes(1001))).status, 201);
  await relay.sweep();
  clock += 60_000;
  await relay.sweep();
  assert.match(logs.join("\n"), /refused disk_low=1/);
  assert.match(logs.join("\n"), /stored 2 chunks, 0\.0 MiB/);
});

test("1 GiB of uploads a day from one address", async () => {
  await fresh({ uploadBytesPerIp: 2500 });
  const s = await revealed();
  assert.equal((await put(s, 0, randomBytes(1500), "192.0.2.1")).status, 201);
  assert.deepEqual(await put(s, 1, randomBytes(1500), "192.0.2.1"), { status: 429, json: { error: "rate_limited" } });
  assert.equal((await put(s, 1, randomBytes(1500), "192.0.2.2")).status, 201);
});

test("a restart wipes the chunks of sessions it no longer knows, and nothing else", async () => {
  const s = await revealed({ approve: true });
  await put(s, 0, randomBytes(100));
  await put(s, 1, randomBytes(100));
  await writeFile(join(dir, "not-a-session.txt"), "keep me");

  store = new ChunkStore(dir, { now: () => clock, freeBytes: async () => free });
  assert.equal(await store.wipe(), 1);
  relay = new Relay({ now: () => clock, chunks: store });
  assert.deepEqual(await readdir(dir), ["not-a-session.txt"]);
  assert.deepEqual(await get(s, 0), { status: 404, json: { error: "not_found" } });
  assert.deepEqual(await put(s, 2, randomBytes(100)), { status: 404, json: { error: "not_found" } });
});

test("the four limits come from the environment in MiB", () => {
  assert.deepEqual(chunkLimitsFromEnv({}), {});
  assert.deepEqual(
    chunkLimitsFromEnv({
      GRYT_PAIRING_CHUNKS_SESSION_MIB: "128",
      GRYT_PAIRING_CHUNKS_TOTAL_MIB: "1024",
      GRYT_PAIRING_CHUNKS_MIN_FREE_MIB: "0",
      GRYT_PAIRING_CHUNKS_PER_IP_MIB: " 512 ",
    }),
    { sessionBytes: 128 * 1024 ** 2, totalBytes: GiB, minFreeBytes: 0, uploadBytesPerIp: 512 * 1024 ** 2 },
  );
  assert.throws(() => chunkLimitsFromEnv({ GRYT_PAIRING_CHUNKS_TOTAL_MIB: "2GiB" }), /GRYT_PAIRING_CHUNKS_TOTAL_MIB/);
});

// Last, since the server hangs up on a body it won't read and the next fetch can hit that socket.
test("a chunk request body past 2 MiB in base64 is refused before it's parsed", async () => {
  const s = await revealed();
  assert.equal((await put(s, 0, randomBytes(2 * 1024 * 1024))).status, 201);
  const huge = await call("PUT", `/sessions/${s.id}/chunks/1`, { token: s.a, body: { body: "A".repeat(3_000_000) } });
  assert.deepEqual(huge, { status: 413, json: { error: "too_large" } });
});
