import assert from "node:assert/strict";
import { test } from "node:test";

import { Hono } from "hono";

import { Relay } from "../src/pairing/relay.js";
import { pairingRoutes, trustedProxies } from "../src/pairing/routes.js";

/* GRYT-2055: message history goes through the user's own server. The relay takes none of it. */

const app = new Hono();
app.route("/p", pairingRoutes(new Relay(), trustedProxies("")));

test("a history chunk of any size is refused as full before its body is read", async () => {
  for (const size of [1, 2 * 1024 * 1024]) {
    const res = await app.request("/p/sessions/whatever/chunks/0", {
      method: "PUT",
      headers: { "content-type": "application/json", "content-length": String(size) },
      body: "x".repeat(size),
    });
    assert.equal(res.status, 507, `${size} bytes`);
    assert.deepEqual(await res.json(), { error: "full" }, "an older app reads full as its cap and links without history");
  }
});

test("there is never a chunk to read, and deleting one is a no-op", async () => {
  assert.equal((await app.request("/p/sessions/whatever/chunks/0")).status, 404);
  assert.equal((await app.request("/p/sessions/whatever/chunks/0", { method: "DELETE" })).status, 204);
});
