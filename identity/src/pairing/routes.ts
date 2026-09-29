import { BlockList, isIP } from "node:net";

import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { ContentfulStatusCode } from "hono/utils/http-status";

import { CHUNK_LIMITS } from "./chunks.js";
import { Relay, RelayError } from "./relay.js";

/** Addresses allowed to speak for the client through CF-Connecting-IP: the tunnel, nothing else. */
export function trustedProxies(value = ""): (address: string) => boolean {
  const list = new BlockList();
  for (const entry of value.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [address, prefix] = entry.split("/");
    const family = isIP(address);
    if (!family || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) {
      throw new Error(`GRYT_PAIRING_TRUSTED_PROXIES: "${entry}" isn't an address or a CIDR range.`);
    }
    const type = family === 6 ? "ipv6" : "ipv4";
    if (prefix === undefined) list.addAddress(address, type);
    else list.addSubnet(address, Number(prefix), type);
  }
  return (raw) => {
    const address = raw.replace(/^::ffff:(?=\d+\.)/, "");
    const family = isIP(address);
    return family !== 0 && list.check(address, family === 6 ? "ipv6" : "ipv4");
  };
}

const regionNames = new Intl.DisplayNames(["en"], { type: "region" });

/** "Oslo, Norway" from Cloudflare's visitor location headers, or the country alone. */
export function visitorLocation(header: (name: string) => string | undefined): string | null {
  let country: string | undefined;
  const code = header("cf-ipcountry")?.trim().toUpperCase();
  if (code && /^[A-Z]{2}$/.test(code) && code !== "XX" && code !== "T1") {
    try {
      country = regionNames.of(code);
    } catch {
      country = undefined;
    }
  }
  const city = header("cf-ipcity")?.replace(/[\p{C}]/gu, "").trim().slice(0, 64);
  const parts = [city, country].filter((p): p is string => Boolean(p));
  return parts.length > 0 ? parts.join(", ") : null;
}

export function pairingRoutes(relay: Relay, trusted: (address: string) => boolean): Hono {
  const routes = new Hono();
  const base64 = (bytes: number) => Math.ceil((bytes * 4) / 3) + 1024;
  const tooLarge = (c: Context) => c.json({ error: "too_large" }, 413);
  const messageLimit = bodyLimit({ maxSize: base64(relay.limits.envelopeBytes), onError: tooLarge });
  const chunkBytes = relay.chunks?.limits.chunkBytes ?? CHUNK_LIMITS.chunkBytes;
  const chunkLimit = bodyLimit({ maxSize: base64(chunkBytes), onError: tooLarge });

  const client = (c: Context) => {
    const socket = getConnInfo(c).remote.address ?? "";
    if (!trusted(socket)) return { ip: socket, location: null };
    const forwarded = c.req.header("cf-connecting-ip")?.trim();
    return { ip: forwarded || socket, location: visitorLocation((name) => c.req.header(name)) };
  };
  const bearer = (c: Context) => c.req.header("authorization")?.match(/^Bearer (\S+)$/)?.[1];
  const json = async (c: Context): Promise<Record<string, unknown>> => {
    const body: unknown = await c.req.json().catch(() => null);
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new RelayError(400, "invalid_body");
    return body as Record<string, unknown>;
  };

  routes.use("*", (c, next) => (/\/chunks\/[^/]*$/.test(c.req.path) ? chunkLimit : messageLimit)(c, next));

  routes.onError((err, c) => {
    if (err instanceof RelayError) return c.json({ error: err.code }, err.status as ContentfulStatusCode);
    console.error("pairing: request failed:", err instanceof Error ? err.message : String(err));
    return c.json({ error: "internal" }, 500);
  });

  routes.post("/sessions", async (c) => {
    const { ip, location } = client(c);
    return c.json(relay.create(ip, (await json(c)).commit, location), 201);
  });

  routes.post("/sessions/claim", async (c) => {
    const { ip, location } = client(c);
    return c.json(relay.claim(ip, await json(c), location));
  });

  routes.post("/sessions/:id/messages", async (c) => {
    return c.json(relay.post(c.req.param("id"), bearer(c), await json(c)), 201);
  });

  routes.get("/sessions/:id/messages", async (c) => {
    const after = Number(c.req.query("after") ?? 0);
    const wait = Number(c.req.query("wait") ?? 0);
    if (!Number.isInteger(after) || after < 0 || !Number.isFinite(wait) || wait < 0) {
      throw new RelayError(400, "invalid_query");
    }
    return c.json({ messages: await relay.poll(c.req.param("id"), bearer(c), after, wait * 1000) });
  });

  routes.put("/sessions/:id/chunks/:n", async (c) => {
    const { ip } = client(c);
    await relay.putChunk(c.req.param("id"), bearer(c), ip, c.req.param("n"), (await json(c)).body);
    return c.json({}, 201);
  });

  routes.get("/sessions/:id/chunks/:n", async (c) => {
    return c.json({ body: await relay.getChunk(c.req.param("id"), bearer(c), c.req.param("n")) });
  });

  routes.delete("/sessions/:id/chunks/:n", async (c) => {
    await relay.deleteChunk(c.req.param("id"), bearer(c), c.req.param("n"));
    return c.body(null, 204);
  });

  routes.delete("/sessions/:id", (c) => {
    relay.close(c.req.param("id"), bearer(c));
    return c.body(null, 204);
  });

  return routes;
}
