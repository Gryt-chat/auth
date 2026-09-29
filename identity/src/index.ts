import { serve } from "@hono/node-server";

import { app, chunks, relay } from "./routes.js";

const port = parseInt(process.env.PORT || "3000", 10);

console.log(`Gryt Identity Service starting on port ${port}...`);
if (!process.env.GRYT_PAIRING_TRUSTED_PROXIES) {
  console.warn("pairing: GRYT_PAIRING_TRUSTED_PROXIES is empty, so every client counts as the tunnel's address");
}
const wiped = await chunks.wipe();
if (wiped > 0) console.log(`pairing: removed ${wiped} chunk folders left from before the restart`);
relay.start();

serve({
  fetch: app.fetch,
  port,
});

console.log(`Gryt Identity Service listening on http://0.0.0.0:${port}`);
