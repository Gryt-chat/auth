import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";

const dir = mkdtempSync(join(tmpdir(), "gryt-approve-ticket-"));
process.env.GRYT_IDENTITY_DATA_DIR = dir;
after(() => rmSync(dir, { recursive: true, force: true }));

const { issueApproveTicket, APPROVE_TICKET_SECONDS } = await import("../src/certificate.js");
const { getCAPublicJwk, CA_ALG } = await import("../src/keys.js");

test("an approve ticket is signed, short-lived, its own type, and carries no key", async () => {
  const ticket = await issueApproveTicket("acct-1", "Windows PC");
  const key = await importJWK(await getCAPublicJwk(), CA_ALG);
  const { payload } = await jwtVerify(ticket, key, { typ: "gryt-approve+jwt", subject: "acct-1" });
  assert.equal(payload.purpose, "approve-ask");
  assert.equal(payload.deviceType, "Windows PC");
  assert.equal((payload.exp ?? 0) - (payload.iat ?? 0), APPROVE_TICKET_SECONDS);
  assert.ok(typeof payload.jti === "string" && payload.jti.length > 0);
  assert.equal("jwk" in payload, false, "never usable as a certificate");
  assert.equal(decodeProtectedHeader(ticket).typ, "gryt-approve+jwt");
  await assert.rejects(jwtVerify(ticket, key, { subject: "acct-2" }), "only for its own account");
});
