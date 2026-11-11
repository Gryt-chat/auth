import assert from "node:assert/strict";
import { test } from "node:test";

import { generateKeyPairSync, verify } from "node:crypto";

import { ascToken, classify, packageDownloads, Registry } from "./reach.ts";

test("signs an App Store Connect token Apple can check", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const [h, b, s] = ascToken("KEY123", "issuer-id", pem, 1_700_000_000_000).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url").toString()), { alg: "ES256", kid: "KEY123", typ: "JWT" });
  assert.deepEqual(JSON.parse(Buffer.from(b, "base64url").toString()), { iss: "issuer-id", iat: 1_700_000_000, exp: 1_700_000_600, aud: "appstoreconnect-v1" });
  const sig = Buffer.from(s, "base64url");
  assert.equal(sig.length, 64, "raw r||s, not DER");
  assert.ok(verify("sha256", Buffer.from(`${h}.${b}`), { key: publicKey, dsaEncoding: "ieee-p1363" }, sig));
});

test("sorts release assets into installers and update checks", () => {
  assert.deepEqual(classify("latest.yml"), { platform: "windows", kind: "update-check" });
  assert.deepEqual(classify("latest-mac.yml"), { platform: "mac", kind: "update-check" });
  assert.deepEqual(classify("latest-linux.yml"), { platform: "linux", kind: "update-check" });
  assert.deepEqual(classify("Gryt-Setup-1.15.9.exe"), { platform: "windows", kind: "installer" });
  assert.deepEqual(classify("Gryt-1.15.9-arm64.dmg"), { platform: "mac", kind: "installer" });
  assert.deepEqual(classify("Gryt-1.15.9-arm64-mac.zip"), { platform: "mac", kind: "installer" });
  assert.deepEqual(classify("Gryt-1.15.9.AppImage"), { platform: "linux", kind: "installer" });
  assert.deepEqual(classify("gryt-server-linux-x64-v1.12.1.zip"), { platform: "linux", kind: "installer" });
  assert.deepEqual(classify("gryt-server-windows-x64-v1.12.1.zip"), { platform: "windows", kind: "installer" });
  assert.equal(classify("Gryt-Setup-1.15.9.exe.blockmap"), null);
  assert.equal(classify("manifest.json"), null);
});

test("reads the exact pull count, not the rounded one", () => {
  const html = `<span class="d-block color-fg-muted text-small tmp-mb-1">Total downloads</span>\n            <h3 title="23647">23.6K</h3>`;
  assert.equal(packageDownloads(html), 23647);
  assert.equal(packageDownloads("<h3>nothing</h3>"), null);
});

test("renders Prometheus text", () => {
  const reg = new Registry();
  reg.define("a_total", "counter", "A.");
  reg.set("a_total", { repo: "gryt", kind: "installer" }, 5);
  reg.set("a_total", { repo: "gryt", kind: "installer" }, 6);
  reg.define("b", "gauge", "B.");
  reg.set("b", {}, 1);
  assert.equal(reg.render(), '# HELP a_total A.\n# TYPE a_total counter\na_total{repo="gryt",kind="installer"} 6\n# HELP b B.\n# TYPE b gauge\nb 1\n');
  reg.clear("a_total");
  reg.set("a_total", { host: 'x"\\\ny' }, 1);
  assert.match(reg.render(), /^a_total\{host="x\\"\\\\\\ny"\} 1$/m, "label values from request headers are escaped");
});
