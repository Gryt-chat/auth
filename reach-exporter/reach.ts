// Public numbers on how far Gryt reaches, as Prometheus metrics: downloads, pulls, stars, visitors.
// Nothing here reports home; every source is a public page or an API the project owns.
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

const ORG = "Gryt-chat";
const RELEASE_REPOS = ["gryt", "server"];
const PACKAGES = ["server", "sfu", "client", "push", "reports", "image-worker", "console"];
const NPM = ["@gryt/crypto", "@gryt/core", "@gryt/ui", "@gryt/voice", "@gryt/theme"];
const REFRESH_MS = 60 * 60 * 1000;

export type Kind = "installer" | "update-check";

// electron-updater fetches latest*.yml on every check and the installer on every update.
export function classify(asset: string): { platform: string; kind: Kind } | null {
  if (/\.ya?ml$/i.test(asset)) {
    const platform = /mac/i.test(asset) ? "mac" : /linux/i.test(asset) ? "linux" : "windows";
    return { platform, kind: "update-check" };
  }
  if (/\.(blockmap|sha256|sig|json|txt)$/i.test(asset)) return null;
  if (/\.(exe|msi|msix|appx)$/i.test(asset) || /windows.*\.zip$/i.test(asset)) return { platform: "windows", kind: "installer" };
  if (/\.dmg$/i.test(asset) || (/\.zip$/i.test(asset) && /mac|darwin/i.test(asset))) return { platform: "mac", kind: "installer" };
  if (/\.(appimage|deb|rpm|snap|flatpak|pacman|tar\.gz)$/i.test(asset) || /linux.*\.zip$/i.test(asset)) {
    return { platform: "linux", kind: "installer" };
  }
  return { platform: "other", kind: "installer" };
}

export function packageDownloads(html: string): number | null {
  const m = /Total downloads<\/span>\s*<h3 title="(\d+)"/.exec(html);
  return m ? Number(m[1]) : null;
}

type Labels = Record<string, string>;
interface Metric { help: string; type: "counter" | "gauge"; samples: Map<string, number> }

export class Registry {
  metrics = new Map<string, Metric>();
  define(name: string, type: Metric["type"], help: string): void {
    this.metrics.set(name, { help, type, samples: new Map() });
  }
  set(name: string, labels: Labels, value: number): void {
    const escape = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
    const key = Object.entries(labels).map(([k, v]) => `${k}="${escape(v)}"`).join(",");
    this.metrics.get(name)?.samples.set(key, value);
  }
  clear(name: string): void {
    this.metrics.get(name)?.samples.clear();
  }
  render(): string {
    const out: string[] = [];
    for (const [name, m] of this.metrics) {
      out.push(`# HELP ${name} ${m.help}`, `# TYPE ${name} ${m.type}`);
      for (const [key, v] of m.samples) out.push(`${name}${key ? `{${key}}` : ""} ${v}`);
    }
    return out.join("\n") + "\n";
  }
}

const reg = new Registry();
reg.define("gryt_release_downloads_total", "counter", "GitHub release asset downloads, summed over every release.");
reg.define("gryt_container_pulls_total", "counter", "Container image pulls from GHCR, as the package page shows them.");
reg.define("gryt_github_stars", "gauge", "Stars on each public repository.");
reg.define("gryt_github_forks", "gauge", "Forks of each public repository.");
reg.define("gryt_github_followers", "gauge", "Followers of the GitHub organisation.");
reg.define("gryt_npm_downloads_month", "gauge", "npm downloads over the last 30 days.");
reg.define("gryt_discord_members", "gauge", "Members of the Discord server, from its public invite.");
reg.define("gryt_web_pageviews_day", "gauge", "Page views on the zone yesterday, from Cloudflare.");
reg.define("gryt_web_visitors_day", "gauge", "Unique visitors on the zone yesterday, from Cloudflare.");
for (const label of ["host", "country", "device"]) {
  reg.define(`gryt_web_pageviews_24h_by_${label}`, "gauge", `Pages opened by people over the last 24 hours, by ${label}, from Cloudflare.`);
}
reg.define("gryt_testflight_testers", "gauge", "Testers on the iPhone app's TestFlight, from App Store Connect.");
reg.define("gryt_server_members", "gauge", "Members of a public Gryt server, from its /info.");
reg.define("gryt_reach_source_ok", "gauge", "1 if the last read of this source worked.");

const githubHeaders = (): Record<string, string> => ({
  accept: "application/vnd.github+json",
  ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
});

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return (await res.json()) as T;
}

async function source(name: string, read: () => Promise<void>): Promise<void> {
  try {
    await read();
    reg.set("gryt_reach_source_ok", { source: name }, 1);
  } catch (e) {
    console.error(name, e);
    reg.set("gryt_reach_source_ok", { source: name }, 0);
  }
}

async function releases(repo: string): Promise<void> {
  const sums = new Map<string, number>();
  for (let page = 1; ; page++) {
    const list = await json<{ assets: { name: string; download_count: number }[] }[]>(
      `https://api.github.com/repos/${ORG}/${repo}/releases?per_page=100&page=${page}`,
      { headers: githubHeaders() },
    );
    for (const a of list.flatMap((r) => r.assets)) {
      const c = classify(a.name);
      if (c) sums.set(`${c.platform}|${c.kind}`, (sums.get(`${c.platform}|${c.kind}`) ?? 0) + a.download_count);
    }
    if (list.length < 100) break;
  }
  for (const [key, n] of sums) {
    const [platform, kind] = key.split("|");
    reg.set("gryt_release_downloads_total", { repo, platform, kind }, n);
  }
}

async function repos(): Promise<void> {
  const list = await json<{ name: string; stargazers_count: number; forks_count: number; private: boolean }[]>(
    `https://api.github.com/orgs/${ORG}/repos?per_page=100&type=public`,
    { headers: githubHeaders() },
  );
  for (const r of list.filter((r) => !r.private)) {
    reg.set("gryt_github_stars", { repo: r.name }, r.stargazers_count);
    reg.set("gryt_github_forks", { repo: r.name }, r.forks_count);
  }
  const org = await json<{ followers: number }>(`https://api.github.com/orgs/${ORG}`, { headers: githubHeaders() });
  reg.set("gryt_github_followers", {}, org.followers);
}

async function ghcr(pkg: string): Promise<void> {
  const res = await fetch(`https://github.com/${ORG}/${pkg}/pkgs/container/${pkg}`);
  const n = res.ok ? packageDownloads(await res.text()) : null;
  if (n === null) throw new Error(`${pkg} package page: ${res.status}, no download count`);
  reg.set("gryt_container_pulls_total", { package: pkg }, n);
}

async function npm(): Promise<void> {
  for (const pkg of NPM) {
    const d = await json<{ downloads: number }>(`https://api.npmjs.org/downloads/point/last-month/${pkg}`);
    reg.set("gryt_npm_downloads_month", { package: pkg }, d.downloads);
  }
}

async function discord(invite: string): Promise<void> {
  const d = await json<{ approximate_member_count: number }>(`https://discord.com/api/v10/invites/${invite}?with_counts=true`);
  reg.set("gryt_discord_members", {}, d.approximate_member_count);
}

async function cloudflare(token: string, zoneId: string, zone: string): Promise<void> {
  const day = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  const query = `query($z:String!,$d:Date!){viewer{zones(filter:{zoneTag:$z}){httpRequests1dGroups(limit:1,filter:{date:$d}){sum{pageViews} uniq{uniques}}}}}`;
  const r = await json<{ data?: { viewer: { zones: { httpRequests1dGroups: { sum: { pageViews: number }; uniq: { uniques: number } }[] }[] } } }>(
    "https://api.cloudflare.com/client/v4/graphql",
    { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ query, variables: { z: zoneId, d: day } }) },
  );
  const row = r.data?.viewer.zones[0]?.httpRequests1dGroups[0];
  if (!row) throw new Error(`cloudflare: no data for ${day}`);
  reg.set("gryt_web_pageviews_day", { zone }, row.sum.pageViews);
  reg.set("gryt_web_visitors_day", { zone }, row.uniq.uniques);
}

const BREAKDOWNS = { clientRequestHTTPHost: "host", clientCountryName: "country", clientDeviceType: "device" } as const;

// Pages people opened over the last 24 hours, split three ways. Bots and assets are left out.
async function cloudflareBreakdown(token: string, zoneId: string): Promise<void> {
  const since = new Date(Date.now() - 86_400_000).toISOString();
  for (const [dim, label] of Object.entries(BREAKDOWNS)) {
    const query = `query($z:String!,$s:Time!){viewer{zones(filter:{zoneTag:$z}){httpRequestsAdaptiveGroups(limit:20,orderBy:[count_DESC],filter:{datetime_geq:$s,requestSource:"eyeball",edgeResponseContentTypeName:"html"}){count dimensions{${dim}}}}}}`;
    const r = await json<{ data?: { viewer: { zones: { httpRequestsAdaptiveGroups: { count: number; dimensions: Record<string, string> }[] }[] } } }>(
      "https://api.cloudflare.com/client/v4/graphql",
      { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ query, variables: { z: zoneId, s: since } }) },
    );
    const rows = r.data?.viewer.zones[0]?.httpRequestsAdaptiveGroups;
    if (!rows) throw new Error(`cloudflare: no ${label} breakdown`);
    const name = `gryt_web_pageviews_24h_by_${label}`;
    reg.clear(name);
    for (const row of rows) {
      const value = row.dimensions[dim];
      if (label === "host" && value.includes(":")) continue;
      reg.set(name, { [label]: value || "unknown" }, row.count);
    }
  }
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");

// App Store Connect wants an ES256 JWT, at most 20 minutes long, with the signature in raw r||s form.
export function ascToken(keyId: string, issuer: string, pem: string, now = Date.now()): string {
  const iat = Math.floor(now / 1000);
  const head = b64url(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JWT" }));
  const body = b64url(JSON.stringify({ iss: issuer, iat, exp: iat + 600, aud: "appstoreconnect-v1" }));
  const sig = sign("sha256", Buffer.from(`${head}.${body}`), { key: createPrivateKey(pem), dsaEncoding: "ieee-p1363" });
  return `${head}.${body}.${b64url(sig)}`;
}

async function testflight(keyId: string, issuer: string, keyFile: string, bundleId: string): Promise<void> {
  const headers = { authorization: `Bearer ${ascToken(keyId, issuer, readFileSync(keyFile, "utf8"))}` };
  const api = "https://api.appstoreconnect.apple.com/v1";
  const apps = await json<{ data: { id: string }[] }>(`${api}/apps?filter[bundleId]=${bundleId}`, { headers });
  const app = apps.data[0]?.id;
  if (!app) throw new Error(`testflight: no app ${bundleId}`);
  const testers = await json<{ meta: { paging: { total: number } } }>(`${api}/betaTesters?filter[apps]=${app}&limit=1`, { headers });
  reg.set("gryt_testflight_testers", { app: bundleId }, testers.meta.paging.total);
}

async function members(host: string): Promise<void> {
  const info = await json<{ members: string }>(`https://${host}/info`);
  reg.set("gryt_server_members", { server: host }, Number(info.members));
}

async function refresh(): Promise<void> {
  for (const host of (process.env.SERVERS ?? "").split(",").filter(Boolean)) await source(`server:${host}`, () => members(host));
  for (const repo of RELEASE_REPOS) await source(`releases:${repo}`, () => releases(repo));
  await source("github", repos);
  for (const pkg of PACKAGES) await source(`ghcr:${pkg}`, () => ghcr(pkg));
  await source("npm", npm);
  const env = process.env;
  if (env.DISCORD_INVITE) await source("discord", () => discord(env.DISCORD_INVITE as string));
  if (env.CLOUDFLARE_API_TOKEN && env.CLOUDFLARE_ZONE_ID) {
    await source("cloudflare", () => cloudflare(env.CLOUDFLARE_API_TOKEN as string, env.CLOUDFLARE_ZONE_ID as string, env.CLOUDFLARE_ZONE ?? "gryt.chat"));
    await source("cloudflare:breakdown", () => cloudflareBreakdown(env.CLOUDFLARE_API_TOKEN as string, env.CLOUDFLARE_ZONE_ID as string));
  }
  if (env.ASC_KEY_ID && env.ASC_ISSUER_ID && env.ASC_KEY_FILE) {
    const { ASC_KEY_ID: id, ASC_ISSUER_ID: iss, ASC_KEY_FILE: file } = env;
    await source("testflight", () => testflight(id, iss, file, env.ASC_BUNDLE_ID ?? "chat.gryt.app"));
  }
}

if (process.argv[1]?.endsWith("reach.ts")) {
  await refresh();
  setInterval(() => void refresh(), REFRESH_MS);
  createServer((req, res) => {
    if (req.url !== "/metrics") return void res.writeHead(404).end();
    res.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end(reg.render());
  }).listen(Number(process.env.PORT ?? 9800));
}
