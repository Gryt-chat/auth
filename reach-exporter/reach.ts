// Public numbers on how far Gryt reaches, as Prometheus metrics: downloads, pulls, stars, visitors.
// Nothing here reports home; every source is a public page or an API the project owns.
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
  // Labels are ours or GitHub's names, never user input, so no escaping.
  set(name: string, labels: Labels, value: number): void {
    const key = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(",");
    this.metrics.get(name)?.samples.set(key, value);
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

async function refresh(): Promise<void> {
  for (const repo of RELEASE_REPOS) await source(`releases:${repo}`, () => releases(repo));
  await source("github", repos);
  for (const pkg of PACKAGES) await source(`ghcr:${pkg}`, () => ghcr(pkg));
  await source("npm", npm);
  const env = process.env;
  if (env.DISCORD_INVITE) await source("discord", () => discord(env.DISCORD_INVITE as string));
  if (env.CLOUDFLARE_API_TOKEN && env.CLOUDFLARE_ZONE_ID) {
    await source("cloudflare", () => cloudflare(env.CLOUDFLARE_API_TOKEN as string, env.CLOUDFLARE_ZONE_ID as string, env.CLOUDFLARE_ZONE ?? "gryt.chat"));
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
