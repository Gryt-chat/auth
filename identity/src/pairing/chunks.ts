import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, statfs, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { RelayError } from "./relay.js";

const MiB = 1024 * 1024;

/** History chunk storage on disk. See "The disk" in docs/pairing-design.md in Gryt-chat/crypto. */
export const CHUNK_LIMITS = {
  chunkBytes: 2 * MiB,
  sessionBytes: 256 * MiB,
  totalBytes: 2048 * MiB,
  minFreeBytes: 5120 * MiB,
  uploadBytesPerIp: 1024 * MiB,
  uploadWindowMs: 24 * 60 * 60_000,
  maxAgeMs: 60 * 60_000,
  maxSlot: 65_535,
  // What the total cap charges a file at least, so a flood of tiny chunks still counts.
  fileBytes: 4096,
};
export type ChunkLimits = typeof CHUNK_LIMITS;

const ENV: [string, keyof ChunkLimits][] = [
  ["GRYT_PAIRING_CHUNKS_SESSION_MIB", "sessionBytes"],
  ["GRYT_PAIRING_CHUNKS_TOTAL_MIB", "totalBytes"],
  ["GRYT_PAIRING_CHUNKS_MIN_FREE_MIB", "minFreeBytes"],
  ["GRYT_PAIRING_CHUNKS_PER_IP_MIB", "uploadBytesPerIp"],
];

export function chunkLimitsFromEnv(env: Record<string, string | undefined>): Partial<ChunkLimits> {
  const limits: Partial<ChunkLimits> = {};
  for (const [name, key] of ENV) {
    const raw = env[name]?.trim();
    if (!raw) continue;
    if (!/^\d{1,7}$/.test(raw)) throw new Error(`${name}: "${raw}" isn't a whole number of MiB.`);
    limits[key] = Number(raw) * MiB;
  }
  return limits;
}

// Session ids are 16 random bytes in Crockford base32. Nothing else in the folder is ours to delete.
const SESSION_DIR = /^[0-9A-HJKMNP-TV-Z]{26}$/;

interface Slot {
  bytes: number;
  hash: Buffer;
  ready: boolean;
  storedAt: number;
  fetches: number;
}

interface Held {
  slots: Map<number, Slot>;
  bytes: number;
}

export interface ChunkStoreOptions {
  limits?: Partial<ChunkLimits>;
  now?: () => number;
  log?: (line: string) => void;
  /** Free bytes on the disk under `dir`. Tests swap it for a number. */
  freeBytes?: (dir: string) => Promise<number>;
}

const sha256 = (data: Buffer) => createHash("sha256").update(data).digest();
const errorCode = (e: unknown) => (e as NodeJS.ErrnoException)?.code ?? "unknown";

async function statfsFree(dir: string): Promise<number> {
  const s = await statfs(dir);
  return s.bavail * s.bsize;
}

/** Sealed chunk files under `<dir>/<session>/<n>`, and in memory only what they cost. */
export class ChunkStore {
  readonly dir: string;
  readonly limits: ChunkLimits;
  private readonly held = new Map<string, Held>();
  private readonly uploads = new Map<string, { bytes: number; start: number }>();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private readonly freeBytes: (dir: string) => Promise<number>;
  private total = 0;
  private stored = { count: 0, bytes: 0 };

  constructor(dir: string, options: ChunkStoreOptions = {}) {
    this.dir = dir;
    this.limits = { ...CHUNK_LIMITS, ...options.limits };
    this.now = options.now ?? Date.now;
    this.log = options.log ?? ((line) => console.log(line));
    this.freeBytes = options.freeBytes ?? statfsFree;
  }

  /** At startup: the sessions went with the last process, so their chunks go too. */
  async wipe(): Promise<number> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    let removed = 0;
    for (const name of await readdir(this.dir)) {
      if (!SESSION_DIR.test(name)) continue;
      await rm(join(this.dir, name), { recursive: true, force: true }).then(
        () => removed++,
        (e) => this.log(`pairing: couldn't remove a chunk folder at startup: ${errorCode(e)}`),
      );
    }
    return removed;
  }

  /** What the total cap currently counts, in bytes. */
  get totalBytes(): number {
    return this.total;
  }

  async put(id: string, n: number, body: Buffer, ip: string): Promise<void> {
    let held = this.held.get(id);
    const hash = sha256(body);
    const existing = held?.slots.get(n);
    if (existing) {
      // A retry after a lost response sends the same bytes again, and that's fine.
      if (existing.ready && existing.hash.equals(hash)) return;
      throw new RelayError(409, "exists");
    }
    const charge = Math.max(body.length, this.limits.fileBytes);
    if ((held?.bytes ?? 0) + body.length > this.limits.sessionBytes) throw new RelayError(507, "session_full");
    if (this.total + charge > this.limits.totalBytes) throw new RelayError(507, "full");
    const t = this.now();
    let up = this.uploads.get(ip);
    if (!up || up.start + this.limits.uploadWindowMs <= t) {
      up = { bytes: 0, start: t };
      this.uploads.set(ip, up);
    }
    if (up.bytes + body.length > this.limits.uploadBytesPerIp) throw new RelayError(429, "rate_limited");

    if (!held) {
      held = { slots: new Map(), bytes: 0 };
      this.held.set(id, held);
    }
    const slot: Slot = { bytes: body.length, hash, ready: false, storedAt: t, fetches: 0 };
    held.slots.set(n, slot);
    held.bytes += body.length;
    this.total += charge;
    up.bytes += body.length;

    const file = join(this.dir, id, String(n));
    try {
      if ((await this.freeBytes(this.dir)) - body.length < this.limits.minFreeBytes) {
        throw new RelayError(507, "disk_low");
      }
      await mkdir(join(this.dir, id), { recursive: true, mode: 0o700 });
      await writeFile(file, body, { flag: "wx", mode: 0o600 });
    } catch (e) {
      this.forget(id, n, slot);
      up.bytes = Math.max(0, up.bytes - body.length);
      if (e instanceof RelayError) throw e;
      this.log(`pairing: storing a chunk failed: ${errorCode(e)}`);
      throw new RelayError(503, "busy");
    }
    if (this.held.get(id)?.slots.get(n) !== slot) {
      await this.track(rm(file, { force: true }).catch(() => undefined));
      return;
    }
    slot.ready = true;
    slot.storedAt = this.now();
    this.stored.count++;
    this.stored.bytes += body.length;
  }

  /** The chunk in slot `n`, or null. The second fetch deletes it, as N's DELETE would. */
  async get(id: string, n: number): Promise<Buffer | null> {
    const slot = this.held.get(id)?.slots.get(n);
    if (!slot?.ready) return null;
    let body: Buffer;
    try {
      body = await readFile(join(this.dir, id, String(n)));
    } catch (e) {
      if (errorCode(e) !== "ENOENT") this.log(`pairing: reading a chunk failed: ${errorCode(e)}`);
      this.forget(id, n, slot);
      if (errorCode(e) === "ENOENT") return null;
      throw new RelayError(503, "busy");
    }
    if (++slot.fetches >= 2) await this.delete(id, n);
    return body;
  }

  async delete(id: string, n: number): Promise<void> {
    const slot = this.held.get(id)?.slots.get(n);
    if (!slot) return;
    this.forget(id, n, slot);
    if (!slot.ready) return;
    await this.track(
      unlink(join(this.dir, id, String(n))).catch((e) => {
        if (errorCode(e) !== "ENOENT") this.log(`pairing: deleting a chunk failed: ${errorCode(e)}`);
      }),
    );
  }

  /** The session is gone: every chunk it had goes with it. */
  drop(id: string): void {
    const held = this.held.get(id);
    if (held) for (const [n, slot] of held.slots) this.forget(id, n, slot);
    this.held.delete(id);
    void this.track(
      rm(join(this.dir, id), { recursive: true, force: true }).catch((e) => {
        this.log(`pairing: removing a session's chunks failed: ${errorCode(e)}`);
      }),
    );
  }

  /** Chunks past their hour, sessions the relay no longer has, and folders nobody owns. */
  async sweep(live: (id: string) => boolean, orphans = false): Promise<void> {
    const t = this.now();
    for (const [id, held] of this.held) {
      if (!live(id)) {
        this.drop(id);
        continue;
      }
      for (const [n, slot] of held.slots) {
        if (slot.ready && slot.storedAt + this.limits.maxAgeMs <= t) await this.delete(id, n);
      }
    }
    for (const [ip, up] of this.uploads) if (up.start + this.limits.uploadWindowMs <= t) this.uploads.delete(ip);
    if (!orphans) return;
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch (e) {
      return this.log(`pairing: listing the chunk folder failed: ${errorCode(e)}`);
    }
    for (const name of names) {
      if (SESSION_DIR.test(name) && !this.held.has(name) && !live(name)) this.drop(name);
    }
  }

  /** Chunks stored since the last call, for the relay's once-a-minute log line. */
  flushStats(): { count: number; bytes: number } {
    const stats = this.stored;
    this.stored = { count: 0, bytes: 0 };
    return stats;
  }

  /** Resolves once every file operation started so far has finished. */
  async idle(): Promise<void> {
    while (this.pending.size > 0) await Promise.all([...this.pending]);
  }

  private forget(id: string, n: number, slot: Slot): void {
    const held = this.held.get(id);
    if (!held || held.slots.get(n) !== slot) return;
    held.slots.delete(n);
    held.bytes -= slot.bytes;
    this.total -= Math.max(slot.bytes, this.limits.fileBytes);
  }

  private track<T>(work: Promise<T>): Promise<T> {
    this.pending.add(work);
    return work.finally(() => this.pending.delete(work));
  }
}
