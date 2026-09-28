import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** The relay's half of pairing, in memory only. See docs/pairing-design.md in Gryt-chat/crypto. */
export const LIMITS = {
  openMs: 5 * 60_000,
  approveMs: 2 * 60_000,
  sessionMs: 60 * 60_000,
  messageBytes: 64 * 1024,
  envelopeBytes: 256 * 1024,
  messagesPerSession: 64,
  maxWaitMs: 25_000,
  maxSessions: 1000,
  maxStoredBytes: 256 * 1024 * 1024,
  sessionsPerIp: 10,
  sessionWindowMs: 10 * 60_000,
  codeFailuresPerIp: 20,
  codeFailureWindowMs: 10 * 60_000,
  codeBlockMs: 60 * 60_000,
  tombstoneMs: 10 * 60_000,
};
export type Limits = typeof LIMITS;

export class RelayError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

type Side = "n" | "a";
type State = "open" | "claimed" | "revealed" | "approved";

export interface Message {
  seq: number;
  type: "claim" | "reveal" | "sealed";
  pkA?: string;
  pkN?: string;
  body?: string;
}

interface Session {
  id: string;
  code: string | null;
  commit: Buffer;
  tokens: { n: Buffer; a: Buffer | null };
  location: string | null;
  state: State;
  createdAt: number;
  claimedAt: number;
  expiresAt: number;
  sent: { n: Message[]; a: Message[] };
  seq: { n: number; a: number };
  posted: number;
  bigUsed: boolean;
  bytes: number;
  waiters: Set<() => void>;
}

interface Hits {
  count: number;
  start: number;
}

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD = /^[0-9A-HJKMNP-TV-Z]+$/;
const B64U = /^[A-Za-z0-9_-]+$/;

function crockford(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** Typed text to the canonical code, forgiving case, dashes, O, I and L like recovery-key.ts. */
export function normalizeCode(text: string): string | null {
  const clean = text.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  return clean.length === 8 && CROCKFORD.test(clean) ? clean : null;
}

/** A 32-byte key or commitment as unpadded base64url, spelled exactly one way. */
function decodeKey(value: unknown): Buffer | null {
  if (typeof value !== "string" || value.length !== 43 || !B64U.test(value)) return null;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes : null;
}

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();
const commitOf = (pkN: Buffer) => sha256(Buffer.concat([Buffer.from("gryt-pair-v1 commit"), pkN]));
const seconds = (ms: number) => `${Math.round(ms / 1000)}s`;

export interface RelayOptions {
  limits?: Partial<Limits>;
  now?: () => number;
  log?: (line: string) => void;
}

export class Relay {
  readonly limits: Limits;
  readonly sessions = new Map<string, Session>();
  private readonly codes = new Map<string, string>();
  private readonly ended = new Map<string, { reason: string; until: number }>();
  private readonly opened = new Map<string, Hits>();
  private readonly codeFailures = new Map<string, Hits>();
  private readonly blocked = new Map<string, number>();
  private readonly refusals = new Map<string, number>();
  private readonly now: () => number;
  private readonly log: (line: string) => void;
  private storedBytes = 0;
  private lastFlush: number;
  private timer: NodeJS.Timeout | null = null;

  constructor(options: RelayOptions = {}) {
    this.limits = { ...LIMITS, ...options.limits };
    this.now = options.now ?? Date.now;
    this.log = options.log ?? ((line) => console.log(line));
    this.lastFlush = this.now();
  }

  start(intervalMs = 5000): void {
    this.timer ??= setInterval(() => this.sweep(), intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  create(ip: string, commit: unknown, location: string | null) {
    const commitBytes = decodeKey(commit);
    if (!commitBytes) throw this.refuse(400, "invalid_commit");
    if (this.hit(this.opened, ip, this.limits.sessionWindowMs) > this.limits.sessionsPerIp) {
      throw this.refuse(429, "rate_limited");
    }
    if (this.sessions.size >= this.limits.maxSessions) throw this.refuse(503, "busy");

    let id: string;
    do id = crockford(randomBytes(16));
    while (this.sessions.has(id) || this.ended.has(id));
    let code: string;
    do code = crockford(randomBytes(5));
    while (this.codes.has(code));

    const token = randomBytes(32).toString("base64url");
    const t = this.now();
    this.sessions.set(id, {
      id, code, commit: commitBytes, location, state: "open",
      tokens: { n: sha256(token), a: null },
      createdAt: t, claimedAt: 0, expiresAt: t + this.limits.openMs,
      sent: { n: [], a: [] }, seq: { n: 0, a: 0 },
      posted: 0, bigUsed: false, bytes: 0, waiters: new Set(),
    });
    this.codes.set(code, id);
    this.log(`pairing: session opened, ${this.sessions.size} live`);
    return { id, code, token, expiresAt: new Date(t + this.limits.openMs).toISOString() };
  }

  claim(ip: string, input: { id?: unknown; code?: unknown; pkA?: unknown }, yourLocation: string | null) {
    const pkA = decodeKey(input.pkA);
    if (!pkA) throw this.refuse(400, "invalid_key");

    let session: Session;
    if (input.code !== undefined && input.id === undefined) {
      if ((this.blocked.get(ip) ?? 0) > this.now()) throw this.refuse(429, "rate_limited");
      const code = typeof input.code === "string" ? normalizeCode(input.code) : null;
      const found = code ? this.live(this.codes.get(code)) : undefined;
      if (!found) {
        if (this.hit(this.codeFailures, ip, this.limits.codeFailureWindowMs) >= this.limits.codeFailuresPerIp) {
          this.blocked.set(ip, this.now() + this.limits.codeBlockMs);
          this.codeFailures.delete(ip);
        }
        throw this.refuse(404, "not_found");
      }
      session = found;
    } else if (typeof input.id === "string" && input.code === undefined) {
      session = this.find(input.id);
    } else {
      throw this.refuse(400, "invalid_body");
    }
    if (session.state !== "open") throw this.refuse(409, "already_claimed");

    const token = randomBytes(32).toString("base64url");
    const t = this.now();
    const location = session.location;
    if (session.code) this.codes.delete(session.code);
    session.code = null;
    session.location = null;
    session.state = "claimed";
    session.claimedAt = t;
    session.expiresAt = t + this.limits.approveMs;
    session.tokens.a = sha256(token);
    this.push(session, "a", { type: "claim", pkA: input.pkA as string }, 0);
    this.log(`pairing: session claimed after ${seconds(t - session.createdAt)}`);
    return { id: session.id, token, commit: session.commit.toString("base64url"), location, yourLocation };
  }

  post(id: string, token: string | undefined, message: { type?: unknown; pkN?: unknown; body?: unknown }) {
    const session = this.find(id);
    const side = this.auth(session, token);
    if (session.posted >= this.limits.messagesPerSession) throw this.refuse(429, "too_many_messages");

    if (message.type === "reveal") {
      if (side !== "n") throw this.refuse(403, "wrong_side");
      if (session.state === "open") throw this.refuse(409, "not_claimed");
      if (session.state !== "claimed") throw this.refuse(409, "already_revealed");
      const pkN = decodeKey(message.pkN);
      if (!pkN) throw this.refuse(400, "invalid_key");
      if (!commitOf(pkN).equals(session.commit)) throw this.refuse(409, "commit_mismatch");
      session.state = "revealed";
      return this.push(session, "n", { type: "reveal", pkN: message.pkN as string }, 1);
    }

    if (message.type !== "sealed") throw this.refuse(400, "invalid_body");
    if (session.state === "open" || session.state === "claimed") throw this.refuse(409, "not_revealed");
    const body = message.body;
    if (typeof body !== "string" || !B64U.test(body) || body.length % 4 === 1) {
      throw this.refuse(400, "invalid_body");
    }
    const bytes = Math.floor((body.length * 3) / 4);
    const big = bytes > this.limits.messageBytes;
    if (bytes > this.limits.envelopeBytes || (big && (side !== "a" || session.bigUsed))) {
      throw this.refuse(413, "too_large");
    }
    if (this.storedBytes + body.length > this.limits.maxStoredBytes) throw this.refuse(503, "busy");
    if (big) session.bigUsed = true;
    if (side === "a" && session.state === "revealed") {
      session.state = "approved";
      session.expiresAt = session.claimedAt + this.limits.sessionMs;
    }
    return this.push(session, side, { type: "sealed", body }, 1);
  }

  /** The other side's messages after `after`. Asking past a message is its ack, so R drops it. */
  async poll(id: string, token: string | undefined, after: number, waitMs: number): Promise<Message[]> {
    const session = this.find(id);
    const from: Side = this.auth(session, token) === "n" ? "a" : "n";
    for (const m of session.sent[from]) if (m.seq <= after) this.drop(session, m);
    session.sent[from] = session.sent[from].filter((m) => m.seq > after);

    const deadline = Date.now() + Math.min(waitMs, this.limits.maxWaitMs);
    while (session.sent[from].length === 0 && Date.now() < deadline) {
      await new Promise<void>((resolve) => {
        const wake = () => {
          clearTimeout(timer);
          session.waiters.delete(wake);
          resolve();
        };
        const timer = setTimeout(wake, deadline - Date.now());
        session.waiters.add(wake);
      });
      this.find(id);
    }
    return session.sent[from];
  }

  close(id: string, token: string | undefined): void {
    const session = this.find(id);
    this.auth(session, token);
    this.end(session, "closed");
  }

  sweep(): void {
    const t = this.now();
    for (const session of this.sessions.values()) if (session.expiresAt <= t) this.end(session, "expired");
    for (const [id, e] of this.ended) if (e.until <= t) this.ended.delete(id);
    for (const [ip, h] of this.opened) if (h.start + this.limits.sessionWindowMs <= t) this.opened.delete(ip);
    for (const [ip, h] of this.codeFailures) if (h.start + this.limits.codeFailureWindowMs <= t) this.codeFailures.delete(ip);
    for (const [ip, until] of this.blocked) if (until <= t) this.blocked.delete(ip);
    if (t - this.lastFlush >= 60_000) {
      if (this.refusals.size > 0) {
        const counts = [...this.refusals].map(([reason, n]) => `${reason}=${n}`).join(" ");
        this.log(`pairing: refused ${counts}`);
        this.refusals.clear();
      }
      this.lastFlush = t;
    }
  }

  private live(id: string | undefined): Session | undefined {
    const session = id ? this.sessions.get(id) : undefined;
    if (session && session.expiresAt <= this.now()) {
      this.end(session, "expired");
      return undefined;
    }
    return session;
  }

  private find(id: string): Session {
    const session = this.live(id);
    if (session) return session;
    const ended = this.ended.get(id);
    if (ended) throw this.refuse(410, ended.reason);
    throw this.refuse(404, "not_found");
  }

  private auth(session: Session, token: string | undefined): Side {
    const hash = sha256(token ?? "");
    if (token && timingSafeEqual(hash, session.tokens.n)) return "n";
    if (token && session.tokens.a && timingSafeEqual(hash, session.tokens.a)) return "a";
    throw this.refuse(401, "unauthorized");
  }

  private push(session: Session, side: Side, message: Omit<Message, "seq">, counts: number) {
    const seq = ++session.seq[side];
    const size = message.body?.length ?? 0;
    session.sent[side].push({ seq, ...message });
    session.posted += counts;
    session.bytes += size;
    this.storedBytes += size;
    for (const wake of [...session.waiters]) wake();
    return { seq };
  }

  private drop(session: Session, message: Message): void {
    const size = message.body?.length ?? 0;
    session.bytes -= size;
    this.storedBytes -= size;
  }

  private end(session: Session, reason: "closed" | "expired"): void {
    this.sessions.delete(session.id);
    if (session.code) this.codes.delete(session.code);
    this.storedBytes -= session.bytes;
    this.ended.set(session.id, { reason, until: this.now() + this.limits.tombstoneMs });
    for (const wake of [...session.waiters]) wake();
    this.log(`pairing: session ${reason} after ${seconds(this.now() - session.createdAt)}, ${session.state}`);
  }

  private hit(map: Map<string, Hits>, ip: string, windowMs: number): number {
    const t = this.now();
    let hits = map.get(ip);
    if (!hits || hits.start + windowMs <= t) {
      hits = { count: 0, start: t };
      map.set(ip, hits);
    }
    return ++hits.count;
  }

  private refuse(status: number, reason: string): RelayError {
    this.refusals.set(reason, (this.refusals.get(reason) ?? 0) + 1);
    return new RelayError(status, reason);
  }
}
