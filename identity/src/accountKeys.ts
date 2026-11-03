import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { calculateJwkThumbprint, EmbeddedJWK, jwtVerify, type JWK } from "jose";

/**
 * Which seed an account's devices hold (GRYT-2016). A certificate request carries a proof signed by a
 * key derived from the seed, so a linked device or the 24 words pass and a password alone doesn't.
 */

export type GateMode = "off" | "learn" | "enforce";

export function gateModeFromEnv(value: string | undefined): GateMode {
  return value === "off" || value === "enforce" ? value : "learn";
}

/** Same as the DM key reset: long enough that you notice, short enough to get back in. */
export const RESET_DELAY_MS = 30 * 24 * 60 * 60 * 1000;
const PROOF_MAX_AGE_S = 5 * 60;

interface KeyRecord { thumb: string; firstSeen: number; lastSeen: number }
interface AccountRecord { keys: KeyRecord[]; reset: { thumb: string; at: number } | null }

/** The seed key's thumbprint, once the proof is checked against this account and this certificate key. */
export async function verifyProof(proof: unknown, sub: string, certJwk: JWK, nowS = Math.floor(Date.now() / 1000)): Promise<string | null> {
  if (typeof proof !== "string" || proof.length > 4096) return null;
  try {
    const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, { algorithms: ["ES256"], subject: sub, currentDate: new Date(nowS * 1000) });
    if (payload.cnf !== (await calculateJwkThumbprint(certJwk))) return null;
    if (typeof payload.iat !== "number" || Math.abs(nowS - payload.iat) > PROOF_MAX_AGE_S) return null;
    return await calculateJwkThumbprint(protectedHeader.jwk as JWK);
  } catch {
    return null;
  }
}

export type CertDecision = { ok: true } | { ok: false; resetAt: number | null };

export class AccountKeys {
  constructor(private dir: string, private now: () => number = Date.now) {}

  private file(sub: string) {
    return join(this.dir, `${createHash("sha256").update(sub).digest("hex")}.json`);
  }

  async read(sub: string): Promise<AccountRecord> {
    try {
      return JSON.parse(await readFile(this.file(sub), "utf8")) as AccountRecord;
    } catch {
      return { keys: [], reset: null };
    }
  }

  private async write(sub: string, rec: AccountRecord) {
    await mkdir(this.dir, { recursive: true });
    const tmp = `${this.file(sub)}.tmp`;
    await writeFile(tmp, JSON.stringify(rec));
    await rename(tmp, this.file(sub));
  }

  /** Due 30 days after the ask, or 30 days after any known key was last used, whichever is first. */
  resetDueAt(rec: AccountRecord): number | null {
    if (!rec.reset) return null;
    const lastSeen = Math.max(0, ...rec.keys.map((k) => k.lastSeen));
    return Math.min(rec.reset.at, lastSeen + RESET_DELAY_MS);
  }

  /** Whether this seed key may get a certificate, recording it as it goes. */
  async decide(sub: string, thumb: string | null, mode: GateMode): Promise<CertDecision> {
    if (mode === "off") return { ok: true };
    const rec = await this.read(sub);
    const now = this.now();
    const known = thumb ? rec.keys.find((k) => k.thumb === thumb) : undefined;
    if (known) {
      known.lastSeen = now;
      await this.write(sub, rec);
      return { ok: true };
    }
    if (thumb && (mode === "learn" || rec.keys.length === 0)) {
      rec.keys.push({ thumb, firstSeen: now, lastSeen: now });
      await this.write(sub, rec);
      return { ok: true };
    }
    if (mode === "learn") return { ok: true };
    const due = this.resetDueAt(rec);
    if (thumb && rec.reset?.thumb === thumb && due !== null && due <= now) {
      await this.write(sub, { keys: [{ thumb, firstSeen: now, lastSeen: now }], reset: null });
      return { ok: true };
    }
    return { ok: false, resetAt: rec.reset?.thumb === thumb ? due : null };
  }

  /** Lost every device and the words: this seed key takes over later. Asking again doesn't restart the clock. */
  async requestReset(sub: string, thumb: string): Promise<number | null> {
    const rec = await this.read(sub);
    if (rec.keys.some((k) => k.thumb === thumb)) return null;
    if (rec.reset?.thumb !== thumb) {
      rec.reset = { thumb, at: this.now() + RESET_DELAY_MS };
      await this.write(sub, rec);
    }
    return this.resetDueAt(rec);
  }

  /** "That wasn't me": only a known seed key can stop it. */
  async cancelReset(sub: string, thumb: string): Promise<boolean> {
    const rec = await this.read(sub);
    if (!rec.keys.some((k) => k.thumb === thumb)) return false;
    if (rec.reset) {
      rec.reset = null;
      await this.write(sub, rec);
    }
    return true;
  }

  /** What a device with this seed key should know: whether it's on record, and any reset under way. */
  async status(sub: string, thumb: string): Promise<{ known: boolean; resetAt: number | null; resetIsYours: boolean }> {
    const rec = await this.read(sub);
    return { known: rec.keys.some((k) => k.thumb === thumb), resetAt: this.resetDueAt(rec), resetIsYours: rec.reset?.thumb === thumb };
  }
}
