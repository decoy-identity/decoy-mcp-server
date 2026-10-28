// RFC 6238 TOTP generation from a sealed seed.
//
// The Decoy device seals a TOTP *seed* (base32 secret + algorithm/digits/period), never a live
// code — a sealed 6-digit code would expire ~30s after the grant. So the agent regenerates the
// current code on demand from the seed, here, with the user's phone off. Pure + dependency-free
// (node:crypto only) so it's unit-tested against the RFC 6238 vectors.

import { createHmac } from 'node:crypto';

export interface TotpSeed {
  secret_base32: string;
  algorithm?: string; // SHA1 | SHA256 | SHA512 (default SHA1)
  digits?: number;    // default 6
  period?: number;    // default 30
}

/** The longest text read as a secret. A secret is at most 64 bytes (SHA-512): 103 characters, or
 *  about 130 in groups; anything longer than this is not one and is not decoded. */
export const SEED_MAX_TEXT = 512;
/** Text without the "=" at its end (a loop: a pattern for this is slow on a long run of "="). */
const withoutPadding = (s: string): string => { let end = s.length; while (end > 0 && s.charCodeAt(end - 1) === 61) end--; return s.slice(0, end); };

/** Decode an RFC 4648 base32 string (case-insensitive, padding optional) to bytes. */
export function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of withoutPadding(input.toUpperCase())) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue; // skip stray separators/whitespace
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** Generate the current TOTP code for a sealed seed. `nowMs` is injectable for deterministic tests. */
export function generateTOTPCode(seed: TotpSeed, nowMs: number = Date.now()): string {
  const period = seed.period && seed.period > 0 ? seed.period : 30;
  const digits = seed.digits && seed.digits > 0 ? seed.digits : 6;
  const algo = (seed.algorithm ?? 'SHA1').toLowerCase(); // 'sha1' | 'sha256' | 'sha512'

  const counter = Math.floor(Math.floor(nowMs / 1000) / period);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac(algo, base32Decode(seed.secret_base32)).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

/** A sealed seed, checked: anything else (no seed saved, a malformed one) is null. */
export function asTotpSeed(v: unknown): TotpSeed | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const s = v as Record<string, unknown>;
  if (typeof s.secret_base32 !== 'string' || s.secret_base32.length > SEED_MAX_TEXT || base32Decode(s.secret_base32).length === 0) return null;
  const algorithm = typeof s.algorithm === 'string' ? s.algorithm.toUpperCase().replace('-', '') : 'SHA1';
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) return null;
  const whole = (n: unknown, max: number) => (typeof n === 'number' && Number.isInteger(n) && n > 0 && n <= max ? n : undefined);
  return { secret_base32: s.secret_base32, algorithm, digits: whole(s.digits, 10) ?? 6, period: whole(s.period, 3600) ?? 30 };
}

/** The code that is valid now and how long it stays valid. The seed itself is never returned. */
export function currentTotp(seed: unknown, nowMs: number = Date.now()): { code: string; expires_in_seconds: number } | null {
  const s = asTotpSeed(seed);
  if (!s) return null;
  const period = s.period!;
  try {
    return { code: generateTOTPCode(s, nowMs), expires_in_seconds: period - (Math.floor(nowMs / 1000) % period) };
  } catch { return null; }
}

/** A key name with case and separators removed: totpSeed, TOTP-Seed and totp_seed are one name. */
const plainKey = (k: string) => k.toLowerCase().replace(/[^a-z0-9]/g, '');
/** A key that names 2FA material. Nothing under such a key is ever handed to an agent. */
export const isTotpKey = (k: string): boolean => /totp|otp|seed|secretbase32/.test(plainKey(k));
/** Text that holds a provisioning URI (it carries the secret). */
export const hasOtpAuthUri = (v: unknown): boolean => typeof v === 'string' && /otpauth:\/\//i.test(v);
/**
 * Text shaped like a bare 2FA secret, as authenticator set-up screens show one or as a person
 * types one. After the space around it and any "=" padding at its end are taken off, it is one of:
 *
 *  1. Base32 (A-Z and 2-7) in ONE case, 16 characters or more, either unbroken or in even groups
 *     (of four, or of eight) with one kind of separator between them (hyphens, or space: any run
 *     of spaces, tabs or line breaks counts as one). The 16 are counted without the separators,
 *     so groups of four are four groups or more and groups of eight are two or more. No digit is
 *     asked for: about one 16-character secret in 28 has none.
 *  2. Base32 in ONE case and ANY grouping (all space, hyphens and "=" taken out), 16 characters or
 *     more, with at least one of the digits 2-7 in it: a secret typed with other spacing.
 *
 * A value in that shape is treated as a secret wherever one must not leave: it can give a code,
 * and it is never handed on as a password or a note. Ordinary text is not in that shape ("Shared
 * with the family": two cases, uneven words, no digit), so it is returned. Four words of four
 * letters in one case ("call home once more") ARE in the shape, and so are letters in one case,
 * spaces and hyphens with a digit from 2 to 7 and no other digit or symbol ("garden gate code
 * 47"): nothing tells them from a secret, so they are held back, and the read says that it held
 * a value back (never that none is saved).
 *
 * What is left: a value in TWO cases is never in the shape, because a generated password of
 * mixed-case letters and digits looks the same (about one in four of 16 characters has only the
 * digits 2-7). So a secret typed in mixed case ("JbswY3dpEhpk3pxp") is returned as text by a
 * password or a note read, though a 2FA read would make a code from it. So is a secret with no
 * digit in uneven groups. Text longer than SEED_MAX_TEXT is not in the shape.
 */
const SEED_MIN_CHARS = 16;
const SEED_SHAPES: RegExp[] = ['A-Z2-7', 'a-z2-7'].flatMap((c) => [
  new RegExp(`^[${c}]{16,}$`),
  ...[' ', '-'].flatMap((sep) => [
    new RegExp(`^(?:[${c}]{4}${sep}){3,}[${c}]{1,4}$`),
    new RegExp(`^(?:[${c}]{8}${sep})+[${c}]{8}(?:${sep}[${c}]{1,8})?$|^(?:[${c}]{8}${sep}){2,}[${c}]{1,8}$`),
  ]),
]);
export const isSeedShaped = (v: unknown): v is string => {
  if (typeof v !== 'string' || v.length > SEED_MAX_TEXT) return false;
  const t = withoutPadding(v.trim()).replace(/\s+/g, ' ');
  if (t.replace(/[ -]/g, '').length >= SEED_MIN_CHARS && SEED_SHAPES.some((shape) => shape.test(t))) return true;
  // Space, hyphens and "=" out, wherever they are; then one case, with a digit.
  const plain = v.replace(/[\s=-]/g, '');
  return plain.length >= SEED_MIN_CHARS && (/^[A-Z2-7]+$/.test(plain) || /^[a-z2-7]+$/.test(plain)) && /[2-7]/.test(plain);
};
/** Text that can be read as a base32 secret when a 2FA code is asked for (any case, any spacing).
 *  Wider than isSeedShaped on purpose (two cases, and words with no digit): this one only ever
 *  leads to a code, never to the text. */
const readsAsBase32 = (v: string): boolean => v.length <= SEED_MAX_TEXT && /^[A-Za-z2-7]{16,}$/.test(v.replace(/[\s=-]/g, ''));
const SECRET_KEYS = new Set(['secretbase32', 'secret', 'seed', 'base32', 'key', 'totpsecret', 'totpseed', 'otpsecret']);

/**
 * The seed in a value, in whatever recognisable shape it arrived: the sealed form, an object with
 * the secret under another name (secret, secretBase32, …), an otpauth:// URI, a bare base32
 * secret, or one of those inside a list or one level down. null when there is none.
 */
export function findTotpSeed(v: unknown, depth = 0): TotpSeed | null {
  if (typeof v === 'string') {
    const uri = /otpauth:\/\/[^\s"']+/i.exec(v)?.[0];
    if (uri) {
      const q = new URLSearchParams(uri.split('?')[1] ?? '');
      const num = (k: string) => (q.get(k) && /^\d+$/.test(q.get(k)!) ? Number(q.get(k)) : undefined);
      return asTotpSeed({ secret_base32: q.get('secret') ?? '', algorithm: q.get('algorithm') ?? undefined, digits: num('digits'), period: num('period') });
    }
    return readsAsBase32(v) ? asTotpSeed({ secret_base32: v.replace(/[\s=-]/g, '') }) : null;
  }
  if (!v || typeof v !== 'object' || depth > 3) return null;
  if (Array.isArray(v)) {
    for (const x of v) { const s = findTotpSeed(x, depth + 1); if (s) return s; }
    return null;
  }
  const entries = Object.entries(v as Record<string, unknown>);
  const named = (name: string) => entries.find(([k]) => plainKey(k) === name)?.[1];
  for (const [k, x] of entries) {
    if (!SECRET_KEYS.has(plainKey(k)) || typeof x !== 'string') continue;
    if (hasOtpAuthUri(x)) return findTotpSeed(x, depth + 1);
    const s = asTotpSeed({ secret_base32: x, algorithm: named('algorithm') ?? undefined, digits: named('digits'), period: named('period') });
    if (s) return s;
  }
  for (const [k, x] of entries) {
    if (!isTotpKey(k) && !hasOtpAuthUri(x)) continue;
    const s = findTotpSeed(x, depth + 1);
    if (s) return s;
  }
  return null;
}
