// key-format: canonical-json, signature, key-set
//
// The bridge's readers of canonical JSON, signatures and key sets (the key format spec's
// canonical-json, signature and key-set), version 1: the same formats byte for byte as the Decoy
// API's, checked against the same sha-pinned vectors (canonical-json.vectors.json,
// signature.vectors.json and key-set.vectors.json).
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalSpki, isKeyId, keyIdFromSpki, keyKind, SEAL_FORMAT_BYTE, SEAL_OVERHEAD_BYTES, SEAL_VERSION } from './key-format.js';

// Canonical JSON for signed data (the key format spec's canonical-json), version 1: RFC 8785
// (JSON Canonicalization Scheme) on a subset small enough that every platform writes it the same
// way with no number formatting and no Unicode collation:
//   - the payload is one object, nested at most 8 deep (the payload at depth 1);
//   - member names are 1 to 64 bytes of ASCII a-z 0-9 _, the first a letter, so RFC 8785's sort by
//     UTF-16 code units is byte order, and no two members of one object share a name;
//   - values are objects, arrays, strings, integers, true, false and null;
//   - integers are 0 to 2^53 - 1 in the shortest decimal (no sign, leading zero, fraction or exponent);
//   - strings are Unicode scalar values (no unpaired surrogate), written as RFC 8785 writes them:
//     `"` and `\` escaped, \b \t \n \f \r for those five, \u00xx (lowercase hex) for every other
//     code point below U+0020, everything else as its own UTF-8 bytes;
//   - no whitespace, no byte-order mark, nothing after the payload.
//
// The reader takes only these bytes: a parser that accepts canonical syntax alone (each object's
// names strictly increasing, so a duplicate is refused too), then the canonical form of what it read
// written back and compared byte for byte. The checks run in this order, and the first that fails
// names the code:
//   1. TOO_LARGE      longer than the format's cap, checked before anything is parsed
//   2. NOT_CANONICAL  anything else: not UTF-8, not JSON, out of the subset, too deep, or not the
//                     canonical form of what it holds
// One code covers every rule, so platforms needn't agree on which rule a bad input breaks first.

export type CanonicalValue = null | boolean | number | string | CanonicalValue[] | { [name: string]: CanonicalValue };

/** The deepest nesting: the payload object is depth 1. */
export const CANONICAL_MAX_DEPTH = 8;
/** The largest integer: 2^53 - 1, the largest every platform's JSON number holds exactly. */
export const CANONICAL_MAX_INTEGER = Number.MAX_SAFE_INTEGER;
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;

export type CanonicalJsonErrorCode = 'TOO_LARGE' | 'NOT_CANONICAL';

/** One fixed message per code, so a refusal carries nothing of the input. */
export const CANONICAL_JSON_MESSAGES: Readonly<Record<CanonicalJsonErrorCode, string>> = Object.freeze({
  TOO_LARGE: 'longer than the largest payload this format takes',
  NOT_CANONICAL: 'not the canonical JSON of a value this format takes',
});

export class CanonicalJsonError extends Error {
  constructor(readonly code: CanonicalJsonErrorCode) {
    super(CANONICAL_JSON_MESSAGES[code]);
    this.name = 'CanonicalJsonError';
  }
}

const notCanonical = () => new CanonicalJsonError('NOT_CANONICAL');

/** Whether a string holds only Unicode scalar values: every surrogate is half of a pair, in order. */
function wellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

const SHORT_ESCAPES: Readonly<Record<number, string>> = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\' };

function writeString(s: string): string {
  if (!wellFormed(s)) throw notCanonical();
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const short = SHORT_ESCAPES[c];
    if (short) out += short;
    else if (c < 0x20) out += `\\u00${c.toString(16).padStart(2, '0')}`;
    else out += s[i];
  }
  return `${out}"`;
}

function writeValue(value: unknown, depth: number): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw notCanonical();
    return String(value);
  }
  if (typeof value === 'string') return writeString(value);
  if (typeof value !== 'object' || depth > CANONICAL_MAX_DEPTH) throw notCanonical();
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) throw notCanonical();
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(value, i)) throw notCanonical(); // a hole
      parts.push(writeValue(value[i], depth + 1));
    }
    return `[${parts.join(',')}]`;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length) throw notCanonical();
  const names = Object.keys(value);
  for (const name of names) if (!NAME_RE.test(name)) throw notCanonical();
  names.sort(); // ASCII names: code-unit order is byte order, RFC 8785's order
  return `{${names.map((name) => `"${name}":${writeValue((value as Record<string, unknown>)[name], depth + 1)}`).join(',')}}`;
}

/**
 * The canonical bytes of a value in the subset. Refuses (NOT_CANONICAL) anything else: a top level
 * that isn't an object, a name out of form, a number that isn't an integer from 0 to 2^53 - 1, an
 * unpaired surrogate, a value JSON has no spelling for, and nesting deeper than 8.
 */
export function writeCanonicalJson(value: unknown): Buffer {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw notCanonical();
  return Buffer.from(writeValue(value, 1), 'utf8');
}

/** A parser of canonical syntax only: it refuses whatever a canonical writer would never write. */
class Parser {
  private at = 0;
  constructor(private readonly s: string) {}

  done(): boolean {
    return this.at === this.s.length;
  }

  value(depth: number): CanonicalValue {
    const c = this.s[this.at];
    if (c === '{') return this.object(depth);
    if (c === '[') return this.array(depth);
    if (c === '"') return this.string();
    if (c !== undefined && c >= '0' && c <= '9') return this.integer();
    for (const [word, v] of [['true', true], ['false', false], ['null', null]] as const) {
      if (this.s.startsWith(word, this.at)) {
        this.at += word.length;
        return v;
      }
    }
    throw notCanonical();
  }

  private expect(c: string): void {
    if (this.s[this.at] !== c) throw notCanonical();
    this.at++;
  }

  object(depth: number): { [name: string]: CanonicalValue } {
    if (depth > CANONICAL_MAX_DEPTH) throw notCanonical();
    this.expect('{');
    const out: { [name: string]: CanonicalValue } = {};
    let last = '';
    if (this.s[this.at] === '}') {
      this.at++;
      return out;
    }
    for (;;) {
      const name = this.string();
      // Strictly increasing names: canonical order, and no name twice.
      if (!NAME_RE.test(name) || (last !== '' && !(name > last))) throw notCanonical();
      last = name;
      this.expect(':');
      out[name] = this.value(depth + 1);
      if (this.s[this.at] === ',') {
        this.at++;
        continue;
      }
      this.expect('}');
      return out;
    }
  }

  array(depth: number): CanonicalValue[] {
    if (depth > CANONICAL_MAX_DEPTH) throw notCanonical();
    this.expect('[');
    const out: CanonicalValue[] = [];
    if (this.s[this.at] === ']') {
      this.at++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth + 1));
      if (this.s[this.at] === ',') {
        this.at++;
        continue;
      }
      this.expect(']');
      return out;
    }
  }

  integer(): number {
    const m = /^(?:0|[1-9][0-9]{0,15})/.exec(this.s.slice(this.at, this.at + 17));
    if (!m) throw notCanonical();
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) throw notCanonical();
    this.at += m[0].length;
    // A fraction, an exponent or more digits than 2^53 - 1 has: never canonical.
    const next = this.s[this.at];
    if (next === '.' || next === 'e' || next === 'E' || (next !== undefined && next >= '0' && next <= '9')) throw notCanonical();
    return n;
  }

  string(): string {
    this.expect('"');
    let out = '';
    for (;;) {
      const c = this.s.charCodeAt(this.at);
      if (Number.isNaN(c) || c < 0x20) throw notCanonical();
      if (c === 0x22) {
        this.at++;
        return out;
      }
      if (c !== 0x5c) {
        out += this.s[this.at++];
        continue;
      }
      // Only the escapes a canonical writer writes: the five short ones, \" and \\, and \u00xx in
      // lowercase hex for a code point below U+0020 that has no short escape.
      const e = this.s[this.at + 1];
      const short: Record<string, string> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
      if (e !== undefined && e in short) {
        out += short[e];
        this.at += 2;
        continue;
      }
      const u = /^u00([01][0-9a-f])/.exec(this.s.slice(this.at + 1, this.at + 6));
      if (!u) throw notCanonical();
      const code = parseInt(u[1], 16);
      if (SHORT_ESCAPES[code]) throw notCanonical();
      out += String.fromCharCode(code);
      this.at += 6;
    }
  }
}

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * The value a payload holds, when the bytes are exactly the canonical JSON of a value in the
 * subset and at most `maxBytes` long. Throws CanonicalJsonError (TOO_LARGE, then NOT_CANONICAL).
 */
export function readCanonicalJson(bytes: Uint8Array, maxBytes: number): CanonicalValue {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new RangeError('maxBytes must be a non-negative integer');
  if (bytes.length > maxBytes) throw new CanonicalJsonError('TOO_LARGE');
  let text: string;
  try {
    // Fatal: bytes that aren't UTF-8 (a lone surrogate's bytes included) are refused, never replaced.
    // ignoreBOM keeps a byte-order mark in the text, where the parser refuses it.
    text = UTF8.decode(bytes);
  } catch {
    throw notCanonical();
  }
  const parser = new Parser(text);
  if (text[0] !== '{') throw notCanonical();
  const value = parser.object(1);
  if (!parser.done()) throw notCanonical();
  // The parser takes canonical syntax only; writing the value back and comparing every byte checks
  // that independently (a string written as itself that must be escaped, and the reverse).
  if (!writeCanonicalJson(value).equals(Buffer.from(bytes))) throw notCanonical();
  return value;
}

// Signatures (the key format spec's signature), version 1: ECDSA P-256 with SHA-256 (FIPS 186-5)
// over
//
//   label (ASCII, `decoy/signature/<format id>`) ‖ 0x00 ‖ the payload's canonical bytes (canonical-json)
//
// sent as base64url, without padding, of exactly 64 bytes: r then s, each 32 bytes big-endian
// (IEEE P1363). The verifier builds the label from the format it is reading, never from the object,
// so a signature over one kind of object never verifies as another. High S is accepted: no format
// hashes, names or deduplicates an object by its signature bytes (a key set's hash is the digest of
// its message), so (r, s) and (r, n - s) are one object.
//
// The checks run in this order, and the first that fails names the code:
//   1. NOT_A_SIGNATURE  missing or not a string; not base64url as key ids spell it (no padding, no
//                       other alphabet, a canonical last character); not exactly 64 bytes; r or s
//                       zero, or not below the curve order n. Checked by the bytes, before any key
//   2. BAD_SIGNATURE    it doesn't verify under the key over the message, or the key isn't a
//                       canonical P-256 public key (key-id)

/** The label of each format that is signed. A format adds its row when it is specified. */
export const SIGNATURE_LABELS: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), {
  'key-set': 'decoy/signature/key-set',
  'agent-directory': 'decoy/signature/agent-directory',
  'agent-session-directory': 'decoy/signature/agent-session-directory',
}));
/** A P1363 P-256 signature: r and s, 32 bytes each. */
export const SIGNATURE_BYTES = 64;
/** n, the order of the P-256 group: r and s are each from 1 to n - 1. */
export const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export type SignatureErrorCode = 'NOT_A_SIGNATURE' | 'BAD_SIGNATURE';

/** One fixed message per code, so a refusal carries nothing of the object. */
export const SIGNATURE_MESSAGES: Readonly<Record<SignatureErrorCode, string>> = Object.freeze({
  NOT_A_SIGNATURE: 'not a signature',
  BAD_SIGNATURE: 'the signature does not verify',
});

export class SignatureError extends Error {
  constructor(readonly code: SignatureErrorCode) {
    super(SIGNATURE_MESSAGES[code]);
    this.name = 'SignatureError';
  }
}

/** The label of a signed format; throws for a format with no row (nothing is signed under it). */
export function signatureLabel(formatId: string): string {
  const label = Object.prototype.hasOwnProperty.call(SIGNATURE_LABELS, formatId) ? SIGNATURE_LABELS[formatId] : undefined;
  if (typeof label !== 'string') throw new TypeError('no signature label for this format');
  return label;
}

/** The bytes a signature is over: the format's label, one 0x00 byte, the payload's canonical bytes. */
export function signedMessage(formatId: string, payload: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(signatureLabel(formatId), 'ascii'), Buffer.from([0]), payload]);
}

/**
 * The bytes a canonical base64url string spells (no padding, only - and _ beyond the alphanumerics,
 * and a last character whose unused bits are zero), or null for any other string.
 */
export function readBase64url(s: unknown): Buffer | null {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const bytes = Buffer.from(s, 'base64url');
  return bytes.toString('base64url') === s ? bytes : null;
}

/** The 64 bytes of a well-formed signature, by its bytes alone (step 1), or NOT_A_SIGNATURE. */
export function readSignature(sig: unknown): Buffer {
  const bytes = readBase64url(sig);
  if (!bytes || bytes.length !== SIGNATURE_BYTES) throw new SignatureError('NOT_A_SIGNATURE');
  for (const half of [bytes.subarray(0, 32), bytes.subarray(32)]) {
    const n = BigInt(`0x${half.toString('hex')}`);
    if (n === 0n || n >= P256_ORDER) throw new SignatureError('NOT_A_SIGNATURE');
  }
  return bytes;
}

/**
 * Verify a signature over a format's payload under a P-256 key (its canonical SPKI DER), which the
 * caller takes from its own state by the format's rule, never only because the object names it.
 * Returns nothing; throws SignatureError with the code of the first check that fails.
 */
export function verifySignature(formatId: string, payload: Uint8Array, sig: unknown, spki: Uint8Array): void {
  const bytes = readSignature(sig);
  const message = signedMessage(formatId, payload);
  let ok = false;
  try {
    const canonical = canonicalSpki(spki);
    if (keyKind(canonical) === 'p256' && canonical.equals(Buffer.from(spki))) {
      ok = verify('sha256', message, { key: createPublicKey({ key: canonical, format: 'der', type: 'spki' }), dsaEncoding: 'ieee-p1363' }, bytes);
    }
  } catch {
    ok = false;
  }
  if (!ok) throw new SignatureError('BAD_SIGNATURE');
}

// The personal key set (the key format spec's key-set), version 1: the reader and the chain
// verifier. Nothing here writes a set. A set is a signed object (signature, label decoy/signature/key-set)
// that travels and is stored as two strings, `payload` (its canonical JSON, canonical-json, at most
// 65,536 bytes, in base64url) and `sig`. The payload has exactly these members:
//
//   v        1
//   account  the account's id, a lowercase hyphenated UUID
//   version  an integer from 1, its place in the chain
//   prev     null for version 1; otherwise the hash of the set at version - 1
//   signer   the key id of the key that signs it: its own `sign` key for version 1, otherwise the
//            `sign` key of the set it extends
//   keys     sorted by kid, no kid twice, each { kid, spki, use }: exactly one `sign` (P-256, the
//            account signing key) and at most four `account` (RSA 2048, 3072 or 4096)
//   sealed   sorted by kid, no kid twice, each { kid, seal }: a version-1 seal of the private key
//            (PKCS #8) of a listed key, under the account unlock key (kind key_set, record id the
//            account, field the key's use); checked here by its header only
//
// A set's hash is base64url(SHA-256(its signed message)): the digest its signature is over, which
// holds no signature, so a set has one hash however it is signed.
//
// The verifier is given the two strings, the account it expects (its own state) and its head: none,
// { version, hash, signKey }, or a pin { version, hash, signKey: null } from a handover. The checks
// run in this order, and the first that fails names the code:
//   1. TOO_LARGE        payload decodes to more than 65,536 bytes
//   2. NOT_CANONICAL    payload missing, not a string, not canonical base64url, or not canonical JSON
//   3. UNKNOWN_VERSION  v an integer other than 1
//   4. NOT_A_KEY_SET    a member missing, extra or out of form
//   5. WRONG_ACCOUNT    account isn't the one expected
//   6. NOT_A_SIGNATURE  sig out of form (signature, step 1)
//   7. GAP / OLDER / FORK, where it sits against the head:
//        GAP    nothing held and it isn't version 1; above the head's version plus one; or above a pin
//        OLDER  below the head's or the pin's version
//        FORK   at the head's or the pin's version with another hash; or at the next version with a
//               prev that isn't the head's hash, or a signer that isn't the head's sign key
//   8. BAD_SIGNATURE    it doesn't verify under its own sign key (a first set) or the head's (the next set)
// It answers `accepted` with the new head, or `current` for the head again, which changes nothing
// whatever its signature bytes. A later set taken by its pin carries no key it can be checked with;
// the pin names every byte of its payload.

export const KEY_SET_VERSION = 1;
/** The longest payload a key set takes, in bytes. */
export const KEY_SET_MAX_PAYLOAD_BYTES = 65536;
/** The most `account` keys a set lists. */
export const KEY_SET_MAX_ACCOUNT_KEYS = 4;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MEMBERS = ['account', 'keys', 'prev', 'sealed', 'signer', 'v', 'version'];

export type KeySetErrorCode =
  | 'TOO_LARGE' | 'NOT_CANONICAL' | 'UNKNOWN_VERSION' | 'NOT_A_KEY_SET' | 'WRONG_ACCOUNT'
  | 'NOT_A_SIGNATURE' | 'GAP' | 'OLDER' | 'FORK' | 'BAD_SIGNATURE';

/** One fixed message per code, so a refusal carries nothing of the set. */
export const KEY_SET_MESSAGES: Readonly<Record<KeySetErrorCode, string>> = Object.freeze({
  TOO_LARGE: 'a key set longer than the largest one allowed',
  NOT_CANONICAL: 'a key set payload that is not canonical JSON',
  UNKNOWN_VERSION: 'a key set version this reader does not know',
  NOT_A_KEY_SET: 'not a key set',
  WRONG_ACCOUNT: 'a key set for another account',
  NOT_A_SIGNATURE: 'a key set signature that is not a signature',
  GAP: 'a key set that does not follow the one held: the sets between come first',
  OLDER: 'a key set older than the one held',
  FORK: 'a key set that competes with the one held',
  BAD_SIGNATURE: 'a key set whose signature does not verify',
});

export class KeySetError extends Error {
  constructor(readonly code: KeySetErrorCode) {
    super(KEY_SET_MESSAGES[code]);
    this.name = 'KeySetError';
  }
}

export type KeySetKey = { kid: string; spki: string; use: 'sign' | 'account' };
export type KeySetSealed = { kid: string; seal: string };
export type KeySetPayload = {
  v: 1; account: string; version: number; prev: string | null; signer: string; keys: KeySetKey[]; sealed: KeySetSealed[];
};
/** What a verifier holds: the last set it accepted (signKey, its `sign` key's SPKI), or a pin with no key yet. */
export type KeySetHead = { version: number; hash: string; signKey: Buffer | null };
export type KeySetResult = { status: 'accepted'; head: KeySetHead } | { status: 'current' };

const fail = (code: KeySetErrorCode): never => {
  throw new KeySetError(code);
};
const notAKeySet = () => fail('NOT_A_KEY_SET');
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const hasExactly = (o: Record<string, unknown>, names: string[]) => {
  const own = Object.keys(o).sort();
  return own.length === names.length && own.every((n, i) => n === names[i]);
};

/** A key set's hash: base64url of the SHA-256 digest of its signed message. */
export function keySetHash(payload: Uint8Array): string {
  return createHash('sha256').update(signedMessage('key-set', payload)).digest('base64url');
}

/** A listed public key, in form: its canonical SPKI, its id, and a use its algorithm allows. */
function readKey(entry: unknown): KeySetKey {
  if (!isObject(entry) || !hasExactly(entry, ['kid', 'spki', 'use'])) return notAKeySet();
  const { kid, spki, use } = entry;
  if (use !== 'sign' && use !== 'account') return notAKeySet();
  const der = readBase64url(spki);
  if (!der || !isKeyId(kid)) return notAKeySet();
  let kind: 'rsa' | 'p256';
  try {
    if (!canonicalSpki(der).equals(der)) return notAKeySet();
    kind = keyKind(der);
    if (keyIdFromSpki(der) !== kid) return notAKeySet();
  } catch {
    return notAKeySet();
  }
  if ((use === 'sign') !== (kind === 'p256')) return notAKeySet();
  return { kid, spki: spki as string, use };
}

/** A sealed private half, in form: a kid and the base64url of a version-1 seal, by its header. */
function readSealed(entry: unknown): KeySetSealed {
  if (!isObject(entry) || !hasExactly(entry, ['kid', 'seal'])) return notAKeySet();
  const { kid, seal } = entry;
  const bytes = readBase64url(seal);
  if (!isKeyId(kid) || !bytes || bytes.length < SEAL_OVERHEAD_BYTES || bytes[0] !== SEAL_FORMAT_BYTE || bytes[1] !== SEAL_VERSION) return notAKeySet();
  return { kid, seal: seal as string };
}

/** Sorted by kid in byte order, no kid twice. */
const strictlySorted = (kids: string[]) => kids.every((k, i) => i === 0 || kids[i - 1] < k);

/**
 * Steps 1 to 4: the set's payload, in form, with its canonical bytes, its hash and its sign key.
 * Checks no account, chain or signature.
 */
export function readKeySet(signed: { payload: unknown; sig: unknown }): { payload: KeySetPayload; bytes: Buffer; hash: string; signKey: Buffer } {
  const p = signed?.payload;
  // 1. The size, from the string's length, before anything is decoded.
  if (typeof p === 'string' && Math.floor((p.length * 3) / 4) > KEY_SET_MAX_PAYLOAD_BYTES) fail('TOO_LARGE');
  // 2. Canonical base64url of canonical JSON.
  const bytes = readBase64url(p);
  if (!bytes) return fail('NOT_CANONICAL');
  let value: unknown;
  try {
    value = readCanonicalJson(bytes, KEY_SET_MAX_PAYLOAD_BYTES);
  } catch (e) {
    if (e instanceof CanonicalJsonError) return fail(e.code);
    throw e;
  }
  const o = value as Record<string, unknown>;
  // 3. A version this reader doesn't know, before the rest of the form, which that version may change.
  if (typeof o.v === 'number' && o.v !== KEY_SET_VERSION) fail('UNKNOWN_VERSION');
  // 4. The form.
  if (!hasExactly(o, MEMBERS) || o.v !== KEY_SET_VERSION) return notAKeySet();
  const { account, version, prev, signer } = o;
  if (typeof account !== 'string' || !UUID_RE.test(account)) return notAKeySet();
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return notAKeySet();
  if (version === 1 ? prev !== null : !isKeyId(prev)) return notAKeySet();
  if (!isKeyId(signer)) return notAKeySet();
  if (!Array.isArray(o.keys) || !Array.isArray(o.sealed)) return notAKeySet();
  const keys = o.keys.map(readKey);
  const sealed = o.sealed.map(readSealed);
  if (!strictlySorted(keys.map((k) => k.kid)) || !strictlySorted(sealed.map((s) => s.kid))) return notAKeySet();
  const sign = keys.filter((k) => k.use === 'sign');
  if (sign.length !== 1 || keys.length - 1 > KEY_SET_MAX_ACCOUNT_KEYS) return notAKeySet();
  if (!sealed.every((s) => keys.some((k) => k.kid === s.kid))) return notAKeySet();
  if (version === 1 && signer !== sign[0].kid) return notAKeySet();
  return {
    payload: { v: KEY_SET_VERSION, account, version, prev: prev as string | null, signer, keys, sealed },
    bytes,
    hash: keySetHash(bytes),
    signKey: Buffer.from(sign[0].spki, 'base64url'),
  };
}

/**
 * Verify a key set against the account a verifier expects and the head it holds. Returns
 * `accepted` with the new head, or `current` for the head again; throws KeySetError with the code of
 * the first check that fails. The head given is never changed.
 */
export function verifyKeySet(signed: { payload: unknown; sig: unknown }, account: string, head: KeySetHead | null): KeySetResult {
  const set = readKeySet(signed);
  const { version, prev, signer } = set.payload;
  // 5. Whose set: the verifier's own state, in the one spelling.
  if (set.payload.account !== account) fail('WRONG_ACCOUNT');
  // 6. The signature's form, by its bytes.
  try {
    readSignature(signed.sig);
  } catch (e) {
    if (e instanceof SignatureError) fail(e.code);
    throw e;
  }
  // 7. Where it sits against the head; 8. the signature, under the key the chain names.
  const accepted = (): KeySetResult => ({ status: 'accepted', head: { version, hash: set.hash, signKey: Buffer.from(set.signKey) } });
  const checkedUnder = (spki: Buffer): KeySetResult => {
    try {
      verifySignature('key-set', set.bytes, signed.sig, spki);
    } catch (e) {
      if (e instanceof SignatureError) fail(e.code);
      throw e;
    }
    return accepted();
  };
  if (head === null) return version === 1 ? checkedUnder(set.signKey) : fail('GAP');
  if (version < head.version) return fail('OLDER');
  if (version === head.version) {
    if (set.hash !== head.hash) return fail('FORK');
    if (head.signKey !== null) return { status: 'current' };
    // Taken by its pin: a first set is still checked under its own key; a later one carries no key
    // it can be checked with, and the pin names every byte of its payload.
    return version === 1 ? checkedUnder(set.signKey) : accepted();
  }
  if (head.signKey === null || version > head.version + 1) return fail('GAP');
  if (prev !== head.hash) return fail('FORK');
  let headSigner: string;
  try {
    headSigner = keyIdFromSpki(head.signKey);
  } catch {
    return fail('BAD_SIGNATURE');
  }
  if (signer !== headSigner) return fail('FORK');
  return checkedUnder(head.signKey);
}
