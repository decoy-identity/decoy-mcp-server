// key-format: key-id
// key-format: pairing-qr
// key-format: seal
// key-format: wrap
//
// Key ids, the pairing QR, and the seal and wrap readers: the same formats byte for byte as the
// Decoy API's, checked against the same sha-pinned vectors (key-id.vectors.json,
// pairing-qr.vectors.json, seal.vectors.json and wrap.vectors.json). This module reads seals and
// wraps; it writes neither.
//   key id     = base64url, no padding, of SHA-256 over the public key's canonical SubjectPublicKeyInfo DER;
//                for a 32-byte symmetric key, of HMAC-SHA256 of the key over decoy/key-id/symmetric
//   seal       = 0xC5 ‖ 0x01 ‖ key_id (32) ‖ nonce (12) ‖ AES-256-GCM ciphertext ‖ tag (16), the header,
//                kind, record id and field bound as associated data (openSeal)
//   wrap       = 0xC6 ‖ 0x01 ‖ recipient_key_id (32) ‖ RSA-OAEP-SHA-256 of the same 34 bytes ‖
//                wrapped_key_id (32) ‖ key (32) (openWrap)
//   pairing QR = decoy://connect?code=CODE[&kid=KEY_ID][&keep=KEY_ID]&v=1 (decoy-dev:// for development),
//                written from the requester's own keys; the hand-off link
//                https://www.decoys.me/connect?code=CODE[&env=dev][&kid=…][&keep=…]&v=1 carries the same
//   kid is written by a requester from its own connection key (the web app and the extension write
//   it; this bridge's own pairing link, pairingPageUrl, carries none); no requester writes keep
//
// The bytes are checked by a strict DER walk before anything parses them, so the result never
// depends on how lenient a platform's key parser is, and malformed input never reaches one. The
// checks run in this order, and the first that fails names the code:
//   1. NOT_A_KEY        longer than 4096 bytes, or not exactly one strict-DER structure. The rules
//                       are a closed set, for every element, nested ones included: only the tags an
//                       SPKI uses (SEQUENCE, the one constructed tag; INTEGER, BIT STRING, OCTET
//                       STRING, NULL, OBJECT IDENTIFIER, all primitive), so BOOLEAN, end-of-contents,
//                       SET, constructed strings, context-specific and high tags are refused; nested
//                       at most 8 deep (the outermost element is level 1); a definite minimal length
//                       inside its parent; INTEGERs non-empty, minimal and not negative; OIDs
//                       non-empty, minimal and not cut short; a BIT STRING's unused-bits byte at most
//                       7 with those bits zero (and 0 for the key itself); NULL empty. Then not the
//                       SubjectPublicKeyInfo shape (SEQUENCE { AlgorithmIdentifier, BIT STRING } and
//                       nothing else; the AlgorithmIdentifier a SEQUENCE of an OID and at most one
//                       parameter, never empty): another tag the walk takes in any of these places
//                       is refused, though its contents would read as the same key
//   2. UNSUPPORTED_KEY  a strict SPKI of another algorithm or curve (P-384, secp256k1, Ed25519,
//                       explicit EC parameters): the OID decides
//   3. P-256: NOT_CANONICAL for a compressed (02/03, 33 bytes) or hybrid (06/07, 65 bytes) point,
//      a form with no id whether or not the point is valid; NOT_A_KEY for any other point that is
//      not 65 bytes starting 04, or not on the curve
//      RSA (rsaEncryption with NULL parameters only; without them NOT_A_KEY): the RSAPublicKey is
//      SEQUENCE { modulus, exponent }, two INTEGERs, in strict DER (else NOT_A_KEY); WEAK_KEY for
//      a modulus under 2048 bits; UNSUPPORTED_KEY for any size but 2048, 3072 or 4096 (an even
//      modulus included: the size comes first); WEAK_KEY for an exponent other than 65537 (0
//      included) or an even modulus, which nothing can wrap to.
import { constants, createDecipheriv, createHash, createHmac, createPublicKey, privateDecrypt, type KeyObject } from 'node:crypto';

// 32 bytes leave 2 unused bits in the 43rd base64url character, so only 16 characters can end a
// canonical id. Another last character spells the same bytes differently and is refused.
const KEY_ID_RE = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** The DER header of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1), before the point. */
const P256_SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
/** AlgorithmIdentifier rsaEncryption with NULL parameters, the only RSA spelling with an id. */
const RSA_ALGORITHM = Buffer.from('300d06092a864886f70d0101010500', 'hex');
const RSA_OID = Buffer.from('06092a864886f70d010101', 'hex');
const EC_PUBLIC_KEY_OID = Buffer.from('06072a8648ce3d0201', 'hex');
const P256_OID = Buffer.from('06082a8648ce3d030107', 'hex');
const RSA_MODULUS_BITS = new Set([2048, 3072, 4096]);
/** The longest input read, in bytes: more than any key with an id needs (RSA-4096 is 550). */
export const MAX_KEY_BYTES = 4096;
/** The deepest element read: the outermost is level 1, a P-256 SPKI reaches 3, explicit curve parameters 5. */
const MAX_DER_LEVEL = 8;
/** The only tags an SPKI uses: SEQUENCE, the one constructed tag; INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER. */
const SPKI_TAGS = new Set([0x30, 0x02, 0x03, 0x04, 0x05, 0x06]);

export type KeyIdErrorCode = 'NOT_A_KEY' | 'NOT_CANONICAL' | 'UNSUPPORTED_KEY' | 'WEAK_KEY';

export class KeyIdError extends Error {
  constructor(readonly code: KeyIdErrorCode, message: string) {
    super(message);
    this.name = 'KeyIdError';
  }
}

const notAKey = (why: string) => new KeyIdError('NOT_A_KEY', why);

type Tlv = { tag: number; start: number; end: number };

/** One strict-DER element at `at`, which must end by `limit` (its parent's end). */
function tlv(b: Buffer, at: number, limit: number): Tlv {
  if (at + 2 > limit) throw notAKey('truncated DER');
  const tag = b[at];
  if (!SPKI_TAGS.has(tag)) throw notAKey('a tag no SubjectPublicKeyInfo uses');
  let len = b[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2 || start + n > limit) throw notAKey('a DER length that is indefinite or in more than two bytes');
    if (b[start] === 0) throw notAKey('a DER length with a leading zero');
    len = n === 1 ? b[start] : (b[start] << 8) | b[start + 1];
    if (len < 0x80 || (n === 2 && len < 0x100)) throw notAKey('a DER length that is not minimal');
    start += n;
  }
  const end = start + len;
  if (end > limit) throw notAKey('an element past its parent');
  return { tag, start, end };
}

/** Every element from `start` to `end`, at `level`, exactly, in strict DER, nested ones included. */
function strictDer(b: Buffer, start: number, end: number, level: number): Tlv[] {
  const out: Tlv[] = [];
  let at = start;
  while (at < end) {
    if (level > MAX_DER_LEVEL) throw notAKey('nested more than 8 deep');
    const el = tlv(b, at, end);
    const v = b.subarray(el.start, el.end);
    if (el.tag === 0x30) strictDer(b, el.start, el.end, level + 1);
    else if (el.tag === 0x02) {
      if (v.length === 0) throw notAKey('an empty INTEGER');
      if (v[0] & 0x80) throw notAKey('a negative INTEGER');
      if (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) throw notAKey('an INTEGER that is not minimal');
    } else if (el.tag === 0x06) {
      if (v.length === 0 || (v[v.length - 1] & 0x80)) throw notAKey('an OID that is empty or cut short');
      for (let i = 0; i < v.length; i++) if (v[i] === 0x80 && (i === 0 || !(v[i - 1] & 0x80))) throw notAKey('an OID arc that is not minimal');
    } else if (el.tag === 0x03) {
      if (v.length === 0 || v[0] > 7 || (v.length === 1 && v[0] !== 0) || (v[v.length - 1] & ((1 << v[0]) - 1))) throw notAKey('a BIT STRING that is not strict');
    } else if (el.tag === 0x05) {
      if (v.length !== 0) throw notAKey('a NULL with contents');
    }
    out.push(el);
    at = el.end;
  }
  return out;
}

/** The elements of a whole input, which is never longer than MAX_KEY_BYTES. */
function walk(b: Buffer): Tlv[] {
  if (b.length > MAX_KEY_BYTES) throw notAKey('longer than any key with an id');
  return strictDer(b, 0, b.length, 1);
}

/** A non-negative INTEGER's magnitude (no sign byte; empty for zero). The walk has refused a negative one. */
function magnitude(b: Buffer, el: Tlv): Buffer {
  if (el.tag !== 0x02) throw notAKey('not an INTEGER');
  const v = b.subarray(el.start, el.end);
  let i = 0;
  while (i < v.length && v[i] === 0) i++;
  return v.subarray(i);
}

/** RSAPublicKey (PKCS #1): exactly SEQUENCE { modulus, publicExponent } over all of `b`. */
function rsaPublicKey(b: Buffer): void {
  const top = walk(b);
  if (top.length !== 1 || top[0].tag !== 0x30) throw notAKey('not exactly one RSAPublicKey');
  const parts = strictDer(b, top[0].start, top[0].end, 2);
  if (parts.length !== 2) throw notAKey('RSAPublicKey is not exactly a modulus and an exponent');
  const n = magnitude(b, parts[0]);
  const e = magnitude(b, parts[1]);
  const bits = n.length === 0 ? 0 : n.length * 8 - Math.clz32(n[0]) + 24;
  if (bits < 2048) throw new KeyIdError('WEAK_KEY', `an RSA modulus of ${bits} bits`);
  if (!RSA_MODULUS_BITS.has(bits)) throw new KeyIdError('UNSUPPORTED_KEY', `an RSA modulus of ${bits} bits`);
  if (!(e.length === 3 && e[0] === 1 && e[1] === 0 && e[2] === 1)) throw new KeyIdError('WEAK_KEY', 'an RSA public exponent other than 65537');
  if (!(n[n.length - 1] & 1)) throw new KeyIdError('WEAK_KEY', 'an even RSA modulus');
}

/**
 * The key's one canonical SubjectPublicKeyInfo DER: P-256 with the uncompressed point on the
 * curve, or RSA (2048, 3072 or 4096 bits, exponent 65537, odd modulus) with NULL parameters;
 * strict DER, nothing after it. Anything else is refused with the code its bytes earn, in the
 * order above, so no key ever has two ids and no platform gives a different answer.
 */
export function canonicalSpki(spkiDer: Uint8Array): Buffer {
  const b = Buffer.from(spkiDer);
  const top = walk(b);
  if (top.length !== 1 || top[0].tag !== 0x30) throw notAKey('not exactly one SubjectPublicKeyInfo');
  const parts = strictDer(b, top[0].start, top[0].end, 2);
  if (parts.length !== 2 || parts[0].tag !== 0x30 || parts[1].tag !== 0x03) throw notAKey('not an AlgorithmIdentifier and a BIT STRING');
  const [alg, bits] = parts;
  if (b[bits.start] !== 0) throw notAKey('a key BIT STRING with unused bits');
  const algParts = strictDer(b, alg.start, alg.end, 3);
  if (algParts.length === 0 || algParts[0].tag !== 0x06 || algParts.length > 2) throw notAKey('an AlgorithmIdentifier that is not an OID and at most one parameter');
  const key = b.subarray(bits.start + 1, bits.end);
  const algorithm = b.subarray(top[0].start, alg.end);

  if (algorithm.equals(RSA_ALGORITHM)) {
    rsaPublicKey(key);
    return b;
  }
  const oidBytes = b.subarray(alg.start, algParts[0].end);
  if (oidBytes.equals(RSA_OID)) throw notAKey('rsaEncryption without exactly NULL parameters');
  if (oidBytes.equals(EC_PUBLIC_KEY_OID)) {
    if (algParts.length !== 2 || !b.subarray(algParts[0].end, algParts[1].end).equals(P256_OID)) {
      throw new KeyIdError('UNSUPPORTED_KEY', 'only the named P-256 curve has key ids among EC keys');
    }
    if ((key.length === 33 && (key[0] === 2 || key[0] === 3)) || (key.length === 65 && (key[0] === 6 || key[0] === 7))) {
      throw new KeyIdError('NOT_CANONICAL', 'a P-256 point in the compressed or hybrid form, which has no id');
    }
    if (key.length !== 65 || key[0] !== 4) throw notAKey('not a P-256 point');
    // Only now, with exactly the 91-byte uncompressed form, is the point handed to a parser: it
    // must be on the curve.
    try {
      createPublicKey({ key: b, format: 'der', type: 'spki' });
    } catch {
      throw notAKey('a point not on the curve');
    }
    return b;
  }
  throw new KeyIdError('UNSUPPORTED_KEY', 'only P-256 and RSA public keys have key ids');
}

/** Which kind of key a canonical SPKI holds: RSA (a connection key, wrapped to) or P-256 (signing, agreement). */
export function keyKind(spkiDer: Uint8Array): 'rsa' | 'p256' {
  const b = canonicalSpki(spkiDer);
  return b.subarray(0, 2).equals(P256_SPKI_HEADER.subarray(0, 2)) && b.length === 91 ? 'p256' : 'rsa';
}

/** The key id of a public key, from its canonical SubjectPublicKeyInfo DER (refused otherwise). */
export function keyIdFromSpki(spkiDer: Uint8Array): string {
  return createHash('sha256').update(canonicalSpki(spkiDer)).digest('base64url');
}

/** True when the string is a canonical key id: 43 base64url characters, no padding. */
export function isKeyId(value: unknown): value is string {
  return typeof value === 'string' && KEY_ID_RE.test(value);
}

/**
 * The SubjectPublicKeyInfo DER of a P-256 key given as an uncompressed X9.63 point (0x04 ‖ X ‖ Y),
 * the form iOS exports. Its key id is the same as the key's SPKI id on every other platform.
 */
export function spkiFromP256X963(point: Uint8Array): Buffer {
  if (point.length !== 65) throw notAKey(`a P-256 point is 65 bytes, not ${point.length}`);
  if (point[0] !== 0x04) throw notAKey('only an uncompressed P-256 point (first byte 0x04) is accepted');
  return canonicalSpki(Buffer.concat([P256_SPKI_HEADER, Buffer.from(point)]));
}

const derLength = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));

/**
 * The SubjectPublicKeyInfo DER of an RSA key given as a bare PKCS #1 RSAPublicKey (the form iOS
 * exports). The input must be exactly one key in strict DER, nothing before or after it.
 */
export function spkiFromRsaPkcs1(rsaPublicKeyDer: Uint8Array): Buffer {
  const pkcs1 = Buffer.from(rsaPublicKeyDer);
  rsaPublicKey(pkcs1);
  const bitString = Buffer.concat([Buffer.from([0x03]), derLength(pkcs1.length + 1), Buffer.from([0x00]), pkcs1]);
  const body = Buffer.concat([RSA_ALGORITHM, bitString]);
  return canonicalSpki(Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]));
}

/** The label a symmetric key's id is the HMAC of (hkdf-labels: decoy/<format id>/<purpose>). */
export const SYMMETRIC_KEY_ID_LABEL = 'decoy/key-id/symmetric';
/** The only length of a symmetric key with an id: AES-256. */
export const SYMMETRIC_KEY_BYTES = 32;

/**
 * The key id of a symmetric key: HMAC-SHA256 with the key itself as the HMAC key, over the ASCII
 * label, base64url without padding. Only a key of exactly 32 bytes has one: HMAC pads a shorter key
 * with zeros (so K and K followed by a zero byte would share an id) and hashes a key longer than 64
 * bytes first, and neither can happen at exactly 32. Any other length is NOT_A_KEY.
 */
export function symmetricKeyId(key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.length !== SYMMETRIC_KEY_BYTES) throw notAKey('only a 32-byte symmetric key has an id');
  return createHmac('sha256', key).update(SYMMETRIC_KEY_ID_LABEL, 'ascii').digest('base64url');
}


export type PairingQr = { code: string; env: 'dev' | null; kid: string | null; keep: string | null };
export type PairingQrErrorCode =
  | 'NOT_A_PAIRING_QR' | 'BAD_ENCODING' | 'BAD_PARAMETER' | 'REPEATED_PARAMETER' | 'UNKNOWN_VERSION'
  | 'BAD_CODE' | 'BAD_ENV' | 'BAD_KID' | 'BAD_KEEP';

export class PairingQrError extends Error {
  constructor(readonly code: PairingQrErrorCode, message: string) {
    super(message);
    this.name = 'PairingQrError';
  }
}

/** The format version this reader and writer know. A QR with no v is version 1 (written before v existed). */
export const PAIRING_QR_VERSION = '1';
/** The longest QR or link read; anything longer is refused before it is parsed. */
export const PAIRING_QR_MAX_LENGTH = 512;

/** The parameters this format reads, compared byte for byte; any other parameter is ignored, whatever its value. */
const KNOWN = ['v', 'code', 'env', 'kid', 'keep'] as const;

/** A pairing code: 8 characters from the alphabet the server draws codes from (no I, O, 0 or 1). */
const CODE_RE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/;

/**
 * Lowercase scheme and host, exactly these paths, then a query of printable ASCII with no
 * fragment, no space and nothing around it.
 */
const SHAPE_RE = /^(decoy:\/\/connect|decoy-dev:\/\/connect|https:\/\/(?:www\.)?decoys\.me\/connect)\?([!"$-~]*)$/;

function check({ code, env, kid, keep }: PairingQr): void {
  if (typeof code !== 'string' || !CODE_RE.test(code)) throw new PairingQrError('BAD_CODE', 'the pairing code is not 8 characters from the code alphabet');
  if (env !== null && env !== 'dev') throw new PairingQrError('BAD_ENV', 'env is dev or absent');
  if (kid !== null && !isKeyId(kid)) throw new PairingQrError('BAD_KID', 'kid is not a key id');
  if (keep !== null && !isKeyId(keep)) throw new PairingQrError('BAD_KEEP', 'keep is not a key id');
}

const ids = (qr: PairingQr) => `${qr.kid ? `&kid=${qr.kid}` : ''}${qr.keep ? `&keep=${qr.keep}` : ''}&v=${PAIRING_QR_VERSION}`;

/**
 * The QR text: the development app's scheme for dev (the phone's Camera hands it to the dev app),
 * then code, kid and keep when the requester has those keys, then v.
 */
export function writePairingQr(qr: PairingQr): string {
  check(qr);
  return `${qr.env === 'dev' ? 'decoy-dev' : 'decoy'}://connect?code=${qr.code}${ids(qr)}`;
}

/**
 * The hand-off link a requester builds from its own keys and the code (RFC 8628's user_code), for
 * the connect page to render and hand on; env=dev for development. A requester never shows a link
 * the server built. A requester with no key writes the link without kid.
 */
export function writePairingLink(qr: PairingQr): string {
  check(qr);
  return `https://www.decoys.me/connect?code=${qr.code}${qr.env === 'dev' ? '&env=dev' : ''}${ids(qr)}`;
}

/**
 * Reads a pairing QR or hand-off link. The checks run in this order, and the first that fails
 * names the error: NOT_A_PAIRING_QR (length, scheme, host, path, characters, a fragment),
 * BAD_ENCODING (a percent or plus sign in any parameter name, or in the value of a known one),
 * BAD_PARAMETER (a name that matches a known one only when case is ignored), REPEATED_PARAMETER,
 * UNKNOWN_VERSION, then BAD_CODE, BAD_ENV, BAD_KID and BAD_KEEP. Parameters may come in any order;
 * empty segments and unknown parameters are ignored. An empty or bare known parameter is
 * malformed, never the same as an absent one. Values are compared byte for byte; nothing is
 * decoded.
 */
export function readPairingQr(text: string): PairingQr {
  // Every message is fixed by its code: an error carries no part of the scanned text.
  const notAPairingQr = () => new PairingQrError('NOT_A_PAIRING_QR', 'not a pairing QR or the decoys.me hand-off link, or longer than 512 characters');
  if (typeof text !== 'string' || text.length > PAIRING_QR_MAX_LENGTH) throw notAPairingQr();
  const m = SHAPE_RE.exec(text);
  if (!m) throw notAPairingQr();
  const devScheme = m[1] === 'decoy-dev://connect';
  const pairs = m[2].split('&').filter((p) => p !== '').map((pair) => {
    const eq = pair.indexOf('=');
    return eq < 0 ? { name: pair, value: '' } : { name: pair.slice(0, eq), value: pair.slice(eq + 1) };
  });
  const known = (name: string) => (KNOWN as readonly string[]).includes(name);
  for (const { name, value } of pairs) {
    if (/[%+]/.test(name) || (known(name) && /[%+]/.test(value))) {
      throw new PairingQrError('BAD_ENCODING', 'parameter names, and the values of v, code, env, kid and keep, are plain text: no percent or plus signs');
    }
  }
  for (const { name } of pairs) {
    if (!known(name) && known(name.toLowerCase())) throw new PairingQrError('BAD_PARAMETER', 'parameter names are lowercase');
  }
  const values: Record<string, string> = {};
  for (const { name, value } of pairs) {
    if (!known(name)) continue;
    if (name in values) throw new PairingQrError('REPEATED_PARAMETER', 'a parameter appears more than once');
    values[name] = value;
  }
  if ('v' in values && values.v !== PAIRING_QR_VERSION) throw new PairingQrError('UNKNOWN_VERSION', 'a pairing QR version this reader does not know');
  // The development scheme means dev; an env with it can only say dev.
  const env = 'env' in values ? values.env : devScheme ? 'dev' : null;
  const qr: PairingQr = {
    code: values.code ?? '',
    env: env as 'dev' | null,
    kid: 'kid' in values ? values.kid : null,
    keep: 'keep' in values ? values.keep : null,
  };
  check(qr);
  return qr;
}

/** The longest session key read, in UTF-16 code units (JavaScript's length): standard base64 of key-id's 4096-byte limit (5464). */
export const MAX_SESSION_KEY_CHARS = 4 * Math.ceil(MAX_KEY_BYTES / 3);

/**
 * The key id of a public key the server returns for a session (agent_public_key, or the keep key):
 * strict standard base64 (no PEM, whitespace, base64url or missing padding) of the key's canonical
 * SPKI DER. A string longer than MAX_SESSION_KEY_CHARS is refused (NOT_A_KEY) before anything is
 * decoded, whatever it holds. The device hashes exactly these bytes, and wraps only to a key
 * imported from them.
 */
export function sessionKeyId(publicKeyBase64: string): string {
  if (typeof publicKeyBase64 === 'string' && publicKeyBase64.length > MAX_SESSION_KEY_CHARS) throw new KeyIdError('NOT_A_KEY', 'longer than any key with an id');
  const ok = typeof publicKeyBase64 === 'string' && publicKeyBase64.length > 0 && publicKeyBase64.length % 4 === 0
    && /^[A-Za-z0-9+/]+={0,2}$/.test(publicKeyBase64)
    && Buffer.from(publicKeyBase64, 'base64').toString('base64') === publicKeyBase64;
  if (!ok) throw new PairingQrError('BAD_ENCODING', 'a session key is strict standard base64 of the SPKI DER');
  return keyIdFromSpki(Buffer.from(publicKeyBase64, 'base64'));
}

export type PairingCheckError =
  | 'WRONG_ENV' | 'BAD_SESSION_KEY' | 'WRONG_KEY_KIND' | 'KEY_MISSING' | 'KEY_MISMATCH' | 'KID_MISSING'
  | 'KEEP_MISSING' | 'KEEP_MISMATCH' | 'KEEP_ID_MISSING';
/** The ids the approving device pins for the connection (Rules, Recipients); null: none. */
export type PairingPins = { kid: string | null; keep: string | null };
export type PairingKeyCheck =
  | { approve: true; checked: boolean; pin: PairingPins }
  | { approve: false; error: PairingCheckError };

type Kind = 'rsa' | 'p256';
type Outcome = { error: PairingCheckError } | { checked: string } | { firstUse: string | null } | { none: true };

/** A session key's id, if it reads as a canonical key of the kind its role needs. */
function idOf(raw: string, kind: Kind): { id: string } | { error: PairingCheckError } {
  let id: string;
  try { id = sessionKeyId(raw); } catch { return { error: 'BAD_SESSION_KEY' }; }
  if (keyKind(Buffer.from(raw, 'base64')) !== kind) return { error: 'WRONG_KEY_KIND' };
  return { id };
}

/** One key the session carries against the id the QR names for it. */
function compare(
  named: string | null, raw: string | null, kind: Kind, strict: boolean,
  missing: PairingCheckError, mismatch: PairingCheckError, idMissing: PairingCheckError,
): Outcome {
  if (named !== null) {
    if (raw === null) return { error: missing };
    const r = idOf(raw, kind);
    if ('error' in r) return r;
    return r.id === named ? { checked: r.id } : { error: mismatch };
  }
  if (raw === null) return { none: true };
  if (strict) return { error: idMissing };
  // A legacy pairing (the QR names no id): pinned on first use when the key reads, as today unchecked.
  const r = idOf(raw, kind);
  return { firstUse: 'id' in r ? r.id : null };
}

/**
 * What the approving device decides from the QR it scanned and the keys the server returns for the
 * session, as the server returns them (null: the session has none; anything else, an empty string
 * included, is a key that must read). approverEnv: the API the approver itself uses (null for
 * production); a QR for another environment is refused, and the approver never switches API.
 * kid names an RSA connection key and keep a P-256 signing key (WRONG_KEY_KIND otherwise).
 * Once a QR names any id, every key the session carries must have its id in the QR, so a key the
 * server adds is refused; kidRequired (fixed in the approver's own build, never read from a server
 * answer) refuses a keyed session whose QR names no ids at all. checked: the session carries at
 * least one key, and every key it carries matched the id the QR names for it (false with no key).
 * pin: the ids the device pins for the connection,
 * the checked ones, or for a legacy pairing (no ids in the QR, before kidRequired) the ids of the
 * keys it is given on first use (null when a key does not read).
 */
export function checkPairing(
  qr: PairingQr,
  session: { agentPublicKey: string | null; keepPublicKey: string | null },
  { kidRequired, approverEnv }: { kidRequired: boolean; approverEnv: 'dev' | null },
): PairingKeyCheck {
  if (qr.env !== approverEnv) return { approve: false, error: 'WRONG_ENV' };
  const strict = kidRequired || qr.kid !== null || qr.keep !== null;
  const agent = compare(qr.kid, session.agentPublicKey, 'rsa', strict, 'KEY_MISSING', 'KEY_MISMATCH', 'KID_MISSING');
  const keep = compare(qr.keep, session.keepPublicKey, 'p256', strict, 'KEEP_MISSING', 'KEEP_MISMATCH', 'KEEP_ID_MISSING');
  for (const r of [agent, keep]) if ('error' in r) return { approve: false, error: r.error };
  const pinOf = (r: Outcome) => ('checked' in r ? r.checked : 'firstUse' in r ? r.firstUse : null);
  const checked = ('checked' in agent || 'checked' in keep) && !('firstUse' in agent) && !('firstUse' in keep);
  return { approve: true, checked, pin: { kid: pinOf(agent), keep: pinOf(keep) } };
}

export const SEAL_FORMAT_BYTE = 0xc5;
export const SEAL_VERSION = 0x01;
/** Format byte, version and key id: the header, and the start of the associated data. */
export const SEAL_HEADER_BYTES = 34;
export const SEAL_NONCE_BYTES = 12;
export const SEAL_TAG_BYTES = 16;
/** Everything but the ciphertext: an empty plaintext gives a seal of exactly this length. */
export const SEAL_OVERHEAD_BYTES = 62;
/** The longest plaintext a seal holds: 64 MiB. */
export const SEAL_MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;

export type SealErrorCode = 'NOT_A_SEAL' | 'UNKNOWN_VERSION' | 'TOO_LARGE' | 'KEY_MISMATCH' | 'BAD_CONTEXT' | 'OPEN_FAILED';

/** One fixed message per code, so a refusal carries nothing of the seal or its context. */
export const SEAL_MESSAGES: Readonly<Record<SealErrorCode, string>> = Object.freeze({
  NOT_A_SEAL: 'not a seal',
  UNKNOWN_VERSION: 'a seal version this reader does not know',
  TOO_LARGE: 'a seal longer than the largest one allowed',
  KEY_MISMATCH: "the seal is not under the record's key, or that key is not held",
  BAD_CONTEXT: 'a seal context out of form',
  OPEN_FAILED: 'the seal does not open',
});

export class SealError extends Error {
  constructor(readonly code: SealErrorCode, message: string) {
    super(message);
    this.name = 'SealError';
  }
}

const sealError = (code: SealErrorCode) => new SealError(code, SEAL_MESSAGES[code]);

/** Where a seal is stored: the record's kind, its id and the field, or '' for the whole record. */
export type SealContext = { kind: string; recordId: string; field: string };

/** 1-64 bytes of a-z 0-9 _, first a letter. */
const SEAL_KIND_RE = /^[a-z][a-z0-9_]{0,63}$/;
/** A UUID, lowercase and hyphenated: exactly 36 bytes. Any other spelling is refused, never lower-cased. */
const SEAL_RECORD_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Empty (the whole record), or 1-64 bytes of a-z 0-9 _ ., first a letter. */
const SEAL_FIELD_RE = /^(?:[a-z][a-z0-9_.]{0,63})?$/;

/**
 * The associated data of a seal: its 34-byte header, then kind, record id and field, each after a
 * one-byte length. A context out of form is BAD_CONTEXT, for a writer as for the reader.
 */
export function sealAssociatedData(header: Uint8Array, context: SealContext): Buffer {
  if (header.length !== SEAL_HEADER_BYTES) throw sealError('NOT_A_SEAL');
  const { kind, recordId, field } = context ?? ({} as SealContext);
  if (typeof kind !== 'string' || typeof recordId !== 'string' || typeof field !== 'string') throw sealError('BAD_CONTEXT');
  if (!SEAL_KIND_RE.test(kind) || !SEAL_RECORD_ID_RE.test(recordId) || !SEAL_FIELD_RE.test(field)) throw sealError('BAD_CONTEXT');
  const part = (s: string) => Buffer.concat([Buffer.from([s.length]), Buffer.from(s, 'ascii')]);
  return Buffer.concat([Buffer.from(header), part(kind), part(recordId), part(field)]);
}

/**
 * Open a seal with the record's key: `expectedKeyId` is the symmetric key id of the key the record
 * must be under, from the caller's own state, never from the seal or the row. The header must name
 * that id and a held key must have it (a held key that isn't 32 bytes has no id, so it is never
 * picked); the seal is checked against the context it is stored under. Returns the plaintext, or
 * throws SealError with the code of the first check that fails. Every code but OPEN_FAILED comes
 * before any tag check.
 */
export function openSeal(seal: Uint8Array, keys: readonly Uint8Array[], context: SealContext, expectedKeyId: string): Buffer {
  if (!(seal instanceof Uint8Array)) throw sealError('NOT_A_SEAL');
  const b = Buffer.from(seal.buffer, seal.byteOffset, seal.byteLength);
  if (b.length < SEAL_OVERHEAD_BYTES || b[0] !== SEAL_FORMAT_BYTE) throw sealError('NOT_A_SEAL');
  if (b[1] !== SEAL_VERSION) throw sealError('UNKNOWN_VERSION');
  if (b.length - SEAL_OVERHEAD_BYTES > SEAL_MAX_PLAINTEXT_BYTES) throw sealError('TOO_LARGE');
  const named = b.subarray(2, SEAL_HEADER_BYTES).toString('base64url');
  if (named !== expectedKeyId) throw sealError('KEY_MISMATCH');
  const key = keys.find((k) => k instanceof Uint8Array && k.length === SYMMETRIC_KEY_BYTES && symmetricKeyId(k) === named);
  if (!key) throw sealError('KEY_MISMATCH');
  const ad = sealAssociatedData(b.subarray(0, SEAL_HEADER_BYTES), context);
  const nonce = b.subarray(SEAL_HEADER_BYTES, SEAL_HEADER_BYTES + SEAL_NONCE_BYTES);
  const ciphertext = b.subarray(SEAL_HEADER_BYTES + SEAL_NONCE_BYTES, b.length - SEAL_TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: SEAL_TAG_BYTES });
  decipher.setAAD(ad);
  decipher.setAuthTag(b.subarray(b.length - SEAL_TAG_BYTES));
  // decipher.update returns bytes before the tag is checked: they are kept here, wiped and never
  // returned unless final() passes.
  const plaintext = decipher.update(ciphertext);
  try {
    decipher.final();
  } catch {
    plaintext.fill(0);
    throw sealError('OPEN_FAILED');
  }
  return plaintext;
}

export const WRAP_FORMAT_BYTE = 0xc6;
export const WRAP_VERSION = 0x01;
/** Format byte, version and recipient key id, outside and again at the start of the payload. */
export const WRAP_HEADER_BYTES = 34;
/** The OAEP plaintext: the header, the wrapped key's id and the 32-byte key. */
export const WRAP_PAYLOAD_BYTES = 98;
/** The only lengths a wrap has: the header and one RSA-2048, RSA-3072 or RSA-4096 block. */
export const WRAP_BYTES: readonly number[] = [290, 418, 546];

export type WrapErrorCode = 'NOT_A_WRAP' | 'UNKNOWN_VERSION' | 'NOT_FOR_ME' | 'OPEN_FAILED' | 'BAD_PAYLOAD' | 'KEY_MISMATCH' | 'NOT_COMMITTED';

/** One fixed message per code, so a refusal carries nothing of the wrap (no oracle in the OAEP failures). */
export const WRAP_MESSAGES: Readonly<Record<WrapErrorCode, string>> = Object.freeze({
  NOT_A_WRAP: 'not a wrap',
  UNKNOWN_VERSION: 'a wrap version this reader does not know',
  NOT_FOR_ME: 'the wrap names a recipient key this reader does not hold',
  OPEN_FAILED: 'the wrap does not open',
  BAD_PAYLOAD: 'the wrap payload is not the one its header names',
  KEY_MISMATCH: 'the wrapped key is not the key its id names',
  NOT_COMMITTED: 'the wrapped key is not the key the signed object names',
});

export class WrapError extends Error {
  constructor(readonly code: WrapErrorCode, message: string) {
    super(message);
    this.name = 'WrapError';
  }
}

const wrapError = (code: WrapErrorCode) => new WrapError(code, WRAP_MESSAGES[code]);

/** A held RSA private key's key id, or null when it is not an RSA private key with an id (key-id). */
function heldRsaKeyId(key: KeyObject): string | null {
  if (key?.type !== 'private' || key.asymmetricKeyType !== 'rsa') return null;
  try {
    return keyIdFromSpki(createPublicKey(key).export({ type: 'spki', format: 'der' }));
  } catch {
    return null;
  }
}

/**
 * Open a wrap with the held RSA private key its recipient id names, and return the wrapped key and
 * its id once that id is `committedKeyId`, the id a signed object the caller trusts names for this
 * key (the wrap's own ids prove only that they match its key). Throws WrapError with the code of
 * the first check that fails. NOT_A_WRAP, UNKNOWN_VERSION and NOT_FOR_ME come before anything is
 * decrypted.
 */
export function openWrap(wrap: Uint8Array, held: readonly KeyObject[], committedKeyId: string): { key: Buffer; keyId: string } {
  if (!(wrap instanceof Uint8Array)) throw wrapError('NOT_A_WRAP');
  const b = Buffer.from(wrap.buffer, wrap.byteOffset, wrap.byteLength);
  if (b.length < 2 || b[0] !== WRAP_FORMAT_BYTE) throw wrapError('NOT_A_WRAP');
  if (b[1] !== WRAP_VERSION) throw wrapError('UNKNOWN_VERSION');
  if (!WRAP_BYTES.includes(b.length)) throw wrapError('NOT_A_WRAP');
  const named = b.subarray(2, WRAP_HEADER_BYTES);
  const recipient = held.find((k) => {
    const id = heldRsaKeyId(k);
    return id !== null && Buffer.from(id, 'base64url').equals(named);
  });
  if (!recipient) throw wrapError('NOT_FOR_ME');
  const ciphertext = b.subarray(WRAP_HEADER_BYTES);
  if (ciphertext.length * 8 !== recipient.asymmetricKeyDetails?.modulusLength) throw wrapError('OPEN_FAILED');
  let payload: Buffer;
  try {
    payload = privateDecrypt({ key: recipient, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, ciphertext);
  } catch {
    throw wrapError('OPEN_FAILED');
  }
  if (payload.length !== WRAP_PAYLOAD_BYTES || !payload.subarray(0, WRAP_HEADER_BYTES).equals(b.subarray(0, WRAP_HEADER_BYTES))) {
    payload.fill(0);
    throw wrapError('BAD_PAYLOAD');
  }
  // A buffer of its own, never a slice of Node's shared pool, so wiping it wipes the only copy.
  const key = Buffer.allocUnsafeSlow(32);
  payload.copy(key, 0, 66, 98);
  const keyId = symmetricKeyId(key);
  const claimed = payload.subarray(34, 66).toString('base64url');
  payload.fill(0);
  if (claimed !== keyId) {
    key.fill(0);
    throw wrapError('KEY_MISMATCH');
  }
  if (keyId !== committedKeyId) {
    key.fill(0);
    throw wrapError('NOT_COMMITTED');
  }
  return { key, keyId };
}
