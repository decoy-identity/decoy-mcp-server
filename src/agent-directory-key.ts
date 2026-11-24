// key-format: agent-directory
// Account-signed connection snapshots; keep-signed session snapshots. No server-authored entries.
import { createHash } from 'node:crypto';
import { readCanonicalJson, CanonicalJsonError } from './signed-key-set.js';
import { canonicalSpki, isKeyId, keyIdFromSpki, keyKind } from './key-format.js';
import { readBase64url, signedMessage, verifySignature, SignatureError } from './signed-key-set.js';

export const DIRECTORY_MAX_BYTES = 65536;
export const DIRECTORY_MAX_ENTRIES = 32;
export type SignedDirectory = { payload: string; sig: string };
export type DirectoryHead = { version: number; hash: string };
export type DirectoryAuthority = DirectoryHead & { kid: string; spki: string };
export type DirectoryKey = { kid: string; spki: string };
export type ConnectionEntry = DirectoryKey & { keep: DirectoryKey | null; enclave: boolean };
export interface DirectoryPayload { v: 1; account: string; version: number; signer: string; key_set: DirectoryHead; entries: ConnectionEntry[] }
export interface SessionPayload { v: 1; account: string; version: number; signer: string; connection: string; directory: string; entries: (DirectoryKey & { expires: number })[] }
export type SessionParent = { hash: string; entry: ConnectionEntry };
export type DirectoryCode = 'TOO_LARGE' | 'NOT_CANONICAL' | 'UNKNOWN_VERSION' | 'NOT_A_DIRECTORY' | 'WRONG_ACCOUNT' | 'KEY_SET_MISMATCH' | 'NOT_A_SIGNATURE' | 'BAD_SIGNATURE' | 'GAP' | 'OLDER' | 'FORK' | 'WRONG_CONNECTION';
export class DirectoryError extends Error {
  constructor(readonly code: DirectoryCode) { super(`Directory refused: ${code}`); this.name = 'DirectoryError'; }
}
const fail = (code: DirectoryCode): never => { throw new DirectoryError(code); };
const object = (v: unknown): v is Record<string, any> => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, any> => object(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const positive = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) > 0;
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

function publicKey(v: unknown, kind: 'rsa' | 'p256'): DirectoryKey {
  if (!exact(v, ['kid', 'spki']) || !isKeyId(v.kid)) return fail('NOT_A_DIRECTORY');
  const der = readBase64url(v.spki);
  if (!der || der.length > 4096) return fail('NOT_A_DIRECTORY');
  try {
    if (!canonicalSpki(der).equals(der) || keyKind(der) !== kind || keyIdFromSpki(der) !== v.kid) return fail('NOT_A_DIRECTORY');
  } catch { return fail('NOT_A_DIRECTORY'); }
  return { kid: v.kid, spki: v.spki };
}
function base(signed: { payload: unknown; sig: unknown }, session: boolean) {
  if (typeof signed?.payload === 'string' && Math.floor(signed.payload.length * 3 / 4) > DIRECTORY_MAX_BYTES) fail('TOO_LARGE');
  const bytes = readBase64url(signed?.payload);
  if (!bytes) return fail('NOT_CANONICAL');
  let p: any;
  try { p = readCanonicalJson(bytes, DIRECTORY_MAX_BYTES); }
  catch (e) { if (e instanceof CanonicalJsonError) return fail(e.code); throw e; }
  if (object(p) && typeof p.v === 'number' && p.v !== 1) fail('UNKNOWN_VERSION');
  const keys = session ? ['v', 'account', 'version', 'signer', 'connection', 'directory', 'entries'] : ['v', 'account', 'version', 'signer', 'key_set', 'entries'];
  if (!exact(p, keys) || p.v !== 1 || typeof p.account !== 'string' || !uuid.test(p.account) || !positive(p.version) || !isKeyId(p.signer)
    || !Array.isArray(p.entries) || p.entries.length > DIRECTORY_MAX_ENTRIES) return fail('NOT_A_DIRECTORY');
  let previous = '';
  for (const entry of p.entries) {
    const members = session ? ['kid', 'spki', 'expires'] : ['kid', 'spki', 'keep', 'enclave'];
    if (!exact(entry, members)) fail('NOT_A_DIRECTORY');
    publicKey({ kid: entry.kid, spki: entry.spki }, 'rsa');
    if (entry.kid <= previous) fail('NOT_A_DIRECTORY');
    previous = entry.kid;
    if (session) { if (!positive(entry.expires)) fail('NOT_A_DIRECTORY'); }
    else {
      if (typeof entry.enclave !== 'boolean') fail('NOT_A_DIRECTORY');
      if (entry.keep !== null) publicKey(entry.keep, 'p256');
    }
  }
  if (session) {
    if (!isKeyId(p.connection) || !isKeyId(p.directory)) fail('NOT_A_DIRECTORY');
  } else if (!exact(p.key_set, ['version', 'hash']) || !positive(p.key_set.version) || !isKeyId(p.key_set.hash)) fail('NOT_A_DIRECTORY');
  const label = session ? 'agent-session-directory' : 'agent-directory';
  return { payload: p, bytes, hash: createHash('sha256').update(signedMessage(label, bytes)).digest('base64url') };
}
export function readDirectory(signed: { payload: unknown; sig: unknown }) { const r = base(signed, false); return { ...r, payload: r.payload as DirectoryPayload }; }
export function readSessionDirectory(signed: { payload: unknown; sig: unknown }) { const r = base(signed, true); return { ...r, payload: r.payload as SessionPayload }; }
function position(version: number, hash: string, head: DirectoryHead | null | undefined): 'accepted' | 'current' {
  if (head === undefined) return 'current'; // read: verify bytes and signature, not a new submission
  if (head === null) { if (version !== 1) fail('GAP'); return 'accepted'; }
  if (version < head.version) fail('OLDER');
  if (version === head.version) { if (hash !== head.hash) fail('FORK'); return 'current'; }
  if (version !== head.version + 1) fail('GAP');
  return 'accepted';
}
function signature(label: string, bytes: Buffer, sig: unknown, spki: string) {
  try { verifySignature(label, bytes, sig, Buffer.from(spki, 'base64url')); }
  catch (e) { if (e instanceof SignatureError) return fail(e.code); throw e; }
}
export function verifyDirectory(signed: { payload: unknown; sig: unknown }, account: string, authority: DirectoryAuthority, head?: DirectoryHead | null) {
  const r = readDirectory(signed);
  if (r.payload.account !== account) fail('WRONG_ACCOUNT');
  if (r.payload.signer !== authority.kid || r.payload.key_set.version !== authority.version || r.payload.key_set.hash !== authority.hash) fail('KEY_SET_MISMATCH');
  signature('agent-directory', r.bytes, signed.sig, authority.spki);
  return { ...r, status: position(r.payload.version, r.hash, head) };
}
export function verifySessionDirectory(signed: { payload: unknown; sig: unknown }, account: string, parent: SessionParent, head?: DirectoryHead | null) {
  const r = readSessionDirectory(signed);
  if (r.payload.account !== account) fail('WRONG_ACCOUNT');
  const keep = parent.entry.keep;
  if (r.payload.directory !== parent.hash || r.payload.connection !== parent.entry.kid || !keep || r.payload.signer !== keep.kid) return fail('WRONG_CONNECTION');
  signature('agent-session-directory', r.bytes, signed.sig, keep.spki);
  return { ...r, status: position(r.payload.version, r.hash, head) };
}
