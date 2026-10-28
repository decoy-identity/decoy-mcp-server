// Agent-written secret fields on an account — the sealed payload.
// The same format as the Decoy API's own implementation, byte for byte; both are checked against
// one set of sha-pinned golden vectors.
//
// Each field is its own row (account_fields), sealed with its OWN random 32-byte key:
//   kid         = lowercase hex of the first 8 bytes of SHA-256(key)
//   ciphertext  = VAULT SealedBlob under that key: [0x01][0x01][12B nonce][AES-256-GCM(JSON)][16B tag]
//   payload     = a CXF EditableField bound to its row:
//                 { id, account_id, fieldType: 'concealed-string' | 'string', label, value, …unknown }
// The payload names its own `id` and `account_id`, so a blob moved to another row (or another
// account) is refused on open. Unknown keys are carried through every edit untouched, so a newer
// surface's additions survive an older surface's edit.
//
// The key is wrapped per reader (account_field_wraps): to the owner (ENVELOPE to users.public_key,
// converged by the phone to a VAULT wrap under the vault key) and to each connection (the headerless
// agent envelope, lib/sealed-blob wrapVaultKeyForRecipient). The server never decrypts anything here.
//

import crypto from 'node:crypto';

const SEALED_BLOB_VERSION = 0x01;
const SealMode = { VAULT: 0x01 } as const;
function openVault(blob: Buffer, key: Buffer): unknown {
  const nonce = blob.subarray(2, 14);
  const ctWithTag = blob.subarray(14);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(ctWithTag.subarray(ctWithTag.length - 16));
  const out = Buffer.concat([decipher.update(ctWithTag.subarray(0, ctWithTag.length - 16)), decipher.final()]);
  return JSON.parse(out.toString('utf8'));
}

export const ACCOUNT_FIELD_TYPES = ['concealed-string', 'string'] as const;
export type AccountFieldType = typeof ACCOUNT_FIELD_TYPES[number];

/** The sealed plaintext. Unknown keys are preserved verbatim. */
export interface AccountFieldPayload {
  id: string;
  account_id: string;
  fieldType: AccountFieldType;
  label: string;
  value: string;
  [k: string]: unknown;
}

export const MAX_LABEL_CHARS = 200;
export const MAX_VALUE_CHARS = 12_000;
/** Server cap on the whole ciphertext (bytes). */
export const MAX_FIELD_CIPHERTEXT_BYTES = 16 * 1024;

const NONCE_LEN = 12;
const TAG_LEN = 16;
const KNOWN = ['id', 'account_id', 'fieldType', 'label', 'value'] as const;

export class AccountFieldError extends Error {
  constructor(public readonly code: 'SHAPE' | 'BINDING_MISMATCH' | 'OPEN_FAILED' | 'TOO_LARGE', message: string) {
    super(message);
    this.name = 'AccountFieldError';
  }
}

/** `kid` of a field key: hex of the first 8 bytes of SHA-256(key). */
export function fieldKid(key: Buffer): string {
  if (key.length !== 32) throw new AccountFieldError('SHAPE', 'a field key is 32 bytes');
  return crypto.createHash('sha256').update(key).digest().subarray(0, 8).toString('hex');
}

export function newFieldKey(): Buffer {
  return crypto.randomBytes(32);
}

function checkShape(f: Record<string, unknown>, strict: boolean): asserts f is AccountFieldPayload {
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new AccountFieldError('SHAPE', 'a field payload is a JSON object');
  if (typeof f.id !== 'string' || !f.id) throw new AccountFieldError('SHAPE', 'id is required');
  if (typeof f.account_id !== 'string' || !f.account_id) throw new AccountFieldError('SHAPE', 'account_id is required');
  if (!ACCOUNT_FIELD_TYPES.includes(f.fieldType as AccountFieldType)) throw new AccountFieldError('SHAPE', `fieldType must be one of ${ACCOUNT_FIELD_TYPES.join(', ')}`);
  if (typeof f.label !== 'string') throw new AccountFieldError('SHAPE', 'label is a string');
  if (typeof f.value !== 'string') throw new AccountFieldError('SHAPE', 'value is a string');
  if (strict) {
    if (!f.label.trim()) throw new AccountFieldError('SHAPE', 'label must not be empty');
    if (f.label.length > MAX_LABEL_CHARS) throw new AccountFieldError('TOO_LARGE', `label is at most ${MAX_LABEL_CHARS} characters`);
    if (f.value.length > MAX_VALUE_CHARS) throw new AccountFieldError('TOO_LARGE', `value is at most ${MAX_VALUE_CHARS} characters`);
  }
}

/** Canonical key order: the five known keys, then every unknown key in its original order. */
export function canonicalField(f: AccountFieldPayload): AccountFieldPayload {
  const out: Record<string, unknown> = {};
  for (const k of KNOWN) out[k] = f[k];
  for (const [k, v] of Object.entries(f)) if (!(KNOWN as readonly string[]).includes(k)) out[k] = v;
  return out as AccountFieldPayload;
}

/** Seal a field under its key. `nonce` is for golden vectors only — omit it in real use. */
export function sealAccountField(field: AccountFieldPayload, key: Buffer, nonce?: Buffer): Buffer {
  if (key.length !== 32) throw new AccountFieldError('SHAPE', 'a field key is 32 bytes');
  checkShape(field as Record<string, unknown>, true);
  const iv = nonce ?? crypto.randomBytes(NONCE_LEN);
  if (iv.length !== NONCE_LEN) throw new AccountFieldError('SHAPE', 'nonce is 12 bytes');
  const plaintext = Buffer.from(JSON.stringify(canonicalField(field)), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const blob = Buffer.concat([Buffer.from([SEALED_BLOB_VERSION, SealMode.VAULT]), iv, ct, cipher.getAuthTag()]);
  if (blob.length > MAX_FIELD_CIPHERTEXT_BYTES) throw new AccountFieldError('TOO_LARGE', `a sealed field is at most ${MAX_FIELD_CIPHERTEXT_BYTES} bytes`);
  return blob;
}

/**
 * Open a field and check it belongs where it was served: its `id` and `account_id` must be the
 * row's. A blob swapped between rows or accounts throws BINDING_MISMATCH; a wrong key or tampered
 * bytes throw OPEN_FAILED.
 */
export function openAccountField(blob: Buffer, key: Buffer, expect: { id: string; account_id: string }): AccountFieldPayload {
  if (blob.length < 2 + NONCE_LEN + TAG_LEN || blob[0] !== SEALED_BLOB_VERSION || blob[1] !== SealMode.VAULT) {
    throw new AccountFieldError('OPEN_FAILED', 'not a VAULT SealedBlob');
  }
  let parsed: unknown;
  try {
    parsed = openVault(blob, key);
  } catch {
    throw new AccountFieldError('OPEN_FAILED', 'the field did not open with this key');
  }
  checkShape(parsed as Record<string, unknown>, false);
  const f = parsed as AccountFieldPayload;
  if (f.id.toLowerCase() !== expect.id.toLowerCase() || f.account_id.toLowerCase() !== expect.account_id.toLowerCase()) {
    throw new AccountFieldError('BINDING_MISMATCH', 'this field was sealed for a different row');
  }
  return f;
}

/** Change label / value / fieldType, keeping the binding and every unknown key. */
export function editAccountField(
  field: AccountFieldPayload,
  patch: { label?: string; value?: string; fieldType?: AccountFieldType },
): AccountFieldPayload {
  const next = { ...field } as AccountFieldPayload;
  if (patch.label !== undefined) next.label = patch.label;
  if (patch.value !== undefined) next.value = patch.value;
  if (patch.fieldType !== undefined) next.fieldType = patch.fieldType;
  checkShape(next as Record<string, unknown>, true);
  return canonicalField(next);
}
