/**
 * Lossless account-record edits for account_update, credential_set and
 * account_set_credential.
 *
 * The bridge used to turn an opened record into a flat object of ten known keys
 * and re-seal THAT, so any edit through these tools:
 *   - dropped everything outside the allowlist: TOTP, passkeys, a second login,
 *     the CXF credentials array itself, favicon/avatar and unknown keys;
 *   - downcast field kinds while converting CXF (name → custom, dob → date,
 *     security-question → secret, unmodelled types → custom);
 *   - replaced the whole custom-field / structured list with whatever was
 *     passed, restamping every id.
 *
 * This module PATCHES the opened record instead. It takes the decrypted record
 * exactly as stored, applies only the requested change to a deep copy, and
 * leaves every other byte alone. Each logical field is written where readers
 * look for it:
 *
 *   flat record (no `credentials`)   the flat key (service_name, password, …)
 *   CXF-shaped (has `credentials`)   the CXF carrier (title, first basic-auth
 *                                    urls/username/password, first custom-fields
 *                                    note, decoys.me/category extension) AND any
 *                                    flat mirror key that already exists, so a
 *                                    stale mirror never shadows the edit.
 *
 * Secret values are written exactly as given: never trimmed or normalized.
 * Custom fields and structured entries use set/remove semantics: `setFields`
 * upserts by label (an existing field keeps its id, kind and extras), and
 * `removeFields` removes by label. Nothing is replaced wholesale.
 *
 * An edit this module cannot apply without loss (a non-login item, an ambiguous
 * label, fields kept only in the legacy list a CXF reader would hide) throws
 * RecordEditError BEFORE anything is sealed or written.
 */
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

type Obj = Record<string, unknown>;

export class RecordEditError extends Error {
  readonly code = 'UNSUPPORTED_RECORD_EDIT';
  constructor(message: string) {
    super(message);
    this.name = 'RecordEditError';
  }
}

/** Single-value field kinds (the Decoy iPhone app's CustomFieldKind raw values). */
export type FieldKind =
  | 'name' | 'dob' | 'email' | 'phone' | 'url' | 'number' | 'date' | 'secret' | 'note' | 'security-question' | 'custom';

export interface FieldSet {
  label: string;
  value: string;
  kind?: FieldKind;
  secret?: boolean;
}

export interface StructuredSet {
  kind: 'address' | 'credit-card';
  label?: string;
  /** Members to set (CXF member names). A member set to '' is removed. Members not named are kept. */
  values: Record<string, string>;
}

export interface StructuredRef {
  kind: 'address' | 'credit-card';
  label?: string;
}

/** The change to apply. Absent keys are not touched. */
export interface AccountEdit {
  service_name?: string;
  service_url?: string;
  login_url?: string;
  username?: string;
  password?: string;
  category?: string;
  notes?: string;
  tags?: string[];
  setFields?: FieldSet[];
  removeFields?: string[];
  setStructured?: StructuredSet[];
  removeStructured?: StructuredRef[];
}

const CATEGORY_EXT = 'decoys.me/category';
const STRUCTURED_KINDS = new Set(['address', 'credit-card']);

/** CXF member fieldTypes (the members the Decoy apps read). */
const STRUCTURED_MEMBER_TYPES: Record<string, Record<string, string>> = {
  address: { streetAddress: 'string', apt: 'string', city: 'string', territory: 'subdivision-code', postalCode: 'string', country: 'country-code' },
  'credit-card': { number: 'concealed-string', fullName: 'string', expiryDate: 'year-month', verificationNumber: 'concealed-string' },
};

// ── CXF kind ontology (the same as the Decoy apps') ──

function cxfFieldKind(fieldType: string, designation: string): string {
  if (fieldType === 'string' && designation === 'name') return 'name';
  if (fieldType === 'date' && designation === 'bday') return 'dob';
  if (fieldType === 'email') return 'email';
  if (fieldType === 'number') return 'number';
  if (fieldType === 'date') return 'date';
  if (fieldType === 'concealed-string' && designation === 'security-question') return 'security-question';
  if (fieldType === 'concealed-string') return 'secret';
  if (fieldType === 'string' && designation === 'tel') return 'phone';
  if (fieldType === 'string' && designation === 'url') return 'url';
  if (fieldType === 'string' && designation === 'cf-note') return 'note';
  return 'custom';
}

function cxfFieldTypeForKind(kind: string): string {
  switch (kind) {
    case 'email': return 'email';
    case 'number': return 'number';
    case 'date': case 'dob': return 'date';
    case 'secret': case 'security-question': return 'concealed-string';
    default: return 'string';
  }
}

function cxfDesignationForKind(kind: string): string | undefined {
  switch (kind) {
    case 'name': return 'name';
    case 'dob': return 'bday';
    case 'phone': return 'tel';
    case 'url': return 'url';
    case 'note': return 'cf-note';
    case 'security-question': return 'security-question';
    default: return undefined;
  }
}

function kindIsSecret(kind: string): boolean {
  return kind === 'secret' || kind === 'security-question';
}

/** The plain kind a CXF designation names (the inverse of cxfDesignationForKind). */
function kindForDesignation(designation: string): string | undefined {
  switch (designation) {
    case 'name': return 'name';
    case 'bday': return 'dob';
    case 'tel': return 'phone';
    case 'url': return 'url';
    case 'cf-note': return 'note';
    default: return undefined;
  }
}

/** The CXF fieldType an entry of `kind` is written with: concealment IS the fieldType (record-patch v4). */
function cxfTypeFor(kind: string, secret: boolean): string {
  return secret ? 'concealed-string' : cxfFieldTypeForKind(kind);
}

// ── helpers ──

const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

function clone<T>(v: T): T {
  if (Array.isArray(v)) return v.map((x) => clone(x)) as unknown as T;
  if (isObj(v)) {
    const out: Obj = {};
    for (const [k, x] of Object.entries(v)) out[k] = clone(x);
    return out as T;
  }
  return v;
}

/** A credential member that is either a bare string (web shape) or a CXF EditableField ({ fieldType, value }). */
function memberValue(v: unknown): string {
  if (typeof v === 'string') return v;
  if (isObj(v) && typeof v.value === 'string') return v.value;
  return '';
}

/** A member value as Decoy's web reader reads it: a CXF typed field unwraps
 *  to its value, null/objects are empty, numbers stringify, whitespace-only is empty. */
function readerValue(v: unknown): string {
  const x = isObj(v) && 'fieldType' in v && 'value' in v ? v.value : v;
  if (x == null || typeof x === 'object') return '';
  const s = typeof x === 'string' ? x : String(x);
  return s.trim() === '' ? '' : s;
}

/** True when the record is CXF-shaped (the Decoy iPhone app decodes any blob with a credentials array as a CXF item). */
export function isCxfShaped(record: Obj): boolean {
  return Array.isArray(record.credentials) && record.credentials.length > 0;
}

function firstIndex(creds: unknown[], type: string): number {
  return creds.findIndex((c) => isObj(c) && c.type === type);
}

/** The visible label a field matches on: trimmed, so "API key " and "API key" are the same field. */
function sameLabel(a: unknown, b: string): boolean {
  return str(a) === b.trim();
}

function only<T>(matches: T[], what: string): T | undefined {
  if (matches.length > 1) {
    throw new RecordEditError(`${matches.length} entries match ${what}, so this edit can't tell which one to change. ` +
      'Nothing was written. Edit it in the Decoy app.');
  }
  return matches[0];
}

// ── reads used by the tools (never returned to the agent) ──

/** Whether the record holds a password, wherever its readers look (flat key, then first login). */
export function recordHoldsPassword(record: Obj): boolean {
  if (typeof record.password === 'string' && record.password.trim() !== '') return true;
  const creds = Array.isArray(record.credentials) ? record.credentials : [];
  const ba = creds.find((c) => isObj(c) && c.type === 'basic-auth') as Obj | undefined;
  return memberValue(ba?.password).trim() !== '';
}

/** The login's username and URLs, for the write-through cache. */
export function recordLogin(record: Obj): { username: string | null; serviceUrl: string | null; loginUrl: string | null } {
  const creds = Array.isArray(record.credentials) ? record.credentials : [];
  const ba = creds.find((c) => isObj(c) && c.type === 'basic-auth') as Obj | undefined;
  const urls = Array.isArray(ba?.urls) ? (ba!.urls as unknown[]).filter((u): u is string => typeof u === 'string') : [];
  const username = (typeof record.username === 'string' && record.username) || memberValue(ba?.username) || null;
  const serviceUrl = urls[0] ?? (typeof record.service_url === 'string' ? record.service_url : null);
  const loginUrl = urls[1] ?? (typeof record.login_url === 'string' ? record.login_url : null);
  return { username, serviceUrl, loginUrl };
}

// ── the editor ──

/** SECRET read: the value exactly as given, or '' when absent or whitespace-only (never trims content). */
function exact(v: unknown): string {
  const x = typeof v === 'string' ? v : isObj(v) && typeof v.value === 'string' ? v.value : '';
  return x.trim() === '' ? '' : x;
}

function setOrDelete(o: Obj, key: string, value: string): void {
  if (value) o[key] = value;
  else delete o[key];
}

/** A flat mirror on a CXF record: refreshed only where it already exists, never invented. */
function mirror(o: Obj, key: string, value: string): void {
  if (key in o) setOrDelete(o, key, value);
}

/** The record's current logical values, read where Decoy's readers read them. */
function currentValues(rec: Obj, cxf: boolean) {
  const creds = cxf ? (rec.credentials as unknown[]) : [];
  const ba = creds.find((c) => isObj(c) && c.type === 'basic-auth') as Obj | undefined;
  const cf = creds.find((c) => isObj(c) && c.type === 'custom-fields') as Obj | undefined;
  const urls = Array.isArray(ba?.urls) ? (ba!.urls as unknown[]) : [];
  const note = (Array.isArray(cf?.fields) ? (cf!.fields as unknown[]) : []).find((f) => isObj(f) && f.designation === 'notes') as Obj | undefined;
  const ext = (Array.isArray(rec.extensions) ? (rec.extensions as unknown[]) : []).find((e) => isObj(e) && e.name === CATEGORY_EXT) as Obj | undefined;
  const first = (...v: unknown[]) => v.map((x) => str(typeof x === 'string' ? x : isObj(x) ? x.value : '')).find((x) => x) ?? '';
  return {
    service_name: first(rec.title, rec.service_name),
    service_url: first(urls[0], rec.service_url),
    login_url: first(urls[1], rec.login_url),
    // Every carrier that holds a login value (flat mirror, CXF login). Readers disagree on which
    // wins (web prefers the flat mirror; the bridge's reader and iOS read the CXF login), so an
    // edit counts as a change when it differs from ANY of them, and then rewrites all of them: a
    // stale mirror can never make a real change look like a no-op.
    usernames: [str(rec.username), str(memberValue(ba?.username))].filter((x) => x !== ''),
    passwords: [exact(rec.password), exact(ba?.password)].filter((x) => x !== ''),
    notes: exact(note?.value) || exact(rec.notes),
    category: first(ext?.value, rec.category),
    tags: Array.isArray(rec.tags) ? (rec.tags as unknown[]) : [],
  };
}

/**
 * Apply `edit` to an opened record and return the record to re-seal. Pure: the
 * input is not mutated, so it can be re-run on a fresh record after a 409.
 * Throws RecordEditError, before any write, when the edit cannot be lossless.
 *
 * Same patch rules as the Decoy web and iPhone apps
 * AccountRecordPatch (pinned by the shared record-patch vectors): only values that
 * DIFFER are written (identifiers trimmed, secrets exact, '' == whitespace-only ==
 * absent); a v1 record (no credentials, or []) stays v1; a CXF record stays CXF,
 * its login members keep their stored shape, and flat mirrors are refreshed only
 * where they exist.
 */
export function applyAccountEdit(
  record: unknown,
  edit: AccountEdit,
  genId: () => string = randomUUID,
  now: () => number = () => Math.floor(Date.now() / 1000),
): Obj {
  if (!isObj(record)) throw new RecordEditError('This account\'s record is not an object, so it can\'t be edited safely. Nothing was written.');
  if (record.credentials != null && !Array.isArray(record.credentials)) {
    throw new RecordEditError('This account\'s record has a credentials entry in a shape this tool does not know. Nothing was written. Edit it in the Decoy app.');
  }
  if (typeof record.type === 'string' && record.type !== 'login') {
    throw new RecordEditError(`This record is a "${record.type}" item, not a login, so login fields can't be edited here. Nothing was written.`);
  }
  if (edit.service_name !== undefined && str(edit.service_name) === '') {
    // Decoy never writes a nameless account (web's editor skips a blank title, the SDK refuses one,
    // the Decoy API refuses a blank service_name), so a blank name is refused rather than deleting the title.
    throw new RecordEditError('An account needs a name, so service_name can\'t be blank. Nothing was written.');
  }
  for (const f of edit.setFields ?? []) {
    if (typeof f.value !== 'string' || f.value.trim() === '') {
      throw new RecordEditError(`The custom field "${String(f.label).trim()}" has an empty value. To remove a field, pass its label in remove_custom_fields. Nothing was written.`);
    }
  }
  for (const s of edit.setStructured ?? []) {
    for (const [k, v] of Object.entries(s.values)) {
      if (v !== '' && v.trim() === '') {
        throw new RecordEditError(`The ${s.kind} member "${k}" is only whitespace. Pass "" to remove a member. Nothing was written.`);
      }
    }
  }
  const next = clone(record);
  const cxf = Array.isArray(next.credentials) && (next.credentials as unknown[]).length > 0;
  const creds = cxf ? (next.credentials as unknown[]) : [];
  const cur = currentValues(record, cxf);
  const ident = (k: 'service_name' | 'service_url' | 'login_url' | 'category') =>
    edit[k] !== undefined && str(edit[k]) !== cur[k] ? str(edit[k]) : null;
  /** Changed when it differs from any carrier holding a value (or, with none, when it has one). */
  const differs = (want: string, held: string[]) => (held.length === 0 ? want !== '' : held.some((x) => x !== want));
  const name = ident('service_name');
  const serviceUrl = ident('service_url');
  const loginUrl = ident('login_url');
  const username = edit.username !== undefined && differs(str(edit.username), cur.usernames) ? str(edit.username) : null;
  const category = ident('category');
  const password = edit.password !== undefined && differs(exact(edit.password), cur.passwords) ? exact(edit.password) : null;
  const notes = edit.notes !== undefined && exact(edit.notes) !== cur.notes ? exact(edit.notes) : null;
  const tags = edit.tags !== undefined && JSON.stringify(edit.tags) !== JSON.stringify(cur.tags) ? edit.tags : null;

  if (!cxf) {
    // A legacy v1 record: flat keys only (iOS patchV1). Decoy's web reader prefers `title`
    // where a flat record has one, so it is refreshed too (and set on a bare record).
    if (name !== null) {
      const writeTitle = 'title' in next || !('service_name' in next);
      setOrDelete(next, 'service_name', name);
      if (writeTitle) setOrDelete(next, 'title', name);
    }
    if (serviceUrl !== null) setOrDelete(next, 'service_url', serviceUrl);
    if (loginUrl !== null) setOrDelete(next, 'login_url', loginUrl);
    if (username !== null) setOrDelete(next, 'username', username);
    if (category !== null) setOrDelete(next, 'category', category);
    if (password !== null) setOrDelete(next, 'password', password);
    if (notes !== null) setOrDelete(next, 'notes', notes);
    if (tags !== null) {
      if (tags.length > 0) next.tags = tags;
      else delete next.tags;
    }
  } else {
    patchCxfScalars(next, creds, { name, serviceUrl, loginUrl, username, password, notes, category, tags });
  }

  const insertAfterLogin = (cred: Obj) => {
    const ba = firstIndex(creds, 'basic-auth');
    creds.splice(ba >= 0 ? ba + 1 : 0, 0, cred);
  };
  if ((edit.setFields?.length ?? 0) > 0 || (edit.removeFields?.length ?? 0) > 0) {
    applyFieldEdits(next, creds, cxf, edit.setFields ?? [], edit.removeFields ?? [], genId, insertAfterLogin);
  }
  if ((edit.setStructured?.length ?? 0) > 0 || (edit.removeStructured?.length ?? 0) > 0) {
    applyStructuredEdits(next, creds, cxf, edit.setStructured ?? [], edit.removeStructured ?? [], genId);
  }
  // Never leave `credentials: []` behind on a CXF record this edit emptied: readers (iOS
  // included) treat [] as a v1 record, so the emptied list goes, as web and iOS drop it.
  if (cxf && creds.length === 0) delete next.credentials;
  // A CXF item that changed is stamped, as iOS patchCXF does: only where it keeps a modifiedAt,
  // and only when something actually changed (a no-op stays byte-identical).
  if (cxf && typeof next.modifiedAt === 'number' && !isDeepStrictEqual(next, record)) next.modifiedAt = now();
  return next;
}

/** A CXF record's scalar fields: the carriers readers use, in the shape already stored (iOS patchCXF). */
function patchCxfScalars(
  next: Obj,
  creds: unknown[],
  v: { name: string | null; serviceUrl: string | null; loginUrl: string | null; username: string | null; password: string | null; notes: string | null; category: string | null; tags: string[] | null },
): void {
  if (v.name !== null) {
    setOrDelete(next, 'title', v.name);
    mirror(next, 'service_name', v.name);
  }
  if (v.serviceUrl !== null || v.loginUrl !== null || v.username !== null || v.password !== null) {
    const at = firstIndex(creds, 'basic-auth');
    const ba: Obj = at >= 0 ? { ...(creds[at] as Obj) } : { type: 'basic-auth' };
    // No login carrier: a value whose flat key exists is written there only (the mirror);
    // a carrier is created only for values with nowhere else to go (iOS `carries`).
    const carries = (flatKey: string) => at >= 0 || !(flatKey in next);
    const urlsCarried = at >= 0 ||
      (v.serviceUrl !== null && carries('service_url')) || (v.loginUrl !== null && carries('login_url'));
    if ((v.serviceUrl !== null || v.loginUrl !== null) && !urlsCarried) {
      if (v.serviceUrl !== null) mirror(next, 'service_url', v.serviceUrl);
      if (v.loginUrl !== null) mirror(next, 'login_url', v.loginUrl);
    } else if (v.serviceUrl !== null || v.loginUrl !== null) {
      const urls = Array.isArray(ba.urls) ? (ba.urls as unknown[]) : [];
      // The site URL readers show: the login's first URL, else the flat key (a passkey-only record).
      const svc = v.serviceUrl ?? (str(urls[0]) || str(next.service_url));
      const login = v.loginUrl ?? str(urls[1]);
      if (login && !svc) {
        throw new RecordEditError('This login has no site URL yet, so a login URL has nowhere to go. ' +
          'Pass service_url together with login_url. Nothing was written.');
      }
      const all = [svc, login].filter((u) => u !== '').concat(urls.slice(2) as string[]);
      if (all.length > 0) ba.urls = all;
      else delete ba.urls;
      if (v.serviceUrl !== null) mirror(next, 'service_url', v.serviceUrl);
      if (v.loginUrl !== null) mirror(next, 'login_url', v.loginUrl);
    }
    if (v.username !== null) {
      if (carries('username')) setLoginMember(ba, 'username', v.username);
      mirror(next, 'username', v.username);
    }
    if (v.password !== null) {
      if (carries('password')) setLoginMember(ba, 'password', v.password);
      mirror(next, 'password', v.password);
    }
    // A login entry left holding nothing but its type goes; one that still holds anything
    // (a secondary URL, its id, provider extras) is kept, as iOS keeps it.
    const empty = Object.keys(ba).every((k) => k === 'type');
    if (at >= 0) {
      if (empty) creds.splice(at, 1);
      else creds[at] = ba;
    } else if (!empty) {
      creds.unshift(ba);
    }
  }
  if (v.notes !== null) {
    const notes = v.notes;
    mirror(next, 'notes', notes);
    const ci = firstIndex(creds, 'custom-fields');
    const hasNoteEntry = ci >= 0 && Array.isArray((creds[ci] as Obj).fields) &&
      ((creds[ci] as Obj).fields as unknown[]).some((f) => isObj(f) && f.designation === 'notes');
    if (!hasNoteEntry && 'notes' in next) {
      // The note lives in the flat key only (the mirror above): nothing to add.
    } else if (ci >= 0) {
      const cf = { ...(creds[ci] as Obj) };
      const fields = Array.isArray(cf.fields) ? [...(cf.fields as unknown[])] : [];
      const k = fields.findIndex((f) => isObj(f) && f.designation === 'notes');
      if (!notes) {
        if (k >= 0) fields.splice(k, 1);
      } else if (k >= 0) {
        fields[k] = { ...(fields[k] as Obj), value: notes };
      } else {
        fields.unshift(noteEntry(notes));
      }
      // A custom-fields credential this edit emptied goes, as Decoy's other writers omit it.
      if (fields.length === 0) creds.splice(ci, 1);
      else creds[ci] = { ...cf, fields };
    } else if (notes) {
      const ba = firstIndex(creds, 'basic-auth');
      creds.splice(ba >= 0 ? ba + 1 : 0, 0, { type: 'custom-fields', label: 'Fields', fields: [noteEntry(notes)] });
    }
  }
  if (v.category !== null) {
    const exts = Array.isArray(next.extensions) ? [...(next.extensions as unknown[])] : [];
    const k = exts.findIndex((e) => isObj(e) && e.name === CATEGORY_EXT);
    if (!v.category) {
      if (k >= 0) exts.splice(k, 1);
    } else if (k >= 0) {
      exts[k] = { ...(exts[k] as Obj), value: v.category };
    } else {
      exts.push({ name: CATEGORY_EXT, value: v.category });
    }
    if (exts.length > 0) next.extensions = exts;
    else delete next.extensions;
    mirror(next, 'category', v.category);
  }
  if (v.tags !== null) {
    if (v.tags.length > 0) next.tags = v.tags;
    else delete next.tags;
  }
}

function noteEntry(notes: string): Obj {
  return { fieldType: 'string', value: notes, label: 'Notes', designation: 'notes' };
}

/** Set a login member in the shape already stored (iOS setMember): an EditableField keeps its
 *  id/label/extras and changes only `value`; a bare string stays a bare string; a new member
 *  follows its sibling's shape, else the CXF EditableField shape. */
function setLoginMember(ba: Obj, key: 'username' | 'password', value: string): void {
  if (!value) {
    delete ba[key];
    return;
  }
  const cur = ba[key];
  if (isObj(cur)) ba[key] = { ...cur, value };
  else if (typeof cur === 'string') ba[key] = value;
  else if (typeof ba[key === 'username' ? 'password' : 'username'] === 'string') ba[key] = value;
  else ba[key] = { fieldType: key === 'password' ? 'concealed-string' : 'string', value, label: key === 'password' ? 'Password' : 'Username' };
}

/** The (kind, secret) an edit asks for, given the entry's current ones. An omitted kind keeps the
 *  current kind, except that revealing a secret-kind field (secret: false) gives it a plain kind
 *  (from its designation, else custom). An omitted secret keeps the current concealment when the
 *  kind is unchanged; a changed kind takes the new kind's (an explicitly concealed plain field
 *  stays concealed). A secret kind is always concealed (record-patch v4: concealment follows secret). */
function wantedKind(f: FieldSet, curKind: string, curSecret: boolean, explicitPlainSecret: boolean, designation: string): { kind: string; secret: boolean } {
  let kind = f.kind ?? curKind;
  if (f.kind === undefined && f.secret === false && kindIsSecret(curKind)) kind = kindForDesignation(designation) ?? 'custom';
  const implied = kind === curKind ? curSecret : kindIsSecret(kind) || explicitPlainSecret;
  return { kind, secret: (f.secret ?? implied) || kindIsSecret(kind) };
}

function v1Patch(entry: Obj, f: FieldSet): Obj {
  const out: Obj = { ...entry, value: f.value };
  const curKind = str(entry.kind) || 'custom';
  const curSecret = entry.secret === true || kindIsSecret(curKind);
  const want = wantedKind(f, curKind, curSecret, entry.secret === true && !kindIsSecret(curKind), '');
  if (want.kind !== curKind) out.kind = want.kind;
  if (want.secret !== curSecret) out.secret = want.secret;
  return out;
}

function v1New(f: FieldSet, genId: () => string): Obj {
  const kind = f.kind ?? 'custom';
  return { id: genId(), label: f.label.trim(), value: f.value, kind, secret: f.secret === true || kindIsSecret(kind) };
}

/** Patch a stored CXF field, changing only what differs (as the Decoy apps do). */
function cxfPatch(entry: Obj, f: FieldSet): Obj {
  const out: Obj = { ...entry, value: f.value };
  const ft = str(entry.fieldType);
  const designation = str(entry.designation);
  const curKind = ft ? cxfFieldKind(ft, designation) : 'custom';
  const curSecret = ft === 'concealed-string';
  const want = wantedKind(f, curKind, curSecret, false, designation);
  if (want.kind !== curKind) {
    // The kind changed, so its CXF type must too. An UNCHANGED kind keeps whatever the owner's
    // app stored, including fieldTypes and designations this ontology lacks.
    out.fieldType = cxfTypeFor(want.kind, want.secret);
    const dg = cxfDesignationForKind(want.kind);
    if (dg) out.designation = dg;
    else delete out.designation;
  } else if (want.secret !== curSecret) {
    // Concealment follows `secret`: concealing makes it concealed-string and keeps its designation;
    // revealing restores the kind's type.
    out.fieldType = cxfTypeFor(want.kind, want.secret);
  }
  return out;
}

/** A NEW CXF field (iOS freshCXFEntry): concealed when secret; designation from the kind. */
function cxfNew(f: FieldSet, genId: () => string): Obj {
  const kind = f.kind ?? 'custom';
  const out: Obj = { id: genId(), fieldType: cxfTypeFor(kind, f.secret === true || kindIsSecret(kind)), value: f.value, label: f.label.trim() };
  const dg = cxfDesignationForKind(kind);
  if (dg) out.designation = dg;
  return out;
}

function applyFieldEdits(
  next: Obj,
  creds: unknown[],
  cxf: boolean,
  sets: FieldSet[],
  removes: string[],
  genId: () => string,
  insertAfterLogin: (c: Obj) => void,
): void {
  const v1 = Array.isArray(next.customFields) ? [...(next.customFields as unknown[])] : null;
  const v1Matches = (label: string) => (v1 ?? []).filter((e) => isObj(e) && sameLabel(e.label, label)) as Obj[];

  const ci = firstIndex(creds, 'custom-fields');
  const cf = ci >= 0 ? { ...(creds[ci] as Obj) } : null;
  const fields = cf && Array.isArray(cf.fields) ? [...(cf.fields as unknown[])] : [];
  const visible = (e: unknown): e is Obj => isObj(e) && e.designation !== 'notes' && str(e.label) !== '' && memberValue(e.value).trim() !== '';
  const v1Visible = (v1 ?? []).some((e) => isObj(e) && str(e.label) !== '' && memberValue(e.value).trim() !== '');

  // A v1 record, or a CXF record whose readers show the v1 `customFields` list (the CXF
  // credential has no visible fields): patch that list in place, as iOS does. Nothing is
  // copied into a new CXF credential, so the list is never hidden or duplicated.
  if (!cxf || (!fields.some(visible) && v1Visible)) {
    const list = v1 ?? [];
    for (const label of removes) {
      const e = only(v1Matches(label), `the custom field "${label.trim()}"`);
      if (!e) throw new RecordEditError(`No custom field is labelled "${label.trim()}". Nothing was written.`);
      list.splice(list.indexOf(e), 1);
    }
    for (const f of sets) {
      const e = only((list.filter((x) => isObj(x) && sameLabel(x.label, f.label)) as Obj[]), `the custom field "${f.label.trim()}"`);
      if (e) list[list.indexOf(e)] = v1Patch(e, f);
      else list.push(v1New(f, genId));
    }
    setOrDeleteList(next, 'customFields', list);
    return;
  }

  const cxfMatches = (label: string) => fields.filter((e) => isObj(e) && e.designation !== 'notes' && sameLabel(e.label, label)) as Obj[];

  for (const label of removes) {
    const e = only(cxfMatches(label), `the custom field "${label.trim()}"`);
    const m = only(v1Matches(label), `the custom field "${label.trim()}"`);
    if (!e && !m) throw new RecordEditError(`No custom field is labelled "${label.trim()}". Nothing was written.`);
    if (e) fields.splice(fields.indexOf(e), 1);
    if (m && v1) v1.splice(v1.indexOf(m), 1);
  }
  for (const f of sets) {
    const e = only(cxfMatches(f.label), `the custom field "${f.label.trim()}"`);
    const m = only(v1Matches(f.label), `the custom field "${f.label.trim()}"`);
    if (e) {
      fields[fields.indexOf(e)] = cxfPatch(e, f);
      if (m && v1) v1[v1.indexOf(m)] = v1Patch(m, f);
    } else if (m && v1) {
      // Kept only in the v1 mirror: patch that entry in place and give the new CXF entry its
      // id, so the two stay twins (never a second mirror entry with the same label).
      const id = str(m.id) || genId();
      const patched: Obj = { ...v1Patch(m, f), id };
      v1[v1.indexOf(m)] = patched;
      fields.push(cxfFromLegacy({ id, label: patched.label, value: patched.value, kind: patched.kind, secret: patched.secret }));
    } else {
      const fresh = cxfNew(f, genId);
      fields.push(fresh);
      // Keep an existing legacy mirror in step (same id), as Decoy's other writers do.
      if (v1) v1.push({ ...v1New(f, genId), id: fresh.id });
    }
  }
  if (cf) {
    // A custom-fields credential this edit emptied goes, as Decoy's other writers omit it.
    if (fields.length === 0) creds.splice(ci, 1);
    else {
      cf.fields = fields;
      creds[ci] = cf;
    }
  } else if (fields.length > 0) {
    insertAfterLogin({ type: 'custom-fields', label: 'Fields', fields });
  }
  if (v1) setOrDeleteList(next, 'customFields', v1);
}

/** A list key an edit emptied goes, never left as [] (iOS removes it). */
function setOrDeleteList(o: Obj, key: string, list: unknown[]): void {
  if (list.length > 0) o[key] = list;
  else delete o[key];
}

/** A v1 custom field as the CXF entry Decoy's readers show (same id, label, value, kind). */
function cxfFromLegacy(e: Obj): Obj {
  const { label, value, kind, secret, ...rest } = e;
  const k = str(kind) || 'custom';
  const out: Obj = { ...rest, fieldType: cxfTypeFor(k, secret === true || kindIsSecret(k)), value, label };
  const dg = cxfDesignationForKind(k);
  if (dg) out.designation = dg;
  return out;
}

function structuredLabel(v: unknown): string {
  return str(v);
}

function applyStructuredEdits(
  next: Obj,
  creds: unknown[],
  cxf: boolean,
  sets: StructuredSet[],
  removes: StructuredRef[],
  genId: () => string,
): void {
  const v1 = Array.isArray(next.structured) ? [...(next.structured as unknown[])] : null;
  const same = (kind: string, label: string | undefined) => (e: unknown) =>
    isObj(e) && (cxf ? e.type === kind : e.kind === kind) && structuredLabel(e.label) === (label ?? '').trim();
  const v1Same = (kind: string, label: string | undefined) => (e: unknown) =>
    isObj(e) && e.kind === kind && structuredLabel(e.label) === (label ?? '').trim();
  const what = (kind: string, label?: string) => `the ${kind}${label ? ` "${label.trim()}"` : ''}`;

  const patchV1 = (list: unknown[], s: StructuredSet) => {
    const e = only(list.filter(v1Same(s.kind, s.label)) as Obj[], what(s.kind, s.label));
    const values: Record<string, unknown> = { ...(e && isObj(e.values) ? (e.values as Obj) : {}) };
    for (const [k, v] of Object.entries(s.values)) {
      if (v === '') delete values[k];
      else values[k] = v;
    }
    if (e) list[list.indexOf(e)] = { ...e, values };
    else list.push({ id: genId(), kind: s.kind, label: s.label?.trim() || null, values });
  };

  // A v1 record, or a CXF record whose readers show the v1 `structured` list (no CXF address
  // or card they surface): patch that list in place, as iOS does. Nothing is copied into new
  // CXF credentials, so the list is never hidden or duplicated.
  // Shown exactly as Decoy's web reader decides: a modelled type
  // with at least one member that has a designation AND a value. One with only empty members is
  // not shown, so readers show the v1 list.
  const shownCxf = creds.some((c) => isObj(c) && STRUCTURED_KINDS.has(str(c.type)) && Array.isArray(c.fields) &&
    (c.fields as unknown[]).some((m) => isObj(m) && str(m.designation) !== '' && readerValue(m.value) !== ''));
  if (!cxf || (!shownCxf && v1 !== null)) {
    const list = v1 ?? [];
    for (const r of removes) {
      const e = only(list.filter(v1Same(r.kind, r.label)), what(r.kind, r.label));
      if (!e) throw new RecordEditError(`No ${what(r.kind, r.label).slice(4)} is stored on this account. Nothing was written.`);
      list.splice(list.indexOf(e), 1);
    }
    for (const s of sets) patchV1(list, s);
    setOrDeleteList(next, 'structured', list);
    return;
  }

  for (const r of removes) {
    const c = only(creds.filter(same(r.kind, r.label)), what(r.kind, r.label));
    if (!c) throw new RecordEditError(`No ${what(r.kind, r.label).slice(4)} is stored on this account. Nothing was written.`);
    creds.splice(creds.indexOf(c), 1);
    const m = v1 ? only(v1.filter(v1Same(r.kind, r.label)), what(r.kind, r.label)) : undefined;
    if (m && v1) v1.splice(v1.indexOf(m), 1);
  }
  for (const s of sets) {
    const c = only(creds.filter(same(s.kind, s.label)), what(s.kind, s.label)) as Obj | undefined;
    const types = STRUCTURED_MEMBER_TYPES[s.kind] ?? {};
    let written: Obj;
    if (c) {
      const out: Obj = { ...c };
      const members = Array.isArray(c.fields) ? [...(c.fields as unknown[])] : [];
      for (const [key, value] of Object.entries(s.values)) {
        const i = members.findIndex((m) => isObj(m) && m.designation === key);
        if (value === '') {
          if (i >= 0) members.splice(i, 1);
        } else if (i >= 0) {
          members[i] = { ...(members[i] as Obj), value };
        } else {
          members.push({ fieldType: types[key] ?? 'string', value, label: key, designation: key });
        }
      }
      out.fields = members;
      creds[creds.indexOf(c)] = out;
      written = out;
    } else {
      const members = Object.entries(s.values)
        .filter(([, v]) => v !== '')
        .map(([key, value]) => ({ fieldType: types[key] ?? 'string', value, label: key, designation: key }));
      const cred: Obj = { type: s.kind, ...(s.label?.trim() ? { label: s.label.trim() } : {}), fields: members };
      creds.push(cred);
      written = cred;
    }
    if (v1) {
      // The v1 mirror follows: a twin is patched member by member; with no twin, the entry is
      // mirrored IN FULL from the credential just written (never only the members this edit named).
      if (v1.some(v1Same(s.kind, s.label))) patchV1(v1, s);
      else {
        const values: Record<string, string> = {};
        for (const m of Array.isArray(written.fields) ? (written.fields as unknown[]) : []) {
          if (isObj(m) && str(m.designation) !== '' && readerValue(m.value) !== '') values[str(m.designation)] = memberValue(m.value);
        }
        v1.push({ id: str(written.id) || genId(), kind: s.kind, label: s.label?.trim() || null, values });
      }
    }
  }
  if (v1) setOrDeleteList(next, 'structured', v1);
}
