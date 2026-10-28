// The personal-info kinds the identity_* MCP tools speak, and the pure
// payload/merge rules for the generic kinds. Kept out of index.ts so
// the rules are unit-testable without the server.
import { FixedRefusal } from './scrub.js';

/** The original six — each lives in its own personal_* table. */
export const LEGACY_PERSONAL_TYPES = ['email', 'phone', 'card', 'address', 'name', 'birthday'] as const;

/** Generic kinds — all rows of the ONE personal_items table,
 *  discriminated by type. `identity` is the whole-person RECORD (a field map:
 *  name, birthday, address, phone, employer, linked email) that My Info edits
 *  and one-tap autofill reads; the scalar kinds are `{ value, label }` rows.
 *  `fold_marker` (vault bookkeeping) is deliberately absent — never a tool's
 *  business. */
export const ITEM_PERSONAL_TYPES = ['company', 'job_title', 'website', 'gender', 'department', 'custom', 'identity'] as const;

export const PERSONAL_TYPES = [...LEGACY_PERSONAL_TYPES, ...ITEM_PERSONAL_TYPES] as const;
export type PersonalType = (typeof PERSONAL_TYPES)[number];

export function isItemKind(t: string): boolean {
  return (ITEM_PERSONAL_TYPES as readonly string[]).includes(t);
}

/** The blob an item-kind write seals. Identity records store the provided
 *  field map verbatim (arrays like `custom` included, undefined dropped);
 *  scalar kinds normalise to `{ value, label? }` — the shape iOS and the
 *  extension already read. */
export function itemPayload(type: string, data: Record<string, unknown>): Record<string, unknown> {
  if (type === 'identity') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(data)) if (v !== undefined) out[k] = v;
    return out;
  }
  const label = typeof data.label === 'string' && data.label ? data.label : undefined;
  return { value: String(data.value ?? ''), ...(label && { label }) };
}

/** Agent edit semantics for an identity RECORD: overlay ONLY the provided
 *  fields on the stored record; a field set to null or '' is DELETED.
 *  Unmentioned fields — including keys this build has never heard of —
 *  survive verbatim. (UI editors own a fixed key set instead; an agent has
 *  no form, so explicit overlay is the honest contract. Same re-seal
 *  landmine as everywhere else, same close: never seal a record you didn't
 *  start from.) */
export function mergeIdentityAgentEdit(
  stored: Record<string, unknown> | null | undefined,
  provided: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(stored ?? {}) };
  for (const [k, v] of Object.entries(provided)) {
    if (v === null || v === '') delete out[k];
    else if (v !== undefined) out[k] = v;
  }
  return out;
}

// ── The classic six and the scalar kinds: one payload rule per kind ─────────────────────────────
//
// What each kind's sealed record holds. `required` + `optional` are the fields a caller may send
// (plus `label`, on every kind); the Decoy app reads the same keys. A card also holds `lastFour`
// and `cardType`, which are derived from its number here and never taken from the caller.

export type PersonalFieldKind = (typeof LEGACY_PERSONAL_TYPES)[number] | 'scalar';
export const PERSONAL_FIELDS: Record<PersonalFieldKind, { required: readonly string[]; optional: readonly string[] }> = {
  email: { required: ['email'], optional: [] },
  phone: { required: ['phone'], optional: [] },
  name: { required: ['name'], optional: ['first', 'middle', 'last'] },
  birthday: { required: ['date'], optional: [] },
  address: { required: ['street', 'city', 'state', 'zip'], optional: ['country'] },
  card: { required: ['number', 'cardholderName', 'expiration', 'cvv', 'zip'], optional: ['billsToIdentityId'] },
  scalar: { required: ['value'], optional: [] },
};

/** A `data` argument that doesn't fit its kind. The message is written for the calling agent,
 *  from fixed strings and field names: it never holds a value that was sent or stored. */
export class PersonalDataError extends FixedRefusal {}

const fieldKind = (type: string): PersonalFieldKind =>
  ((LEGACY_PERSONAL_TYPES as readonly string[]).includes(type) ? type : 'scalar') as PersonalFieldKind;
const blank = (v: unknown) => v === null || (typeof v === 'string' && v.trim() === '');
const needsOf = (type: string) => {
  const spec = PERSONAL_FIELDS[fieldKind(type)];
  return `it takes ${spec.required.join(', ')}${spec.optional.length ? ` (optional: ${spec.optional.join(', ')}, label)` : ' (optional: label)'}`;
};

// ── Cards ───────────────────────────────────────────────────────────────────────────────────────
//
// A saved card has a card number, name on card, expiry, security code and postcode. The rule is
// the shared one every Decoy surface follows (one shared set of test
// vectors): validateCard says which of the five fail, and
// cardRecordForSave builds the record a write seals. The record is the one the Decoy app reads
// (CardData): number (digits only), cardholderName, cvv, zip, expiration ("MM/YYYY"), label,
// lastFour, cardType (the app's brand names, from the number).

/** A required value is text; anything else (a number, null) is no value. */
const cardText = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** The digits of a card number written with spaces (U+0020) or hyphens; null when it is not
 *  text or anything else is in it (a tab, a line break, a letter, a digit that is not ASCII). */
export function cardDigits(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return /^[0-9 -]*$/.test(t) ? t.replace(/[ -]/g, '') : null;
}

/** The Luhn check over a string of ASCII digits; false for anything else. */
export function passesLuhn(digits: string): boolean {
  if (typeof digits !== 'string' || !/^[0-9]+$/.test(digits)) return false;
  let sum = 0;
  for (let i = digits.length - 1, double = false; i >= 0; i--, double = !double) {
    let n = digits.charCodeAt(i) - 48;
    if (double) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

/** A card number as its digits: 12 to 19 of them, passing the Luhn check, and not one digit
 *  repeated (twelve zeros pass the Luhn check and are no card number). */
const validCardDigits = (v: unknown): string | null => {
  const d = cardDigits(v);
  return d !== null && d.length >= 12 && d.length <= 19 && passesLuhn(d) && !/^(\d)\1+$/.test(d) ? d : null;
};

/** The names a stored card holds in `cardType`; a card of no network here stores "". */
export const CARD_BRANDS = ['Amex', 'Visa', 'Mastercard', 'Discover', 'JCB', 'Diners', 'UnionPay', 'Maestro'] as const;
export type CardBrand = (typeof CARD_BRANDS)[number];

/**
 * The networks' prefixes ([first, last] of the leading digits of that width) and lengths, in the
 * order they are tried. The first network whose prefix matches owns the number: Discover and
 * UnionPay sit inside Maestro's 56-69, so they come before it. A prefix belongs to its network
 * alone: with a number of digits that network does not issue there is no brand, and no later
 * network is tried.
 * Not the table in src/scrub.ts (holdsCardNumber): that one decides what is refused in text sent in the clear, and looks for Maestro at 16 to 19 digits only so that ordinary ids are not refused; this one names the brand of a number already saved as a card.
 */
const CARD_BRAND_NETWORKS: readonly { brand: CardBrand; prefixes: readonly [number, number][]; lengths: readonly [number, number][] }[] = [
  { brand: 'Amex', prefixes: [[34, 34], [37, 37]], lengths: [[15, 15]] },
  { brand: 'JCB', prefixes: [[3528, 3589]], lengths: [[16, 19]] },
  { brand: 'Diners', prefixes: [[300, 305], [36, 36], [38, 39]], lengths: [[14, 19]] },
  { brand: 'Visa', prefixes: [[4, 4]], lengths: [[13, 13], [16, 16], [19, 19]] },
  { brand: 'Mastercard', prefixes: [[51, 55], [2221, 2720]], lengths: [[16, 16]] },
  { brand: 'Discover', prefixes: [[6011, 6011], [644, 649], [65, 65]], lengths: [[16, 19]] },
  { brand: 'UnionPay', prefixes: [[62, 62]], lengths: [[16, 19]] },
  { brand: 'Maestro', prefixes: [[50, 50], [56, 69]], lengths: [[12, 19]] },
];

/** The brand of a card number, from its leading digits and its length; null for a number in no
 *  network's range and for anything that is not 12 to 19 digits. */
export function cardBrand(number: string): CardBrand | null {
  const d = String(number).replace(/[^0-9]/g, '');
  if (d.length < 12 || d.length > 19) return null;
  for (const network of CARD_BRAND_NETWORKS) {
    const owns = network.prefixes.some(([first, last]) => {
      const lead = Number(d.slice(0, String(first).length));
      return lead >= first && lead <= last;
    });
    if (!owns) continue;
    return network.lengths.some(([min, max]) => d.length >= min && d.length <= max) ? network.brand : null;
  }
  return null;
}

const CARD_BRAND_SPELLINGS: Readonly<Record<string, CardBrand>> = { 'american express': 'Amex', 'diners club': 'Diners', 'china unionpay': 'UnionPay' };
/** A brand name as one of CARD_BRANDS (letters compare without case), or "" for anything else.
 *  The rule for a card that holds no number; a card the bridge writes always has one, and its
 *  number decides its brand. */
export function normalizeCardBrand(raw: unknown): CardBrand | '' {
  if (typeof raw !== 'string') return '';
  const t = raw.trim().toLowerCase();
  return CARD_BRANDS.find((b) => b.toLowerCase() === t) ?? CARD_BRAND_SPELLINGS[t] ?? '';
}

function expiryFrom(month: string, year: string): string | null {
  const mm = Number(month);
  if (mm < 1 || mm > 12) return null;
  const yyyy = year.length === 2 ? `20${year}` : year;
  if (Number(yyyy) < 2000 || Number(yyyy) > 2099) return null;
  return `${String(mm).padStart(2, '0')}/${yyyy}`;
}

/** An expiry as the one stored shape, "MM/YYYY", from "MM/YYYY" or "MM/YY" (20YY); null for
 *  anything else. Month 01-12, year 2000-2099; a past date is an expiry. */
export function normalizeExpiry(v: unknown): string | null {
  const m = /^([0-9]{2})\/([0-9]{2}|[0-9]{4})$/.exec(cardText(v));
  return m ? expiryFrom(m[1]!, m[2]!) : null;
}

/** The forms an expiry may be SENT in: also M/YY, a hyphen or spaces around the separator, MMYY,
 *  MMYYYY and YYYY-MM. What is stored is the result, "MM/YYYY"; null when it is none of them. */
export function normalizeExpiryLenient(v: unknown): string | null {
  const t = cardText(v);
  let m = /^([0-9]{4})\s*-\s*([0-9]{1,2})$/.exec(t);
  if (m) return expiryFrom(m[2]!, m[1]!);
  m = /^([0-9]{1,2})\s*[/-]\s*([0-9]{2}|[0-9]{4})$/.exec(t) ?? /^([0-9]{2})([0-9]{2}|[0-9]{4})$/.exec(t);
  return m ? expiryFrom(m[1]!, m[2]!) : null;
}

const CARD_REQUIRED = PERSONAL_FIELDS.card.required;
export type CardField = 'number' | 'cardholderName' | 'expiration' | 'cvv' | 'zip';

/**
 * The required fields of a card record that are empty or not valid, in order; none when it is
 * a card. Each value is text, read without the spaces around it: a number of 12 to 19 digits
 * (not all the same) that passes the Luhn check, a name, an expiry as MM/YYYY or MM/YY, a
 * security code of 3 or 4 digits, a postcode.
 */
export function validateCard(record: Record<string, unknown> | null | undefined): CardField[] {
  const v = record ?? {};
  const failing: CardField[] = [];
  if (validCardDigits(v.number) === null) failing.push('number');
  if (!cardText(v.cardholderName)) failing.push('cardholderName');
  if (normalizeExpiry(v.expiration) === null) failing.push('expiration');
  if (!/^[0-9]{3,4}$/.test(cardText(v.cvv))) failing.push('cvv');
  if (!cardText(v.zip)) failing.push('zip');
  return failing;
}

/** validateCard's fields, split into the ones with no value and the ones whose value is not valid. Field names only. */
export function cardProblems(record: Record<string, unknown>): { missing: string[]; invalid: string[] } {
  const failing = validateCard(record);
  const missing = failing.filter((k) => record[k] === undefined || blank(record[k]));
  return { missing, invalid: failing.filter((k) => !missing.includes(k)) };
}

/**
 * Refuse a record that is not a card, naming the fields (never a value). `fromStored`: the
 * fields of an edit that were not sent, so what is wrong with them is what the saved card holds;
 * the refusal then says which fields to send to be able to edit that card.
 */
function requireCard(record: Record<string, unknown>, sent: string, fromStored: readonly string[] = []): void {
  const { missing, invalid } = cardProblems(record);
  if (!missing.length && !invalid.length) return;
  const what = [missing.length ? `missing: ${missing.join(', ')}` : '', invalid.length ? `invalid: ${invalid.join(', ')}` : ''].filter(Boolean).join('; ');
  const stored = [...missing, ...invalid].filter((k) => fromStored.includes(k));
  throw new PersonalDataError(`data does not match type "card": ${needsOf('card')} (${what}). ` +
    'number is a card number of 12 to 19 digits, expiration a month and year (MM/YYYY), cvv 3 or 4 digits. ' +
    (stored.length ? `The saved card has no valid ${stored.join(', ')}: to edit this card, send ${stored.join(', ')} in the same call. ` : '') + sent);
}

/** The keys the card rule names: the five required fields, the label, and the two it works out. */
const CARD_RULE_KEYS: readonly string[] = [...CARD_REQUIRED, 'label', 'lastFour', 'cardType'];

/**
 * The record a card write seals, or a PersonalDataError when validateCard names any field.
 * Every key of `record` is kept: text is stored without the spaces around it and empty text is
 * dropped; the number is stored as digits; lastFour and cardType are worked out from the number
 * (never taken from `record`); the expiry is stored as MM/YYYY; a card with no label is "Card".
 *
 * `asStored`: on an edit, the keys of the stored card that the rule does not name and the edit
 * did not send. Each stays exactly as it is in `record`: the same value of the same type, blank,
 * null and untrimmed text included. The shared vectors ask nothing else of such a key.
 */
export function cardRecordForSave(record: Record<string, unknown> | null | undefined, sent = 'Nothing was sent.', fromStored: readonly string[] = [], asStored: readonly string[] = []): Record<string, unknown> {
  requireCard(record ?? {}, sent, fromStored);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record ?? {})) {
    if (asStored.includes(k)) out[k] = v;
    else if (typeof v === 'string') { const t = v.trim(); if (t) out[k] = t; }
    else if (v !== null && v !== undefined) out[k] = v;
  }
  const number = validCardDigits(out.number)!;
  out.number = number;
  out.lastFour = number.slice(-4);
  out.cardType = cardBrand(number) ?? '';
  out.expiration = normalizeExpiry(out.expiration)!;
  if (typeof out.label !== 'string') out.label = 'Card';
  return out;
}

/**
 * A stored card (or none) with what was sent laid over it. A sent expiry is read in any of the
 * forms normalizeExpiryLenient takes; a stored one is left as it is, for validateCard to judge.
 * A required field sent blank changes nothing; null or "" removes any other key. lastFour and
 * cardType are not taken from what was sent.
 */
function cardWithSent(stored: Record<string, unknown> | null | undefined, data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(stored ?? {}) };
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined || k === 'lastFour' || k === 'cardType') continue;
    if ((CARD_REQUIRED as readonly string[]).includes(k)) {
      if (!blank(v)) out[k] = k === 'expiration' ? normalizeExpiryLenient(v) ?? v : v;
    } else if (k === 'label') out[k] = v;
    else if (blank(v)) delete out[k];
    else out[k] = v;
  }
  return out;
}

/**
 * Check `data` for a create (every required field present and non-blank) or an update (only the
 * fields to change; null or "" removes an optional one). Values must be text. Fields that belong
 * to another kind are ignored, never stored. Not for the `identity` RECORD, which is a free map.
 * A card is also checked as a whole: on a create here, on an update once it is merged
 * (mergePersonalPayload), since the stored card supplies the fields that were not sent.
 */
export function checkPersonalData(type: string, data: Record<string, unknown>, mode: 'create' | 'update'): void {
  const kind = fieldKind(type);
  const spec = PERSONAL_FIELDS[kind];
  const needs = needsOf(type);
  const sent = mode === 'create' ? 'Nothing was sent.' : 'Nothing was written.';
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new PersonalDataError(`data does not match type "${type}": ${needs}. ${sent}`);
  }
  const known = [...spec.required, ...spec.optional, 'label'];
  // A card's values are judged by validateCard, which names a field that is not text as invalid.
  for (const k of kind === 'card' ? [] : known) {
    const v = data[k];
    if (v === undefined || v === null) continue;
    if (typeof v !== 'string') throw new PersonalDataError(`data does not match type "${type}": ${k} must be text. ${sent}`);
  }
  if (mode === 'create') {
    if (kind === 'card') { requireCard(cardWithSent(null, data), sent); return; }
    const missing = spec.required.filter((k) => data[k] === undefined || blank(data[k]));
    if (missing.length) {
      throw new PersonalDataError(`data does not match type "${type}": ${needs} (missing or invalid: ${missing.join(', ')}). ${sent}`);
    }
  } else {
    // A card keeps every key it is sent, so any key is a field of it.
    if (!(kind === 'card' ? Object.keys(data) : known).some((k) => data[k] !== undefined)) {
      throw new PersonalDataError(`data names no field of type "${type}": ${needs}. Send only the fields to change. ${sent}`);
    }
    const cleared = spec.required.filter((k) => data[k] !== undefined && blank(data[k]));
    if (cleared.length) {
      throw new PersonalDataError(`${cleared.join(', ')} can't be removed from a ${type} entry: ${cleared.length === 1 ? 'it is' : 'they are'} required. ` +
        `Send a new value, or delete the entry. ${sent}`);
    }
  }
}

/** The record a new entry seals: every field the kind defines that was sent, and `label`. */
export function newPersonalPayload(type: string, data: Record<string, unknown>): Record<string, unknown> {
  return mergePersonalPayload(type, null, data);
}

/**
 * The record an update seals: the stored record with only the sent fields changed. Every other
 * key survives as stored, including keys this build has never heard of. null or "" removes an
 * optional field; a blank label is stored as "" (the app requires the key).
 *
 * A card: what is sent is laid over the stored card and the result is built by cardRecordForSave,
 * which throws (and nothing is written) unless it is a card. So an edit can complete a stored
 * card that lacks fields and can never leave one incomplete; a key the rule does not name is
 * kept: one that is sent as cardRecordForSave stores it, one that is stored and not sent exactly
 * as it is stored; lastFour and cardType are worked out from the number on every write;
 * the expiry is stored as MM/YYYY; a blank label is stored as "Card".
 */
export function mergePersonalPayload(type: string, stored: Record<string, unknown> | null | undefined, data: Record<string, unknown>): Record<string, unknown> {
  const kind = fieldKind(type);
  const spec = PERSONAL_FIELDS[kind];
  const out: Record<string, unknown> = { ...(stored ?? {}) };
  const set = (k: string, v: unknown, optional: boolean) => {
    if (v === undefined) return;
    if (blank(v)) { if (optional) delete out[k]; return; }
    out[k] = v;
  };
  if (kind === 'card') {
    return cardRecordForSave(cardWithSent(stored, data), stored ? 'Nothing was written.' : 'Nothing was sent.',
      stored ? CARD_REQUIRED.filter((k) => data[k] === undefined || blank(data[k])) : [],
      stored ? Object.keys(stored).filter((k) => !CARD_RULE_KEYS.includes(k) && data[k] === undefined) : []);
  } else {
    for (const k of spec.required) set(k, data[k], false);
    for (const k of spec.optional) set(k, data[k], true);
  }
  if (data.label !== undefined) out.label = blank(data.label) ? '' : data.label;
  // Created here: the classic kinds always carry a label key; a scalar kind only when it has one.
  if (!stored && out.label === undefined && kind !== 'scalar') out.label = '';
  if (!stored && kind === 'scalar' && out.label === '') delete out.label;
  return out;
}
