/**
 * Keeps a connection's tokens out of anything handed to an agent or written to a log.
 *
 * The bridge relays a server's own words (an error message, a field in a result). If a server,
 * or a proxy in front of one, ever sends a token back in that text, it is cut out here, in every
 * form it could come back in: as it is, URL-encoded, base64 or base64url encoded, and any piece of
 * 16 or more characters of it (an echo that was cut short). Text that holds no such piece is
 * returned exactly as it was.
 *
 * Two parts of an access token say nothing about which token it is, and pieces that lie wholly
 * inside them are left alone: its first segment (the header every such token shares) and the
 * first 24 characters of its payload (the same claim name, and the first characters of its
 * value, in every token). Matching on those would mangle another token a user keeps. The whole
 * token, and every other piece of it, is still removed.
 */
const MIN_PIECE = 16;
export const REMOVED = '[token removed]';

/** The forms of one secret to look for. */
function forms(secret: string): string[] {
  const b64 = Buffer.from(secret, 'utf8').toString('base64');
  const out = new Set([secret, encodeURIComponent(secret), b64, b64.replace(/=+$/, ''), b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')]);
  return [...out].filter((f) => f.length >= MIN_PIECE);
}

/** How much of a JWT's payload segment is shared between tokens: it opens with the same claim
 *  name and the first characters of its value (`{"userId":"` and a hex digit or two), so a piece
 *  that lies wholly inside this many characters says nothing about WHICH token it came from. */
const SHARED_PAYLOAD_PREFIX = 24;

/** Where pieces may be taken from: the whole form, minus a JWT's shared header segment; and how
 *  many leading characters of that are shared with other tokens. */
function pieceSource(form: string, isRawJwt: boolean): { text: string; shared: number } {
  if (!isRawJwt) return { text: form, shared: 0 };
  return { text: form.slice(form.indexOf('.') + 1), shared: SHARED_PAYLOAD_PREFIX };
}

export function makeScrubber(secrets: () => Array<string | undefined | null>): (text: string) => string {
  let cacheKey = '';
  let cached: { whole: string[]; sources: string[]; grams: Map<string, Array<[number, number]>> } | null = null;
  const prepare = () => {
    const list = [...new Set(secrets().filter((s): s is string => typeof s === 'string' && s.length >= MIN_PIECE))];
    const key = list.join('\u0000');
    if (cached && key === cacheKey) return cached;
    const whole: string[] = [], sources: string[] = [];
    const grams = new Map<string, Array<[number, number]>>();
    for (const secret of list) {
      const isJwt = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(secret);
      for (const form of forms(secret)) {
        whole.push(form);
        const { text: src, shared } = pieceSource(form, isJwt && form === secret);
        if (src.length < MIN_PIECE) continue;
        const si = sources.push(src) - 1;
        // A window that ends inside the shared prefix is skipped; every other piece still counts.
        for (let i = Math.max(0, shared - MIN_PIECE + 1); i + MIN_PIECE <= src.length; i++) {
          const g = src.slice(i, i + MIN_PIECE);
          const at = grams.get(g);
          if (at) at.push([si, i]); else grams.set(g, [[si, i]]);
        }
      }
    }
    whole.sort((a, b) => b.length - a.length);
    cacheKey = key;
    return (cached = { whole, sources, grams });
  };

  return (text: string): string => {
    if (typeof text !== 'string' || text.length < MIN_PIECE) return text;
    const p = prepare();
    if (p.whole.length === 0) return text;
    // Whole forms first (so a JWT's header goes with it when the whole token is there).
    let out = text;
    for (const w of p.whole) if (out.includes(w)) out = out.split(w).join(REMOVED);
    // Then any piece of 16+ characters: extend each hit as far as it keeps matching.
    let result = '';
    let i = 0, copiedTo = 0;
    while (i + MIN_PIECE <= out.length) {
      const hits = p.grams.get(out.slice(i, i + MIN_PIECE));
      if (!hits) { i++; continue; }
      let best = 0;
      for (const [si, at] of hits) {
        const src = p.sources[si]!;
        let k = MIN_PIECE;
        while (i + k < out.length && at + k < src.length && out[i + k] === src[at + k]) k++;
        if (k > best) best = k;
      }
      result += out.slice(copiedTo, i) + REMOVED;
      i += best; copiedTo = i;
    }
    return copiedTo === 0 ? out : result + out.slice(copiedTo);
  };
}

// ── Card numbers ───────────────────────────────────────────────────────────────
//
// A card an agent saves passes through a tool call's arguments. What keeps its number and its
// security code out of everything but the sealed record is how the tools that save personal info
// are built: their errors, results and log lines are made of fixed strings and field names, and
// a server's free text is not relayed for them (src/index.ts, PERSONAL_WRITE_TOOLS). Nothing here
// looks for a security code: three or four digits cannot be told from any other number.
//
// Two checks back that up:
//   ownNumberScrubber  removes the digits of the one number a call carried from that call's
//                      error and result, however the digits are separated;
//   holdsCardNumber    says whether a card number is found in a text: a number with the length
//                      and first digits of a card network that passes the Luhn check. Short
//                      free text the bridge sends to the server in the clear (a `reason`, an
//                      approval's `description` and `metadata`, a label) is refused when one is.

export const CARD_NUMBER_REMOVED = '[card number removed]';

/** An error whose message the bridge built from fixed strings and field names: safe to hand to
 *  the agent as it is, on any tool. */
export class FixedRefusal extends Error {}

/** A digit in any script or width, as NFKC gives it (full-width, superscript, circled…). */
const DIGIT = /\p{Nd}/u;
const LETTER = /\p{L}/u;
const SPACE = /\p{White_Space}/u;
/** Characters that take no room on the line: format characters (zero-width space and joiners,
 *  soft hyphen, byte order mark, direction controls), combining marks, variation selectors and
 *  the blank Hangul fillers. They are read as if they were not there. */
const INVISIBLE = /[\p{Cf}\p{M}ᅟᅠㅤﾠ]/u;

/**
 * The card networks' published issuer ranges: for each network, the lengths its numbers have and
 * the ranges their first digits fall in ([how many leading digits, lowest, highest]).
 * Not the table in src/identity-kinds.ts (cardBrand): that one names the brand of a number already saved as a card, by the rule the Decoy apps share (Maestro at 12 to 19 digits); this one decides what is refused in text sent in the clear, so its limits are narrower on purpose.
 *
 * Maestro publishes 12 to 19 digits. Only its 16 to 19 are looked for: a number of 12 to 15
 * digits that begins 50 or 56 to 69 is, far more often than a card, a phone number with its
 * country code (+57, +60 to +66) or an id.
 */
export const CARD_NETWORKS: ReadonlyArray<{ name: string; lengths: readonly number[]; prefixes: ReadonlyArray<readonly [number, number, number]> }> = [
  { name: 'Visa', lengths: [13, 16, 19], prefixes: [[1, 4, 4]] },
  { name: 'Mastercard', lengths: [16], prefixes: [[2, 51, 55], [4, 2221, 2720]] },
  { name: 'American Express', lengths: [15], prefixes: [[2, 34, 34], [2, 37, 37]] },
  { name: 'Discover', lengths: [16, 17, 18, 19], prefixes: [[4, 6011, 6011], [3, 644, 649], [2, 65, 65]] },
  { name: 'JCB', lengths: [16, 17, 18, 19], prefixes: [[4, 3528, 3589]] },
  { name: 'Diners Club', lengths: [14, 15, 16, 17, 18, 19], prefixes: [[3, 300, 305], [2, 36, 36], [2, 38, 38], [2, 39, 39]] },
  { name: 'UnionPay', lengths: [16, 17, 18, 19], prefixes: [[2, 62, 62]] },
  { name: 'Maestro', lengths: [16, 17, 18, 19], prefixes: [[2, 50, 50], [2, 56, 69]] },
];
const MIN_CARD = Math.min(...CARD_NETWORKS.flatMap((n) => n.lengths));
const MAX_CARD = Math.max(...CARD_NETWORKS.flatMap((n) => n.lengths));
/** For each length, the network (its place in the table, plus one) of every four leading digits. */
const NETWORK_OF: Uint8Array[] = [];
for (let len = MIN_CARD; len <= MAX_CARD; len++) {
  const row = new Uint8Array(10_000);
  CARD_NETWORKS.forEach((network, at) => {
    if (!network.lengths.includes(len)) return;
    for (const [width, low, high] of network.prefixes) {
      const scale = 10 ** (4 - width);
      for (let first = low * scale; first < (high + 1) * scale; first++) if (!row[first]) row[first] = at + 1;
    }
  });
  NETWORK_OF[len] = row;
}

/** The network whose published lengths and ranges fit digits[from, from + length); null when none does. */
export function cardNetwork(digits: ArrayLike<number>, from: number, length: number): string | null {
  if (length < MIN_CARD || length > MAX_CARD || from < 0 || from + length > digits.length) return null;
  const at = NETWORK_OF[length]![digits[from]! * 1000 + digits[from + 1]! * 100 + digits[from + 2]! * 10 + digits[from + 3]!]!;
  return at ? CARD_NETWORKS[at - 1]!.name : null;
}

/** Whether digits[from, to) pass the Luhn check and are not one digit repeated. */
function cardLike(digits: ArrayLike<number>, from: number, to: number): boolean {
  let sum = 0, same = true;
  for (let i = to - 1, double = false; i >= from; i--, double = !double) {
    let n = digits[i]!;
    if (n !== digits[from]) same = false;
    if (double) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return !same && sum % 10 === 0;
}

/**
 * Whether one number holds a card number. `starts` are the places in `digits` where a group of
 * digits begins (the first digit, and each digit written after a separator) and `seps` names the
 * separator written before each group. A card number is one group or several groups in a row:
 * digits whose count and first digits are a network's, which pass the Luhn check and are not one
 * digit repeated. So a security code, an expiry or anything else written before or after it, with
 * a separator between, changes nothing.
 *
 * Several groups are read as one number when they are written the way a number is: with the same
 * separator between all of them (`4242 4242 4242 4242`, one digit per word, groups of any size),
 * or in groups of four digits or more whatever stands between them (`4242 4242.4242-4242`), of
 * which the first or the last, not both, may be shorter (`4222 2222-2222 2`). Other groups of one
 * to three digits with different separators between them are prices, dates and times
 * (`$1,299.00, $2,450.00`, `2026-10-11 14:30:55`): their digits are not read together.
 *
 * At most 19 groups are tried from each group.
 */
function holdsCardDigits(digits: number[], starts: number[], seps: number[]): boolean {
  const n = digits.length, groups = starts.length;
  for (let g = 0; g < groups; g++) {
    const from = starts[g]!;
    if (n - from < MIN_CARD) break;
    const first = digits[from]! * 1000 + digits[from + 1]! * 100 + digits[from + 2]! * 10 + digits[from + 3]!;
    // firstShort: the first group has fewer than four digits. innerShort: a group that is neither
    // the first nor the last so far has. With different separators, the groups read together are
    // of four or more, but for one short group at an end.
    let sameSeparator = true, firstShort = false, lastShort = false, innerShort = false;
    for (let last = g; last < groups; last++) {
      const to = last + 1 < groups ? starts[last + 1]! : n;
      const len = to - from;
      if (len > MAX_CARD) break;
      if (last > g + 1 && seps[last] !== seps[g + 1]) sameSeparator = false;
      if (lastShort && last > g + 1) innerShort = true;
      lastShort = to - starts[last]! < 4;
      if (last === g) firstShort = lastShort;
      if (!sameSeparator && (innerShort || (firstShort && lastShort))) { if (innerShort) break; continue; }
      if (len >= MIN_CARD && NETWORK_OF[len]![first] && cardLike(digits, from, to)) return true;
    }
  }
  return false;
}

/** The most separators that may stand between two digits of one number. */
const MAX_GAP = 24;
/** How many times a URL escape of a URL escape is read back. */
const MAX_UNESCAPES = 3;

const unescapeRun = (run: string): string => {
  try { return decodeURIComponent(run); }
  catch { return run.replace(/%([0-9A-Fa-f]{2})/g, (_m, hex: string) => { const code = parseInt(hex, 16); return code < 128 ? String.fromCharCode(code) : ' '; }); }
};
const entity = (_m: string, hex: string | undefined, dec: string | undefined): string => {
  const code = hex !== undefined ? parseInt(hex, 16) : parseInt(dec!, 10);
  return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : ' ';
};
/** The text as a reader would see it: URL escapes read back (up to three times over), HTML
 *  numeric character references read back, then NFKC. */
function asRead(text: string): string {
  let t = text;
  for (let pass = 0; pass < MAX_UNESCAPES && t.includes('%'); pass++) {
    const next = t.replace(/(?:%[0-9A-Fa-f]{2})+/g, unescapeRun);
    if (next === t) break;
    t = next;
  }
  if (t.includes('&#')) t = t.replace(/&#(?:[xX]([0-9A-Fa-f]{1,6})|([0-9]{1,7}));?/g, entity);
  return t.normalize('NFKC');
}

/**
 * True when a payment card number is found in `text`.
 *
 * How the text is read: URL escapes are read back (an escaped escape too, up to three times),
 * HTML numeric character references are read back, the text is NFKC-normalised, a decimal digit of
 * any script counts as its ASCII digit, and invisible characters are skipped.
 *
 * A number is a run of digits in which one digit and the next have nothing between them but
 * characters that are neither letters nor digits: spaces of any kind, line breaks, punctuation,
 * symbols. A stretch of white space counts as one separator however long it is, and at most 24
 * separators may stand between two digits: without that limit two unrelated numbers in a sentence,
 * joined by a long row of punctuation, would be read as one. A letter ends the number; letters
 * right before or after it change nothing.
 *
 * A card number is found in such a number when one of its groups of digits, or several in a row
 * that are written as one number (holdsCardDigits), have the length and the first digits of a card
 * network (CARD_NETWORKS), pass the Luhn check and are not one digit repeated.
 *
 * Not looked for: a number with letters or words between its digits, digits spelled as words, a
 * letter standing in for a digit, any other encoding (base64), a card number with other digits
 * written right before or after it with no separator, and one written with different separators
 * between its groups when two or more of them, or one that is neither first nor last, have fewer
 * than four digits.
 *
 * One pass over the text; each digit takes a fixed amount of work.
 */
export function holdsCardNumber(text: unknown): boolean {
  if (typeof text !== 'string' || text.length < MIN_CARD) return false;
  const read = asRead(text);
  const digits: number[] = [], starts: number[] = [], seps: number[] = [];
  // The separators seen, each given a number: a stretch of white space is one space.
  const separators = new Map<string, number>();
  let gap = 0, inSpace = false, between = '';
  const found = (): boolean => {
    const hit = digits.length >= MIN_CARD && holdsCardDigits(digits, starts, seps);
    digits.length = 0; starts.length = 0; seps.length = 0; gap = 0; inSpace = false; between = '';
    return hit;
  };
  for (let i = 0; i < read.length; i++) {
    let code = read.charCodeAt(i);
    let ch = '';
    if (code >= 128) {
      code = read.codePointAt(i)!;
      ch = String.fromCodePoint(code);
      if (code > 0xffff) i++;
    }
    const digit = code >= 48 && code <= 57 ? code - 48 : code >= 128 ? DIGIT_VALUES.get(code) ?? -1 : -1;
    if (digit >= 0) {
      if (digits.length === 0 || gap > 0) {
        let id = separators.get(between);
        if (id === undefined) separators.set(between, id = separators.size);
        starts.push(digits.length); seps.push(id);
      }
      digits.push(digit);
      gap = 0; inSpace = false; between = '';
      continue;
    }
    if (digits.length === 0) continue;
    if (code < 128) {
      if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) { if (found()) return true; continue; }
      if (code === 32 || (code >= 9 && code <= 13)) { if (!inSpace) { gap++; inSpace = true; between += ' '; } }
      else { gap++; inSpace = false; between += read[i]; }
    } else {
      if (INVISIBLE.test(ch)) continue;
      if (LETTER.test(ch)) { if (found()) return true; continue; }
      if (SPACE.test(ch)) { if (!inSpace) { gap++; inSpace = true; between += ' '; } }
      else { gap++; inSpace = false; between += ch; }
    }
    if (gap > MAX_GAP && found()) return true;
  }
  return found();
}

/** How deep a value's nesting is followed one value at a time; below that it is read as one text. */
const MAX_DEPTH = 8;

/**
 * Whether a JSON value holds a card number: in a string, in a number, in a key, or in the items
 * of one list or the values of one object read side by side (a number written as its groups).
 * Nesting is followed to a fixed depth; anything deeper is read as one text, as it would be sent.
 */
export function valueHoldsCardNumber(value: unknown, depth: number = MAX_DEPTH): boolean {
  if (typeof value === 'string') return holdsCardNumber(value);
  if (typeof value === 'number' || typeof value === 'bigint') return holdsCardNumber(String(value));
  if (!value || typeof value !== 'object') return false;
  if (depth <= 0) {
    try { return holdsCardNumber(JSON.stringify(value) ?? ''); } catch { return true; }
  }
  const items = Array.isArray(value) ? value : Object.values(value);
  const plain = items.filter((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'bigint');
  if (plain.length > 1 && holdsCardNumber(plain.join(' '))) return true;
  if (!Array.isArray(value)) for (const key of Object.keys(value)) if (holdsCardNumber(key)) return true;
  return items.some((v) => valueHoldsCardNumber(v, depth - 1));
}

/** The arguments a card number is looked for in, and the one sentence each is refused with.
 *  The sentence names the argument and nothing of its value. */
const CARD_REFUSALS = {
  reason: '`reason` looks like it contains a payment card number. It is sent as written and shown to the owner, so nothing was sent. Say it again without the number.',
  description: '`description` looks like it contains a payment card number. It is sent as written and shown to the owner, so nothing was sent. Say it again without the number.',
  metadata: '`metadata` looks like it contains a payment card number. It is sent as written with the approval request, so nothing was sent. Send it again without the number.',
  label: '`label` looks like it contains a payment card number. A label is stored as written, not encrypted, so nothing was sent. Send it again without the number.',
  agent_label: '`agent_label` looks like it contains a payment card number. A label is stored as written, not encrypted, so nothing was sent. Send it again without the number.',
} as const;
export type CardCheckedField = keyof typeof CARD_REFUSALS;

/** What a tool answers when an argument it would send in the clear holds a card number. */
export const cardNumberRefusal = (field: CardCheckedField): string => CARD_REFUSALS[field];

/** The most characters that may stand between two digits of the number being removed. */
const MAX_OWN_GAP = 4;

/**
 * A scrubber for one call that carried a card number: removes that number's digits from a text
 * wherever they appear in order, with up to four other characters between one digit and the
 * next (a URL escape counts as one), in any script or width. It matches the digit sequence of this one number and nothing
 * else, so a text that does not hold it is returned exactly as it was. null when the call
 * carried no number (fewer than 8 digits).
 */
export function ownNumberScrubber(number: unknown): ((text: string) => string) | null {
  if (typeof number !== 'string' && typeof number !== 'number') return null;
  const own = [...String(number).normalize('NFKC')].map(digitValue).join('');
  if (own.length < 8) return null;
  const clean = (norm: string): string | null => {
    // The digits of the text, and where each stands.
    let digits = '';
    const pos: number[] = [];
    let i = 0;
    for (const ch of norm) {
      const code = ch.codePointAt(0)!;
      if (code >= 48 && code <= 57) { digits += ch; pos.push(i); }
      else if (code >= 128 && DIGIT_VALUES.has(code)) { digits += digitValue(ch); pos.push(i); }
      i += ch.length;
    }
    if (digits.length < own.length) return null;
    const cuts: Array<[number, number]> = [];
    for (let k = digits.indexOf(own); k !== -1; k = digits.indexOf(own, k + 1)) {
      let close = true;
      for (let j = k; j < k + own.length - 1 && close; j++) close = pos[j + 1]! - pos[j]! - 1 <= MAX_OWN_GAP;
      if (!close) continue;
      const start = pos[k]!, end = pos[k + own.length - 1]!;
      const last = cuts[cuts.length - 1];
      if (last && start <= last[1]) last[1] = Math.max(last[1], end); else cuts.push([start, end]);
    }
    if (!cuts.length) return null;
    let out = '', from = 0;
    for (const [start, end] of cuts) {
      out += norm.slice(from, start) + CARD_NUMBER_REMOVED;
      from = end + String.fromCodePoint(norm.codePointAt(end)!).length;
    }
    return out + norm.slice(from);
  };
  return (text) => {
    if (typeof text !== 'string' || text.length < own.length) return text;
    const norm = text.normalize('NFKC');
    // As it is; then with each URL escape (%20) read as the one character it stands for.
    return clean(norm) ?? (/%[0-9A-Fa-f]{2}/.test(norm) ? clean(norm.replace(/%[0-9A-Fa-f]{2}/g, ' ')) : null) ?? text;
  };
}

/**
 * The value of every decimal digit (\p{Nd}) by code point, built once. Unicode gives each script's
 * digits as ten code points in a row, zero first, and some scripts' digits follow another's with
 * no gap: so each unbroken run of digits is read in tens from its first code point. A run that is
 * not whole tens is left out (none is, in any Unicode version to date).
 */
const DIGIT_VALUES: ReadonlyMap<number, number> = (() => {
  const values = new Map<number, number>();
  const run: number[] = [];
  const close = () => { if (run.length % 10 === 0) run.forEach((code, at) => values.set(code, at % 10)); run.length = 0; };
  for (let code = 0; code <= 0x10ffff; code++) {
    if (code >= 0xd800 && code <= 0xdfff) { close(); continue; }
    if (DIGIT.test(String.fromCodePoint(code))) run.push(code); else if (run.length) close();
  }
  close();
  return values;
})();

/** The value 0-9 of a decimal digit of any script, as an ASCII digit ("" for anything else). */
export function digitValue(ch: string): string {
  const value = DIGIT_VALUES.get(ch.codePointAt(0)!);
  return value === undefined ? '' : String(value);
}
