// What this connection may do, in plain words: the first lines of my_permissions.
//
// GET /policies starts with capability scopes, which have no entry for memories at all: an agent
// reading the top of it decided it had no memory access when it had all of it. my_permissions
// therefore leads with `summary` (a few plain lines, memories first) and `access` (the same answer
// as data), then the detail.
//
// `access` is the server's own object when it sends one: it is
// authoritative and is passed on untouched. For a server that does not send it yet, this file
// computes the SAME object (same fields, same words for how far something reaches) from the
// detail, marked `computed_by: "bridge"`, by the rules the server enforces:
//   - only policies that are approved and not past their end count (loadActivePerms)
//   - a level row is what it expands to (lib/policies.ts expandLevelRows): an account level is the
//     account and its own inbox; a message level counts on a Personal Alias row only; any other
//     level row expands to nothing
//   - a row with no level and NO `actions` covers every action of its kind (coversAction: NULL is
//     the wildcard, and the endpoint leaves a NULL out); creating is never one of them
//   - each plain verb has its own reach (the server's answer to "which accounts can I edit?"):
//     `none` unless the token holds the scope that verb needs (ACTION_SCOPE, legacy scope names
//     included), `all` only when a row with no selector covers it, `some` when only rows that
//     name something do, `created_by_you` when only what the connection made itself does
//   - memories: all / some by the memory rows and the account rows that bring an account's
//     memories (lib/memory-access.ts memorySelectors); saving is the `create` action alone
//   - Create accounts is the account.write and decoy.write scopes together
// What this file cannot know it does not guess: an unknown kind, level or action goes under
// `not_summarised`; a row limited by a field it does not know is `some`, never `all`; counts it
// cannot make are null. It assumes the server enforces grants (its normal mode).
//
// The plain lines are rendered from the `access` object alone, whichever side made it.
//
// Pure functions: no network, no clock but the one passed in.

import { createHash } from 'node:crypto';

type Row = Record<string, unknown>;
type Kind = 'account' | 'message' | 'personal' | 'memory';
export type Reach = 'all' | 'some' | 'created_by_you' | 'none';
export type MailReach = Reach | 'all_account_inboxes';
export type PersonalReach = 'all' | 'some' | 'none';
export type MemoryReach = 'all' | 'some' | 'own_only' | 'none';

const isObj = (v: unknown): v is Row => !!v && typeof v === 'object' && !Array.isArray(v);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** What each level expands to (lib/policies.ts LEVEL_ACTIONS). */
const LEVEL_ACTIONS: Record<'account' | 'message' | 'memory', Record<string, string[]>> = {
  account: { read: ['read_metadata', 'unlock_credential'], read_write: ['read_metadata', 'unlock_credential', 'write'], full: ['read_metadata', 'unlock_credential', 'write', 'destroy'] },
  message: { read: ['read_metadata', 'unlock_content'], read_write: ['read_metadata', 'unlock_content', 'write'], full: ['read_metadata', 'unlock_content', 'write', 'destroy'] },
  memory: { read: ['read_metadata'], read_write: ['read_metadata', 'write'], full: ['read_metadata', 'write', 'destroy'] },
};
/** Every action of a kind that this summary reports: what a row with no `actions` covers. */
const KNOWN_ACTIONS: Record<Kind, string[]> = {
  account: ['read_metadata', 'unlock_credential', 'write', 'destroy'],
  message: ['read_metadata', 'unlock_content', 'write', 'destroy'],
  personal: ['read_metadata', 'unlock_content', 'write', 'destroy'],
  memory: ['read_metadata', 'write', 'destroy'],
};
/** Actions that exist but have no line here (passkey sign-in is strict and separate; creating is its own line). */
const UNREPORTED = new Set(['unlock_passkey_assert', 'create', 'read_content']);
/** The plain verbs of each kind and the action each is at the gate (lib/access-summary.ts). */
const ACCOUNT_VERBS = { read: 'read_metadata', reveal_password: 'unlock_credential', write: 'write', delete: 'destroy' } as const;
const MAIL_VERBS = { list: 'read_metadata', read: 'unlock_content', send: 'write', delete: 'destroy' } as const;
// Reading personal info is one ability: an entry is read, or there is no access to it.
const PERSONAL_VERBS = { read: 'unlock_content', write: 'write', delete: 'destroy' } as const;
/** The scope every endpoint for (kind, action) checks first (lib/grant-request-scopes.ts ACTION_SCOPE). */
const ACTION_SCOPE: Record<string, string> = {
  'account:read_metadata': 'account.read', 'account:unlock_credential': 'account.unlock', 'account:write': 'account.write', 'account:destroy': 'account.write',
  'message:read_metadata': 'message.read', 'message:unlock_content': 'message.unlock', 'message:write': 'message.write', 'message:destroy': 'message.write',
  'personal:read_metadata': 'personal.read', 'personal:unlock_content': 'personal.unlock', 'personal:write': 'personal.write', 'personal:destroy': 'personal.write',
};
/** Older scope names and the one capability each is (lib/agent-auth.ts SCOPE_EXPANSIONS). */
const LEGACY_SCOPE: Record<string, string> = {
  'decoys:read': 'decoy.read', 'decoys:write': 'decoy.write', 'inbox:read': 'message.read', 'inbox:write': 'message.write', 'inbox:content': 'message.unlock',
  'forwarding:read': 'forwarding.read', 'forwarding:write': 'forwarding.write', 'alerts:read': 'alert.read', 'alerts:write': 'alert.write',
  'accounts:read': 'account.read', 'accounts:write': 'account.write', 'profile:read': 'profile.read', 'profile:write': 'personal.write',
};

/** Fields a row may carry. Any other field with a value limits the row in a way this code does not know. */
const KNOWN_FIELDS = new Set(['type', 'kind', 'level', 'actions', 'datatypes', 'about', 'account_id', 'decoy_id', 'personal_id', 'domain',
  'created_by_self', 'user_choice', 'account_inboxes', 'namespace_id', 'personal_aliases', 'content', 'implicit']);
const ALL_SELECTORS = ['account_id', 'decoy_id', 'personal_id', 'domain', 'account_inboxes', 'namespace_id', 'personal_aliases', 'about', 'datatypes'];
/** The selectors each kind is read by here. Another one on a row of that kind limits it. */
const SELECTORS_READ: Record<Kind, string[]> = {
  account: ['account_id', 'domain', 'datatypes'],
  message: ['decoy_id', 'account_inboxes', 'namespace_id', 'personal_aliases'],
  personal: ['personal_id', 'datatypes'],
  memory: ['datatypes', 'about'],
};

/** One row's worth of access: how far it reaches (`keys` name what, for `some`) and which actions. */
interface Grant { scope: 'all' | 'some' | 'own'; keys: string[]; actions: Set<string> }

export interface AccessSummary {
  /** One sentence, as the server words it. */
  summary: string;
  accounts: { allowed: boolean; which: Reach; count: number | null; can: Record<keyof typeof ACCOUNT_VERBS, Reach> };
  /** POST /accounts: Create accounts and the right to change accounts. */
  create_accounts: { allowed: boolean | 'unknown' };
  /** POST /decoys (a new address): Create accounts alone. */
  create_addresses: { allowed: boolean | 'unknown' };
  mail: { allowed: boolean; which: MailReach; count: number | null; personal_alias: boolean; can: Record<keyof typeof MAIL_VERBS, MailReach> };
  personal_info: { allowed: boolean; which: PersonalReach; can: Record<keyof typeof PERSONAL_VERBS, PersonalReach> };
  /** `by` names what reading reaches when it is `some`. */
  memories: { save: boolean; read: MemoryReach; write: MemoryReach; delete: MemoryReach; by: { categories: string[]; topics: number; accounts: number | 'all' } };
  ends_at: string | null;
  can_request_more: true;
  /** Only on a summary this bridge computed. */
  computed_by: 'bridge';
  not_counted?: string[];
  not_summarised?: string[];
}

/** Policies that count, with why the others do not. */
function countedPolicies(resp: Row, now: Date): { counted: Array<{ rows: Row[]; ends: string | null }>; notCounted: string[] } {
  const counted: Array<{ rows: Row[]; ends: string | null }> = [];
  const skipped = { status: 0, expired: 0, unreadable: 0 };
  for (const p of Array.isArray(resp.policies) ? resp.policies : []) {
    if (!isObj(p)) { skipped.unreadable++; continue; }
    if (p.status !== undefined && p.status !== 'approved') { skipped.status++; continue; }
    let ends: string | null = null;
    if (p.expires_at !== undefined && p.expires_at !== null) {
      const t = typeof p.expires_at === 'string' || typeof p.expires_at === 'number' ? new Date(p.expires_at).getTime() : NaN;
      if (Number.isNaN(t)) { skipped.unreadable++; continue; }
      if (t <= now.getTime()) { skipped.expired++; continue; }
      ends = new Date(t).toISOString();
    }
    if (!Array.isArray(p.permissions)) { skipped.unreadable++; continue; }
    counted.push({ rows: p.permissions.filter(isObj), ends });
  }
  const notCounted = [
    skipped.status ? `${skipped.status} not approved` : '', skipped.expired ? `${skipped.expired} ended` : '',
    skipped.unreadable ? `${skipped.unreadable} this bridge could not read` : '',
  ].filter(Boolean);
  return { counted, notCounted };
}

/**
 * Whether a GET /policies answer gives this connection every secret kind of one account: a
 * counted account row that allows revealing secrets, is not limited to some kinds, and names this
 * account or no account at all. `accountId` null = the account is known only by its site, so only
 * a row on every account counts. What the connection created itself is not counted: the answer
 * does not say which accounts those are. Anything this code cannot read counts as no.
 */
export function holdsWholeAccount(response: unknown, accountId: string | null, now: Date = new Date()): boolean {
  if (!isObj(response)) return false;
  const set = (v: unknown) => v !== null && v !== undefined && v !== false && !(Array.isArray(v) && v.length === 0);
  const id = accountId?.toLowerCase() ?? null;
  return countedPolicies(response, now).counted.some(p => p.rows.some((row) => {
    if (row.kind !== 'account' || row.user_choice || row.created_by_self === true || row.implicit === true) return false;
    if (Object.keys(row).some(k => set(row[k]) && (!KNOWN_FIELDS.has(k) || (ALL_SELECTORS.includes(k) && !SELECTORS_READ.account.includes(k))))) return false;
    const level = row.level !== undefined && row.level !== null;
    if (level ? !(typeof row.level === 'string' && LEVEL_ACTIONS.account[row.level]) : !(row.actions === undefined || row.actions === null || strings(row.actions).includes('unlock_credential'))) return false;
    // A row that names kinds is access to those kinds only, with a level or without one.
    if (set(row.datatypes)) return false;
    if (typeof row.account_id === 'string') return id !== null && row.account_id.toLowerCase() === id;
    return !set(row.account_id) && !set(row.domain);
  }));
}

const ORDER = ['none', 'created_by_you', 'some', 'all_account_inboxes', 'all'];
/** The widest reach among the verbs, and the first verb that has it. */
function widest<V extends string, R extends string>(can: Record<V, R>): { which: R; verb: V } {
  let verb = Object.keys(can)[0] as V;
  for (const v of Object.keys(can) as V[]) if (ORDER.indexOf(can[v]) > ORDER.indexOf(can[verb])) verb = v;
  return { which: can[verb], verb };
}
/** The narrower of two reaches of personal info. */
const narrower = (a: PersonalReach, b: PersonalReach): PersonalReach => (ORDER.indexOf(a) <= ORDER.indexOf(b) ? a : b);
const isReach = (v: unknown): v is PersonalReach => v === 'all' || v === 'some' || v === 'none';
const VERB_WORDS: Record<string, string> = { read: 'read', reveal_password: 'reveal passwords', write: 'write', delete: 'delete', list: 'list', send: 'send' };
const joinWith = (w: string[], last: string) => (w.length <= 1 ? w.join('') : `${w.slice(0, -1).join(', ')} ${last} ${w[w.length - 1]}`);
const joinAnd = (w: string[]) => joinWith(w, 'and');

// One part of the sentence, worded as the server words it: one clause per group of abilities, each
// with its own reach and its own count.
const describe = (can: Record<string, string>, counts: Record<string, number | null>, noun: { one: string; many: string; prep: string }) => {
  const verbs = Object.keys(can);
  if (verbs.every(v => can[v] === 'none')) return 'none';
  const where = (v: string) => {
    const n = counts[v] ?? null;
    switch (can[v]) {
      case 'all': return `${noun.prep} all ${noun.many}`;
      case 'all_account_inboxes': return `${noun.prep} every account inbox`;
      case 'created_by_you': return `only ${noun.prep} ${noun.many} you create`;
      default: return `${noun.prep} ${n === null ? `some ${noun.many}` : plural(n, noun.one, noun.many)}`;
    }
  };
  const clauses: { text: string; verbs: string[] }[] = [];
  for (const v of verbs.filter(x => can[x] !== 'none')) {
    const text = where(v), same = clauses.find(c => c.text === text);
    if (same) same.verbs.push(v); else clauses.push({ text, verbs: [v] });
  }
  const no = verbs.filter(v => can[v] === 'none').map(v => VERB_WORDS[v] ?? v);
  return [...clauses.map(c => `${joinAnd(c.verbs.map(v => VERB_WORDS[v] ?? v))} ${c.text}`), ...(no.length ? [`cannot ${joinWith(no, 'or')}`] : [])].join('; ');
};
const PERSONAL_NOUN = { one: 'item', many: 'items', prep: 'on' };
/**
 * Personal info in words. Reading it is `Read` or `No access`; `Read (on some entries)` when the
 * grants name entries one by one. What the connection may add, edit or delete follows as its own
 * sentence, so a connection that can write and not read reads "No access. Can add and edit
 * entries; cannot delete".
 */
const personalWords = (can: Record<string, string>): string => {
  const read = can.read === 'all' ? 'Read' : can.read === 'some' ? 'Read (on some entries)' : 'No access';
  const w = can.write === 'all' || can.write === 'some' ? can.write : 'none', d = can.delete === 'all' || can.delete === 'some' ? can.delete : 'none';
  const entries = (r: string) => (r === 'some' ? 'some entries' : 'entries');
  if (w === 'none' && d === 'none') return read === 'No access' ? read : `${read}. Cannot add, edit or delete entries`;
  const rest = w !== 'none' && d !== 'none'
    ? (w === d ? `Can add, edit and delete ${entries(w)}` : `Can add and edit ${entries(w)}; can delete ${entries(d)}`)
    : w !== 'none' ? `Can add and edit ${entries(w)}; cannot delete` : `Can delete ${entries(d)}; cannot add or edit`;
  return `${read}. ${rest}`;
};
/** How memories are worded from save / read / write / delete. */
const memoryWords = (save: boolean, reach: Record<'read' | 'write' | 'delete', MemoryReach>): string => {
  const memWords: Record<MemoryReach, string> = { all: 'all', some: 'some', own_only: 'your own', none: '' };
  const memVerbs = ['read', 'write', 'delete'] as const;
  const groups = (['all', 'some', 'own_only'] as MemoryReach[])
    .map(r => ({ r, verbs: memVerbs.filter(v => reach[v] === r) })).filter(g => g.verbs.length)
    .map(g => `${joinAnd([...g.verbs])} ${memWords[g.r]}`);
  const no = memVerbs.filter(v => reach[v] === 'none');
  return !groups.length ? (save ? 'save' : 'none')
    : (save ? `save, and ${groups.join(', ')}` : `${groups.join(', ')} (no saving)`) + (no.length ? `; cannot ${joinWith([...no], 'or')}` : '');
};
/** The access objects this bridge computed itself: their sentences are its own words. Any other
 *  `access` object is Decoy's, and is worded here from its structured values only. */
const COMPUTED_HERE = new WeakSet<object>();
/** A word of a policy row that is safe to repeat: a short lower-case name. */
const rowWord = (v: unknown): string => (typeof v === 'string' && /^[a-z][a-z_]{0,29}$/.test(v) ? `"${v}"` : 'this bridge does not know');

/** The `access` object for a GET /policies answer that carries none. `now` decides what has ended. */
export function summarizeAccess(response: unknown, now: Date = new Date()): AccessSummary {
  const resp = isObj(response) ? response : {};
  const { counted, notCounted } = countedPolicies(resp, now);
  const accounts: Grant[] = [], personal: Grant[] = [], memory: Grant[] = [];
  const mail = { whole: [] as Grant[], accountInboxes: [] as Grant[], alias: [] as Grant[], inbox: [] as Grant[] };
  const odd = new Set<string>();
  /** Each distinct grant with when it ends: null if any copy of it has no end, else its latest. */
  const grantEnds = new Map<string, string | null>();
  let save = false, waiting = 0;

  /** The actions a row covers. null = the row is not counted. */
  const actionsOf = (kind: Kind, row: Row): Set<string> | null => {
    let actions: string[];
    if (row.level !== undefined && row.level !== null) {
      const known = kind !== 'personal' && typeof row.level === 'string' ? LEVEL_ACTIONS[kind][row.level] : undefined;
      if (!known) { odd.add(`${kind} row with level ${rowWord(row.level)}`); return null; }
      actions = known;
    } else if (row.actions === undefined || row.actions === null) actions = KNOWN_ACTIONS[kind];
    else actions = strings(row.actions);
    const out = new Set<string>();
    for (const a of actions) {
      if (KNOWN_ACTIONS[kind].includes(a)) out.add(a);
      else if (kind === 'message' && a === 'read_content') out.add('unlock_content');
      else if (!UNREPORTED.has(a)) odd.add(`${kind} action ${rowWord(a)}`);
    }
    if (kind === 'message' && row.content === false) out.delete('unlock_content');
    return out;
  };
  const set = (v: unknown) => v !== null && v !== undefined && v !== false && !(Array.isArray(v) && v.length === 0);
  const limitedUnknown = (kind: Kind, row: Row) =>
    Object.keys(row).some(k => set(row[k]) && (!KNOWN_FIELDS.has(k) || (ALL_SELECTORS.includes(k) && !SELECTORS_READ[kind].includes(k))));

  const take = (row: Row, policyEnds: string | null, implicit: boolean) => {
    const kind = row.kind;
    if (kind !== 'account' && kind !== 'message' && kind !== 'personal' && kind !== 'memory') {
      odd.add(`kind ${rowWord(kind)}`);
      return;
    }
    if (row.user_choice) { waiting++; return; } // an unresolved owner choice is not access
    const own = row.created_by_self === true || implicit;
    const alias = row.personal_aliases === true || typeof row.namespace_id === 'string';
    // Rows the server matches nothing with (coversTarget, expandLevelRows): said, not counted.
    if (!own && kind === 'account' && typeof row.domain === 'string' && typeof row.account_id !== 'string') { odd.add('account row naming a site, with no account chosen'); return; }
    if (!own && kind === 'message' && row.level !== undefined && row.level !== null && !alias) { odd.add('message row with a level and no Personal Alias'); return; }
    if (!own && kind === 'message' && !alias && row.account_inboxes !== true && typeof row.decoy_id !== 'string'
      && (typeof row.account_id === 'string' || typeof row.domain === 'string')) { odd.add('message row naming an account, not an inbox'); return; }
    const saves = kind === 'memory' && !implicit && strings(row.actions).includes('create');
    if (saves) save = true;
    const actions = actionsOf(kind, row);
    if (!implicit && (saves || actions?.size)) {
      const key = JSON.stringify(canonical(row)), held = grantEnds.get(key);
      grantEnds.set(key, !grantEnds.has(key) ? policyEnds : held === null || policyEnds === null ? null : policyEnds > held! ? policyEnds : held!);
    }
    if (!actions || !actions.size) return;
    const limited = !own && limitedUnknown(kind, row);
    const grant = (keys: string[]): Grant =>
      ({ scope: own ? 'own' : keys.length || limited ? 'some' : 'all', keys: keys.length || !limited ? keys : [`limited:${JSON.stringify(row)}`], actions });

    if (kind === 'account') {
      const id = typeof row.account_id === 'string' ? row.account_id : '';
      const g = grant(id ? [id] : []);
      // `reveal_password` is the password itself: a row limited to other kinds of secret (2FA codes
      // only) does not give it (the matcher's datatype rule; a level row has no such limit).
      const kinds = row.level ? [] : strings(row.datatypes);
      accounts.push(kinds.length && !kinds.includes('basic-auth') ? { ...g, actions: new Set([...actions].filter(a => a !== 'unlock_credential')) } : g);
      if (own) return;
      // An account level includes that account's own inbox (never the Personal Alias).
      if (typeof row.level === 'string') mail.accountInboxes.push({ ...g, actions: new Set(LEVEL_ACTIONS.message[row.level]) });
      // An account row with no datatypes brings the memories about that account, at what it allows (memorySelectors).
      if (!strings(row.datatypes).length && !limited) memory.push({ scope: 'some', keys: [`account:${id || '*'}`], actions });
    } else if (kind === 'message') {
      if (row.personal_aliases === true) mail.alias.push(grant([]));
      else if (typeof row.namespace_id === 'string') mail.alias.push(grant([row.namespace_id]));
      else if (row.account_inboxes === true) mail.accountInboxes.push(grant([]));
      else if (typeof row.decoy_id === 'string') mail.inbox.push(grant([`inbox:${row.decoy_id}`]));
      else mail.whole.push(grant([]));
    } else if (kind === 'personal') {
      // An entry by id; else every entry of the kinds named; else every entry (grantedPersonalView).
      personal.push(grant(typeof row.personal_id === 'string' ? [`entry:${row.personal_id}`] : strings(row.datatypes).map(k => `kind:${k}`)));
    } else memory.push(grant([...strings(row.datatypes).map(c => `category:${c}`), ...strings(row.about)]));
  };
  for (const p of counted) for (const row of p.rows) take(row, p.ends, false);
  for (const row of Array.isArray(resp.implicit) ? resp.implicit.filter(isObj) : []) take(row, null, true);

  // The scope ceiling: a verb whose scope the token does not hold is refused whatever the rows say.
  const listed = Array.isArray(resp.scopes) ? strings(resp.scopes) : isObj(resp.token) && Array.isArray(resp.token.scopes) ? strings(resp.token.scopes) : null;
  const caps = listed ? new Set(listed.map(s => LEGACY_SCOPE[s] ?? s)) : null;
  // Reading mail content needs the inbox read scope as well as the unlock scope.
  const scopeHeld = (kind: string, action: string) => !!caps?.has(ACTION_SCOPE[`${kind}:${action}`])
    && (kind !== 'message' || action !== 'unlock_content' || caps.has('message.read'));
  const has = (grants: Grant[], scope: Grant['scope'], action: string) => grants.some(g => g.scope === scope && g.actions.has(action));

  const accountCan = Object.fromEntries(Object.entries(ACCOUNT_VERBS).map(([verb, a]): [string, Reach] =>
    [verb, !scopeHeld('account', a) ? 'none' : has(accounts, 'all', a) ? 'all' : has(accounts, 'some', a) ? 'some' : has(accounts, 'own', a) ? 'created_by_you' : 'none'])) as AccessSummary['accounts']['can'];
  const bounded = [...mail.accountInboxes, ...mail.alias, ...mail.inbox, ...mail.whole.filter(g => g.scope === 'some')];
  const mailOwn = [...mail.whole, ...mail.inbox, ...mail.accountInboxes, ...mail.alias];
  const mailCan = Object.fromEntries(Object.entries(MAIL_VERBS).map(([verb, a]): [string, MailReach] =>
    [verb, !scopeHeld('message', a) ? 'none' : has(mail.whole, 'all', a) ? 'all' : has(mail.accountInboxes, 'all', a) ? 'all_account_inboxes'
      : bounded.some(g => g.scope !== 'own' && g.actions.has(a)) ? 'some' : has(mailOwn, 'own', a) ? 'created_by_you' : 'none'])) as AccessSummary['mail']['can'];
  const personalReach = (a: string): PersonalReach =>
    !scopeHeld('personal', a) ? 'none' : has(personal, 'all', a) ? 'all' : has(personal, 'some', a) ? 'some' : 'none';
  // Reading takes both read actions (the entries are listed under one and opened under the other).
  const personalCan = Object.fromEntries(Object.entries(PERSONAL_VERBS).map(([verb, a]): [string, PersonalReach] =>
    [verb, verb === 'read' ? narrower(personalReach('read_metadata'), personalReach(a)) : personalReach(a)])) as AccessSummary['personal_info']['can'];
  // No scope gates memories. Access is exactly the grant: saving gives none, and deleting takes write.
  const memoryReach = (a: string): MemoryReach => has(memory, 'all', a) ? 'all' : has(memory, 'some', a) ? 'some' : 'none';

  const acct = widest(accountCan), mailW = widest(mailCan), pers = widest(personalCan);
  const named = (grants: Grant[], action: string) => new Set(grants.filter(g => g.scope === 'some' && g.actions.has(action)).flatMap(g => g.keys));
  // How many each verb reaches, where the detail names every one of them; null where it cannot be
  // known from here (a row limited in an unknown way; an account's inbox or an alias's addresses).
  const accountCounts = Object.fromEntries(Object.entries(ACCOUNT_VERBS).map(([verb, a]) => {
    const keys = named(accounts, a);
    return [verb, accountCan[verb as keyof typeof ACCOUNT_VERBS] === 'some' && ![...keys].some(k => k.startsWith('limited:')) ? keys.size : null];
  })) as Record<string, number | null>;
  const mailCounts = Object.fromEntries(Object.entries(MAIL_VERBS).map(([verb, a]) => {
    const keys = named(bounded, a);
    return [verb, mailCan[verb as keyof typeof MAIL_VERBS] === 'some' && keys.size > 0 && [...keys].every(k => k.startsWith('inbox:'))
      && !bounded.some(g => g.scope === 'all' && g.actions.has(a)) ? keys.size : null];
  })) as Record<string, number | null>;
  const everyAlias = mailW.which !== 'none' && (mailW.which === 'all' || has(mail.alias, 'all', MAIL_VERBS[mailW.verb]));
  // An address needs Create accounts alone; an account needs it and the right to change accounts.
  const createAddresses: boolean | 'unknown' = caps ? caps.has('decoy.write') : 'unknown';
  const createAccounts: boolean | 'unknown' = caps ? caps.has('decoy.write') && caps.has('account.write') : 'unknown';

  const readKeys = named(memory, 'read_metadata'), readAll = has(memory, 'all', 'read_metadata');
  const memories: AccessSummary['memories'] = {
    save, read: memoryReach('read_metadata'), write: memoryReach('write'), delete: memoryReach('write'),
    by: {
      categories: readAll ? [] : [...readKeys].filter(k => k.startsWith('category:')).map(k => k.slice('category:'.length)).sort(),
      topics: readAll ? 0 : [...readKeys].filter(k => k.startsWith('topic:')).length,
      accounts: readAll ? 0 : readKeys.has('account:*') ? 'all' : [...readKeys].filter(k => k.startsWith('account:')).length,
    },
  };
  const ends = [...grantEnds.values()].filter((e): e is string => !!e).sort();
  if (!listed && (accounts.length || personal.length || mailOwn.length)) odd.add('the answer lists no scopes, so accounts, mail and personal info read as none');
  if (waiting) odd.add(`${plural(waiting, 'selection', 'selections')} the owner has not made yet`);

  const memSentence = memoryWords(save, memories);
  const yn = (v: boolean | 'unknown') => (v === 'unknown' ? 'unknown' : v ? 'yes' : 'no');
  const summary = [
    `Accounts: ${describe(accountCan, accountCounts, { one: 'account', many: 'accounts', prep: 'on' })}`,
    `create accounts: ${yn(createAccounts)}`,
    `create addresses: ${yn(createAddresses)}`,
    `mail: ${describe(mailCan, mailCounts, { one: 'inbox', many: 'inboxes', prep: 'in' })}${everyAlias && mailW.which !== 'all' ? ` (every Personal Alias: ${VERB_WORDS[mailW.verb]})` : ''}`,
    `personal info: ${personalWords(personalCan)}`,
    `memories: ${memSentence}`,
  ].join('; ') + (ends[0] ? `. Part of this ends ${ends[0]}.` : '.');

  const computed: AccessSummary = {
    summary,
    // `count` goes with `which`: the count of the verb that reaches furthest. Other verbs may reach fewer.
    accounts: { allowed: acct.which !== 'none', which: acct.which, count: accountCounts[acct.verb], can: accountCan },
    create_accounts: { allowed: createAccounts },
    create_addresses: { allowed: createAddresses },
    mail: { allowed: mailW.which !== 'none', which: mailW.which, count: mailCounts[mailW.verb], personal_alias: everyAlias, can: mailCan },
    personal_info: { allowed: pers.which !== 'none', which: pers.which, can: personalCan },
    memories,
    ends_at: ends[0] ?? null,
    can_request_more: true,
    computed_by: 'bridge',
    ...(notCounted.length ? { not_counted: notCounted } : {}),
    ...(odd.size ? { not_summarised: [...odd].sort() } : {}),
  };
  COMPUTED_HERE.add(computed);
  return computed;
}

/** What the lines above know how to word. Anything else in the object is listed, never dropped. */
const KNOWN_ACCESS: Record<string, string[] | null> = {
  summary: null, ends_at: null, can_request_more: null, updated_at: null, version: null, computed_by: null, not_counted: null, not_summarised: null,
  create_accounts: ['allowed'], create_addresses: ['allowed'],
  accounts: ['allowed', 'which', 'count', 'can'], mail: ['allowed', 'which', 'count', 'personal_alias', 'can'], personal_info: ['allowed', 'which', 'can'],
  memories: ['save', 'read', 'write', 'delete', 'by'],
};
const KNOWN_VERBS: Record<string, string[]> = { accounts: Object.keys(ACCOUNT_VERBS), mail: Object.keys(MAIL_VERBS), personal_info: Object.keys(PERSONAL_VERBS) };
function unknownParts(access: Row): string[] {
  const out: string[] = [];
  // The name of what is there, never its value: a value is Decoy's text, and a name is repeated
  // only when it is a plain field name.
  const show = (path: string, _v: unknown) => { if (/^[a-z][a-z_.]{0,59}$/.test(path)) out.push(path); else out.push('a field this bridge does not name'); };
  for (const [key, value] of Object.entries(access)) {
    if (!(key in KNOWN_ACCESS)) { show(key, value); continue; }
    const fields = KNOWN_ACCESS[key];
    if (!fields || !isObj(value)) continue;
    for (const [f, v] of Object.entries(value)) if (!fields.includes(f)) show(`${key}.${f}`, v);
    if (isObj(value.can)) for (const [verb, v] of Object.entries(value.can)) if (!KNOWN_VERBS[key]?.includes(verb)) show(`${key}.can.${verb}`, v);
  }
  return out.sort();
}

/** The server's sentence cut at its sections ("label: …; label: …."), with the trailing end date apart. */
function sections(sentence: unknown): { parts: Array<{ label: string; text: string }>; ends: string | null } | null {
  if (typeof sentence !== 'string' || !sentence.trim()) return null;
  const tail = / Part of this ends ([^ ]+)\.$/.exec(sentence.trim());
  const body = (tail ? sentence.trim().slice(0, tail.index) : sentence.trim()).replace(/\.$/, '');
  const parts = body.split(/; (?=[A-Za-z][A-Za-z ]{0,40}: )/).map((part) => {
    const m = /^([A-Za-z][A-Za-z ]{0,40}): ([\s\S]+)$/.exec(part);
    return m ? { label: m[1], text: m[2] } : null;
  });
  return parts.length && parts.every((x): x is { label: string; text: string } => !!x) ? { parts: parts as Array<{ label: string; text: string }>, ends: tail?.[1] ?? null } : null;
}

/**
 * The plain lines that open my_permissions, memories first, from an `access` object alone.
 *
 * Decoy's object is worded here from its structured values (`can`, `allowed`, `count`, the
 * memory reaches), in this bridge's own words: its `summary` sentence and any other text in it
 * are not shown. A value that is not one this bridge knows reads "not stated". An object this
 * bridge computed keeps its own sentence, cut at its sections. Personal info reads "Read" or
 * "No access".
 */
const REACHES = new Set(['all', 'some', 'created_by_you', 'all_account_inboxes', 'none']);
const MEMORY_REACHES = new Set(['all', 'some', 'own_only', 'none']);
const MEMORY_CATEGORIES = new Set(['personal_details', 'family', 'professional_details', 'sports', 'travel', 'food', 'music', 'health', 'technology',
  'hobbies', 'fashion', 'entertainment', 'milestones', 'user_preferences', 'misc']);
const DATE_TIME = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
/** One kind's sentence from Decoy's `can`: each verb at the reach given, the count on the widest. */
function areaWords(area: unknown, verbs: readonly string[], noun: { one: string; many: string; prep: string }): string {
  if (!isObj(area) || !isObj(area.can)) return isObj(area) && area.allowed === false ? 'none' : 'not stated';
  const can = Object.fromEntries(verbs.filter(v => typeof (area.can as Row)[v] === 'string' && REACHES.has((area.can as Row)[v] as string)).map(v => [v, (area.can as Row)[v] as string]));
  if (!Object.keys(can).length) return 'not stated';
  const top = widest(can as Record<string, Reach>);
  const count = typeof area.count === 'number' && Number.isInteger(area.count) && area.count >= 0 && area.which === 'some' ? area.count : null;
  return describe(can, count !== null ? { [top.verb]: count } : {}, noun);
}
export function renderAccess(given: unknown): string[] {
  if (!isObj(given)) return [];
  const own = COMPUTED_HERE.has(given);
  const access = onePersonalRead(given);
  const m = isObj(access.memories) ? access.memories : null;
  const by = m && isObj(m.by) ? m.by : {};
  const categories = strings(by.categories).filter(c => MEMORY_CATEGORIES.has(c));
  const whole = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n > 0;
  const reaches = [categories.length ? `categories: ${categories.join(', ')}` : '',
    whole(by.topics) ? plural(by.topics, 'topic', 'topics') : '',
    by.accounts === 'all' ? 'about accounts you can read' : whole(by.accounts) ? `about ${plural(by.accounts, 'account', 'accounts')}` : ''].filter(Boolean).join('; ');
  const allowed = (v: unknown) => (isObj(v) ? (v.allowed === true ? 'yes' : v.allowed === false ? 'no' : v.allowed === 'unknown' ? 'unknown' : 'not stated') : 'not stated');
  const personal = isObj(access.personal_info) && isObj(access.personal_info.can)
    ? personalWords(Object.fromEntries(Object.entries(access.personal_info.can).filter(([v, r]) => Object.keys(PERSONAL_VERBS).includes(v) && isReach(r))) as Record<string, string>)
    : isObj(access.personal_info) && access.personal_info.allowed === false ? 'No access' : 'not stated';
  const cut = own ? sections(access.summary) : null;
  const readReaches = m?.read === 'some' && reaches ? ` Read reaches: ${reaches}.` : '';
  let lines: string[];
  if (cut) {
    const line = (x: { label: string; text: string }) => `${x.label[0].toUpperCase()}${x.label.slice(1)}: ${x.text}.`;
    const isMemory = (x: { label: string }) => x.label.toLowerCase() === 'memories';
    lines = [...cut.parts.filter(isMemory).map(x => line(x) + readReaches), ...cut.parts.filter(x => !isMemory(x)).map(line)];
  } else {
    const reach = (r: unknown): MemoryReach | null => (typeof r === 'string' && MEMORY_REACHES.has(r) ? r as MemoryReach : null);
    const mem = m && typeof m.save === 'boolean' && reach(m.read) && reach(m.write) && reach(m.delete)
      ? memoryWords(m.save, { read: reach(m.read)!, write: reach(m.write)!, delete: reach(m.delete)! }) : 'not stated';
    const mail = areaWords(access.mail, KNOWN_VERBS.mail, { one: 'inbox', many: 'inboxes', prep: 'in' });
    const everyAlias = isObj(access.mail) && access.mail.personal_alias === true && access.mail.which !== 'all' && mail !== 'none' && mail !== 'not stated';
    lines = [
      `Memories: ${mem}.${readReaches}`,
      `Accounts: ${areaWords(access.accounts, KNOWN_VERBS.accounts, { one: 'account', many: 'accounts', prep: 'on' })}.`,
      `Create accounts: ${allowed(access.create_accounts)}.`,
      `Create addresses: ${allowed(access.create_addresses)}.`,
      `Mail: ${mail}${everyAlias ? ' (every Personal Alias included)' : ''}.`,
      `Personal info: ${personal}.`,
    ];
  }
  const endsAt = typeof access.ends_at === 'string' && DATE_TIME.test(access.ends_at) ? access.ends_at : own ? cut?.ends : null;
  const also = unknownParts(access);
  // What was left out of the count: this bridge's own notes are shown; Decoy's are counted.
  const notCounted = strings(access.not_counted), notSummarised = strings(access.not_summarised);
  // How to ask for the two things an agent most often lacks, only when it lacks them.
  const cannotCreate = isObj(access.create_addresses) ? access.create_addresses.allowed === false : isObj(access.create_accounts) && access.create_accounts.allowed === false;
  const asks = [m?.save === false ? 'to save memories: { permissions: ["memory.save"] }' : '', cannotCreate ? 'to create accounts: { permissions: ["account.create"] }' : ''].filter(Boolean);
  return [
    ...lines,
    ...(endsAt ? [`Access ends: ${endsAt} (the first of it to end).`] : []),
    ...(notCounted.length ? [own ? `Not counted: policies ${notCounted.join(', ')}.` : `Not counted: ${plural(notCounted.length, 'policy', 'policies')} (see policies).`] : []),
    ...(notSummarised.length ? [own ? `Not summarised (see policies): ${notSummarised.join('; ')}.` : `Not summarised: ${plural(notSummarised.length, 'thing', 'things')} (see policies).`] : []),
    ...(also.length ? [`Also in access (not worded above): ${[...new Set(also)].join('; ')}.`] : []),
    ...(access.can_request_more === false ? [] : [`More: ask with request_access by permission name (${[...asks, 'after a refusal: send its permission_request'].join('; ')}).`]),
  ];
}

/** Asking again for held access asks the owner to keep it only in its last 7 days. */
export const RENEWAL_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** The permission names each held grant gives (policies[].permissions[].permissions), with what
 *  its row names; null when the answer names none (a server that does not send them). */
export function heldPermissionsLine(response: unknown, now: Date = new Date()): string | null {
  if (!isObj(response)) return null;
  const { counted } = countedPolicies(response, now);
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const NAME = /^(account|acctmail|acctmem|alias|personal|memory)\.[a-z]{3,8}$|^everything$/;
  const parts = new Map<string, Set<string>>();
  for (const p of counted) for (const row of p.rows) {
    const names = strings(row.permissions).filter(n => NAME.test(n));
    if (!names.length) continue;
    const id = (k: string) => (typeof row[k] === 'string' && UUID.test(row[k] as string) ? row[k] as string : null);
    const about = strings(row.about).filter(t => /^(topic|account):([0-9a-f-]{36}|\*)$/i.test(t));
    const cats = strings(row.datatypes).filter(c => MEMORY_CATEGORIES.has(c) || ['identity', 'phone', 'address', 'email', 'credit-card'].includes(c));
    const target = [
      id('account_id') ? `account ${id('account_id')}` : '', id('namespace_id') ? `Personal Alias ${id('namespace_id')}` : '',
      typeof row.domain === 'string' && /^[a-z0-9.-]{1,253}$/i.test(row.domain) ? `site ${row.domain}` : '',
      id('decoy_id') ? `address ${id('decoy_id')}` : '', id('personal_id') ? `entry ${id('personal_id')}` : '',
      about.length ? `about ${about.join(', ')}` : '', cats.length ? `${cats.join(', ')}` : '',
    ].filter(Boolean).join(', ');
    const key = target ? `on ${target}` : '';
    const set = parts.get(key) ?? new Set<string>();
    for (const n of names) set.add(n);
    parts.set(key, set);
  }
  if (!parts.size) return null;
  return `Permissions: ${[...parts].map(([on, n]) => `${[...n].join(', ')}${on ? ` ${on}` : ''}`).join('; ')}.`;
}

/**
 * JSON that stays readable without paying for indentation: anything whose one-line form fits in
 * `width` characters is written on one line, and so is a list of short plain values; anything
 * longer gets one line per member, indented one space per level. Always valid JSON, every value kept.
 */
export function compactJson(value: unknown, width = 170, indent = ''): string {
  const flat = JSON.stringify(value);
  if (value === null || typeof value !== 'object' || flat === undefined || flat.length <= width) return flat;
  // A list of short plain values (scope names) stays on one line however many there are.
  if (Array.isArray(value) && value.every(v => v === null || typeof v !== 'object') && value.every(v => String(v).length <= 40)) return flat;
  const inner = `${indent} `;
  if (Array.isArray(value)) return `[\n${value.map(v => inner + compactJson(v === undefined ? null : v, width, inner)).join(',\n')}\n${indent}]`;
  const members = Object.entries(value as Row).filter(([, v]) => v !== undefined && typeof v !== 'function')
    .map(([k, v]) => `${JSON.stringify(k)}: ${compactJson(v, width, inner)}`);
  // Short members share a line; one that spans lines, or would overflow, starts its own.
  const rows: string[] = [];
  for (const m of members) {
    const last = rows.length - 1;
    if (last >= 0 && !m.includes('\n') && !rows[last].includes('\n') && rows[last].length + m.length + 2 <= width) rows[last] += `, ${m}`;
    else rows.push(m);
  }
  return `{\n${rows.map(r => inner + r).join(',\n')}\n${indent}}`;
}

/** Stable JSON: keys sorted, lists of plain values sorted. */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) {
    const items = v.map(canonical);
    return items.every(i => i === null || typeof i !== 'object') ? [...items].sort() : items.map(i => JSON.stringify(i)).sort();
  }
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])]));
  return v;
}

/** A fingerprint of the effective access: the server's `access.version` when it sends one, else a
 *  hash of what counts (scopes, the counted policies' rows and end dates, the implicit rows). Two
 *  answers that grant the same thing give the same fingerprint, whatever their order or ids. */
export function accessFingerprint(response: unknown, now: Date = new Date()): string | null {
  if (!isObj(response)) return null;
  const version = isObj(response.access) ? response.access.version : undefined;
  if (typeof version === 'string' || typeof version === 'number') return `v:${version}`;
  if (!Array.isArray(response.policies)) return null;
  const { counted } = countedPolicies(response, now);
  const scopes = Array.isArray(response.scopes) ? response.scopes : isObj(response.token) ? response.token.scopes : [];
  const body = canonical({ scopes, policies: counted.map(p => ({ ends: p.ends, rows: p.rows })), implicit: response.implicit ?? [] });
  return `h:${createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 32)}`;
}
/** Two fingerprints say "changed" only when they are of the same kind (a version, or a hash). */
export const accessChanged = (before: string | null | undefined, after: string | null | undefined) =>
  !!before && !!after && before !== after && before.slice(0, 2) === after.slice(0, 2);

/**
 * Reading personal info is one ability: identity_get lists the entries and opens them, and needs
 * both. A server answer that reports `can.list` beside `can.read` is given here without `list`,
 * and with `read` as the narrower of the two, so `read` is said only where the connection can
 * read. `allowed`, `which` and the sentence's personal info part follow from `read`, `write` and
 * `delete`. Any other answer is returned as it is.
 */
export function onePersonalRead(access: Row): Row {
  const p = access.personal_info;
  if (!isObj(p) || !isObj(p.can) || !('list' in p.can)) return access;
  const { list, ...kept } = p.can;
  const rest: Row = { ...kept, ...(isReach(kept.read) ? { read: isReach(list) ? narrower(list, kept.read) : 'none' } : {}) };
  const can = Object.fromEntries(Object.entries(rest).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
  const which = Object.keys(can).length ? widest(can).which : 'none';
  const own = COMPUTED_HERE.has(access);
  const cut = own ? sections(access.summary) : null;
  const summary = cut && cut.parts.some(x => x.label.toLowerCase() === 'personal info')
    ? cut.parts.map(x => `${x.label}: ${x.label.toLowerCase() === 'personal info' ? personalWords(can) : x.text}`).join('; ') + (cut.ends ? `. Part of this ends ${cut.ends}.` : '.')
    : access.summary;
  const out = { ...access, ...(summary !== undefined ? { summary } : {}), personal_info: { ...p, allowed: which !== 'none', which, can: rest } };
  if (own) COMPUTED_HERE.add(out);
  return out;
}

/**
 * How far this connection reads personal info, by the access the SERVER reports in a GET /policies
 * answer: all | some | none. null when the answer carries no such report (nothing is known).
 */
export function personalReadReach(response: unknown): PersonalReach | null {
  if (!isObj(response) || !isObj(response.access)) return null;
  const p = onePersonalRead(response.access).personal_info;
  return isObj(p) && isObj(p.can) && isReach(p.can.read) ? p.can.read : null;
}

/**
 * Whether the connection can read the personal info one request_access call asked for: one entry
 * (`id`), some kinds (`datatypes`), or whatever the owner chose (neither). The server's report
 * decides "none" and "all"; in between, the counted rows are read: rows on one target add up, and
 * the target is read when between them they hold both read actions (a row with no `actions`
 * holds every action). null when the answer carries no report, or when one entry was asked for
 * and neither its own rows nor its kind (`kind`) settle it.
 */
export function personalReadCovers(response: unknown, target: { id?: string; datatypes?: readonly string[]; kind?: string | null }, now: Date = new Date()): boolean | null {
  const reach = personalReadReach(response);
  if (reach === null) return null;
  if (reach !== 'some') return reach === 'all';
  const READ = ['read_metadata', 'unlock_content'];
  const rows = countedPolicies(response as Row, now).counted.flatMap(p => p.rows).filter(r => r.kind === 'personal' && r.user_choice !== true);
  const holds = (r: Row): string[] => (r.actions === undefined || r.actions === null ? READ : strings(r.actions));
  const reads = (set: Row[]) => READ.every(a => set.some(r => holds(r).includes(a)));
  const kindsOf = (r: Row) => (Array.isArray(r.datatypes) && r.datatypes.length ? strings(r.datatypes) : null);
  const byEntry = new Map<string, Row[]>();
  for (const r of rows) if (typeof r.personal_id === 'string') byEntry.set(r.personal_id.toLowerCase(), [...(byEntry.get(r.personal_id.toLowerCase()) ?? []), r]);
  const wide = rows.filter(r => typeof r.personal_id !== 'string');
  const kindRead = (k: string) => reads(wide.filter(r => { const ks = kindsOf(r); return !ks || ks.includes(k); }));
  const anyKindRead = () => reads(wide.filter(r => !kindsOf(r))) || [...new Set(wide.flatMap(r => kindsOf(r) ?? []))].some(kindRead);
  if (target.datatypes?.length) return target.datatypes.every(kindRead);
  // One entry: its own rows, or rows that cover its own kind. The answer does not say which kind
  // the entry is: `kind` does (null: a kind no grant names, or an entry this connection is not
  // shown, which only a grant on every kind reads). When the kind is not known, nothing is
  // confirmed: a grant on some other kind does not read this entry.
  if (target.id) {
    if (reads(byEntry.get(target.id.toLowerCase()) ?? [])) return true;
    if (target.kind === undefined) return reads(wide.filter(r => !kindsOf(r))) ? true : null;
    return target.kind === null ? reads(wide.filter(r => !kindsOf(r))) : kindRead(target.kind);
  }
  return anyKindRead() || [...byEntry.values()].some(reads);
}

/**
 * Decoy's `access` object as data: the fields this bridge knows, each with a value of the kind it
 * takes (a reach, yes or no, a count, a date). Its sentences (`summary`, `lines`), a field the
 * bridge does not name and a value that is not of that kind are left out; the lines name what
 * was left unworded.
 */
function accessValues(a: Row): Row {
  const out: Row = {};
  const int = (v: unknown) => (typeof v === 'number' && Number.isInteger(v) && v >= 0 ? v : null);
  const area = (v: unknown, verbs: string[], reaches: Set<string>, extra: (x: Row) => Row = () => ({})): Row | undefined => {
    if (!isObj(v)) return undefined;
    const can = isObj(v.can) ? Object.fromEntries(Object.entries(v.can).filter(([k, r]) => verbs.includes(k) && typeof r === 'string' && reaches.has(r))) : undefined;
    return { ...(typeof v.allowed === 'boolean' ? { allowed: v.allowed } : {}), ...(typeof v.which === 'string' && reaches.has(v.which) ? { which: v.which } : {}), ...extra(v), ...(can ? { can } : {}) };
  };
  const put = (k: string, v: Row | undefined) => { if (v) out[k] = v; };
  put('accounts', area(a.accounts, KNOWN_VERBS.accounts, REACHES, v => ('count' in v ? { count: int(v.count) } : {})));
  for (const k of ['create_accounts', 'create_addresses']) {
    const v = a[k];
    if (isObj(v) && (typeof v.allowed === 'boolean' || v.allowed === 'unknown')) out[k] = { allowed: v.allowed };
  }
  put('mail', area(a.mail, KNOWN_VERBS.mail, REACHES, v => ({ ...('count' in v ? { count: int(v.count) } : {}), ...(typeof v.personal_alias === 'boolean' ? { personal_alias: v.personal_alias } : {}) })));
  put('personal_info', area(a.personal_info, KNOWN_VERBS.personal_info, REACHES));
  if (isObj(a.memories)) {
    const m = a.memories, by = isObj(m.by) ? m.by : null;
    out.memories = {
      ...(typeof m.save === 'boolean' ? { save: m.save } : {}),
      ...Object.fromEntries(['read', 'write', 'delete'].filter(k => typeof m[k] === 'string' && MEMORY_REACHES.has(m[k] as string)).map(k => [k, m[k]])),
      ...(by ? { by: { categories: strings(by.categories).filter(c => MEMORY_CATEGORIES.has(c)), topics: int(by.topics) ?? 0, accounts: by.accounts === 'all' ? 'all' : int(by.accounts) ?? 0 } } : {}),
    };
  }
  for (const k of ['ends_at', 'updated_at']) if (a[k] === null || (typeof a[k] === 'string' && DATE_TIME.test(a[k] as string))) out[k] = a[k];
  if (typeof a.can_request_more === 'boolean') out.can_request_more = a.can_request_more;
  if (int(a.version) !== null || (typeof a.version === 'string' && /^[0-9a-f]{1,64}$/i.test(a.version))) out.version = a.version;
  return out;
}

/** my_permissions' answer: the plain lines, then `access` (the server's own when it sends one, else
 *  computed here), then the detail. */
export function withAccessFirst(response: unknown, now: Date = new Date()): Record<string, unknown> {
  if (!isObj(response)) { const access = summarizeAccess({}, now); return { summary: renderAccess(access), access, detail: response }; }
  // The fields Decoy documents for this answer, and no other: a field it does not document is
  // not data this tool returns.
  const { access: sent, policies, implicit } = response;
  const rest = Object.fromEntries(['implicit_scopes', 'token', 'scopes'].filter(k => k in response).map(k => [k, response[k]]));
  // Decoy's own object is returned as data without its sentences (`summary`, `lines`): the lines
  // above it are this bridge's wording of the same values.
  const access = isObj(sent) ? accessValues(onePersonalRead(sent)) : summarizeAccess(response, now);
  const lines = renderAccess(access);
  const held = heldPermissionsLine(response, now);
  // The names held go after the plain lines, before the end date and how to ask for more.
  if (held) {
    const at = lines.findIndex(l => /^(Access ends|Not counted|Not summarised|Also in access|More):/.test(l));
    lines.splice(at === -1 ? lines.length : at, 0, held);
  }
  // How to keep access: ask again in its last 7 days (the owner is asked to renew it).
  // Not when only the owner can grant this access (renderAccess leaves out its "More:" line too).
  const endsAt = lines.findIndex(l => l.startsWith('Access ends: '));
  if (endsAt !== -1 && access.can_request_more !== false) {
    const t = Date.parse(lines[endsAt].slice('Access ends: '.length).split(' ')[0]);
    lines[endsAt] += !Number.isNaN(t) && t - now.getTime() <= RENEWAL_WINDOW_MS
      ? ' It ends within 7 days: to keep it, ask again with request_access (the same permissions and selection); the owner is asked to keep it.'
      : ' To keep it, ask again with request_access in its last 7 days; earlier, the same ask answers already_granted and reaches no one.';
  }
  return { summary: lines, access, policies, implicit, ...rest };
}

/** Where the fingerprint a bridge last saw is kept between runs (a file-based connection only). */
export interface AccessStore { load(): string | null; save(fingerprint: string): void }

/**
 * The access fingerprint this bridge last saw for one connection. `current` is what any session
 * saw last in this run; `previous()` is what the last RUN of the bridge saw (from the store),
 * handed once to the first session that looks, so a change made between runs is announced in the
 * next one. Without a store both live in memory only.
 */
export class AccessWatch {
  current: string | null = null;
  private fromLastRun: string | null | undefined;
  constructor(private readonly store?: AccessStore) {}
  previous(): string | null {
    if (this.fromLastRun === undefined) { try { this.fromLastRun = this.store?.load() ?? null; } catch { this.fromLastRun = null; } }
    const p = this.fromLastRun;
    this.fromLastRun = null;
    return p;
  }
  see(fingerprint: string | null) {
    if (!fingerprint || fingerprint === this.current) return;
    this.previous(); // what the last run saw is read before it is replaced
    this.current = fingerprint;
    try { this.store?.save(fingerprint); } catch { /* not kept: the next run has nothing to compare with */ }
  }
}

/**
 * One session's view. A session is told of a change only against something it has itself seen:
 * its own first look is its baseline (another session's looks are not), except that the first
 * session of a run starts from what the last run saw.
 */
export class AccessSession {
  private known: string | null = null;
  private looked = false;
  constructor(private readonly watch: AccessWatch) {}
  /** A look this session made (its first, or one after a refusal). */
  seen(fingerprint: string | null) {
    if (!fingerprint) return;
    const first = !this.looked;
    this.looked = true;
    const fromLastRun = first ? this.watch.previous() : null;
    this.watch.see(fingerprint);
    if (first) this.known = fromLastRun ?? fingerprint;
  }
  /** The agent is reading its access now (my_permissions): nothing left to announce. */
  read(fingerprint: string | null) {
    if (!fingerprint) return;
    this.looked = true;
    this.watch.see(fingerprint);
    this.known = this.watch.current;
  }
  /** True once per change: access differs from what this session's agent knows. A fingerprint of
   *  another kind (a version where there was a hash) is a new baseline, said silently. */
  takeNotice(): boolean {
    const now = this.watch.current;
    if (!this.looked || !now || now === this.known) return false;
    const changed = accessChanged(this.known, now);
    this.known = now;
    return changed;
  }
}
