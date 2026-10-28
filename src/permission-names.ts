/**
 * Named permissions: what an agent asks for, by name, with one selection, as the
 * Decoy API reads it. Pure: no I/O.
 *
 * A permission is `entity.verb`. One ask is one row: the names, and at most one selection that
 * every named entity takes. `account.create` and `memory.save` are asked for alone, and so is
 * `everything`. What a name needs (edit needs read, …) Decoy adds by itself.
 *
 * The owner's words for each name (`PERMISSION_COPY`) are the phone's (permissionCopy), kept equal
 * to the server's table by a test.
 */

export const PERMISSION_NAMES = [
  'account.create', 'account.read', 'account.edit',
  'acctmail.read', 'acctmail.mark', 'acctmail.send', 'acctmail.edit', 'acctmail.delete',
  'acctmem.read', 'acctmem.edit', 'acctmem.delete',
  'account.delete',
  'alias.read', 'alias.mark', 'alias.send', 'alias.edit', 'alias.delete', 'alias.burn',
  'personal.read', 'personal.edit', 'personal.delete',
  'memory.read', 'memory.save', 'memory.edit', 'memory.delete',
] as const;
export type PermissionName = typeof PERMISSION_NAMES[number];
export const EVERYTHING = 'everything';
/** Every value `permissions` takes. */
export const ASKABLE_PERMISSIONS = [...PERMISSION_NAMES, EVERYTHING] as const;
export type AskablePermission = typeof ASKABLE_PERMISSIONS[number];

/** Asked for alone: no other name and no selection in the same ask. */
export const SOLO: ReadonlySet<string> = new Set(['account.create', 'memory.save', EVERYTHING]);

export const RECORD_TYPES = ['identities', 'emails', 'cards'] as const;

/** The selection keys an ask may carry, besides `permissions` and `reason`. */
export const SELECTION_KEYS = ['account_id', 'domain', 'namespace_id', 'record_type', 'personal_id', 'datatypes', 'about'] as const;
export type SelectionKey = typeof SELECTION_KEYS[number];

type Entity = 'account' | 'acctmail' | 'acctmem' | 'alias' | 'personal' | 'memory';
export const entityOf = (name: string): Entity | null => {
  const e = name.split('.')[0];
  return ['account', 'acctmail', 'acctmem', 'alias', 'personal', 'memory'].includes(e) ? e as Entity : null;
};

/** Which entities each selection key fits (domain: an account's site, account.* only). */
const FITS: Record<SelectionKey, readonly Entity[]> = {
  account_id: ['account', 'acctmail', 'acctmem'],
  domain: ['account'],
  namespace_id: ['alias'],
  record_type: ['personal'],
  personal_id: ['personal'],
  datatypes: ['memory'],
  about: ['memory'],
};
const KEY_WORDS: Record<SelectionKey, string> = {
  account_id: 'account_id goes with account.*, acctmail.* and acctmem.*',
  domain: 'domain goes with account.* only (account.read, account.edit, account.delete)',
  namespace_id: 'namespace_id goes with alias.*',
  record_type: 'record_type goes with personal.*',
  personal_id: 'personal_id goes with personal.*',
  datatypes: 'datatypes (memory categories) go with memory.*',
  about: 'about (topics) goes with memory.*',
};

export type NamedAsk = { permissions: string[] } & Partial<Record<SelectionKey, unknown>>;

/**
 * Why this ask is not one Decoy takes, in the bridge's words, or null when it is. Checks the names,
 * the solo rules and that the one selection fits every name.
 */
export function namedAskProblem(ask: NamedAsk): string | null {
  const names = ask.permissions;
  if (!Array.isArray(names) || names.length === 0) return 'permissions names at least one permission.';
  const unknown = names.filter((n) => !(ASKABLE_PERMISSIONS as readonly string[]).includes(n));
  if (unknown.length) return `Unknown permission name: ${unknown.map(String).join(', ')}.`;
  const sent = SELECTION_KEYS.filter((k) => ask[k] !== undefined);
  const solo = names.find((n) => SOLO.has(n));
  if (solo && (new Set(names).size > 1 || sent.length)) {
    return `"${solo}" is asked for alone: { permissions: ["${solo}"] }, with no other permission and no selection.`;
  }
  const memorySel = sent.filter((k) => k === 'datatypes' || k === 'about');
  const personalSel = sent.filter((k) => k === 'record_type' || k === 'personal_id');
  const groups = sent.length - memorySel.length - personalSel.length + (memorySel.length ? 1 : 0) + (personalSel.length ? 1 : 0);
  if (memorySel.length > 1) return 'Send memory categories (datatypes) or topics (about), not both.';
  if (groups > 1) return `One ask carries one selection; this one has ${sent.join(', ')}. Ask once per target.`;
  for (const k of sent) {
    const off = names.filter((n) => !FITS[k].includes(entityOf(n)!));
    if (off.length) return `${KEY_WORDS[k]}, not ${off.join(', ')}.`;
  }
  if (ask.record_type !== undefined && !(RECORD_TYPES as readonly unknown[]).includes(ask.record_type)) {
    return `record_type is one of: ${RECORD_TYPES.join(', ')}.`;
  }
  if (Array.isArray(ask.datatypes) && ask.datatypes.length === 0) return 'datatypes names at least one category; leave it out for every memory.';
  if (Array.isArray(ask.about) && ask.about.length === 0) return 'about names at least one topic; leave it out for every memory.';
  if (names.includes('personal.edit') && !names.includes('personal.delete') && ask.record_type === 'emails' && ask.personal_id !== undefined) {
    return 'Adding verified addresses is for all of them: send personal.edit with record_type "emails" and no personal_id.';
  }
  return null;
}

/** The owner's words for each name (permissionCopy: the headline and line for all, the headline for one). */
export const PERMISSION_COPY: Record<PermissionName, { all: string; sub: string; one?: string; sensitive?: true }> = {
  'account.create': { all: 'Add accounts to Decoy', sub: 'Saves details for new or existing accounts' },
  'account.read': { all: 'Read details from all accounts', sub: 'Password, 2FA codes, notes, custom fields', one: 'Read details from this account' },
  'account.edit': { all: 'Edit all accounts', sub: 'Password, 2FA setup, notes, custom fields', one: 'Edit this account' },
  'acctmail.read': { all: 'Read all accounts’ email', sub: 'Messages and attachments', one: 'Read this account’s email' },
  'acctmail.mark': { all: 'Mark read or unread', sub: 'Read or unread state' },
  'acctmail.send': { all: 'Send and reply from them', sub: 'From each account’s Decoy email', one: 'Send and reply from it' },
  'acctmail.edit': { all: 'Edit their addresses', sub: 'Pause, forwarding, notifications', one: 'Edit its address' },
  'acctmail.delete': { all: 'Delete emails', sub: 'Removes messages from all accounts', sensitive: true },
  'acctmem.read': { all: 'Read memories about all accounts', sub: 'Shared context and preferences', one: 'Read memories about this account' },
  'acctmem.edit': { all: 'Edit memories about all accounts', sub: 'Change, re-file, share', one: 'Edit memories about this account' },
  'acctmem.delete': { all: 'Delete memories about all accounts', sub: 'Removed for good', one: 'Delete memories about this account', sensitive: true },
  'account.delete': { all: 'Delete all accounts', sub: 'Each account, its details and its Decoy email', one: 'Delete this account', sensitive: true },
  'alias.read': { all: 'Read email', sub: 'Messages and attachments' },
  'alias.mark': { all: 'Mark read or unread', sub: 'Read or unread state' },
  'alias.send': { all: 'Send and reply', sub: 'As your aliases' },
  'alias.edit': { all: 'Edit your aliases', sub: 'Pause, on or off, forwarding, new aliases', one: 'Edit this alias' },
  'alias.delete': { all: 'Delete emails', sub: 'Removes messages from your aliases', sensitive: true },
  'alias.burn': { all: 'Burn alias addresses', sub: 'They stop receiving for good', one: 'Burn this alias', sensitive: true },
  'personal.read': { all: 'Read all personal info', sub: 'Identities, emails, cards' },
  'personal.edit': { all: 'Edit all personal info', sub: 'Edit and add identities, emails, cards' },
  'personal.delete': { all: 'Delete all personal info', sub: 'Identities, emails, cards', sensitive: true },
  'memory.read': { all: 'Read all memories', sub: 'Shared context and preferences' },
  'memory.save': { all: 'Save new memories', sub: 'Can read and edit its own' },
  'memory.edit': { all: 'Edit all memories', sub: 'Change, re-file, share' },
  'memory.delete': { all: 'Delete all memories', sub: 'Removed for good' },
};
export const EVERYTHING_COPY = { all: 'Everything in your Decoy', sub: 'Every account, email, info and memory', sensitive: true as const };
/** Personal info headlines by record type (all of that type). */
const PERSONAL_TYPE_COPY: Record<string, Record<typeof RECORD_TYPES[number], string>> = {
  'personal.read': { identities: 'Read all identities', emails: 'Read your verified addresses', cards: 'Read all cards' },
  'personal.edit': { identities: 'Edit all identities', emails: 'Add verified addresses', cards: 'Edit all cards' },
  'personal.delete': { identities: 'Delete all identities', emails: 'Delete your verified addresses', cards: 'Delete all cards' },
};
const PERSONAL_ONE_COPY: Record<string, Record<typeof RECORD_TYPES[number], string>> = {
  'personal.read': { identities: 'Read this identity', emails: 'Read this address', cards: 'Read this card' },
  'personal.edit': { identities: 'Edit this identity', emails: 'Add verified addresses', cards: 'Edit this card' },
  'personal.delete': { identities: 'Delete this identity', emails: 'Delete this address', cards: 'Delete this card' },
};
const MEMORY_SCOPED: Record<string, string> = { 'memory.read': 'Read', 'memory.edit': 'Edit', 'memory.delete': 'Delete' };

/**
 * The headline the owner's phone shows for one name on this selection, so the agent can say what it
 * asked for in the phone's words. `topicNames`: the topic names the agent gave in `about`.
 */
export function ownerWords(name: string, sel: Partial<Record<SelectionKey, unknown>>, topicNames?: string[]): string | null {
  if (name === EVERYTHING) return EVERYTHING_COPY.all;
  const copy = PERMISSION_COPY[name as PermissionName];
  if (!copy) return null;
  const one = sel.account_id !== undefined || sel.domain !== undefined || sel.namespace_id !== undefined;
  if (name.startsWith('personal.')) {
    const t = typeof sel.record_type === 'string' ? sel.record_type as typeof RECORD_TYPES[number] : null;
    if (t && sel.personal_id !== undefined) return PERSONAL_ONE_COPY[name][t];
    if (t) return PERSONAL_TYPE_COPY[name][t];
    // One record of a type the ask does not name: never worded as all personal info.
    if (sel.personal_id !== undefined) return `${({ 'personal.read': 'Read', 'personal.edit': 'Edit', 'personal.delete': 'Delete' } as Record<string, string>)[name]} this record`;
    return copy.all;
  }
  if (MEMORY_SCOPED[name] && topicNames?.length) return `${MEMORY_SCOPED[name]} memories about ${topicNames.join(', ')}`;
  // Topics named by id whose names this agent can't read: never worded as all memories.
  if (MEMORY_SCOPED[name] && Array.isArray(sel.about) && sel.about.length) {
    return `${MEMORY_SCOPED[name]} memories about the ${sel.about.length === 1 ? 'topic' : 'topics'} you chose`;
  }
  return one && copy.one ? copy.one : copy.all;
}
