// Access v2 — who reaches each memory, and why (`via`): the bridge's port of the Decoy
// API's rule, proven on the same golden vectors.
//
//   self          not a reason: access is exactly the grant, so saving a memory gives no access to it
//   all           a memory grant with no selector
//   category:<c>  a memory grant on one of that observation's mem0 categories (one reason per granted category)
//   topic:<id>    a memory grant on that topic: observations about it, the topic (entity) itself,
//                 and relations whose every end is granted (topics and accounts)
//   and:<r>+<r>   all-of: a relation with several ends — holds only while every part does
//   account:<id>  an account grant brings the memories labelled with that account
//
// The server stores each key wrap with its reasons and re-checks them on every serve, so the
// bridge only needs two questions answered locally:
//   viaForSelectors  a writer wrapping a new memory to ANOTHER connection, knowing only that
//                    connection's selectors (GET /context/memory-grantees)
//   viaHeld          does a reason this connection was served still grant `action` under its own
//                    grants (GET /policies)? Read needs read_metadata; edit, re-file and sharing a
//                    key need write; delete needs destroy (memory.delete, acctmem.delete; an older
//                    grant's write still deletes). While the connection holds memory.save, `self`
//                    reads and edits what it saved, never deletes it. A named account row
//                    (account.*) brings no memories: those are acctmem.* (a memory row about
//                    `account:<id>` or `account:*`).
//   ownSelectors     this connection's own reach at an action, as selectors: with viaForSelectors,
//                    whether a memory with given labels is inside what it can write (a relabel
//                    must keep it there)

export type MemoryAction = 'read' | 'write' | 'destroy';

/** What a writer knows about one memory (labels from the plaintext it is about to seal). */
export interface MemoryFacts {
  row_id: string;
  kind: 'observation' | 'entity' | 'relation';
  /** An observation's mem0 categories, any number (empty = not tagged yet). */
  categories: string[];
  /** 'user' | 'topic:<entity row id>' | 'account:<uuid>' */
  about: string[];
  /** Relations: the ends — 'user', 'topic:<entity row id>' or 'account:<uuid>'. */
  endpoints?: string[];
}

/** Another connection's memory reach, as GET /context/memory-grantees serves it. */
export interface MemorySelectors {
  all: boolean;
  categories: string[];
  topics: string[];
  account_ids: string[];
  account_wildcard: boolean;
}

export function viaForSelectors(s: MemorySelectors, row: MemoryFacts): string[] {
  const via: string[] = [];
  if (s.all) via.push('all');
  if (row.kind === 'observation') {
    for (const c of new Set(row.categories)) if (s.categories.includes(c)) via.push(`category:${c}`);
    for (const t of row.about.filter(a => a.startsWith('topic:'))) if (s.topics.includes(t)) via.push(t);
    for (const a of row.about.filter(x => x.startsWith('account:'))) {
      if (s.account_wildcard || s.account_ids.includes(a.slice('account:'.length))) via.push(a);
    }
  } else if (row.kind === 'entity') {
    const t = `topic:${row.row_id}`;
    if (s.topics.includes(t)) via.push(t);
  } else if (row.kind === 'relation') {
    // Every non-user end must be reachable (a topic by a topic grant, an account by an account
    // grant); several ends → ONE all-of reason, which the server keeps only while every part holds.
    const ends = [...new Set((row.endpoints ?? []).filter(e => e !== 'user'))];
    const granted = (e: string) => e.startsWith('topic:') ? s.topics.includes(e)
      : e.startsWith('account:') ? (s.account_wildcard || s.account_ids.includes(e.slice('account:'.length))) : false;
    if (ends.length && ends.every(granted)) via.push(ends.length === 1 ? ends[0] : `and:${ends.join('+')}`);
  }
  return via;
}

/** One permission row as GET /policies serves it (lib/agent-grants serializePermission). */
export interface ServedPermission {
  kind: string;
  level?: 'read' | 'read_write' | 'full';
  actions?: string[] | null;
  datatypes?: string[] | null;
  about?: string[];
  account_id?: string;
  decoy_id?: string;
  personal_id?: string;
  domain?: string;
  account_inboxes?: boolean;
  created_by_self?: boolean;
  user_choice?: boolean;
  namespace_id?: string;
  personal_aliases?: boolean;
  /** A row asked for by permission name (it is exactly its permissions; an older row is widened). */
  named?: boolean;
  /** The permission names the row gives. */
  permissions?: string[];
}

const NEEDS: Record<MemoryAction, string> = { read: 'read_metadata', write: 'write', destroy: 'destroy' };
const LEVEL_ACTIONS: Record<string, Record<string, string[]>> = {
  account: { read: ['read_metadata', 'unlock_credential'], read_write: ['read_metadata', 'unlock_credential', 'write'], full: ['read_metadata', 'unlock_credential', 'write', 'destroy'] },
  memory: { read: ['read_metadata'], read_write: ['read_metadata', 'write'], full: ['read_metadata', 'write', 'destroy'] },
};

function covers(p: ServedPermission, action: MemoryAction): boolean {
  const actions = p.level ? LEVEL_ACTIONS[p.kind]?.[p.level] ?? [] : p.actions;
  return actions == null || actions.includes(NEEDS[action]);
}
/** The rows as they decide DELETING a memory (as the Decoy API decides it): an older grant (not named)
 *  deleted with its write, so its write counts as destroy too. A named row deletes only with
 *  memory.delete / acctmem.delete. */
export function withV2Deletes(perms: ServedPermission[]): ServedPermission[] {
  return perms.map(p => {
    if (p.named || (p.kind !== 'memory' && p.kind !== 'account')) return p;
    const actions = p.level ? LEVEL_ACTIONS[p.kind]?.[p.level] : p.actions;
    return actions && actions.includes('write') && !actions.includes('destroy') ? { ...p, level: undefined, actions: [...actions, 'destroy'] } : p;
  });
}
/** An older account row brings the memories about that account; a named one never does. */
const accountRowCovers = (p: ServedPermission, action: MemoryAction) =>
  p.kind === 'account' && !p.named && covers(p, action) && !p.created_by_self && !p.user_choice && !p.datatypes;
/** The accounts a memory row is about (acctmem.*): '*' = every account; null = it names none. */
function aboutAccounts(p: ServedPermission): '*' | string[] | null {
  const a = (p.about ?? []).filter(x => x.startsWith('account:'));
  if (!a.length) return null;
  return a.includes('account:*') ? '*' : a.map(x => x.slice('account:'.length));
}
/** Whether the connection holds memory.save. */
const savesMemories = (perms: ServedPermission[]) =>
  perms.some(p => p.kind === 'memory' && (p.permissions?.includes('memory.save') || (Array.isArray(p.actions) && p.actions.includes('create'))));

/** A row with no selector at all targets every account (as the Decoy API reads it). */
const wildcard = (p: ServedPermission) => !p.account_id && !p.decoy_id && !p.personal_id && !p.domain
  && !p.created_by_self && !p.user_choice && !p.account_inboxes && !p.namespace_id && !p.personal_aliases && !p.about?.length;

export function viaHeld(perms: ServedPermission[], via: string, action: MemoryAction): boolean {
  // memory.save: "Can read and edit its own", while it is held. Deleting is memory.delete.
  if (via === 'self') return action !== 'destroy' && savesMemories(perms);
  if (via.startsWith('and:')) {
    const parts = via.slice(4).split('+').filter(Boolean);
    return parts.length > 0 && parts.every(p => !p.startsWith('and:') && p !== 'self' && viaHeld(perms, p, action));
  }
  const memory = perms.filter(p => p.kind === 'memory' && covers(p, action));
  if (via === 'all') return memory.some(p => !p.datatypes?.length && !p.about?.length);
  if (via.startsWith('category:')) return memory.some(p => !!p.datatypes?.includes(via.slice('category:'.length)));
  if (via.startsWith('topic:')) return memory.some(p => !!p.about?.includes(via));
  if (via.startsWith('account:')) {
    const id = via.slice('account:'.length);
    return perms.some(p => accountRowCovers(p, action) && (p.account_id === id || wildcard(p)))
      || memory.some(p => ((x) => x === '*' || (Array.isArray(x) && x.includes(id)))(aboutAccounts(p)));
  }
  return false;
}

/** This connection's own memory reach for `action`, as selectors (GET /policies rows). */
export function ownSelectors(perms: ServedPermission[], action: MemoryAction): MemorySelectors {
  const memory = perms.filter(p => p.kind === 'memory' && covers(p, action) && !p.created_by_self);
  const accounts = perms.filter(p => accountRowCovers(p, action));
  const about = memory.map(aboutAccounts);
  return {
    all: memory.some(p => !p.datatypes?.length && !p.about?.length),
    categories: [...new Set(memory.flatMap(p => p.datatypes ?? []))],
    topics: [...new Set(memory.flatMap(p => (p.about ?? []).filter(x => x.startsWith('topic:'))))],
    account_ids: [...new Set([...accounts.map(p => p.account_id), ...about.flatMap(x => (Array.isArray(x) ? x : []))].filter((x): x is string => !!x))],
    account_wildcard: accounts.some(wildcard) || about.includes('*'),
  };
}
