/**
 * One error shape for every failed API call.
 *
 * The API answers a failure as { error: "<message>", code?, ... } and, for an account
 * compare-and-set miss, as { error: { code, message, current_rev } }. A memory conflict carries
 * `current_rev` (409 REV_CONFLICT) or `kid` (409 KID_CONFLICT) at the top level.
 *
 * A route the server doesn't have is answered by the platform, not the API: a plain-text page, or
 * { error: { code: "404", message } } when the request asks for JSON. Neither is the API's own
 * "no such record" (a 404 whose error is a string, or whose code is a name such as NOT_FOUND), so
 * a tool can tell "this server is older than this feature" from "that id doesn't exist".
 *
 * A refusal for lack of a grant is { error: "access_denied", code: "INSUFFICIENT_GRANT", message?,
 * permission_request?, remediation?: { tool: "request_access", args } }. The agent is told the
 * exact request_access call: the `permission_request` (permission names and one selection) when
 * the server sends one this bridge can check, else the older `remediation`; when the server names
 * neither, none is made up. A `hint` (what was or wasn't done) is passed on too.
 * With can_request: false (access only the owner can grant, when connecting the agent) the
 * server's message is relayed as it is and no request is suggested, whatever else the body holds.
 *
 * One refusal is not a missing grant at all: a read that names no secret kind, made by a connection
 * whose grant on that account is limited to some kinds. The body then carries `granted_datatypes`
 * (the kinds held) and an `error_description`. The retry that works is to name one of those kinds,
 * so the message says which kinds are held and never suggests request_access. A 422
 * ONE_DATATYPE_PER_REQUEST (several kinds named in one read) is told the same way: one per call.
 *
 * A 429 is a rate limit, whatever its body: the message says so and gives the seconds to wait,
 * from the Retry-After header (seconds or an HTTP date) or else the body's retry_after_seconds.
 * The sentence in a 429's body is not relayed.
 *
 * A 426 UPDATE_REQUIRED says this bridge is older than Decoy accepts. It is told in the bridge's
 * own words: the two versions (only when each is a plain version), the command to run, and that
 * nothing was carried out. The command is this bridge's own text, never the server's.
 */
import { FixedRefusal } from './scrub.js';
import { entityOf, namedAskProblem, SELECTION_KEYS, type NamedAsk } from './permission-names.js';

/**
 * A stored record that could not be read or opened, so nothing was written over it.
 *
 * A tool that changes part of a sealed record reads the stored record, opens it, changes what was
 * asked and seals the whole record again: what is sealed from anything less erases the rest. So
 * when the stored record is there and could not be read (a read that did not complete) or opened
 * (another key, a format this version does not know), or the answer does not say whether one is
 * stored, the tool sends no write and answers with this code. An address or entry that has no
 * record yet is not this: there is nothing to erase, and the write goes ahead.
 */
export const RECORD_UNREADABLE = 'RECORD_UNREADABLE';
export class RecordUnreadable extends FixedRefusal {
  readonly code = RECORD_UNREADABLE;
}
/**
 * `what` and `why` are fixed words of this bridge (never a server's text or a caller's value).
 * `retry`: the record could not be READ (no answer, a server failure), which can pass, so the
 * next step is to try again later. Without it the record was read and does not open here, or the
 * answer does not hold it: trying again changes nothing, and the next step is the owner's.
 * `plural`: `what` is a plural ("sealed details").
 */
export function recordUnreadable(what: string, why: string, opts: { retry?: boolean; plural?: boolean } = {}): RecordUnreadable {
  const it = opts.plural ? 'them' : 'it';
  return new RecordUnreadable(`${RECORD_UNREADABLE}: ${what} ${why}, so nothing was changed: a write made without ${it} would erase ` +
    `everything in ${it} that this change does not name. Nothing was written. ` +
    (opts.retry
      ? 'Try again later; if it stays this way, the owner can make the change in the Decoy app.'
      : 'The owner can make the change in the Decoy app.'));
}
/** A read that got no answer, or a server failure: it says nothing about the record. A refusal
 *  the API gives by name (no access, no such record) is the API's own answer and stands. */
export function readDidNotComplete(e: unknown): boolean {
  const status = (e as { status?: unknown } | null)?.status;
  return typeof status !== 'number' || status >= 500;
}

/** The secret kinds of an account a grant can be limited to. */
export const ACCOUNT_SECRET_KINDS = ['basic-auth', 'custom-fields', 'credit-card', 'address', 'totp', 'note'] as const;
export type AccountSecretKind = typeof ACCOUNT_SECRET_KINDS[number];
/** Only kinds this bridge knows are ever repeated to the agent: a server's text is data. */
const knownKinds = (v: unknown): AccountSecretKind[] =>
  Array.isArray(v) ? ACCOUNT_SECRET_KINDS.filter((k) => v.includes(k)) : [];

/** The actions a refusal can name. Only these are passed on: a server's text is data. */
const REQUEST_ACTIONS = new Set(['read', 'read_metadata', 'unlock_content', 'unlock_credential', 'write', 'destroy', 'create']);

export interface ApiFailure extends Error {
  status: number;
  code?: string;
  current_rev?: number;
  kid?: string;
  /** The capability class a 403 SCOPE_MISSING names (ask for it with request_access capabilities). */
  required_scope?: string;
  /** The action a 403 INSUFFICIENT_GRANT says the refused request needed, when it is one this bridge knows. */
  request_action?: string;
  /** false when the server says this access cannot be requested (the owner grants it when connecting the agent). */
  can_request?: false;
  /** On a 403 for a read that named no kind: the secret kinds this connection's grant on that
   *  account does cover. Name ONE of them per read; do not ask for access. */
  granted_datatypes?: AccountSecretKind[];
  /** On a 409 GRANT_ALREADY_REQUESTED: the id of the open request that already holds the ask. */
  request_id?: string;
  /** The server has no such route (a platform 404), as opposed to the API's own not-found. */
  routeMissing?: true;
  /** On a 429: the seconds to wait before trying again, when Decoy gave them. */
  retry_after_seconds?: number;
  /** On a refusal for lack of access: the request_access arguments that ask for it (permission
   *  names and one selection), when Decoy named them and they passed knownPermissionAsk. */
  permission_request?: NamedAsk;
}

/** What the person runs to get the current bridge (the production release). */
export const UPDATE_COMMAND = 'npx decoy-mcp-server@latest';
const PLAIN_VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;
function updateRequired(status: number, data: unknown): ApiFailure {
  const body = (data && typeof data === 'object' ? data : {}) as { installed_version?: unknown; minimum_version?: unknown };
  const plain = (v: unknown) => (typeof v === 'string' && PLAIN_VERSION.test(v) ? v : undefined);
  const installed = plain(body.installed_version);
  const minimum = plain(body.minimum_version);
  const message = `UPDATE_REQUIRED: this Decoy MCP server${installed ? ` (decoy-mcp-server ${installed})` : ''} is older than Decoy accepts` +
    `${minimum ? `: ${minimum} or newer is needed` : ''}. Nothing was carried out, and the connection is kept. ` +
    `Tell the person to update it by running \`${UPDATE_COMMAND}\` and restarting the agent's Decoy connection. Do not retry until it is updated.`;
  return Object.assign(new Error(message), { status, code: 'UPDATE_REQUIRED' });
}

/** The code of a 429 that names none of its own. */
export const RATE_LIMITED = 'RATE_LIMITED';
/** The longest wait repeated to the agent (a week); a longer or malformed one is not a time. */
const MAX_RETRY_AFTER_SECONDS = 7 * 24 * 60 * 60;
/** Retry-After in seconds, rounded up: a number of seconds, or an HTTP date counted from `now`. */
function retryAfterSeconds(header: string | null | undefined, body: unknown, now: number): number | undefined {
  const usable = (n: number) => (Number.isFinite(n) && n > 0 && n <= MAX_RETRY_AFTER_SECONDS ? Math.ceil(n) : undefined);
  const h = typeof header === 'string' ? header.trim() : '';
  if (/^\d+(\.\d+)?$/.test(h)) return usable(Number(h));
  if (h && /[a-z]{3}/i.test(h) && !Number.isNaN(Date.parse(h))) return usable((Date.parse(h) - now) / 1000);
  const b = (body && typeof body === 'object' ? (body as { retry_after_seconds?: unknown }).retry_after_seconds : undefined);
  return typeof b === 'number' ? usable(b) : undefined;
}
function rateLimited(data: unknown, retryAfter: string | null | undefined, now: number): ApiFailure {
  const seconds = retryAfterSeconds(retryAfter, data, now);
  // The bridge's own words and the retry time only: the sentence Decoy sent with it is not relayed.
  const message = `${RATE_LIMITED}: Decoy is limiting how often this connection may do this (HTTP 429), and this request was not carried out. ` +
    (seconds !== undefined ? `Try again in ${seconds} second${seconds === 1 ? '' : 's'}.` : 'Decoy gave no retry time: wait before trying again.');
  return Object.assign(new Error(message), {
    status: 429,
    code: RATE_LIMITED,
    ...(seconds !== undefined ? { retry_after_seconds: seconds } : {}),
  });
}

/**
 * The codes the routes an agent connection calls can answer a failure with (the agent routes and
 * the code they use). A code is repeated to the agent, and kept on the error, only when it is one
 * of these: any other word in a `code` is the server's own text, and
 * becomes UNRECOGNIZED_CODE.
 */
export const KNOWN_CODES: ReadonlySet<string> = new Set([
  'ACCOUNT_BLOB_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_NOT_FOUND', 'ACCOUNT_NOT_LINKED', 'ACCOUNT_PAUSED',
  'ALIAS_HIDDEN', 'ALREADY_RESOLVED', 'AMBIGUOUS_DOMAIN', 'BAD_REQUEST', 'DATATYPE_NOT_THIS_RECORD',
  'DECOY_ADDRESS_NOT_ALLOWED', 'DECOY_EMAIL_TOMBSTONED', 'EDIT_ALREADY_RESOLVED', 'EDIT_NOT_FOUND',
  'EMAIL_EXISTS', 'EMAIL_IN_USE', 'ENCRYPTED_DATA_REQUIRED', 'FIELD_DELETED', 'FIELD_ID_CONFLICT',
  'FIELD_LIMIT', 'FIELD_NOT_FOUND', 'FORWARDING_EMAIL_CHANGE_REQUIRES_ENABLED', 'FORWARDING_EMAIL_REQUIRED',
  'FROM_ALIAS_UNRESOLVED', 'GRANT_ALREADY_REQUESTED', 'GRANT_EXPIRED', 'HOLDERS_MISSING', 'INSUFFICIENT_GRANT',
  'ACCOUNT_EMAIL_GOES_WITH_ACCOUNT', 'ALERTS_OWNER_ONLY', 'NAMED_PERMISSIONS_UNAVAILABLE', 'PASSKEYS_OWNER_ONLY',
  'INVALID_ADDRESS', 'INVALID_METADATA_SEALS', 'INVALID_NAMESPACE', 'INVALID_SEALED_DETAILS',
  'INVALID_SEALED_PATCH', 'INVALID_TOKEN', 'KEEP_MULTIPLE_NETWORKS', 'KEEP_NOT_CARRIED',
  'KEEP_REPLACE_NEEDS_OLD_KEY', 'KEEP_REPLACE_WITHOUT_OLD_KEY', 'KID_CONFLICT', 'LINKED_ADDRESS_NOT_YOURS',
  'MAILBOX_KEY_REQUIRED', 'MEMORY_MOVING', 'METADATA_SEALS_TOO_LARGE', 'METADATA_SEAL_NOT_FOR_CALLER', 'METADATA_SEAL_NO_KEY',
  'METADATA_SEAL_REQUIRED', 'METADATA_SEAL_TOO_LARGE', 'NAMESPACE_LIMIT_REACHED', 'NAMESPACE_NOT_OWNED',
  'NAME_SOURCE_REQUIRED', 'NOT_FOUND', 'NO_AGENT_PUBLIC_KEY', 'NO_CHANGE', 'NO_CREDENTIAL',
  'NO_USER_PUBLIC_KEY', 'ONE_DATATYPE_PER_REQUEST', 'PASSKEY_AMBIGUOUS', 'PASSKEY_ASSERT_REQUIRED',
  'PASSKEY_BAD_CLIENT_DATA', 'PASSKEY_BAD_REQUEST', 'PASSKEY_NOT_FOUND', 'PASSKEY_ORIGIN_MISMATCH',
  'PROVIDER_FAILED', 'RATE_LIMITED', 'REVIEW_BUSY', 'REVIEW_FULL', 'REV_CONFLICT',
  'SAVED_PASSWORD_NOT_CURRENT', 'SCOPE_MISSING', 'SCOPE_UNKNOWN', 'SEALED_DETAILS_TOO_LARGE',
  'SEALED_PATCH_TOO_LARGE', 'SENDING_TERMS_REQUIRED', 'SEND_IN_FLIGHT', 'SERVER_ERROR', 'SHAPE',
  'SPACE_EXISTS', 'STALE_RECORD', 'SUBDOMAIN_ALREADY_CLAIMED', 'SUBDOMAIN_TAKEN', 'SUPPRESSED_RECIPIENT',
  'TOKEN_EXPIRED', 'TOKEN_INVALID', 'TOKEN_MISSING', 'TOKEN_REPLACED', 'TOKEN_REVOKED', 'TOKEN_SUPERSEDED',
  'TOO_MANY_PENDING_EDITS', 'UNAUTHORIZED', 'UNHIDE_THEN_ENABLE', 'UNSUPPORTED_EMAIL_DOMAIN', 'UPDATE_REQUIRED',
  'VAULT_KEY_DRIFT', 'VAULT_KEY_REQUIRED',
]);
/** What a code the bridge does not know is reported as. */
export const UNRECOGNIZED_CODE = 'UNRECOGNIZED_CODE';
const knownCode = (v: unknown): string | undefined =>
  (v === undefined || v === null || v === '' ? undefined : typeof v === 'string' && KNOWN_CODES.has(v) ? v : UNRECOGNIZED_CODE);

/** The capability classes a refusal may name (the Decoy API's scopes, in both spellings). */
const KNOWN_SCOPES: ReadonlySet<string> = new Set([
  'decoy.read', 'decoy.write', 'message.read', 'message.write', 'message.unlock', 'forwarding.read', 'forwarding.write',
  'alert.read', 'alert.write', 'account.read', 'account.write', 'account.unlock', 'account.passkey_assert', 'profile.read',
  'personal.read', 'personal.write', 'personal.unlock', 'webhook.write',
  'decoys:read', 'decoys:write', 'inbox:read', 'inbox:write', 'inbox:content', 'forwarding:read', 'forwarding:write',
  'alerts:read', 'alerts:write', 'accounts:read', 'accounts:write', 'profile:read', 'profile:write',
]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Decoy's hints that say what a refused call did or did not do, word for word. A `hint` is
 * repeated only when it is exactly one of these: without it the agent cannot know that a refused
 * burn burned nothing, or which capability to leave out of an ask.
 */
export const KNOWN_HINTS: ReadonlySet<string> = new Set([
  'Nothing was burned. Pass replace: false to burn this address without minting a replacement; a replacement needs Create accounts (decoy.write).',
  'Leave `webhook.read` out. To register webhooks ask for `webhook.write`.',
  'Read email = discover messages + open sender/subject/body. Request both layers together; the owner approves it as one capability.',
]);
/** Kinds of data an ask may be narrowed to: account secret kinds, memory categories, personal info types. */
const ASK_DATATYPES: ReadonlySet<string> = new Set([
  ...ACCOUNT_SECRET_KINDS,
  'personal_details', 'family', 'professional_details', 'sports', 'travel', 'food', 'music', 'health', 'technology', 'hobbies', 'fashion',
  'entertainment', 'milestones', 'user_preferences', 'misc',
  'email', 'phone', 'card', 'address', 'name', 'birthday',
]);
/** The actions an ask for each kind may name (the same list the Decoy API checks). */
export const ASK_ACTIONS: Record<string, readonly string[]> = {
  account: ['read_metadata', 'unlock_credential', 'write', 'destroy'],
  message: ['read_metadata', 'unlock_content', 'write', 'destroy'],
  personal: ['read_metadata', 'unlock_content', 'write', 'destroy'],
  memory: ['create'],
};
/** How much an action asks for: reading what is listed, opening it, changing it, removing it. */
const ACTION_RANK: Record<string, number> = { read_metadata: 1, unlock_content: 2, unlock_credential: 2, create: 3, write: 3, destroy: 4 };

/** The request a refusal answered, as far as it bounds what may be asked for. */
export interface RefusedRequest { method: string; path: string; body?: unknown }
/**
 * The widest ask the refused request could need: the kind its route is about, and the highest
 * action its method could call for. A read needs no more than opening what it reads; a write
 * needs no more than write; only a delete or a burn can need destroy. `ids`: the records the
 * request named, when it named any: an ask is then for one of those, never for another record
 * and never for every record of the kind. `also`: the one ask of another kind a route can need (burning
 * an account's address needs destroy on that address, which the request does not name).
 * Null: a route for which the bridge suggests no ask.
 */
interface AskCeiling { kinds: string[]; rank: number; ids?: string[]; oneRecord?: true; also?: { kind: string; action: string } }
function askCeiling(r: RefusedRequest): AskCeiling | null {
  const route = r.path.split('?')[0];
  const body = (r.body && typeof r.body === 'object' ? r.body : {}) as { target?: { kind?: unknown; id?: unknown; ids?: unknown } };
  const method = r.method.toUpperCase();
  const removes = method === 'DELETE' || /\/(delete|burn[a-z-]*|batch)(\/|$)/.test(route) || /[?&]action=disable/.test(r.path);
  const rank = method === 'GET' ? 2 : removes ? 4 : 3;
  const named = (prefix: string): string[] | undefined => {
    const m = new RegExp(`^/${prefix}/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)`, 'i').exec(route);
    return m ? [m[1].toLowerCase()] : undefined;
  };
  if (route === '/unlock' || route.startsWith('/unlock/')) {
    const k = body.target?.kind;
    if (typeof k !== 'string' || !['account', 'message', 'personal'].includes(k)) return null;
    // Mail is read by message id and granted by inbox: the inbox is not in the request, so the
    // ask must name one record and cannot be checked against the request's ids.
    if (k === 'message') return { kinds: [k], rank: 2, oneRecord: true };
    const ids = [body.target?.id, ...(Array.isArray(body.target?.ids) ? body.target.ids as unknown[] : [])].filter((x): x is string => typeof x === 'string' && UUID_RE.test(x)).map(x => x.toLowerCase());
    return { kinds: [k], rank: 2, ...(ids.length ? { ids } : {}) };
  }
  if (route.startsWith('/accounts') || route === '/sealed-secrets') {
    const ids = named('accounts');
    return { kinds: ['account'], rank, ...(ids ? { ids } : {}), ...(ids && /\/burn-decoy$/.test(route) && method === 'POST' ? { also: { kind: 'message', action: 'destroy' } } : {}) };
  }
  if (route.startsWith('/personal-info')) { const ids = named('personal-info'); return { kinds: ['personal'], rank, ...(ids ? { ids } : {}) }; }
  if (route.startsWith('/context')) return { kinds: ['memory'], rank };
  if (/^\/(inbox|decoys|forwarding|subdomain)/.test(route)) { const ids = named('decoys'); return { kinds: ['message'], rank, ...(ids ? { ids } : {}) }; }
  return null;
}

const LEGACY_SCOPES: Record<string, string> = {
  'decoys:read': 'decoy.read', 'decoys:write': 'decoy.write', 'inbox:read': 'message.read', 'inbox:write': 'message.write', 'inbox:content': 'message.unlock',
  'forwarding:read': 'forwarding.read', 'forwarding:write': 'forwarding.write', 'alerts:read': 'alert.read', 'alerts:write': 'alert.write',
  'accounts:read': 'account.read', 'accounts:write': 'account.write', 'profile:read': 'profile.read', 'profile:write': 'personal.write',
};
/** The capability classes each group of routes checks. A refusal on a route names one of its own. */
const ROUTE_SCOPES: ReadonlyArray<[RegExp, readonly string[]]> = [
  [/^\/accounts/, ['account.read', 'account.write', 'account.unlock', 'decoy.write']],
  [/^\/sealed-secrets/, ['account.unlock', 'personal.unlock']],
  [/^\/(decoys|subdomain)/, ['decoy.read', 'decoy.write', 'message.read', 'message.write']],
  [/^\/inbox/, ['message.read', 'message.write', 'message.unlock']],
  [/^\/forwarding/, ['forwarding.read', 'forwarding.write']],
  [/^\/personal-info/, ['personal.read', 'personal.write', 'personal.unlock']],
  [/^\/webhooks/, ['webhook.write']],
  [/^\/unlock/, ['account.unlock', 'message.unlock', 'personal.unlock', 'account.passkey_assert', 'account.read', 'message.read', 'personal.read']],
];
/** Whether a capability a refusal names is one the refused request could need: one its route
 *  checks, and for a read not one that writes. Without the request, any capability the bridge knows. */
function scopeFits(scope: string, request?: RefusedRequest): boolean {
  if (!request) return true;
  const canon = LEGACY_SCOPES[scope] ?? scope;
  const own = ROUTE_SCOPES.find(([re]) => re.test(request.path.split('?')[0]))?.[1];
  if (!own?.includes(canon)) return false;
  return request.method.toUpperCase() !== 'GET' || !canon.endsWith('.write');
}

/**
 * The request_access call a refusal names, repeated only when it is exactly a form Decoy uses and
 * no wider than the refused request could need:
 *   { kind, action, resource_id?, datatypes? }                     the access the request lacked
 *   { kind: "message", select: "personal_aliases", level: "read_write" }   the Personal Alias ask
 * Every key must be one of these and every value one this bridge knows. One key or value that is
 * not (a level, a capability list, a reason, an id that is not a UUID, a kind of data the bridge
 * does not name) means no call is suggested: leaving that part out could ask for more than the
 * server named. With `request`, the kind must be the kind that route is about, the action no
 * more than its method could need, and the record the one the request named (askCeiling).
 */
/**
 * Routes whose refusal may name the whole-inbox ask: the ones that manage Personal Aliases (the
 * alias switches, an alias address's status, burn, delete and forwarding switch).
 */
const WHOLE_INBOX_ROUTES = /^\/(subdomain|alias-emails|decoys|forwarding)(\/|$|\?)|^\/accounts\/[0-9a-f-]{36}(\/burn-decoy)?(\?|$)/i;
/**
 * Routes whose refusal may name the Full access ask: the ones only a holder of the whole-vault or
 * whole-mailbox key may use.
 */
const FULL_ACCESS_ROUTES = /^\/(vault-key|mailbox-key|decoy-edits|personal-info)(\/|$|\?)|^\/inbox\/(raw|messages\/[0-9a-f-]{36}\/attachments\/)|^\/decoys\/[0-9a-f-]{36}(\/metadata-recipients)?(\?|$)|^\/accounts\/[0-9a-f-]{36}(\/credential)?(\?|$)/i;
/** The two asks for the whole of something, accepted only exactly as Decoy names them. */
function wholeAsk(a: Record<string, unknown>, request?: RefusedRequest): Record<string, unknown> | null | undefined {
  const keys = Object.keys(a).sort().join();
  const path = request?.path;
  if (keys === 'action,kind,select' && a.kind === 'message' && a.select === 'all_inboxes' && a.action === 'write') {
    return path === undefined || WHOLE_INBOX_ROUTES.test(path) ? { kind: 'message', select: 'all_inboxes', action: 'write' } : null;
  }
  if (keys === 'select' && a.select === 'full_access') {
    return path === undefined || FULL_ACCESS_ROUTES.test(path) ? { select: 'full_access' } : null;
  }
  if (a.select === 'all_inboxes' || a.select === 'full_access') return null;   // any other shape of them
  return undefined;
}

function knownAsk(args: unknown, request?: RefusedRequest): Record<string, unknown> | null {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return null;
  const a = args as Record<string, unknown>;
  const whole = wholeAsk(a, request);
  if (whole !== undefined) return whole;
  const keys = Object.keys(a);
  const ceiling = request ? askCeiling(request) : undefined;
  if (ceiling === null) return null;
  const kind = typeof a.kind === 'string' && Object.hasOwn(ASK_ACTIONS, a.kind) ? a.kind : null;
  if (!kind) return null;
  const id = typeof a.resource_id === 'string' && UUID_RE.test(a.resource_id) ? a.resource_id.toLowerCase() : null;
  if ('resource_id' in a && !id) return null;
  // The one ask of another kind a route can need: exactly that action, on one named record.
  if (ceiling?.also && kind === ceiling.also.kind) {
    return keys.length === 3 && a.action === ceiling.also.action && id ? { kind, action: a.action, resource_id: a.resource_id } : null;
  }
  if (ceiling && !ceiling.kinds.includes(kind)) return null;
  if (keys.length === 3 && a.kind === 'message' && a.select === 'personal_aliases' && a.level === 'read_write') {
    return !ceiling || ceiling.rank >= 3 ? { kind: 'message', select: 'personal_aliases', level: 'read_write' } : null;
  }
  if (!keys.every(k => ['kind', 'action', 'resource_id', 'datatypes'].includes(k))) return null;
  if (typeof a.action !== 'string' || !ASK_ACTIONS[kind].includes(a.action)) return null;
  if (ceiling && ACTION_RANK[a.action] > ceiling.rank) return null;
  // A request that named a record is told to ask for that record: not another, and not all of them.
  if (ceiling?.ids && !(id && ceiling.ids.includes(id))) return null;
  if (ceiling?.oneRecord && !id) return null;
  if ('datatypes' in a && !(Array.isArray(a.datatypes) && a.datatypes.length > 0 && a.datatypes.every(d => typeof d === 'string' && ASK_DATATYPES.has(d)))) return null;
  return Object.fromEntries(keys.map(k => [k, a[k]]));
}

/** The verbs, ranked as askCeiling ranks a request: reading, changing, removing. */
const VERB_RANK: Record<string, number> = { read: 2, mark: 3, send: 3, edit: 3, create: 3, save: 3, delete: 4, burn: 4 };
/** The kinds of record each entity is about, as askCeiling names a route's kinds. */
const ENTITY_KINDS: Record<string, string> = { account: 'account', acctmail: 'message', alias: 'message', personal: 'personal', memory: 'memory', acctmem: 'memory' };
const TOPIC_RE = /^topic:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * A refusal's `permission_request`, repeated only when every key and value is one this bridge
 * knows, it is an ask Decoy takes (namedAskProblem), and it is no wider than the refused request
 * could need: its names are about the kind of record the route is about (an account's routes may
 * also name its email and memories; the verified-address routes, personal info), their verbs no
 * more than the method could need, and when the request named records, the ask names one of them.
 * `everything` only on the routes that need the whole-vault or whole-mailbox key.
 */
function knownPermissionAsk(v: unknown, request?: RefusedRequest): NamedAsk | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const a = v as Record<string, unknown>;
  if (!Object.keys(a).every((k) => k === 'permissions' || (SELECTION_KEYS as readonly string[]).includes(k))) return null;
  if (!Array.isArray(a.permissions) || !a.permissions.every((n) => typeof n === 'string')) return null;
  for (const k of ['account_id', 'namespace_id', 'personal_id'] as const) if (k in a && !(typeof a[k] === 'string' && UUID_RE.test(a[k] as string))) return null;
  if ('domain' in a && !(typeof a.domain === 'string' && /^[a-z0-9.-]{1,253}$/i.test(a.domain))) return null;
  if ('datatypes' in a && !(Array.isArray(a.datatypes) && a.datatypes.every((d) => typeof d === 'string' && ASK_DATATYPES.has(d)))) return null;
  if ('about' in a && !(Array.isArray(a.about) && a.about.every((t) => typeof t === 'string' && TOPIC_RE.test(t)))) return null;
  const ask = Object.fromEntries(Object.entries(a)) as NamedAsk;
  if (namedAskProblem(ask)) return null;
  const names = ask.permissions;
  if (names.includes('everything')) return !request || FULL_ACCESS_ROUTES.test(request.path) ? { permissions: ['everything'] } : null;
  if (!request) return ask;
  const ceiling = askCeiling(request);
  if (!ceiling) return null;
  const route = request.path.split('?')[0];
  // Beyond the route's own kinds: an account's routes also take its email and its memories
  // (acctmail.*, acctmem.*: never every memory or every alias), the verified-address routes personal info.
  const extra = new Set([...(route.startsWith('/accounts') ? ['acctmail', 'acctmem'] : []), ...(route.startsWith('/forwarding') ? ['personal'] : [])]);
  for (const n of names) {
    const entity = entityOf(n) ?? '';
    const kind = ENTITY_KINDS[entity];
    if (!kind || !(ceiling.kinds.includes(kind) || extra.has(entity))) return null;
    if ((VERB_RANK[n.split('.')[1]] ?? 9) > Math.max(ceiling.rank, ceiling.also ? 4 : 0)) return null;
  }
  // A request for one account bounds every name about an account: the account, its email, its memories.
  if (ceiling.ids && ceiling.kinds.includes('account') && names.some((n) => ['account', 'acctmail', 'acctmem'].includes(entityOf(n) ?? '')) && !(typeof ask.account_id === 'string' && ceiling.ids.includes(ask.account_id.toLowerCase()))) return null;
  // Mail read by message id, or a request for one address: the inbox is not in the request, so the
  // ask names one record (an account or an address), never every inbox.
  if ((ceiling.oneRecord || (ceiling.ids && ceiling.kinds.includes('message'))) && !(typeof ask.account_id === 'string' || typeof ask.namespace_id === 'string')) return null;
  if (ceiling.ids && ceiling.kinds.includes('personal') && !(typeof ask.personal_id === 'string' && ceiling.ids.includes(ask.personal_id.toLowerCase()))) return null;
  return ask;
}

/** The older asks this bridge says by name: they mean exactly one permission. */
function namedFromOlder(ask: Record<string, unknown> | null): NamedAsk | null {
  if (ask && Object.keys(ask).length === 2 && ask.kind === 'memory' && ask.action === 'create') return { permissions: ['memory.save'] };
  return null;
}

/**
 * What Decoy wrote in a failed answer (its `error` / `message` text), kept on the error under a
 * symbol: read by this bridge's own code to tell two answers apart (serverSaid), never part of
 * the message, never copied by a spread, and never shown to the agent.
 */
const SERVER_TEXT = Symbol('decoy.serverText');
/** Whether Decoy's own text for this failure matches `pattern`. For the bridge's logic only. */
export function serverSaid(e: unknown, pattern: RegExp): boolean {
  const text = e && typeof e === 'object' ? (e as { [SERVER_TEXT]?: unknown })[SERVER_TEXT] : undefined;
  return typeof text === 'string' && pattern.test(text);
}

/** The bridge's sentence for a code it knows. */
const CODE_SENTENCES: Record<string, string> = {
  // Passkey sign-in (passkey_assert): what to send instead, never the server's own text.
  PASSKEY_AMBIGUOUS: 'This site has more than one passkey in Decoy and the page named none of them: call passkey_assert again with account_id, the account to sign in to (or the credential id the page asked for). Nothing was signed.',
  PASSKEY_NOT_FOUND: 'No passkey in Decoy matches this site and credential. Nothing was signed.',
  PASSKEY_ORIGIN_MISMATCH: 'The page\'s origin does not belong to rp_id, so the phone will not sign for it. Nothing was signed.',
  PASSKEY_BAD_CLIENT_DATA: 'The clientDataJSON sent is not a WebAuthn sign-in for this page (installPasskeyBridge writes it). Nothing was signed.',
  PASSKEY_BAD_REQUEST: 'The sign-in request did not fit: a passkey sign-in is on an account, with passkey alone in datatypes, and credential_id_b64, when sent, is base64 (leave it out, or send "", when the page names no passkey). Nothing was signed.',
  NOT_FOUND: 'Nothing with that id is there for this connection.',
  ACCOUNT_NOT_FOUND: 'No account with that id is there for this connection.',
  DECOY_NOT_FOUND: 'No address with that id is there for this connection.',
  FIELD_NOT_FOUND: 'No field with that id is there for this connection.',
  EDIT_NOT_FOUND: 'No such change request is there for this connection.',
  BAD_REQUEST: 'Decoy did not accept the request as it was sent.',
  SHAPE: 'Decoy did not accept the request as it was sent.',
  REV_CONFLICT: 'The record changed since it was read. Read it again, re-apply the change, and retry.',
  KID_CONFLICT: 'The record was sealed again with another key since it was read. Read it again and retry.',
  HOLDERS_MISSING: 'A new key must reach every connection that reads this memory now; some were not included. Nothing was changed.',
  MEMORY_MOVING: 'This memory is being moved to its own key on the owner\'s phone. Nothing was changed; retry shortly.',
  STALE_RECORD: 'The record changed since it was read. Read it again and retry.',
  GRANT_EXPIRED: 'The access this needs has ended. Ask for it again with request_access: the owner is asked.',
  NAMED_PERMISSIONS_UNAVAILABLE: 'This Decoy server does not accept permission names, so nothing was asked of the owner and nothing was retried. Tell the person; the owner can change this connection\'s access in the Decoy app.',
  GRANT_ALREADY_REQUESTED: 'A request for this access is already open: the owner has not answered it yet.',
  TOKEN_EXPIRED: 'The connection was not accepted: call my_permissions to see its state.',
  TOKEN_INVALID: 'The connection was not accepted: call my_permissions to see its state.',
  TOKEN_MISSING: 'The connection was not accepted: call my_permissions to see its state.',
  TOKEN_REVOKED: 'The connection was revoked or replaced.',
  TOKEN_REPLACED: 'The connection was revoked or replaced.',
  TOKEN_SUPERSEDED: 'This token was replaced by a newer token of the same connection: another task or machine continued or reconnected it. The owner did not end the connection.',
  UNAUTHORIZED: 'The connection was not accepted: call my_permissions to see its state.',
  VAULT_KEY_REQUIRED: 'This needs the vault key, which this connection does not hold.',
  ENCRYPTED_DATA_REQUIRED: 'Decoy takes this only sealed, and this request did not carry it sealed. Nothing was written.',
  ACCOUNT_BLOB_REQUIRED: 'Decoy takes an account\'s record only sealed, and this request did not carry it sealed. Nothing was written.',
  NO_USER_PUBLIC_KEY: 'The owner has no public key on file. The owner opens the Decoy app once to register their key; then retry.',
  NO_AGENT_PUBLIC_KEY: 'Decoy holds no public key for this connection.',
  NO_CREDENTIAL: 'No password is saved for this account.',
  FORWARDING_EMAIL_REQUIRED: 'Forwarding needs a verified forwarding address, and the owner has none: forwarding_get lists them.',
  SENDING_TERMS_REQUIRED: 'The owner has not accepted the terms for sending mail. They do that in the Decoy app.',
  SUPPRESSED_RECIPIENT: 'A recipient cannot be sent to from Decoy.',
  FIELD_LIMIT: 'The account holds as many fields as it can.',
  FIELD_DELETED: 'That field was deleted.',
  TOO_MANY_PENDING_EDITS: 'Too many change requests for this address are still waiting. Wait for the owner\'s Decoy app to apply them.',
  ALREADY_RESOLVED: 'That request was already answered.',
  REQUEST_ALREADY_DECIDED: 'That request was already answered.',
  EDIT_ALREADY_RESOLVED: 'That change request was already resolved.',
  SERVER_ERROR: 'Decoy failed to answer.',
  SUBDOMAIN_TAKEN: 'That subdomain is taken. Choose another.',
  SUBDOMAIN_ALREADY_CLAIMED: 'The owner already has a subdomain, and a subdomain cannot be changed.',
  EMAIL_EXISTS: 'That forwarding address is already added: forwarding_email_list shows it.',
  EMAIL_IN_USE: 'That forwarding address is in use by one or more addresses, so it was not deleted. Turn forwarding off for them first.',
  SPACE_EXISTS: 'That space already exists. Nothing was created.',
  FIELD_ID_CONFLICT: 'A field with that id already exists on another account. Nothing was written.',
  LINKED_ADDRESS_NOT_YOURS: 'This account\'s address is not this connection\'s to remove, and it cannot be left without its account. The owner can delete it in the Decoy app.',
  SAVED_PASSWORD_NOT_CURRENT: 'The saved password is not the current one. Read the account again before changing it.',
  DECOY_EMAIL_TOMBSTONED: 'That address was burned and cannot be used again.',
  REVIEW_FULL: 'The owner has as many requests waiting as there can be. Wait for them to answer one.',
  REVIEW_BUSY: 'Another request from this connection is being answered. Try again shortly.',
  DECOY_ADDRESS_NOT_ALLOWED: 'A Decoy address cannot be a forwarding address. Use an address outside Decoy.',
  ACCOUNT_PAUSED: 'The owner\'s Decoy account is paused.',
  ALIAS_HIDDEN: 'That alias is hidden.',
  NO_CHANGE: 'The request changes nothing.',
};
/**
 * Sentences for refusals Decoy gives without a code of their own, keyed by Decoy's exact text
 * (never repeated: the bridge's sentence is). Each says the rule or the limit that was hit.
 */
const TEXT_SENTENCES: ReadonlyArray<[RegExp, string]> = [
  [/^Forwarding email not verified$/, 'That forwarding address is not verified. The owner verifies it from the mail Decoy sent to it; forwarding_email_list shows which are verified.'],
  [/^Forwarding email not found$/, 'No forwarding address has that id: forwarding_email_list shows them.'],
  [/^Maximum 10 active webhooks per user$/, 'The owner has 10 active webhooks, which is the most there can be. Delete or pause one (webhook_list), then register this one.'],
  [/^Maximum 50 decoys per batch$/, 'One call takes at most 50 addresses. Send them in several calls.'],
  [/^Maximum 100 aliases per request$/, 'One call takes at most 100 aliases. Send them in several calls.'],
  [/^body_text or body_html is required$/, 'A message needs a body: pass body_text or body_html.'],
  [/^attachments exceed the total size limit/, 'The attachments are too large together: about 4 MB of base64 is the most one message takes. Send fewer or smaller files.'],
  [/^domain selector is only valid for kind=account$/, 'domain names an account\'s site: it goes with kind "account" only.'],
  [/^select cannot be combined with resource_id or domain$/, 'select names the target by itself: pass it without resource_id and without domain.'],
  [/^user_choice applies to kind 'message' or 'personal'$/, 'select "user_choice" goes with kind "message" or "personal", not "account".'],
  [/^account_inboxes is only valid for kind=message$/, 'select "account_inboxes" goes with kind "message" only.'],
  [/^invalid action '[a-z_]{1,40}' for kind (account|message|personal|memory)$/, 'That action is not one this kind takes: account takes read_metadata, unlock_credential, write, destroy; message and personal take read_metadata, unlock_content, write, destroy.'],
  [/^login_url must be a valid URL \(include https:\/\/\)$/, 'login_url must be a full URL that starts with https://.'],
  [/^service_url must be a valid URL \(include https:\/\/\)$/, 'service_url must be a full URL that starts with https://.'],
  [/^tags may contain at most 20 items$/, 'An account takes at most 20 tags.'],
];
const textSentence = (text: string): string | undefined => TEXT_SENTENCES.find(([re]) => text.split('\n').some(line => re.test(line)))?.[1];
/** The bridge's sentence for a status, when the code has none of its own. */
const statusSentence = (status: number): string =>
  status === 400 || status === 422 ? 'Decoy did not accept the request as it was sent.'
  : status === 401 ? 'The connection was not accepted: call my_permissions to see its state.'
  : status === 403 ? 'Decoy refused it for this connection.'
  : status === 404 ? 'Nothing is there by that id for this connection.'
  : status === 409 ? 'It conflicts with what is already there, so it was not carried out.'
  : status === 413 ? 'The request was too large.'
  : status >= 500 ? 'Decoy failed to answer.'
  : 'The request was not carried out.';

/**
 * A refusal of POST /api/connect, the request that starts a pairing. A 429 is Decoy's limit on
 * starting pairings, from one network or (`limit: "all"`) from all networks together: a wait, with the seconds from Retry-After (or the body's
 * retry_after_seconds), and nothing was started. Any other status is reported as it was.
 */
export function pairingStartFailure(status: number, data: unknown, retryAfter?: string | null, now: number = Date.now()): ApiFailure {
  if (status !== 429) return Object.assign(new Error(`Failed to start pairing session: HTTP ${status}`), { status });
  const seconds = retryAfterSeconds(retryAfter, data, now);
  const all = (data && typeof data === 'object' ? (data as { limit?: unknown }).limit : undefined) === 'all';
  const message = `${RATE_LIMITED}: Decoy is limiting how often a pairing can be started ${all ? 'from all networks together' : 'from this network'} (HTTP 429). No pairing was started. ` +
    (seconds !== undefined ? `Try again in ${seconds} second${seconds === 1 ? '' : 's'}.` : 'Decoy gave no retry time: wait before trying again.');
  return Object.assign(new Error(message), { status: 429, code: RATE_LIMITED, ...(seconds !== undefined ? { retry_after_seconds: seconds } : {}) });
}

/**
 * `data` is the parsed JSON body, or undefined when the answer was not JSON. `retryAfter` is the
 * answer's Retry-After header, read for a 429 only.
 *
 * The message is this bridge's own: the status, the code when it is one the bridge knows, and a
 * sentence keyed by that code or status. Nothing Decoy wrote as text (`error`, `message`,
 * `error_description`) is in it; a `hint` only when it is one of KNOWN_HINTS, word for word; and
 * a `remediation` is rebuilt from known values (knownAsk).
 */
export function apiFailure(status: number, data: unknown, retryAfter?: string | null, now: number = Date.now(), request?: RefusedRequest): ApiFailure {
  if (status === 429) return rateLimited(data, retryAfter, now);
  if (data && typeof data === 'object' && (data as { code?: unknown }).code === 'UPDATE_REQUIRED') return updateRequired(status, data);
  if (data === undefined) {
    return Object.assign(new Error(`HTTP ${status}: the API returned a non-JSON response`), {
      status, ...(status === 404 ? { routeMissing: true as const } : {}),
    });
  }
  const body = (data && typeof data === 'object' ? data : {}) as {
    error?: unknown; code?: unknown; current_rev?: unknown; kid?: unknown;
    message?: unknown; remediation?: unknown; required_scope?: unknown; can_request?: unknown; hint?: unknown;
    granted_datatypes?: unknown; request_id?: unknown; request_action?: unknown;
    missing?: unknown; retry_after_seconds?: unknown; permission_request?: unknown;
  };
  const nested = body.error && typeof body.error === 'object' ? body.error as { code?: unknown; message?: unknown } : null;
  const rawTop = typeof body.code === 'string' && body.code ? body.code : undefined;
  const rawNested = nested?.code === undefined || nested.code === null ? undefined : String(nested.code);
  const code = knownCode(rawTop ?? (rawNested !== undefined && /^\d+$/.test(rawNested) ? undefined : rawNested));
  const cannotRequest = body.can_request === false;
  const scope = typeof body.required_scope === 'string' && KNOWN_SCOPES.has(body.required_scope) ? body.required_scope : undefined;
  const said = `Decoy answered HTTP ${status}${code ? ` ${code}` : ''}.`;
  const text = [nested?.message, body.error, body.message].filter((x): x is string => typeof x === 'string').join('\n');
  let message: string;
  // A grant limited to some kinds, asked for all of them: say what it covers and what to do.
  // The server listed kinds the connection holds on this account. Whatever they are (a later
  // server may name kinds this bridge does not know), this is never a reason to ask for access.
  const limited = status === 403 && code === 'INSUFFICIENT_GRANT' && Array.isArray(body.granted_datatypes) && body.granted_datatypes.length > 0;
  const granted = limited ? knownKinds(body.granted_datatypes) : [];
  if (limited && !granted.length) {
    message = `This read named no kind, so it asked for every secret kind of the account (${ACCOUNT_SECRET_KINDS.join(', ')}). ` +
      'Your access to this account covers only kinds this version of the bridge does not name. This is not missing access, so do not ask the owner for more: ' +
      'read again naming ONE kind per call (account_unlock with datatypes), or update the bridge.';
  } else if (granted.length) {
    message = `This read named no kind, so it asked for every secret kind of the account (${ACCOUNT_SECRET_KINDS.join(', ')}). ` +
      `Your access to this account covers: ${granted.join(', ')}. This is not missing access, so do not ask the owner for more: ` +
      `read again naming ONE of these kinds per call (account_unlock with datatypes: ["${granted[0]}"]).`;
  } else if (status === 422 && code === 'ONE_DATATYPE_PER_REQUEST') {
    message = 'This read named several kinds in datatypes. Name ONE kind per call: make one call for each kind you need.';
  } else if (code === 'ALERTS_OWNER_ONLY') {
    message = `${said} Alerts are not shared with agents: there is nothing to ask for. Leave them to the owner, who sees them in the Decoy app.`;
  } else if (code === 'PASSKEYS_OWNER_ONLY') {
    message = `${said} Agents do not add or remove passkeys: the owner adds and removes passkeys in the Decoy app. Editing an account (account.edit) covers its password, 2FA codes, notes and custom fields.`;
  } else if (code === 'ACCOUNT_EMAIL_GOES_WITH_ACCOUNT') {
    const acct = typeof (body as { account_id?: unknown }).account_id === 'string' && UUID_RE.test((body as { account_id: string }).account_id) ? (body as { account_id: string }).account_id : null;
    message = `${said} This is an account's Decoy email: it goes only with its account, and an agent does not burn, replace or rotate it on its own. ` +
      `Leave it as it is, or delete the whole account with its email (DELETE /accounts/${acct ?? '<account id>'}, the credential_delete tool; it needs account.delete).`;
  } else if (body.error === 'access_denied' || code === 'INSUFFICIENT_GRANT') {
    message = `Access denied: no grant on this connection covers this${code ? ` (${code})` : ''}.${cannotRequest ? ' This access cannot be requested by an agent; the owner grants it when connecting the agent.' : ''}`;
  } else if (code === 'SCOPE_MISSING') {
    message = scope === 'account.passkey_assert' && status === 403
      // Passkey sign-in is never asked for alone: it comes with Read on the account.
      ? `${said} This connection cannot do this.`
      : `${said} This connection lacks the capability this needs${scope && status === 403 && scopeFits(scope, request) && !knownPermissionAsk(body.permission_request, request) ? ` (${scope}). Ask with request_access(${(LEGACY_SCOPES[scope] ?? scope) === 'decoy.write' ? '{"permissions":["account.create"]}' : `{"capabilities":["${scope}"]}`}), then retry after the owner approves.` : scope ? ` (${scope}).` : '.'}`;
  } else {
    const specific = code && code !== 'BAD_REQUEST' && code !== 'SHAPE' ? CODE_SENTENCES[code] : undefined;
    message = `${said} ${specific ?? textSentence(text) ?? (code && CODE_SENTENCES[code]) ?? statusSentence(status)}`;
  }
  // An ask is suggested only for a refusal for lack of access, and only as far as knownAsk allows.
  // A refusal for want of the whole-vault or whole-mailbox key is one too when Decoy names the
  // Full access ask for it (wholeAsk accepts only that ask, only on those routes; any other ask on a
  // 404 is still held to its route's ceiling).
  const lacksAccess = (status === 403 && (code === 'INSUFFICIENT_GRANT' || code === 'SCOPE_MISSING' || code === 'GRANT_EXPIRED'))
    || ((status === 403 || status === 404) && (code === 'VAULT_KEY_REQUIRED' || code === 'MAILBOX_KEY_REQUIRED'))
    // The key routes answer a Full access that ENDED with GRANT_EXPIRED, on their 404 too.
    || (status === 404 && code === 'GRANT_EXPIRED');
  const remediation = body.remediation && typeof body.remediation === 'object' ? body.remediation as { tool?: unknown; args?: unknown } : null;
  // The permission request Decoy names comes first; the older remediation when it names none this
  // bridge can check (held to the same ceiling by knownAsk).
  const named = lacksAccess && !limited && !cannotRequest && body.permission_request !== undefined ? knownPermissionAsk(body.permission_request, request) : null;
  const older = !named && lacksAccess && !limited && !cannotRequest && remediation?.tool === 'request_access' ? knownAsk(remediation.args, request) : null;
  const ask = named ?? namedFromOlder(older) ?? older;
  if (ask) message += ` Ask with request_access(${JSON.stringify(ask)}), then retry after the owner approves.`;
  const permissionRequest = named ?? namedFromOlder(older);
  if (!limited && typeof body.hint === 'string' && KNOWN_HINTS.has(body.hint)) message += ` ${body.hint}`;
  // The API's own 404 names itself: a string message, or a code that is a name. The platform's
  // has neither (its nested code is the status number).
  const apiOwn = typeof body.error === 'string' || rawTop !== undefined || (rawNested !== undefined && !/^\d+$/.test(rawNested));
  const failure = Object.assign(new Error(message), {
    status,
    ...(code ? { code } : {}),
    ...(typeof body.current_rev === 'number' && Number.isInteger(body.current_rev) ? { current_rev: body.current_rev } : {}),
    ...(typeof body.kid === 'string' && /^[0-9a-f]{1,64}$/i.test(body.kid) ? { kid: body.kid } : {}),
    ...(typeof body.request_id === 'string' && UUID_RE.test(body.request_id) ? { request_id: body.request_id } : {}),
    ...(scope ? { required_scope: scope } : {}),
    ...(typeof body.request_action === 'string' && REQUEST_ACTIONS.has(body.request_action) ? { request_action: body.request_action } : {}),
    ...(cannotRequest ? { can_request: false as const } : {}),
    ...(permissionRequest ? { permission_request: permissionRequest } : {}),
    ...(granted.length ? { granted_datatypes: granted } : {}),
    ...(status === 404 && !apiOwn ? { routeMissing: true as const } : {}),
    // A memory's new key must reach these connections (409 HOLDERS_MISSING): ids, public keys and
    // reasons, checked here, so the bridge can wrap the key to them and send it again.
    ...(code === 'HOLDERS_MISSING' && Array.isArray(body.missing) ? { missing: knownHolders(body.missing) } : {}),
    ...(code === 'MEMORY_MOVING' && typeof body.retry_after_seconds === 'number' && body.retry_after_seconds > 0 && body.retry_after_seconds <= 3600
      ? { retry_after_seconds: Math.round(body.retry_after_seconds) } : {}),
  });
  Object.defineProperty(failure, SERVER_TEXT, { value: text, enumerable: false });
  return failure;
}

/** Holders a refused new key must reach: only well-formed entries (an id, a base64 key, reason words). */
function knownHolders(v: unknown[]): { token_id: string; public_key: string; via: string[] }[] {
  const out: { token_id: string; public_key: string; via: string[] }[] = [];
  for (const h of v.slice(0, 200) as { token_id?: unknown; public_key?: unknown; via?: unknown }[]) {
    if (!h || typeof h.token_id !== 'string' || !UUID_RE.test(h.token_id)) continue;
    if (typeof h.public_key !== 'string' || !/^[A-Za-z0-9+/=]{100,2000}$/.test(h.public_key) || !Array.isArray(h.via)) continue;
    const via = h.via.filter((x): x is string => typeof x === 'string' && /^(all|(category|topic|account):[A-Za-z0-9_:.-]{1,80}|and:[A-Za-z0-9_:.+-]{1,400})$/.test(x));
    if (via.length) out.push({ token_id: h.token_id, public_key: h.public_key, via });
  }
  return out;
}

/** The error for a request to Decoy that got no answer (the connection failed, or timed out). The
 *  runtime's own description of what went wrong is not repeated. It carries no status. */
export function noAnswer(): Error {
  return Object.assign(new Error('The request to Decoy got no answer.'), { code: 'NO_ANSWER' });
}
/** Said after a write that got no answer or a server failure. */
export const WRITE_OUTCOME_UNKNOWN = 'This was a write, and whether it was carried out is not known: read what it would have changed before sending it again.';

/** True only for an error apiFailure marked as a missing route. */
export function isRouteMissing(e: unknown): boolean {
  return !!e && typeof e === 'object' && (e as { routeMissing?: unknown }).routeMissing === true;
}
