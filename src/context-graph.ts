// Context: the official MCP Memory server knowledge graph, stored end-to-end encrypted in
// Decoy (docs/CONTEXT_KEY_PROTOCOL.md, docs/ACCESS_V2_MEMORY_PLAN.md). This module is the
// reference server's KnowledgeGraphManager with the JSONL file swapped for encrypted rows:
//
//   - same nine operations, same inputs, same results, same error text
//     (modelcontextprotocol/servers, src/memory/index.ts)
//   - one memory per graph object (entity, observation, relation), each with its own random
//     key (Access v2): sealed as a VAULT SealedBlob, the key wrapped to the owner, to this
//     agent, and to every other connection whose grant reaches it (lib/memory-access, ported
//     in memory-access.ts). `row_id` rides inside the ciphertext and is checked on open.
//   - a memory says what it is about — the user, a topic (its entity row id) or an account
//     (its id; never the account's name) — and that, with its categories, decides who reads it
//   - reads also merge the rows of the older per-space store (the Me space and account spaces)
//     until the owner's phone migrates them; nothing new is written there
//
// Decoy rules layered on top (spec 4 and 6.4):
//   - each granted account is an entity (`entityType` "account"), provided, not created.
//   - saving takes the "Save memories" grant. Read & write on a memory is the whole rule for changing
//     it — its text, topic and categories — and for deleting it, whoever saved it; the server
//     decides. A change of topic or categories must keep the memory inside what this connection can
//     write: the server can't read labels, so this bridge checks that before it sends. A delete that
//     would touch rows this agent may not remove removes nothing for that target and names it in `refused`.
//   - account entities cannot be deleted: accounts belong to Decoy.
//
// Topics (automatic topics through the normal memory tools): a topic is an entity row, named
// `topic:<row id>`. A memory about it is an observation with `observation.entityName` = the topic's
// name and `about: ["topic:<id>"]` (one topic per memory). A new topic gets one relation row to the
// user (`endpoints: ["user", "topic:<id>"]`) or to an existing topic, saved in the same request as
// the topic and its first memory. A topic is reachable when this agent can open its entity row OR
// any memory about it (a readable memory reveals its topic's name); nothing else is ever listed, so
// an agent that reaches none makes its own. Same-name topics are shown together by name (never
// merged); an exact normalized name reuses the oldest reachable one.

import { waitingFromList, type Waiting } from './waiting.js';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SubscribeRequestSchema, UnsubscribeRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createHash, createPublicKey, publicEncrypt, randomBytes, randomUUID, createCipheriv, constants, type KeyObject } from 'node:crypto';
import { ownSelectors, viaForSelectors, viaHeld, withV2Deletes, type MemoryFacts, type MemorySelectors, type ServedPermission } from './memory-access.js';
import { gatedRegister } from './register-tools.js';
import { MEM0_CATEGORIES } from './memory-engine.js';

export interface Entity { name: string; entityType: string; observations: string[] }
export interface Relation { from: string; to: string; relationType: string }
export interface KnowledgeGraph { entities: Entity[]; relations: Relation[] }

export type ApiCall = <T = unknown>(path: string, method?: string, body?: Record<string, unknown>) => Promise<T>;

export interface ContextGraphDeps {
  call: ApiCall;
  /** Unwrap a headerless RSA-OAEP envelope with this agent's private key → raw bytes. */
  unwrap: (wrappedBase64: string) => Buffer;
  /** This agent's public key (SPKI DER, base64) — for the wrap it keeps of a key it creates. */
  ownPublicKey: string;
  /** Granted accounts with their display names (decrypted locally by the bridge). */
  /** `linked`: whether a memory that was read is linked to an account (a caller that wants the
   *  names only to print them may answer with none when it is false). */
  accounts: (linked?: boolean) => Promise<{ id: string; name: string; site?: string | null }[]>;
  openVault: (blobBase64: string, key: Buffer) => Record<string, unknown>;
  sealVault: (value: unknown, key: Buffer) => string;
}

interface SpaceInfo { id: string; kind: 'me' | 'account'; account_id: string | null; skid: string; wrapped_key: string | null }
// The server stores no row kind: it is read from the opened plaintext.
type RowKind = 'entity' | 'observation' | 'relation';
/** A row as served: a space row (`skid`) or a row-keyed memory (`kid`, `wrapped_key`, `via`). */
interface WireRow {
  id: string; ciphertext: string; mine: boolean; skid?: string; kid?: string; wrapped_key?: string; via?: string[];
  rev?: number; author_kind?: 'owner' | 'agent'; created_at?: string; updated_at?: string;
}
const kindOf = (v: Record<string, unknown>): RowKind | undefined => (['entity', 'observation', 'relation'] as const).find(k => k in v);
/** `space` null = a row-keyed memory; `via` = why this agent reads it (served by the API). */
interface OpenRow { id: string; space: string | null; mine: boolean; via: string[] }

interface Node {
  entity: Entity;
  accountId: string | null;          // set for account entities
  topicId: string | null;            // the entity row id a memory about this topic names
  rows: OpenRow[];                   // entity rows
  obs: Map<string, OpenRow[]>;       // content → rows holding it
}
interface Edge { relation: Relation; rows: OpenRow[] }

interface Loaded {
  nodes: Map<string, Node>;
  edges: Edge[];
  opened: Opened[];
  /** The node each observation row sits on. */
  obsNode: Map<string, Node>;
  /** Every topic this agent reaches, by entity row id: its row, or a memory about it. */
  topics: Map<string, TopicInfo>;
  /** The topic (entity row id) each observation row is about. */
  topicOf: Map<string, string>;
  /** Where each topic hangs, by entity row id: only for a relation row this agent could open. */
  links: Map<string, TopicLink & { at: string; row: string; flagged: boolean }>;
  /** Every relation this agent could open between the user ('user') and topics (entity row ids),
   *  oldest first, with its rows (the same relation may be held by several). */
  ties: Tie[];
}
/** A relation between the user ('user') and a topic, or two topics, by entity row id. */
interface Tie { from: string; to: string; relation: string; rows: OpenRow[]; by?: 'another agent' }

/** The common topic types: the app's type picker and the docs use the same list. */
export const TOPIC_TYPES = ['device', 'document', 'event', 'goal', 'hobby', 'media', 'organization', 'person',
  'pet', 'place', 'product', 'project', 'team', 'trip'] as const;
/** The relation a new topic gets when the writer names none: from the user, or from a parent topic. */
export const DEFAULT_TOPIC_RELATION = 'is interested in';
export const DEFAULT_SUBTOPIC_RELATION = 'includes';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** An id a label inside a row may carry (`topic:<id>`, `account:<id>`): a row id, never text. */
const LABEL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

// ── What a stored row says is data ──
// A row is sealed, so the server cannot check what is inside one, and any connection that may
// save memories writes rows others read. Wherever the bridge prints a field of a row outside the
// memory's own text (a name, a relation, a type, a hint), it is one line and capped, and a value
// from a fixed list is printed only when it is on the list.
/** A topic's or an account's name as shown: at most this many characters. */
export const NAME_CHARS = 200;
/** A relation as shown: the length a writer may give one. */
export const RELATION_CHARS = 100;
/**
 * What one line of text from a stored row never keeps: whitespace and control characters, and
 * every character that is not shown itself but changes what is: format characters (the zero
 * width space, the marks, embeddings, overrides and isolates that reorder text, the word joiner,
 * the soft hyphen, tag characters), line and paragraph separators, variation selectors, the
 * combining grapheme joiner, the letters and symbols that are drawn as blank (Hangul fillers,
 * Khmer inherent vowels, the empty braille pattern), and half of a surrogate pair on its own.
 * The four in JOINS are the exception, and only where they join (see oneLine).
 */
const NOT_SHOWN = /(?:(?![\u200C\u200D\uFE0E\uFE0F])[\s\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Variation_Selector}\u034F\u115F\u1160\u17B4\u17B5\u2800\u3164\uFFA0])+/gu;
/** The characters a script or an emoji is drawn with: the zero width non-joiner and joiner
 *  (Persian, Hindi, emoji made of several), and the text and emoji variation selectors. */
const JOINS = /[\u200C\u200D\uFE0E\uFE0F]/g;
// A selector that does not directly follow a shown character.
const STRAY_SELECTOR = /(?<![^ \u200C\u200D\uFE0E\uFE0F])[\uFE0E\uFE0F]/gu;
// A joiner that is not directly followed by a shown character, then one that does not directly
// follow a shown character (or its selector).
const JOINER_BEFORE_NOTHING = /[\u200C\u200D](?![^ \u200C\u200D\uFE0E\uFE0F])/gu;
const JOINER_AFTER_NOTHING = /(?<![^ \u200C\u200D])[\u200C\u200D]/gu;
/** Text from a stored row as one line: every run of whitespace, control characters and
 *  characters that are not shown (NOT_SHOWN) is one space, and it is cut at `max`, never inside
 *  a character made of two code units. A joiner is kept only directly between two shown
 *  characters and a variation selector only directly after one, never two in a row, so they
 *  cannot stand alone, pad a line or make a blank one. Anything that is not text is nothing. */
export function oneLine(v: unknown, max: number): string {
  const t = (typeof v === 'string' ? v : '').replace(NOT_SHOWN, ' ')
    .replace(STRAY_SELECTOR, '').replace(JOINER_BEFORE_NOTHING, '').replace(JOINER_AFTER_NOTHING, '')
    .replace(/ +/g, ' ').trim();
  if (t.length <= max) return t;
  const lead = t.charCodeAt(max - 1);
  return `${t.slice(0, lead >= 0xD800 && lead <= 0xDBFF ? max - 1 : max).replace(/[\u200C\u200D]+$/, '')}…`;
}
/** A topic's type as shown: one of the known types, "" (none), or null (not known here). */
export const shownTopicType = (t: unknown): string | null =>
  t === '' ? '' : typeof t === 'string' && (TOPIC_TYPES as readonly string[]).includes(t) ? t : null;
/** A topic as shown in a result: its id, its name on one capped line, a known type. */
export const shownTopic = <T extends TopicRef>(t: T): T => ({ ...t, name: oneLine(t.name, NAME_CHARS), type: shownTopicType(t.type) });
const QUOTES = /^["'“”‘’`]+|["'“”‘’`]+$/g;
/** How topic names compare: NFKC, lowercase, whitespace collapsed, trimmed, surrounding quotes stripped. */
export function normalizeTopicName(name: string): string {
  return name.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim().replace(QUOTES, '').trim();
}
/**
 * How a name from an agent is matched with a stored one (a topic's, an account's): both as they
 * are shown (oneLine, at the length a name is shown at), without the joiners and selectors a
 * shown name keeps, then as topic names compare. So the name as stored, the name as shown and
 * the name typed without its joiners are one name.
 */
export function nameKey(name: string): string {
  return normalizeTopicName(oneLine(name, NAME_CHARS).replace(JOINS, ''));
}
/** What a second account of the same name carries after its name, so each can be named. */
export const accountSuffix = (id: string) => ` (${oneLine(id, 8)})`;
/** A new topic's stored name: the writer's, with whitespace collapsed and surrounding quotes stripped. */
const cleanTopicName = (name: string) => name.normalize('NFKC').replace(/\s+/g, ' ').trim().replace(QUOTES, '').trim();
const USER_NAMES = new Set(['default_user', 'user', 'you', 'me']);

/** A topic this agent reaches. `type` is null when only its memories are readable (not its row). */
export interface TopicInfo { id: string; name: string; type: string | null; mine: boolean; memories: number; createdAt: string; rowVisible: boolean }
/** Where a topic hangs: from the user ("you") or a parent topic, and the relation as it was written. */
export interface TopicLink {
  from: string; from_id?: string;
  /** Only when an agent other than this connection wrote the relation: said before it. */
  by?: 'another agent';
  relation: string;
}
/** A topic as a memory names it. `id` is `topic:<entity row id>`. */
export interface TopicRef { id: string; name: string; type: string | null }
/** A topic as list_topics shows it: same-name topics are one entry, under the oldest id. */
export type ListedTopic = TopicRef & { memories: number; mine: boolean; link?: TopicLink; sub_topics?: number };
/** A topic without its text: what read_topic says about every topic it names. */
export interface TopicBrief { id: string; name: string; type: string | null; memories: number }
/** read_topic. `direction` reads from the topic asked for ('out' = it is the relation's subject). */
export interface TopicView {
  topic: TopicBrief & { mine: boolean };
  parent: TopicLink | null;
  children: (TopicBrief & { relation: string; by?: 'another agent' })[];
  connections: ({ direction: 'in' | 'out'; relation: string; by?: 'another agent' } & (TopicBrief | { name: 'you' }))[];
  /** Depth 2 and 3: `via` is the topic it was reached through, `direction` reads from that topic. */
  nearby?: (TopicBrief & { distance: number; via: string; direction: 'in' | 'out'; relation: string })[];
  nearby_more?: number;
  /** The relation words in use (left out when there are none). */
  suggested_relations?: string[];
}
/** A relation as read_topic shows it: its ends by listed id (`topic:<id>`) or 'you'. */
interface ShownTie { from: string; to: string; relation: string; rows: OpenRow[]; by?: 'another agent' }
/** How many relation words list_topics and read_topic suggest. */
export const SUGGESTED_RELATIONS_MAX = 10;
/** How many topics beyond the direct ones read_topic lists (depth 2 and 3). */
export const NEARBY_TOPICS_MAX = 50;
/** `relationDefaulted`: a new topic, hung from the user, whose writer named no relation, so it got DEFAULT_TOPIC_RELATION. */
/** `parent`: the name of the topic it hangs under, when it hangs under one this agent can read. */
export interface TopicResult extends TopicRef { created: boolean; relationDefaulted?: boolean; parent?: string }
/** What a writer asks for: a topic by name or `topic:<id>`; type and link apply only when it is created. */
export interface TopicSpec { topic: string; type?: string; link?: { to?: string; relation?: string } }
/** A change to one memory. `topic` null = back to the user; `categories` replaces the set, `addCategories` adds. */
export interface MemoryChange { text?: string; categories?: string[]; addCategories?: string[]; topic?: TopicSpec | null; expectedRev?: number }
/** `parent`: the name of the topic the memory's topic hangs under, when there is one. */
export interface MemoryEdit { record: MemoryRecord; topic?: TopicResult | null; rotated: boolean; reconciled?: boolean; parent?: string }

/** A relabel that would move a memory outside what this connection can write. */
export const OUTSIDE_WRITE_SET = 'OUTSIDE_WRITE_SET';
/** The old store's answer while the owner's phone moves a row to its own key. */
export const MEMORY_MOVING = 'MEMORY_MOVING';
/** A new key that leaves out a connection reading the memory now: it names them, to wrap and retry. */
export const HOLDERS_MISSING = 'HOLDERS_MISSING';
/** A change to the topics that needs memory.edit (or memory.delete) on a topic this connection lacks it on. */
export const NEEDS_TOPIC_WRITE = 'NEEDS_TOPIC_WRITE';
/** A refusal of a topic tool that carries what to look at (the matches, what to do next). */
export class GraphRefusal extends Error {
  constructor(public payload: { error: string } & Record<string, unknown>) { super(payload.error); }
}
/** A topic as a write's `now` shows it: read_topic at depth 1, with the children counted. */
export interface TopicNow { topic: TopicBrief; parent: TopicLink | null; children: number; connections: TopicView['connections'] }

/** The request_access call that gives edit (or, with `verb` "delete", delete) for one label (a
 *  category from the known list, a topic id, an account id), or on every memory (null). Only values
 *  this bridge checked are named. */
function writeAsk(label: string | null, verb: 'edit' | 'delete' = 'edit'): string {
  if (label?.startsWith('category:') && (MEM0_CATEGORIES as readonly string[]).includes(label.slice(9))) {
    return `request_access({ permissions: ["memory.${verb}"], datatypes: ["${label.slice(9)}"] })`;
  }
  if (label?.startsWith('topic:') && LABEL_ID_RE.test(label.slice(6))) return `request_access({ permissions: ["memory.${verb}"], about: ["${label}"] })`;
  if (label?.startsWith('account:') && LABEL_ID_RE.test(label.slice(8))) return `request_access({ permissions: ["acctmem.${verb}"], account_id: "${label.slice(8)}" })`;
  return `request_access({ permissions: ["memory.${verb}"] })`;
}
/** The request_access call that gives edit (or delete) on this memory, scoped to how it is reached. */
export function writeRequestFor(record: Pick<MemoryRecord, 'via' | 'categories' | 'about'>, verb: 'edit' | 'delete' = 'edit'): string {
  return writeAsk(ContextGraph.askFor(record), verb);
}
/** The label to ask write on for a memory: the reason this connection reads it by, else one of the
 *  memory's own labels — narrowest first (a category, a topic, an account) — and every memory only
 *  when the memory has no label a grant can name. */
function askLabel(via: string[], labels: string[]): string | null {
  for (const prefix of ['category:', 'topic:', 'account:']) {
    const v = via.find(x => x.startsWith(prefix)) ?? via.find(x => x.startsWith('and:'))?.slice(4).split('+').find(x => x.startsWith(prefix));
    if (v) return v;
  }
  for (const prefix of ['category:', 'topic:', 'account:']) {
    const l = labels.find(x => x.startsWith(prefix) && (prefix !== 'category:' || (MEM0_CATEGORIES as readonly string[]).includes(x.slice(9))));
    if (l) return l;
  }
  return null;
}

/** The API answered no: nothing was written (a missing grant, a missing row, a stale revision or key). */
const definitelyRefused = (err: unknown) => {
  const e = err as { status?: number; code?: string } | null;
  return (e?.status !== undefined && [400, 403, 404, 409].includes(e.status))
    || ['INSUFFICIENT_GRANT', 'NOT_FOUND', 'REV_CONFLICT', 'KID_CONFLICT', 'BAD_REQUEST'].includes(e?.code ?? '');
};
/** How long to wait for the owner's phone to move an older memory: Decoy's time when usable, else 30 s. */
export function retryWait(seconds: unknown): number {
  const n = Number(seconds);
  return Number.isFinite(n) && n > 0 && n <= 3600 ? Math.round(n) : 30;
}
/** What is said while the owner's phone moves an older memory to its own key. */
export function movingText(what: 'changed' | 'deleted', wait: number): string {
  return `This memory is still in the older store, and Decoy has asked the user's phone to move it to its own key. Nothing was ${what}; retry in about ${wait} seconds.`;
}
const outcomeUnknown = (id: string) => Object.assign(new Error(`Decoy did not confirm the change to memory ${id}, so its outcome is unknown. ` +
  'Read it again with get_memory before retrying; any topic made for it was kept.'), { code: 'OUTCOME_UNKNOWN' });
/** `space` null = a row-keyed memory; `key` = the key it opened with (its own, or its space's). */
interface Opened { row: WireRow; space: SpaceInfo | null; value: Record<string, unknown>; key: Buffer }
/** A memory about to be saved: its plaintext and the labels that decide who may read it. */
interface NewRow { id: string; value: Record<string, unknown>; facts: Omit<MemoryFacts, 'row_id'> }
interface NewMemory { text: string; metadata?: Record<string, unknown>; categories?: string[] }
interface Grantees {
  owner_public_key: string | null;
  grantees: { token_id: string; public_key: string; selectors: MemorySelectors }[];
  /** This connection's own reach: its own wrap is kept for the read reasons it holds (saving gives none). */
  self?: { token_id: string; selectors: MemorySelectors };
}

/** One observation row as a memory (mem0's unit): the fact, where it sits, who wrote it. */
export interface MemoryRecord {
  id: string;
  text: string;
  entityName: string;
  accountId: string | null;
  mine: boolean;
  authorKind: 'owner' | 'agent';
  rev: number;
  createdAt: string;
  updatedAt: string;
  metadata?: Record<string, unknown>;
  /** mem0's categories (its default list), sealed in the row like metadata. */
  categories?: string[];
  /** A place the writer named that is not a granted account (mem0's app_id), sealed in the row. */
  aboutHint?: string;
  /** The topic it is filed under, or null (about the user, or an account). */
  topic: TopicRef | null;
  /** Its labels as sealed: 'user' | 'topic:<id>' | 'account:<id>'. */
  about: string[];
  /** Why this agent reads it (served by the API); empty for the older store. */
  via: string[];
  /** 'row' = its own key; 'space' = the older per-space store (until the owner's phone migrates it). */
  stored: 'row' | 'space';
}
export const USER_ENTITY = 'default_user';

export const skidOf = (key: Buffer) => createHash('sha256').update(key).digest().subarray(0, 8).toString('hex');

/** Headerless RSA-OAEP-256 + AES-256-GCM wrap of a 32-byte key to a recipient.
 *  Byte-identical to the Decoy API's wrapVaultKeyForRecipient. */
export function wrapKeyForRecipient(key: Buffer, recipientSpkiBase64: string): string {
  return sealBytesForRecipient(key, recipientSpkiBase64);
}

/** The same headerless envelope over any bytes: [2B keyLen BE][RSA-OAEP-SHA256 AES key][12B iv]
 *  [AES-256-GCM ct][16B tag], base64. This is the accounts.encrypted_password format (what
 *  account_set_credential seals) and what the owner's devices open for a decoy edit. */
export function sealBytesForRecipient(plaintext: Buffer, recipientSpkiBase64: string): string {
  const recipient: KeyObject = createPublicKey({ key: Buffer.from(recipientSpkiBase64, 'base64'), format: 'der', type: 'spki' });
  return envelopeBody(plaintext, recipient).toString('base64');
}

/** SealedBlob ENVELOPE ([0x01][0x02] + headerless envelope) of a UTF-8 payload to the owner.
 *  Byte-identical to the Decoy API's sealEnvelopeForOwner. */
export function sealEnvelopeForOwner(payload: string, ownerSpkiBase64: string): string {
  const owner = createPublicKey({ key: Buffer.from(ownerSpkiBase64, 'base64'), format: 'der', type: 'spki' });
  return Buffer.concat([Buffer.from([0x01, 0x02]), envelopeBody(Buffer.from(payload, 'utf8'), owner)]).toString('base64');
}

function envelopeBody(plaintext: Buffer, recipient: KeyObject): Buffer {
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wrapped = publicEncrypt({ key: recipient, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, contentKey);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(wrapped.length, 0);
  return Buffer.concat([len, wrapped, iv, ct, tag]);
}

const sameRelation = (a: Relation, b: Relation) => a.from === b.from && a.to === b.to && a.relationType === b.relationType;
const describeRelation = (r: Relation) => `${r.from} ${r.relationType} ${r.to}`;
/** The API refused for lack of a grant (403 INSUFFICIENT_GRANT). */
const denied = (err: unknown) => {
  const e = err as { status?: number; code?: string } | null;
  return e?.status === 403 || e?.code === 'INSUFFICIENT_GRANT';
};

export class ContextGraph {
  constructor(private deps: ContextGraphDeps) {}

  // Serializes every read-modify-write mutation, as the reference server does (#1819).
  private mutationQueue: Promise<unknown> = Promise.resolve();
  private withLock<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(operation, operation);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private keyCache = new Map<string, Buffer>();   // `${space_id | row_id}:${skid | kid}` → key

  private waitingNow: Waiting[] = [];
  /** The memories the last read found waiting on the owner's Decoy app (src/waiting.ts). They are
   *  in no result: a caller that lists or searches says so beside what it returns. */
  waiting(): Waiting[] { return this.waitingNow; }

  private async load(): Promise<Loaded> {
    const { call } = this.deps;
    const listed = await call<{ spaces: SpaceInfo[]; me_granted: boolean; account_ids: string[] | null }>('/context/spaces');
    const opened: Opened[] = [];
    // The older per-space store, read until the owner's phone migrates it. The spaces are fetched
    // together, then opened in the listed order, so the graph doesn't depend on which answers first.
    const spaces = listed.spaces.flatMap((info) => {
      const key = this.keyFor(`${info.id}:${info.skid}`, info.wrapped_key, info.skid);
      return key ? [{ info, key }] : [];
    });
    const fetched = await Promise.all(spaces.map(({ info }) =>
      call<{ rows: WireRow[] }>(`/context/rows?space_id=${encodeURIComponent(info.id)}`)));
    for (const [i, { info, key }] of spaces.entries()) {
      const got = fetched[i];
      for (const row of got.rows) {
        if (row.skid !== info.skid) continue;
        try {
          const value = this.deps.openVault(row.ciphertext, key);
          // The ids inside the ciphertext bind it to this row in this space (spec 5.1).
          if (value.space_id !== info.id || value.row_id !== row.id) continue;
          opened.push({ row, space: info, value, key });
        } catch { /* unreadable row: skip, as the reference skips a corrupt line */ }
      }
    }
    // Row-keyed memories: the ones this agent can open now, each with its own key. The ones it
    // may read and cannot open are not dropped: Decoy names their state (waitingFromList), and a
    // row listed with no key this connection can use is counted with them (state `unknown` when
    // Decoy gave none for it).
    const served = await call<{ memories: WireRow[] }>('/context/memories');
    const waiting = waitingFromList('memories', served);
    const named = new Set(waiting.flatMap((w) => w.ids ?? []));
    let keyless = 0;
    for (const row of served.memories) {
      const key = row.kid ? this.keyFor(`${row.id}:${row.kid}`, row.wrapped_key ?? null, row.kid) : null;
      if (!key) { if (!named.has(row.id)) keyless++; continue; }
      try {
        const value = this.deps.openVault(row.ciphertext, key);
        if (value.v !== 2 || value.row_id !== row.id) continue;
        opened.push({ row, space: null, value, key });
      } catch { /* unreadable */ }
    }
    if (keyless) waiting.push({ kind: 'memories', state: 'unknown', count: keyless });
    this.waitingNow = waiting;
    // Oldest first across both stores, so the first writer of a name wins its type.
    opened.sort((a, b) => (a.row.created_at ?? '').localeCompare(b.row.created_at ?? ''));

    const nodes = new Map<string, Node>();
    const edges: Edge[] = [];
    const granted = listed.account_ids === null ? null : new Set(listed.account_ids);
    // Whether anything that was read is linked to an account: only then does a name get printed.
    const linked = opened.some(o => o.space?.kind === 'account'
      || (Array.isArray(o.value.about) && o.value.about.some(a => typeof a === 'string' && a.startsWith('account:'))));
    const vault = await this.deps.accounts(linked);
    const names = new Map<string, number>();
    // An account's name is one capped line here, so it is the same wherever it is shown and matched.
    const addAccount = (raw: { id: string; name: string }) => {
      const a = { id: raw.id, name: oneLine(raw.name, NAME_CHARS) || `Account ${oneLine(raw.id, 8)}` };
      // Counted as names are matched, so the second of two that match carries its id.
      const n = (names.get(nameKey(a.name)) ?? 0) + 1;
      names.set(nameKey(a.name), n);
      const name = n === 1 && !nodes.has(a.name) ? a.name : `${a.name}${accountSuffix(a.id)}`;
      const node: Node = { entity: { name, entityType: 'account', observations: [] }, accountId: a.id, topicId: null, rows: [], obs: new Map() };
      nodes.set(name, node);
      return node;
    };
    for (const a of vault) if (!granted || granted.has(a.id)) addAccount(a);
    // A memory may name an account this agent was not granted (it reads it by category, topic or
    // "all"): the account still shows as an entity, named locally — never from the memory.
    const accountNode = (id: string) => [...nodes.values()].find(n => n.accountId === id)
      ?? addAccount(vault.find(a => a.id === id) ?? { id, name: `Account ${id.slice(0, 8)}` });
    // A label names a topic or an account by its id. One that carries anything else is not a label.
    const labelId = (label: string, prefix: string) => { const id = label.slice(prefix.length); return LABEL_ID_RE.test(id) ? id : null; };
    const ref = (o: Opened): OpenRow => ({ id: o.row.id, space: o.space?.id ?? null, mine: o.row.mine, via: o.row.via ?? [] });
    const byTopic = new Map<string, Node>();
    const topics = new Map<string, TopicInfo>();
    const topicOf = new Map<string, string>();
    const links: Loaded['links'] = new Map();
    const ties: Tie[] = [];

    for (const o of opened) {
      const e = o.value.entity as { name?: unknown; entityType?: unknown } | undefined;
      if (kindOf(o.value) !== 'entity' || (o.space && o.space.kind !== 'me') || !e || typeof e.name !== 'string' || typeof e.entityType !== 'string') continue;
      let node = nodes.get(e.name);
      if (node?.accountId) continue;
      if (node) { node.rows.push(ref(o)); node.topicId ??= o.row.id; }
      else {
        node = { entity: { name: e.name, entityType: e.entityType, observations: [] }, accountId: null, topicId: o.row.id, rows: [ref(o)], obs: new Map() };
        nodes.set(e.name, node);
      }
      // The user's own entity row is not a topic: a memory naming its id never lands on the user.
      if (e.name === USER_ENTITY) continue;
      byTopic.set(o.row.id, node);
      topics.set(o.row.id, { id: o.row.id, name: e.name, type: e.entityType, mine: o.row.mine, memories: 0, createdAt: o.row.created_at ?? '', rowVisible: true });
    }
    // Readers are tolerant (same rule as the iOS app): a fact or a connection naming an entity
    // nobody wrote a row for (or one this agent can't see) implies that entity (type unknown,
    // ''), so read_graph and the owner's app never disagree. Writers stay strict: the tools
    // still reject unknown names.
    const implied = (name: string) => {
      const found = nodes.get(name);
      if (found) return found;
      const node: Node = { entity: { name, entityType: '', observations: [] }, accountId: null, topicId: null, rows: [], obs: new Map() };
      nodes.set(name, node);
      return node;
    };
    const obsNode = new Map<string, Node>();
    for (const o of opened) {
      const ob = o.value.observation as { entityName?: unknown; content?: unknown } | undefined;
      if (kindOf(o.value) !== 'observation' || !ob || typeof ob.content !== 'string') continue;
      const named = typeof ob.entityName === 'string' && ob.entityName ? ob.entityName : null;
      let node: Node | undefined;
      let topicId: string | null = null;
      if (o.space) {
        // In an account space every observation belongs to that account, even after a rename.
        node = o.space.kind === 'account' ? [...nodes.values()].find(n => n.accountId === o.space!.account_id) : named ? implied(named) : undefined;
        if (node && o.space.kind === 'me' && node.accountId) continue;
        if (node && o.space.kind === 'me' && node.entity.name !== USER_ENTITY && node.topicId && topics.has(node.topicId)) topicId = node.topicId;
      } else {
        // One topic per memory: the first label decides where it shows.
        const about = (Array.isArray(o.value.about) ? o.value.about : []).find((a): a is string => typeof a === 'string');
        const labelled = about?.startsWith('account:') ? labelId(about, 'account:') : about?.startsWith('topic:') ? labelId(about, 'topic:') : undefined;
        if (labelled === null) continue; // a label that is not an id: the row is not shown anywhere
        if (about === 'user') node = implied(USER_ENTITY);
        else if (about?.startsWith('account:')) node = accountNode(labelled!);
        else if (about?.startsWith('topic:')) {
          topicId = labelled!;
          node = byTopic.get(topicId);
          if (!node) {
            // Its row is not readable here: the memory's sealed name names it. A topic memory is never
            // shown under the user (or an account), even when that name is stale or missing.
            const usable = named && !USER_NAMES.has(nameKey(named)) && !nodes.get(named)?.accountId ? named : null;
            node = implied(usable ?? `Topic ${topicId.slice(0, 8)}`);
            node.topicId ??= topicId;
            byTopic.set(topicId, node);
          }
          if (!topics.has(topicId)) {
            topics.set(topicId, { id: topicId, name: node.entity.name, type: null, mine: false, memories: 0, createdAt: o.row.created_at ?? '', rowVisible: false });
          }
        } else node = named ? implied(named) : undefined;
      }
      if (!node) continue;
      obsNode.set(o.row.id, node);
      if (topicId) { topicOf.set(o.row.id, topicId); topics.get(topicId)!.memories++; }
      const holders = node.obs.get(ob.content);
      if (holders) { holders.push(ref(o)); continue; }
      node.obs.set(ob.content, [ref(o)]);
      node.entity.observations.push(ob.content);
    }
    for (const o of opened) {
      const r = o.value.relation as Partial<Relation> | undefined;
      if (kindOf(o.value) !== 'relation' || !r || typeof r.relationType !== 'string') continue;
      // A row-keyed relation names an account end by id only; the name is resolved here.
      const ends = o.space ? [] : (Array.isArray(o.value.endpoints) ? o.value.endpoints : []) as unknown[];
      const end = (name: unknown, i: number) => {
        const ep = ends[i];
        const id = typeof ep === 'string' && ep.startsWith('account:') ? labelId(ep, 'account:') : null;
        return id ? accountNode(id).entity.name : name;
      };
      const from = end(r.from, 0), to = end(r.to, 1);
      if (typeof from !== 'string' || typeof to !== 'string') continue;
      const relation = { from, to, relationType: r.relationType };
      for (const name of [from, to]) if (name) implied(name);
      const existing = edges.find(x => sameRelation(x.relation, relation));
      if (existing) existing.rows.push(ref(o)); else edges.push({ relation, rows: [ref(o)] });
      // Where a topic hangs: a relation from the user or from another topic to it. A row-keyed
      // relation says so in its ends; an older one only by name. The oldest one is the one the
      // topic was made with.
      const topicIdOf = (i: number, name: string) => {
        const ep = ends[i];
        if (typeof ep === 'string') return ep === 'user' ? 'user' : ep.startsWith('topic:') ? labelId(ep, 'topic:') : null;
        if (name === USER_ENTITY) return 'user';
        const id = nodes.get(name)?.topicId;
        return id && topics.has(id) ? id : null;
      };
      const child = topicIdOf(1, to), parent = topicIdOf(0, from);
      const by = !o.row.mine && (o.row.author_kind ?? 'agent') === 'agent' ? { by: 'another agent' as const } : {};
      if (child && parent && parent !== child) {
        const tie = ties.find(t => t.from === parent && t.to === child && t.relation === r.relationType);
        if (tie) tie.rows.push(ref(o)); else ties.push({ from: parent, to: child, relation: r.relationType, rows: [ref(o)], ...by });
      }
      if (!child || child === 'user' || !parent || parent === child) continue;
      // The parent: the newest link written as one (set_topic_parent flags it with `parent: true` at
      // the top level of the row); with none flagged, the oldest link, the one the topic was made with.
      const at = o.row.created_at ?? '';
      const flagged = o.value.parent === true;
      const held = links.get(child);
      if (held) {
        const newer = (held.at.localeCompare(at) || held.row.localeCompare(o.row.id)) < 0;
        if (held.flagged ? !flagged || !newer : !flagged && newer) continue;
      }
      links.set(child, {
        ...(parent === 'user' ? { from: 'you' } : { from: topics.get(parent)?.name ?? from, from_id: `topic:${parent}` }),
        ...by,
        relation: r.relationType, at, row: o.row.id, flagged,
      });
    }
    return { nodes, edges, opened, obsNode, topics, topicOf, links, ties };
  }

  /** Unwrap a key (a space key or a memory's own) and check it against its fingerprint. */
  private keyFor(cacheKey: string, wrapped: string | null, fingerprint: string): Buffer | null {
    const cached = this.keyCache.get(cacheKey);
    if (cached) return cached;
    if (!wrapped) return null;
    try {
      const key = this.deps.unwrap(wrapped);
      if (key.length !== 32 || skidOf(key) !== fingerprint) return null;
      this.keyCache.set(cacheKey, key);
      return key;
    } catch { return null; }
  }

  // ── Writing: every new object is a row-keyed memory ──

  private static entityRow(name: string, entityType: string): NewRow {
    return { id: randomUUID(), value: { entity: { name, entityType }, about: [] }, facts: { kind: 'entity', categories: [], about: [] } };
  }

  /** What a memory about `node` names: the user, an account (by id), or a topic (its entity row,
   *  queued in `pending` first when the topic has none this agent can see). */
  private labelOf(node: Node, pending: NewRow[]): string {
    if (node.accountId) return `account:${node.accountId}`;
    if (node.entity.name === USER_ENTITY) return 'user';
    if (!node.topicId) {
      const row = ContextGraph.entityRow(node.entity.name, node.entity.entityType);
      pending.push(row);
      node.topicId = row.id;
      node.rows.push({ id: row.id, space: null, mine: true, via: ['self'] });
    }
    return `topic:${node.topicId}`;
  }

  private static observationRow(node: { accountId: string | null; entity: { name: string } }, label: string, content: string, extra: { metadata?: Record<string, unknown>; categories?: string[]; aboutHint?: string } = {}): NewRow {
    const categories = [...new Set(extra.categories ?? [])];
    return {
      id: randomUUID(),
      value: {
        // An account's name is never sealed: readers resolve `account:<id>` locally.
        observation: node.accountId ? { content } : { entityName: node.entity.name, content },
        about: [label],
        ...(categories.length ? { categories } : {}),
        ...(extra.aboutHint ? { about_hint: extra.aboutHint } : {}),
        ...(extra.metadata ? { metadata: extra.metadata } : {}),
      },
      facts: { kind: 'observation', categories, about: [label] },
    };
  }

  private relationRow(g: Loaded, r: Relation, pending: NewRow[]): NewRow {
    const from = g.nodes.get(r.from)!, to = g.nodes.get(r.to)!;
    const endpoints = [this.labelOf(from, pending), this.labelOf(to, pending)];
    return {
      id: randomUUID(),
      value: { relation: { from: from.accountId ? '' : r.from, to: to.accountId ? '' : r.to, relationType: r.relationType }, endpoints, about: [] },
      facts: { kind: 'relation', categories: [], about: [], endpoints },
    };
  }

  /** Seal each row under its own key and save it: wrapped to the owner, to this agent, and to every
   *  other connection whose grant reaches it (no grant is needed to save). */
  private async saveRows(rows: NewRow[]): Promise<void> {
    if (!rows.length) return;
    const keys = await this.deps.call<Grantees>('/context/memory-grantees');
    if (!keys.owner_public_key) throw new Error('The account owner has not finished key setup on a device yet, so context cannot be stored.');
    // A topic, its link and its first memories go in ONE request (rows are queued in that order).
    for (let i = 0; i < rows.length; i += 200) {
      const batch = rows.slice(i, i + 200).map(r => {
        const key = randomBytes(32);
        const kid = skidOf(key);
        this.keyCache.set(`${r.id}:${kid}`, key);
        const facts = { row_id: r.id, ...r.facts };
        return {
          id: r.id, kid,
          ciphertext: this.deps.sealVault({ v: 2, row_id: r.id, ...r.value }, key),
          owner_wrap: sealEnvelopeForOwner(key.toString('base64'), keys.owner_public_key!),
          self_wrap: wrapKeyForRecipient(key, this.deps.ownPublicKey),
          // Kept for the read reasons this connection holds on it now; saving alone gives none.
          ...(keys.self ? { self_via: viaForSelectors(keys.self.selectors, facts) } : {}),
          grantee_wraps: keys.grantees.flatMap(t => {
            const via = viaForSelectors(t.selectors, facts);
            return via.length ? [{ token_id: t.token_id, via, wrapped_key: wrapKeyForRecipient(key, t.public_key) }] : [];
          }),
        };
      });
      await this.postOnce({ rows: batch });
    }
  }

  /** POST sealed rows. When the outcome is unknown (no answer, or a 5xx), the SAME sealed rows with
   *  the same ids are sent again: the server keeps the first copy of an id and answers `existing`
   *  for it, so a lost answer never becomes a second memory. */
  private async postOnce(body: { rows: unknown[] }): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try {
        await this.deps.call('/context/memories', 'POST', body);
        return;
      } catch (err) {
        const status = (err as { status?: number } | null)?.status;
        if ((status !== undefined && status < 500) || attempt >= 3) throw err;
        await new Promise(resolve => setTimeout(resolve, 250 * attempt));
      }
    }
  }

  // ── Deleting: memory.delete on each memory, whoever saved it ──

  /** Which rows this agent may delete, by the same rule the server applies: a reason that grants
   *  write, whoever saved it. An older space row's reason is sealed in it, so any
   *  write this connection holds lets the server decide; if the grants can't be read, the server decides. */
  private async deletable(rows: OpenRow[]): Promise<(r: OpenRow) => boolean> {
    const held = rows.length ? await this.policies() : null;
    const perms = held && withV2Deletes(held);
    const s = perms && ownSelectors(perms, 'destroy');
    const anyDelete = !s || s.all || s.categories.length > 0 || s.topics.length > 0 || s.account_ids.length > 0 || s.account_wildcard;
    // Deleting needs memory.delete (acctmem.delete), also on this agent's own rows (an older
    // grant's write still deletes).
    return (r: OpenRow) => r.space ? anyDelete : (perms === null || r.via.some(v => viaHeld(perms!, v, 'destroy')));
  }

  /** Delete rows; returns the ids the API refused, and the older rows it is moving to their own keys first. */
  private async deleteRows(rows: OpenRow[]): Promise<Set<string>> {
    return (await this.deleteRowsDetailed(rows)).refused;
  }

  private async deleteRowsDetailed(rows: OpenRow[]): Promise<{ refused: Set<string>; moving: Set<string>; retryAfter?: number }> {
    const refused = new Set<string>(), moving = new Set<string>();
    let retryAfter: number | undefined;
    const old = [...new Set(rows.filter(r => r.space).map(r => r.id))];
    const fresh = [...new Set(rows.filter(r => !r.space).map(r => r.id))];
    for (let i = 0; i < old.length; i += 500) {
      const res = await this.deps.call<{ refused?: string[]; moving?: string[]; retry_after_seconds?: number }>('/context/rows/delete', 'POST', { ids: old.slice(i, i + 500) });
      for (const id of res?.refused ?? []) refused.add(id);
      for (const id of res?.moving ?? []) { moving.add(id); refused.add(id); }
      if (res?.moving?.length) retryAfter = res.retry_after_seconds;
    }
    for (let i = 0; i < fresh.length; i += 500) {
      const res = await this.deps.call<{ refused?: string[] }>('/context/memories/delete', 'POST', { ids: fresh.slice(i, i + 500) });
      for (const id of res.refused ?? []) refused.add(id);
    }
    return { refused, moving, ...(retryAfter !== undefined ? { retryAfter } : {}) };
  }

  async createEntities(entities: Entity[]): Promise<Entity[]> {
    return this.withLock(async () => {
      const g = await this.load();
      const newEntities = entities.filter((e, index) =>
        !g.nodes.has(e.name) && !entities.slice(0, index).some(earlier => earlier.name === e.name));
      const rows: NewRow[] = [];
      for (const e of newEntities) {
        const row = ContextGraph.entityRow(e.name, e.entityType);
        rows.push(row);
        const node: Node = { entity: { name: e.name, entityType: e.entityType, observations: [] }, accountId: null, topicId: row.id, rows: [], obs: new Map() };
        const label = this.labelOf(node, rows);
        for (const content of new Set(e.observations)) rows.push(ContextGraph.observationRow(node, label, content));
      }
      await this.saveRows(rows);
      return newEntities;
    });
  }

  async createRelations(relations: Relation[]): Promise<Relation[]> {
    return this.withLock(async () => {
      const g = await this.load();
      relations.forEach(r => {
        if (!g.nodes.has(r.from)) throw new Error(`Entity with name ${r.from} not found`);
        if (!g.nodes.has(r.to)) throw new Error(`Entity with name ${r.to} not found`);
      });
      const newRelations = relations.filter((r, index) =>
        !g.edges.some(e => sameRelation(e.relation, r)) && !relations.slice(0, index).some(earlier => sameRelation(earlier, r)));
      const rows: NewRow[] = [];
      for (const r of newRelations) rows.push(this.relationRow(g, r, rows));
      await this.saveRows(rows);
      return newRelations;
    });
  }

  async addObservations(observations: { entityName: string; contents: string[] }[]): Promise<{ entityName: string; addedObservations: string[] }[]> {
    return this.withLock(async () => {
      const g = await this.load();
      const pending = new Map<Node, string[]>();
      const results = observations.map(o => {
        const node = g.nodes.get(o.entityName);
        if (!node) throw new Error(`Entity with name ${o.entityName} not found`);
        const newObservations = o.contents.filter(content => !node.entity.observations.includes(content));
        node.entity.observations.push(...newObservations);
        pending.set(node, [...(pending.get(node) ?? []), ...newObservations]);
        return { entityName: o.entityName, addedObservations: newObservations };
      });
      const rows: NewRow[] = [];
      for (const [node, contents] of pending) {
        if (!contents.length) continue;
        const label = this.labelOf(node, rows);
        for (const content of new Set(contents)) rows.push(ContextGraph.observationRow(node, label, content));
      }
      await this.saveRows(rows);
      return results;
    });
  }

  async deleteEntities(entityNames: string[]): Promise<{ deleted: string[]; notFound: string[]; refused?: string[]; moving?: string[]; retryAfter?: number }> {
    return this.withLock(async () => {
      const g = await this.load();
      const notFound: string[] = [], refused: string[] = [];
      const cascades = new Map<string, OpenRow[]>();
      for (const name of entityNames) {
        const node = g.nodes.get(name);
        if (!node) { notFound.push(name); continue; }
        if (node.accountId) { refused.push(name); continue; }
        cascades.set(name, [...node.rows, ...[...node.obs.values()].flat(),
          ...g.edges.filter(e => e.relation.from === name || e.relation.to === name).flatMap(e => e.rows)]);
      }
      // Deleting an entity takes its observations and relations with it — all of them are this
      // agent's to remove, or none are.
      const may = await this.deletable([...cascades.values()].flat());
      for (const [name, rows] of cascades) if (rows.some(r => !may(r))) { refused.push(name); cascades.delete(name); }
      const out = await this.deleteRowsDetailed([...cascades.values()].flat());
      const deleted: string[] = [], moving: string[] = [];
      for (const [name, rows] of cascades) (rows.some(r => out.moving.has(r.id)) ? moving : rows.some(r => out.refused.has(r.id)) ? refused : deleted).push(name);
      return { deleted, notFound, ...(refused.length ? { refused } : {}), ...ContextGraph.movingOf(moving, out) };
    });
  }

  async deleteObservations(deletions: { entityName: string; observations: string[] }[]): Promise<{ deletedCount: number; missingEntities: string[]; refused?: string[]; moving?: string[]; retryAfter?: number }> {
    return this.withLock(async () => {
      const g = await this.load();
      const missingEntities: string[] = [], refused: string[] = [];
      const groups: { content: string; rows: OpenRow[] }[] = [];   // one per observation asked for
      deletions.forEach(d => {
        const node = g.nodes.get(d.entityName);
        if (!node) { missingEntities.push(d.entityName); return; }
        for (const content of new Set(d.observations)) {
          const rows = node.obs.get(content);
          if (!rows) continue;
          node.obs.delete(content);
          groups.push({ content, rows });
        }
      });
      const may = await this.deletable(groups.flatMap(x => x.rows));
      const removable = groups.filter(x => {
        if (x.rows.every(may)) return true;
        refused.push(x.content);
        return false;
      });
      const out = await this.deleteRowsDetailed(removable.flatMap(x => x.rows));
      let deletedCount = 0;
      const moving: string[] = [];
      for (const x of removable) {
        if (x.rows.some(r => out.moving.has(r.id))) moving.push(x.content);
        else if (x.rows.some(r => out.refused.has(r.id))) refused.push(x.content); else deletedCount++;
      }
      return { deletedCount, missingEntities, ...(refused.length ? { refused } : {}), ...ContextGraph.movingOf(moving, out) };
    });
  }

  async deleteRelations(relations: Relation[]): Promise<{ deletedCount: number; refused?: string[]; moving?: string[]; retryAfter?: number }> {
    return this.withLock(async () => {
      const g = await this.load();
      const refused: string[] = [];
      const matched = g.edges.filter(edge => relations.some(r => sameRelation(r, edge.relation)));
      const may = await this.deletable(matched.flatMap(e => e.rows));
      const removable = matched.filter(edge => {
        if (edge.rows.every(may)) return true;
        refused.push(describeRelation(edge.relation));
        return false;
      });
      const out = await this.deleteRowsDetailed(removable.flatMap(e => e.rows));
      let deletedCount = 0;
      const moving: string[] = [];
      for (const edge of removable) {
        if (edge.rows.some(r => out.moving.has(r.id))) moving.push(describeRelation(edge.relation));
        else if (edge.rows.some(r => out.refused.has(r.id))) refused.push(describeRelation(edge.relation)); else deletedCount++;
      }
      return { deletedCount, ...(refused.length ? { refused } : {}), ...ContextGraph.movingOf(moving, out) };
    });
  }

  /** The part of a delete's answer for what is still being moved to its own key. */
  private static movingOf(moving: string[], out: { retryAfter?: number }): { moving?: string[]; retryAfter?: number } {
    return moving.length ? { moving, retryAfter: retryWait(out.retryAfter) } : {};
  }

  // ── Memories (mem0's unit): each observation row is one memory, addressed by its row id ──

  private static record(o: Opened, node: Node | undefined, topic: TopicInfo | undefined): MemoryRecord | null {
    const ob = o.value.observation as { entityName?: unknown; content?: unknown } | undefined;
    if (kindOf(o.value) !== 'observation' || !ob || typeof ob.content !== 'string') return null;
    const entityName = node?.entity.name ?? (typeof ob.entityName === 'string' ? ob.entityName : '');
    if (!entityName) return null;
    const metadata = o.value.metadata && typeof o.value.metadata === 'object' ? o.value.metadata as Record<string, unknown> : undefined;
    const categories = Array.isArray(o.value.categories) ? (o.value.categories as unknown[]).filter((c): c is string => typeof c === 'string') : undefined;
    const aboutHint = typeof o.value.about_hint === 'string' && o.value.about_hint ? o.value.about_hint : undefined;
    const at = o.row.created_at ?? new Date(0).toISOString();
    const about = (Array.isArray(o.value.about) ? o.value.about : []).filter((a): a is string => typeof a === 'string');
    return {
      id: o.row.id, text: ob.content, entityName, accountId: node?.accountId ?? o.space?.account_id ?? null, mine: o.row.mine,
      // A row that states no author is never taken for the owner's: this connection's own is an
      // agent's, and so is anyone else's until the server says otherwise.
      authorKind: o.row.author_kind ?? 'agent', rev: o.row.rev ?? 1,
      createdAt: at, updatedAt: o.row.updated_at ?? at, ...(metadata ? { metadata } : {}),
      ...(categories ? { categories } : {}), ...(aboutHint ? { aboutHint } : {}),
      topic: topic ? { id: `topic:${topic.id}`, name: node?.entity.name ?? topic.name, type: topic.type } : null,
      about, via: o.row.via ?? [], stored: o.space ? 'space' : 'row',
    };
  }

  private recordsOf(g: Loaded): MemoryRecord[] {
    return g.opened.flatMap(o => {
      const t = g.topicOf.get(o.row.id);
      const r = ContextGraph.record(o, g.obsNode.get(o.row.id), t ? g.topics.get(t) : undefined);
      return r ? [r] : [];
    });
  }

  // ── Topics ──

  /** Reachable topics, shown once per name (same-name topics together, under the oldest id). */
  private static topicList(g: Loaded, query?: string): ListedTopic[] {
    const { groups, shownId } = ContextGraph.topicGroups(g);
    const q = query ? nameKey(query) : '';
    const linkOf = (list: TopicInfo[]) => list.map(t => g.links.get(t.id)).find(Boolean);
    const children = new Map<string, number>();
    for (const list of groups.values()) {
      const parent = linkOf(list)?.from_id?.slice('topic:'.length);
      const shown = parent ? shownId.get(parent) : undefined;
      if (shown && shown !== list[0].id) children.set(shown, (children.get(shown) ?? 0) + 1);
    }
    const out: (TopicRef & { memories: number; mine: boolean; link?: TopicLink; sub_topics?: number; at: string })[] = [];
    for (const [k, list] of groups) {
      if (q && !k.includes(q)) continue;
      const [oldest] = list;
      const link = linkOf(list);
      const parent = link?.from_id ? shownId.get(link.from_id.slice('topic:'.length)) : undefined;
      out.push({
        id: `topic:${oldest.id}`, name: oldest.name, type: list.find(t => t.type !== null)?.type ?? null,
        memories: list.reduce((n, t) => n + t.memories, 0), mine: oldest.mine,
        ...(link ? { link: { from: link.from, ...(link.from_id ? { from_id: parent ? `topic:${parent}` : link.from_id } : {}), ...(link.by ? { by: link.by } : {}), relation: link.relation } } : {}),
        ...(children.get(oldest.id) ? { sub_topics: children.get(oldest.id) } : {}),
        at: oldest.createdAt,
      });
    }
    return out.sort((a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id)).map(({ at: _at, ...t }) => t);
  }
  private static oldestFirst(a: TopicInfo, b: TopicInfo) { return a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id); }

  /** Same-name topics are one entry: a link names its parent by that entry's id, and a parent
   *  counts the entries that hang under it (whatever `query` narrows the list to). */
  private static topicGroups(g: Loaded): { groups: Map<string, TopicInfo[]>; shownId: Map<string, string> } {
    const groups = new Map<string, TopicInfo[]>();
    for (const t of g.topics.values()) {
      const k = nameKey(t.name);
      groups.set(k, [...(groups.get(k) ?? []), t]);
    }
    const shownId = new Map<string, string>();
    for (const list of groups.values()) {
      list.sort(ContextGraph.oldestFirst);
      for (const t of list) shownId.set(t.id, list[0].id);
    }
    return { groups, shownId };
  }

  /** The relations between the user ("you") and the listed topics, by listed id (`topic:<id>`), each
   *  once, oldest first, with every row that holds it. An end that is not a topic this agent reaches
   *  drops the relation: nothing here ever names one. */
  private static tiesShown(g: Loaded): ShownTie[] {
    const { shownId } = ContextGraph.topicGroups(g);
    const end = (id: string) => (id === 'user' ? 'you' : shownId.has(id) ? `topic:${shownId.get(id)}` : null);
    const shown = new Map<string, ShownTie>();
    for (const t of g.ties) {
      const from = end(t.from), to = end(t.to);
      if (!from || !to || from === to) continue;
      const key = JSON.stringify([from, nameKey(t.relation), to]);
      const held = shown.get(key);
      if (held) { held.rows.push(...t.rows); if (!t.by) delete held.by; continue; }
      shown.set(key, { from, to, relation: t.relation, rows: [...t.rows], ...(t.by ? { by: t.by } : {}) });
    }
    return [...shown.values()];
  }

  /** The relation words already used between the user and the topics this agent reaches: most used
   *  first (then oldest first), as first written, without the two stock relations. */
  private static relationWords(ties: { relation: string }[]): string[] {
    const stock = new Set([DEFAULT_TOPIC_RELATION, DEFAULT_SUBTOPIC_RELATION]);
    const used = new Map<string, { word: string; count: number }>();
    for (const t of ties) {
      const word = oneLine(t.relation, RELATION_CHARS);
      const key = nameKey(word);
      if (!key || stock.has(key)) continue;
      const held = used.get(key);
      if (held) held.count++; else used.set(key, { word, count: 1 });
    }
    return [...used.values()].sort((a, b) => b.count - a.count).slice(0, SUGGESTED_RELATIONS_MAX).map(u => u.word);
  }

  /** The relation words in use (list_topics' `suggested_relations`), whatever a query narrows the topics to. */
  async suggestedRelations(): Promise<string[]> {
    return ContextGraph.relationWords(ContextGraph.tiesShown(await this.load()));
  }

  /** One topic and what is around it, from one load: its parent (the `link` list_topics shows), the
   *  topics hung under it, its other relations and, for depth 2 or 3, the topics further out (each
   *  once, by the first way found; the user is never a way through). Counts only, no memory text;
   *  only topics this agent reaches are ever named. */
  async readTopic(ref: string, depth = 1): Promise<TopicView> {
    return ContextGraph.viewOf(await this.load(), ref, depth);
  }

  private static viewOf(g: Loaded, ref: string, depth = 1): TopicView {
    const found = ContextGraph.findTopic(g, ref);
    if (!found) throw new Error(`No topic "${oneLine(ref, NAME_CHARS)}" among the topics you can read. Use list_topics.`);
    const list = ContextGraph.topicList(g);
    const byId = new Map(list.map(t => [t.id, t]));
    const rootId = `topic:${ContextGraph.topicGroups(g).shownId.get(found.id)}`;
    const root = byId.get(rootId)!;
    const brief = (id: string): TopicBrief => { const t = byId.get(id)!; return { id: t.id, name: oneLine(t.name, NAME_CHARS), type: shownTopicType(t.type), memories: t.memories }; };
    const shownLink = (l: TopicLink): TopicLink => ({ ...l, from: l.from_id ? oneLine(l.from, NAME_CHARS) : l.from, relation: oneLine(l.relation, RELATION_CHARS) });
    const ties = ContextGraph.tiesShown(g);
    // The relation a topic was hung with is its parent's (or its child's), not one more connection.
    const hung = new Set(list.flatMap(t => (t.link ? [JSON.stringify([t.link.from_id ?? 'you', nameKey(t.link.relation), t.id])] : [])));
    const children = list.filter(t => t.link?.from_id === rootId && t.id !== rootId)
      .map(t => ({ ...brief(t.id), relation: oneLine(t.link!.relation, RELATION_CHARS), ...(t.link!.by ? { by: t.link!.by } : {}) }));
    const connections = ties.filter(t => (t.from === rootId || t.to === rootId) && !hung.has(JSON.stringify([t.from, nameKey(t.relation), t.to])))
      .map(t => {
        const other = t.from === rootId ? t.to : t.from;
        const direction = t.from === rootId ? 'out' as const : 'in' as const;
        return { direction, ...(t.by ? { by: t.by } : {}), relation: oneLine(t.relation, RELATION_CHARS), ...(other === 'you' ? { name: 'you' as const } : brief(other)) };
      });
    const suggested = ContextGraph.relationWords(ties);
    const view: TopicView = {
      topic: { ...brief(rootId), mine: root.mine },
      parent: root.link ? shownLink(root.link) : null, children, connections,
      ...(suggested.length ? { suggested_relations: suggested } : {}),
    };
    if (depth <= 1) return view;
    const direct = [root.link?.from_id, ...children.map(c => c.id), ...connections.flatMap(c => ('id' in c ? [c.id] : []))]
      .filter((id): id is string => !!id && byId.has(id));
    const seen = new Set([rootId, ...direct]);
    const nearby: NonNullable<TopicView['nearby']> = [];
    let frontier = [...new Set(direct)];
    for (let distance = 2; distance <= depth && frontier.length; distance++) {
      const next: string[] = [];
      for (const via of frontier) {
        for (const t of ties) {
          const other = t.from === via ? t.to : t.to === via ? t.from : null;
          if (!other || other === 'you' || seen.has(other)) continue;
          seen.add(other);
          next.push(other);
          nearby.push({ ...brief(other), distance, via, direction: t.from === via ? 'out' : 'in', relation: oneLine(t.relation, RELATION_CHARS) });
        }
      }
      frontier = next;
    }
    const more = nearby.length - NEARBY_TOPICS_MAX;
    return { ...view, nearby: nearby.slice(0, NEARBY_TOPICS_MAX), ...(more > 0 ? { nearby_more: more } : {}) };
  }

  // ── Changing the topics (access v3) ──
  // A link is a row whose reason to be read is its ends (memory-access: `and:topic:a+topic:b`).
  // Writing one (connect_topics, set_topic_parent) takes memory.edit on every topic it touches, or,
  // for a topic this connection saved, memory.save ("Can read and edit its own"). Removing one
  // (disconnect_topics, set_topic_parent's old link) takes memory.delete on every topic it touches
  // (an older grant's Read & write still deletes); memory.save never deletes.

  /** An end of a link as a writer names it: the user, or a topic this agent reaches. */
  private static endOf(g: Loaded, ref: string, what: string): { user: true } | { user: false; topic: TopicInfo } {
    const raw = ref.trim();
    if (USER_NAMES.has(nameKey(raw))) return { user: true };
    const topic = ContextGraph.findTopic(g, raw);
    if (!topic) throw new Error(`${what} "${oneLine(raw, NAME_CHARS)}" is not a topic you can read: use "you" or a topic from list_topics.`);
    return { user: false, topic };
  }
  /** The shown id (`topic:<id>`, the oldest of same-name topics) of a topic, or 'you'. */
  private static shownEnd(g: Loaded, end: { user: true } | { user: false; topic: TopicInfo }): string {
    return end.user ? 'you' : `topic:${ContextGraph.topicGroups(g).shownId.get(end.topic.id) ?? end.topic.id}`;
  }
  private static endName(g: Loaded, end: { user: true } | { user: false; topic: TopicInfo }): string {
    return end.user ? USER_ENTITY : g.nodes.get(end.topic.name)?.entity.name ?? end.topic.name;
  }
  private static endBrief(g: Loaded, end: { user: true } | { user: false; topic: TopicInfo }): { name: 'you' } | { id: string; name: string } {
    return end.user ? { name: 'you' } : { id: ContextGraph.shownEnd(g, end), name: oneLine(end.topic.name, NAME_CHARS) };
  }
  /** A relation as a writer gives it: one line, not empty, at most RELATION_CHARS. */
  private static relationWords1(relation: string): string {
    const r = (relation ?? '').normalize('NFKC').replace(/\s+/g, ' ').trim();
    if (!r) throw new Error('relation is required: the words that are true between the two, e.g. "is helping with".');
    if (r.length > RELATION_CHARS) throw new Error(`relation is at most ${RELATION_CHARS} characters.`);
    return r;
  }

  /** The topics in `ids` (entity row ids) this connection may not `verb` ('edit' or 'delete'), by
   *  the server's rule (above); the first of them, or null when it may change them all. */
  private async topicNotAllowed(g: Loaded, ids: string[], verb: 'edit' | 'delete'): Promise<string | null> {
    if (!ids.length) return null;
    const perms = await this.ownPerms();
    const w = verb === 'edit' ? ownSelectors(perms, 'write') : ownSelectors(withV2Deletes(perms), 'destroy');
    const saves = perms.some(p => p.kind === 'memory' && (p.permissions?.includes('memory.save') || (Array.isArray(p.actions) && p.actions.includes('create'))));
    const shown = ContextGraph.topicGroups(g).shownId;
    // A grant names a topic by its row id; same-name topics are one entry, so any of them will do.
    const granted = (id: string) => w.all || [...shown].some(([row, oldest]) => oldest === (shown.get(id) ?? id) && w.topics.includes(`topic:${row}`));
    const own = (id: string) => verb === 'edit' && saves && !!g.topics.get(id)?.mine;
    return ids.find(id => !granted(id) && !own(id)) ?? null;
  }

  /** Refuses, before anything is written, unless this connection may `verb` every topic in `ids`.
   *  The refusal names the one request_access call for the first it can't. */
  private async assertTopicsAllowed(g: Loaded, ids: string[], doing: string, verb: 'edit' | 'delete'): Promise<void> {
    const missing = await this.topicNotAllowed(g, ids, verb);
    if (!missing) return;
    const name = oneLine(g.topics.get(missing)?.name, NAME_CHARS);
    throw Object.assign(new Error(`${doing} needs memory.${verb} on every topic it touches, and this connection does not have it on "${name}". ` +
      `Nothing was ${verb === 'edit' ? 'written' : 'removed'}. If this change is part of what the user asked for, ask once with ${writeAsk(`topic:${missing}`, verb)}, then retry; if it is only tidying, leave it.`), { status: 403, code: NEEDS_TOPIC_WRITE });
  }

  /** The topics touched by a change, as read_topic depth 1 shows them, read again after it. */
  private async nowOf(ids: string[]): Promise<TopicNow[]> {
    const g = await this.load();
    const seen = new Set<string>();
    return ids.flatMap(id => {
      if (!ContextGraph.findTopic(g, id)) return [];
      const v = ContextGraph.viewOf(g, id, 1);
      if (seen.has(v.topic.id)) return [];
      seen.add(v.topic.id);
      const { mine: _mine, ...topic } = v.topic;
      return [{ topic, parent: v.parent, children: v.children.length, connections: v.connections }];
    });
  }

  /** A relation row from one end to the other; `parent` flags it as the child's parent link. */
  private static linkRow(g: Loaded, from: { user: true } | { user: false; topic: TopicInfo }, to: { user: false; topic: TopicInfo } | { user: true }, relationType: string, parent = false): NewRow {
    const endpoints = [from.user ? 'user' : `topic:${from.topic.id}`, to.user ? 'user' : `topic:${to.topic.id}`];
    return {
      id: randomUUID(),
      value: { relation: { from: ContextGraph.endName(g, from), to: ContextGraph.endName(g, to), relationType }, endpoints, about: [], ...(parent ? { parent: true } : {}) },
      facts: { kind: 'relation', categories: [], about: [], endpoints },
    };
  }

  /** connect_topics: one more link "<from> <relation> <to>" between two topics, or the user and a
   *  topic. The same link (same ends, same words, case and spacing aside) is never written twice;
   *  it never moves a topic. */
  async connectTopics(fromRef: string, toRef: string, relation: string) {
    const out = await this.withLock(async () => {
      const g = await this.load();
      const from = ContextGraph.endOf(g, fromRef, 'from'), to = ContextGraph.endOf(g, toRef, 'to');
      if (from.user && to.user) throw new Error('Name a topic: the user cannot be connected to the user.');
      const a = ContextGraph.shownEnd(g, from), b = ContextGraph.shownEnd(g, to);
      if (a === b) throw new Error(`"${oneLine(fromRef, NAME_CHARS)}" cannot be connected to itself.`);
      const words = ContextGraph.relationWords1(relation);
      const held = ContextGraph.tiesShown(g).find(t => t.from === a && t.to === b && nameKey(t.relation) === nameKey(words));
      if (held) throw new Error(`That link is already there ("${oneLine(held.relation, RELATION_CHARS)}"): nothing was written. read_topic shows the links a topic has.`);
      await this.assertTopicsAllowed(g, [from, to].flatMap(e => (e.user ? [] : [e.topic.id])), 'Connecting two topics', 'edit');
      await this.saveRows([ContextGraph.linkRow(g, from, to, words)]);
      return { connected: { from: ContextGraph.endBrief(g, from), to: ContextGraph.endBrief(g, to), relation: words }, touched: [a, b].filter(x => x !== 'you') };
    });
    return { connected: out.connected, now: await this.nowOf(out.touched) };
  }

  /** disconnect_topics: removes one link that is not a topic's parent (set_topic_parent replaces
   *  that). Several matches and no relation named: nothing is removed, they are listed. */
  async disconnectTopics(fromRef: string, toRef: string, relation?: string) {
    const out = await this.withLock(async () => {
      const g = await this.load();
      const from = ContextGraph.endOf(g, fromRef, 'from'), to = ContextGraph.endOf(g, toRef, 'to');
      const a = ContextGraph.shownEnd(g, from), b = ContextGraph.shownEnd(g, to);
      const fromName = from.user ? 'you' : oneLine(from.topic.name, NAME_CHARS), toName = to.user ? 'you' : oneLine(to.topic.name, NAME_CHARS);
      const all = ContextGraph.tiesShown(g).filter(t => t.from === a && t.to === b);
      const matches = relation?.trim() ? all.filter(t => nameKey(t.relation) === nameKey(relation)) : all;
      if (!matches.length) throw new Error(`No link from "${fromName}" to "${toName}"${relation?.trim() ? ` with "${oneLine(relation, RELATION_CHARS)}"` : ''} among the ones you can read: read_topic shows a topic's links and their direction.`);
      if (matches.length > 1) {
        throw new GraphRefusal({
          error: `NOT_REMOVED: ${matches.length} links go from "${fromName}" to "${toName}"; nothing was removed.`,
          matches: matches.map(t => ({ from: fromName, to: toName, relation: oneLine(t.relation, RELATION_CHARS) })),
          next: 'Call disconnect_topics again with `relation` set to the words of the one to remove.',
        });
      }
      const [tie] = matches;
      // A topic's parent link is replaced, never removed: a topic always hangs somewhere.
      if (!to.user) {
        const link = ContextGraph.parentLinkOf(g, to.topic.id);
        if (link && tie.rows.some(r => r.id === link.row)) {
          throw new Error(`"${fromName}" ${oneLine(tie.relation, RELATION_CHARS)} "${toName}" is where "${toName}" hangs (its parent link), so it is not removed here: nothing was removed. ` +
            `To hang it elsewhere, set_topic_parent({ topic: "${b}", parent: "<a topic, or you>", relation: "<how it is part of it>" }).`);
        }
      }
      await this.assertTopicsAllowed(g, [from, to].flatMap(e => (e.user ? [] : [e.topic.id])), 'Removing a link between topics', 'delete');
      const done = await this.deleteRowsDetailed(tie.rows);
      if (done.moving.size) throw new Error(movingText('deleted', retryWait(done.retryAfter)));
      if (done.refused.size) {
        throw Object.assign(new Error(`Decoy refused to remove that link: nothing was removed. It needs memory.delete on both topics; ${writeAsk(from.user ? `topic:${(to as { topic: TopicInfo }).topic.id}` : `topic:${from.topic.id}`, 'delete')} asks for it.`), { status: 403, code: NEEDS_TOPIC_WRITE });
      }
      return { disconnected: { from: ContextGraph.endBrief(g, from), to: ContextGraph.endBrief(g, to), relation: oneLine(tie.relation, RELATION_CHARS) }, touched: [a, b].filter(x => x !== 'you') };
    });
    return { disconnected: out.disconnected, now: await this.nowOf(out.touched) };
  }

  /** A topic's parent link as loaded, from its own row or a same-name topic's. */
  private static parentLinkOf(g: Loaded, topicId: string): (TopicLink & { at: string; row: string; flagged: boolean }) | undefined {
    const name = g.topics.get(topicId)?.name;
    const group = name === undefined ? [] : [...g.topics.values()].filter(t => nameKey(t.name) === nameKey(name)).sort(ContextGraph.oldestFirst);
    return g.links.get(topicId) ?? group.map(t => g.links.get(t.id)).find(Boolean);
  }

  /** set_topic_parent: hang a topic under another topic, or the user. The new parent link is
   *  written first (flagged, so it is the parent at once for every reader of both), then the old
   *  one is removed; when Decoy does not remove it, it stays as a plain connection and the result
   *  says so. memory.edit on the topic and its new parent (memory.save for one this connection
   *  saved); removing the old link takes memory.delete on the topic and its old parent. No cycles. */
  async setTopicParent(topicRef: string, parentRef: string, relation: string) {
    const out = await this.withLock(async () => {
      const g = await this.load();
      if (USER_NAMES.has(nameKey(topicRef))) throw new Error('The user is not a topic: name the topic to move.');
      const child = ContextGraph.endOf(g, topicRef, 'topic') as { user: false; topic: TopicInfo };
      const parent = ContextGraph.endOf(g, parentRef, 'parent');
      const childId = ContextGraph.shownEnd(g, child), parentId = ContextGraph.shownEnd(g, parent);
      const childName = oneLine(child.topic.name, NAME_CHARS);
      if (childId === parentId) throw new Error(`"${childName}" cannot be its own parent.`);
      // Not under a topic below it: walk up from the new parent.
      if (!parent.user) {
        const shown = ContextGraph.topicGroups(g).shownId;
        const chain = new Set<string>();
        for (let at: string | undefined = parent.topic.id; at && !chain.has(at); at = ContextGraph.parentLinkOf(g, at)?.from_id?.slice('topic:'.length)) {
          chain.add(at);
          if (shown.get(at) === shown.get(child.topic.id)) {
            throw new Error(`"${oneLine(parent.topic.name, NAME_CHARS)}" is under "${childName}", so "${childName}" cannot hang under it: nothing was written. ` +
              `Move "${oneLine(parent.topic.name, NAME_CHARS)}" first (set_topic_parent), or pick another parent.`);
          }
        }
      }
      const words = ContextGraph.relationWords1(relation);
      const old = ContextGraph.parentLinkOf(g, child.topic.id);
      const oldFrom = old ? (old.from_id ?? 'you') : null;
      if (old && oldFrom === parentId && nameKey(old.relation) === nameKey(words)) {
        throw new Error(`"${childName}" already hangs there with those words: nothing was written.`);
      }
      const oldParentTopic = old?.from_id ? ContextGraph.findTopic(g, old.from_id) : null;
      await this.assertTopicsAllowed(g, [child.topic.id, ...(parent.user ? [] : [parent.topic.id])], 'Moving a topic', 'edit');
      // The old link goes only when this connection may delete it; otherwise it stays a connection.
      const cannotDelete = await this.topicNotAllowed(g, [child.topic.id, ...(oldParentTopic ? [oldParentTopic.id] : [])], 'delete');
      await this.saveRows([ContextGraph.linkRow(g, parent, child, words, true)]);
      let oldLink: 'removed' | 'kept_as_connection' | undefined;
      let note: string | undefined;
      if (old) {
        const tie = g.ties.find(t => t.rows.some(r => r.id === old.row));
        const done = tie && !cannotDelete ? await this.deleteRowsDetailed(tie.rows).catch(() => null) : null;
        oldLink = done && !done.refused.size && !done.moving.size ? 'removed' : 'kept_as_connection';
        if (oldLink === 'kept_as_connection') {
          const oldName = old.from_id ? `"${oneLine(old.from, NAME_CHARS)}"` : 'you';
          note = `The old link (${oldName} ${oneLine(old.relation, RELATION_CHARS)} "${childName}") could not be removed${done?.moving.size ? ' yet' : ''}, so it is still there as a plain connection; the move holds. ` +
            (cannotDelete ? `Removing it needs memory.delete: ${writeAsk(`topic:${cannotDelete}`, 'delete')}. Then: ` : 'To remove it: ') +
            `disconnect_topics({ from: "${oldFrom}", to: "${childId}", relation: ${JSON.stringify(oneLine(old.relation, RELATION_CHARS))} }).`;
        }
      }
      return {
        topic: { id: childId, name: childName },
        parent: { ...(parent.user ? { from: 'you' } : { from: oneLine(parent.topic.name, NAME_CHARS), from_id: parentId }), relation: words },
        ...(old ? { replaced: { from: old.from_id ? oneLine(old.from, NAME_CHARS) : 'you', ...(old.from_id ? { from_id: oldFrom! } : {}), ...(old.by ? { by: old.by } : {}), relation: oneLine(old.relation, RELATION_CHARS) }, old_link: oldLink } : {}),
        ...(note ? { note } : {}),
        touched: [childId, parentId, ...(oldFrom ? [oldFrom] : [])].filter(x => x !== 'you'),
      };
    });
    const { touched, ...rest } = out;
    return { ...rest, now: await this.nowOf(touched) };
  }

  /** The topic a move files memories under: an existing, reachable one (never created here). */
  async existingTopic(ref: string): Promise<TopicRef> {
    const g = await this.load();
    if (USER_NAMES.has(nameKey(ref))) throw new Error('The user is not a topic: to file a memory about the user, update_memory it with topic: null.');
    const found = ContextGraph.findTopic(g, ref);
    if (!found) throw new Error(`No topic "${oneLine(ref, NAME_CHARS)}" among the topics you can read, and move_memories does not create topics: use list_topics for one that exists, or add_memory / update_memory with a new topic name to create it.`);
    const id = `topic:${ContextGraph.topicGroups(g).shownId.get(found.id) ?? found.id}`;
    return { id, name: oneLine(found.name, NAME_CHARS), type: shownTopicType(found.type) };
  }

  /** The touched topics as a change's `now` shows them (for a change made through editMemory). */
  async topicsNow(ids: string[]): Promise<TopicNow[]> {
    return this.nowOf(ids);
  }

  /** The topics this agent reaches (its row, or any memory about it), optionally matching `query`. */
  async topics(query?: string) {
    return (await this.places(query)).topics;
  }

  /** Where a memory can go, from one load: the topics this agent reaches and the accounts it can
   *  name (each by the name app_id takes), optionally only those whose name contains `query`. */
  async places(query?: string) {
    const g = await this.load();
    const q = query ? nameKey(query) : '';
    return {
      topics: ContextGraph.topicList(g, query).map(t => ({
        ...shownTopic(t),
        ...(t.link ? { link: { ...t.link, from: t.link.from_id ? oneLine(t.link.from, NAME_CHARS) : t.link.from, relation: oneLine(t.link.relation, RELATION_CHARS) } } : {}),
      })),
      accounts: [...g.nodes.values()].filter(n => n.accountId && (!q || nameKey(n.entity.name).includes(q)))
        .map(n => ({ accountId: n.accountId!, name: n.entity.name })),
    };
  }

  /** The name of the topic a topic hangs under (`topic:<id>` or a row id), from the relation this
   *  agent could open: its own, or the one a same-name topic has. None when it hangs from the user. */
  private static parentOf(g: Loaded, topicId: string): string | undefined {
    const id = topicId.replace(/^topic:/i, '');
    const name = g.topics.get(id)?.name;
    const group = name === undefined ? [] : [...g.topics.values()].filter(t => nameKey(t.name) === nameKey(name)).sort(ContextGraph.oldestFirst);
    const link = g.links.get(id) ?? group.map(t => g.links.get(t.id)).find(Boolean);
    return link?.from_id ? link.from : undefined;
  }

  /** A reachable topic by `topic:<id>`, a bare row id, or name (exact normalized match, oldest first). */
  private static findTopic(g: Loaded, ref: string): TopicInfo | null {
    const raw = ref.trim();
    const id = /^topic:/i.test(raw) ? raw.slice('topic:'.length).trim() : UUID_RE.test(raw) ? raw : null;
    if (id !== null) return g.topics.get(id) ?? null;
    const norm = nameKey(raw);
    return [...g.topics.values()].filter(t => nameKey(t.name) === norm).sort(ContextGraph.oldestFirst)[0] ?? null;
  }

  /** Resolve what a writer asked for to a topic: reuse a reachable one, or queue the rows of a new
   *  one in `pending` (its entity row, then its one relation). Nothing else is ever consulted, so
   *  an unreachable topic is neither found nor revealed. */
  private resolveTopic(g: Loaded, spec: TopicSpec, pending: NewRow[]): TopicResult {
    const raw = spec.topic.trim();
    const byId = /^topic:/i.test(raw) || UUID_RE.test(raw);
    const found = ContextGraph.findTopic(g, raw);
    if (found) {
      const group = [...g.topics.values()].filter(t => nameKey(t.name) === nameKey(found.name));
      const parent = ContextGraph.parentOf(g, found.id);
      return { id: `topic:${found.id}`, name: g.nodes.get(found.name)?.entity.name ?? found.name, type: found.type ?? group.find(t => t.type !== null)?.type ?? null, created: false, ...(parent ? { parent } : {}) };
    }
    if (byId) throw new Error(`No topic "${raw}" among the topics you can read. Use list_topics, or pass a name to create one.`);
    const name = cleanTopicName(raw);
    const norm = nameKey(raw);
    if (!norm) throw new Error('A topic needs a name, e.g. "Kitchen renovation".');
    if (USER_NAMES.has(norm)) throw new Error('The user is not a topic: leave topic out and the memory is about them.');
    if (name.length > 200) throw new Error('A topic name is at most 200 characters.');
    const account = [...g.nodes.values()].find(n => n.accountId && nameKey(n.entity.name) === norm);
    if (account) throw new Error(`"${account.entity.name}" is an account: save memories about it with app_id, not topic.`);
    // Where the new topic hangs: the user, or a reachable parent topic.
    const to = spec.link?.to?.trim();
    let from = USER_ENTITY, fromEnd = 'user';
    if (to && !USER_NAMES.has(nameKey(to))) {
      const parent = ContextGraph.findTopic(g, to);
      if (!parent) throw new Error(`topic_link.to "${to}" is not a topic you can read: use "default_user" or a topic from list_topics.`);
      from = g.nodes.get(parent.name)?.entity.name ?? parent.name;
      fromEnd = `topic:${parent.id}`;
    }
    const namedRelation = spec.link?.relation?.trim();
    const relationType = namedRelation || (fromEnd === 'user' ? DEFAULT_TOPIC_RELATION : DEFAULT_SUBTOPIC_RELATION);
    if (relationType.length > 100) throw new Error('topic_link.relation is at most 100 characters.');
    const type = spec.type?.trim() ?? '';
    const entity = ContextGraph.entityRow(name, type);
    const label = `topic:${entity.id}`;
    pending.push(entity, {
      id: randomUUID(),
      value: { relation: { from, to: name, relationType }, endpoints: [fromEnd, label], about: [] },
      facts: { kind: 'relation', categories: [], about: [], endpoints: [fromEnd, label] },
    });
    // Later lookups in this same write see it (a second fact, an attach).
    g.topics.set(entity.id, { id: entity.id, name, type, mine: true, memories: 0, createdAt: new Date().toISOString(), rowVisible: true });
    return { id: label, name, type, created: true, ...(!namedRelation && fromEnd === 'user' ? { relationDefaulted: true } : {}), ...(fromEnd === 'user' ? {} : { parent: from }) };
  }

  /** Every memory this agent can read, oldest first. */
  async memories(): Promise<MemoryRecord[]> {
    return this.recordsOf(await this.load());
  }

  /** Memories and the granted accounts' names from one load (the connect-time summary). */
  async memorySnapshot(): Promise<{ records: MemoryRecord[]; accounts: { name: string; accountId: string }[]; topics: (TopicRef & { memories: number; mine: boolean })[] }> {
    const g = await this.load();
    return {
      records: this.recordsOf(g),
      accounts: [...g.nodes.values()].filter(n => n.accountId).map(n => ({ name: n.entity.name, accountId: n.accountId! })),
      topics: ContextGraph.topicList(g),
    };
  }

  /** Granted accounts as the graph names them (entity name → account id). */
  async accountEntities(): Promise<{ name: string; accountId: string }[]> {
    const g = await this.load();
    return [...g.nodes.values()].filter(n => n.accountId).map(n => ({ name: n.entity.name, accountId: n.accountId! }));
  }

  /** The names of these topics (`topic:<id>` or a bare id), each one clean line (they are told to
   *  the person), null for one this agent can't read. */
  async topicNames(ids: string[]): Promise<(string | null)[]> {
    const g = await this.load();
    const byId = new Map([...g.topics.values()].map(t => [t.id.toLowerCase(), oneLine(t.name, NAME_CHARS)]));
    // A name that cleans to nothing (only hidden characters) is no name.
    return ids.map(i => byId.get(i.replace(/^topic:/, '').toLowerCase()) || null);
  }

  /** Topics as a memory grant names them (`topic:<entity row id>`), from the names this agent sees
   *  (or `topic:<id>` passed through) — for request_access. The user and accounts are not topics. */
  async topicSelectors(about: string[]): Promise<string[]> {
    if (about.every(a => a.startsWith('topic:'))) return about;
    const g = await this.load();
    return about.map(name => {
      if (name.startsWith('topic:')) return name;
      const node = g.nodes.get(name);
      if (name === USER_ENTITY) throw new Error('The user is not a topic: ask for memories about them by category (datatypes), e.g. ["personal_details"].');
      if (node?.accountId) throw new Error(`"${name}" is an account: its memories are asked for with the account: request_access({ permissions: ["acctmem.read"], account_id: "${node.accountId}" }).`);
      if (!node?.topicId) throw new Error(`No topic named "${name}" in the memories you can read. Name a topic from read_graph, or pass "topic:<id>".`);
      return `topic:${node.topicId}`;
    });
  }

  /** Store memories as observations: about the user (on default_user, created on first use) or,
   *  with `accountId`, labelled with that account. `aboutHint` keeps a place the writer named that
   *  is not an account. Metadata and the categories are sealed inside the same row. */
  async addMemories(items: NewMemory[], accountId: string | null = null, aboutHint?: string): Promise<MemoryRecord[]> {
    return (await this.saveMemories(items, { accountId, aboutHint })).written;
  }

  /** Store memories, optionally filed under a topic (reused when reachable, created otherwise — the
   *  topic's rows go in the same request as the memories), and attach existing memories to that
   *  topic in place (`attach`: same ids, categories added). Attaching needs the right to edit each
   *  one; any this agent may not edit come back in `refused`. */
  async saveMemories(items: NewMemory[], opts: { accountId?: string | null; aboutHint?: string; topic?: TopicSpec; attach?: { id: string; categories?: string[] }[] } = {}): Promise<{ written: MemoryRecord[]; attached: MemoryRecord[]; refused: string[]; topic: TopicResult | null }> {
    const accountId = opts.accountId ?? null;
    return this.withLock(async () => {
      const g = await this.load();
      if (!items.length && !opts.attach?.length) return { written: [], attached: [], refused: [], topic: null };
      if (opts.topic && accountId) throw new Error('A memory is about one thing: a topic or an account (app_id), not both.');
      // A duplicate add_memory files under the topic in place is only one this connection saved:
      // someone else's is reported as a duplicate and left as it is (update_memory changes it on
      // purpose). Saving it gives no right to change it: like any relabel, it must stay inside what
      // this connection can write, checked before anything (the topic included) is written.
      const attach: { id: string; categories?: string[]; perms: ServedPermission[] | null }[] = [], refused: { id: string; categories?: string[] }[] = [];
      const candidates = opts.topic ? (opts.attach ?? []).filter(a => {
        const o = g.opened.find(x => x.row.id === a.id);
        if (o && o.row.mine && !o.space) return true;
        refused.push(a);
        return false;
      }) : [];
      if (!items.length && !candidates.length) return { written: [], attached: [], refused: refused.map(a => a.id), topic: null };
      const rows: NewRow[] = [];
      const topic = opts.topic ? this.resolveTopic(g, opts.topic, rows) : null;
      const topicRows = rows.slice();
      const held = candidates.length && topic ? await this.policies() : null;
      for (const a of topic ? candidates : []) {
        const record = this.recordsOf(g).find(r => r.id === a.id);
        // It needs write on the memory as it is too (the server decides when the grants can't be read).
        if (!record || (held && !record.via.some(v => viaHeld(held, v, 'write')))) { refused.push(a); continue; }
        try {
          const perms = await this.assertInsideWriteSet(record, ContextGraph.nextLabels(record, { addCategories: a.categories }, topic), topic!.created ? [topic!.id] : []);
          attach.push({ ...a, perms });
        } catch (err) {
          if ((err as { code?: string } | null)?.code !== OUTSIDE_WRITE_SET) throw err;
          refused.push(a);
        }
      }
      if (!items.length && !attach.length) return { written: [], attached: [], refused: refused.map(a => a.id), topic: null };
      let node: { accountId: string | null; entity: { name: string } };
      let label: string;
      if (topic) {
        node = { accountId: null, entity: { name: topic.name } };
        label = topic.id;
      } else {
        let found = accountId ? [...g.nodes.values()].find(n => n.accountId === accountId) : g.nodes.get(USER_ENTITY);
        if (accountId && !found) {
          const named = (await this.deps.accounts()).find(a => a.id === accountId)?.name ?? `Account ${accountId.slice(0, 8)}`;
          found = { entity: { name: named, entityType: 'account', observations: [] }, accountId, topicId: null, rows: [], obs: new Map() };
        }
        if (!found) found = { entity: { name: USER_ENTITY, entityType: 'person', observations: [] }, accountId: null, topicId: null, rows: [], obs: new Map() };
        if (!accountId && !found.rows.length && items.length) rows.push(ContextGraph.entityRow(USER_ENTITY, 'person'));
        label = this.labelOf(found, rows);
        node = found;
      }
      const first = rows.length;
      for (const it of items) {
        rows.push(ContextGraph.observationRow(node, label, it.text, { metadata: it.metadata, categories: it.categories, aboutHint: accountId ? undefined : opts.aboutHint }));
      }
      await this.saveRows(rows);
      const now = new Date().toISOString();
      const written = rows.slice(first).map((r, i): MemoryRecord => {
        const cats = r.value.categories as string[] | undefined;
        return {
          id: r.id, text: items[i].text, entityName: node.entity.name, accountId, mine: true, authorKind: 'agent' as const, rev: 1,
          createdAt: now, updatedAt: now, ...(items[i].metadata ? { metadata: items[i].metadata } : {}),
          ...(cats ? { categories: cats } : {}), ...(r.value.about_hint ? { aboutHint: r.value.about_hint as string } : {}),
          topic: topic ? { id: topic.id, name: topic.name, type: topic.type } : null,
          about: [label], via: ['self'], stored: 'row',
        };
      });
      const attached: MemoryRecord[] = [];
      const unknown: { id: string; rev: number }[] = [];
      for (const a of topic ? attach : []) {
        const rev = this.recordsOf(g).find(r => r.id === a.id)?.rev ?? 0;
        try {
          attached.push((await this.applyEdit(g, a.id, { addCategories: a.categories }, topic, a.perms)).record);
        } catch (err) {
          if (definitelyRefused(err)) refused.push(a); else unknown.push({ id: a.id, rev });
        }
      }
      // No answer (a lost response, a 5xx) may still mean it was saved: read back to find out.
      const uncertain: string[] = [];
      if (unknown.length && topic) {
        const now = this.recordsOf(await this.load());
        for (const u of unknown) {
          const r = now.find(x => x.id === u.id);
          if (r && r.rev > u.rev && r.topic?.id === topic.id) attached.push(r); else uncertain.push(u.id);
        }
      }
      // A topic created only to attach memories: removed again when every attach was refused outright;
      // kept (and the outcome reported unknown) when an attach got no answer and may have landed.
      if (!written.length && !attached.length && topicRows.length) {
        if (uncertain.length) throw outcomeUnknown(uncertain.join(', '));
        // One this connection may not delete stays, and is said (the topic in the result).
        const left = await this.forgetRows(topicRows);
        return { written, attached, refused: refused.map(a => a.id), topic: left ? topic : null };
      }
      return { written, attached, refused: [...refused.map(a => a.id), ...uncertain], topic };
    });
  }

  /** Rewrite one memory in place (same id, first-added date kept). A memory someone else saved
   *  needs Read & write on it; the server decides. */
  async updateMemory(id: string, text: string): Promise<MemoryRecord> {
    return (await this.editMemory(id, { text })).record;
  }

  /** Change one memory in place — its text, categories and/or topic — keeping its id, first-added
   *  date and every other sealed field. A topic is reused or created (its rows saved first); null
   *  files it back under the user. With `expectedRev` (the revision the caller read) a memory
   *  changed since is refused, not overwritten.
   *
   *  Read & write on the memory is the whole rule, whoever saved it. A change of topic or categories
   *  must keep the memory inside what this connection can write (checked here, before anything is
   *  sent: the server can't read labels), so it can never lose a memory by moving it out of reach.
   *
   *  Who may read it afterwards: when a label is REMOVED (a category, its topic or an account) the
   *  key is rotated and wrapped only to the new audience, so the old audience loses it at once.
   *  Adding labels keeps the key; its author wraps it to the newly eligible, and the owner's phone
   *  (nudged by every edit) shares it with anyone else the new labels reach. */
  async editMemory(id: string, change: MemoryChange): Promise<MemoryEdit> {
    return this.withLock(async () => {
      const g = await this.load();
      const o = g.opened.find(x => x.row.id === id);
      const record = o && this.recordsOf(g).find(r => r.id === id);
      if (!o || !record) throw new Error(`Memory ${id} not found`);
      ContextGraph.checkRev(record, change.expectedRev);
      let topic: TopicResult | null | undefined;
      const created: NewRow[] = [];
      if (change.topic !== undefined) {
        if (record.accountId) throw new Error('This memory is about an account (app_id); it stays with the account and cannot be filed under a topic.');
        if (o.space) throw new Error('This memory is still in the older store until the user\'s Decoy app moves it; its topic can be changed after that.');
        if (change.topic === null) topic = null;
        else if (record.topic && !/^topic:/i.test(change.topic.topic.trim()) && !UUID_RE.test(change.topic.topic.trim())
          && nameKey(change.topic.topic) === nameKey(record.topic.name)) {
          topic = { ...record.topic, created: false };   // already filed under (a same-name copy of) it
        } else {
          topic = this.resolveTopic(g, change.topic, created);
        }
      }
      // Before anything is written (a new topic included): the memory must stay inside what this
      // connection can write.
      const perms = await this.assertInsideWriteSet(record, ContextGraph.nextLabels(record, change, topic), topic?.created ? [topic.id] : []);
      if (created.length) await this.saveRows(created);
      // Where the memory's topic hangs, for the result's `filed`.
      const filedUnder = topic === undefined ? record.topic : topic;
      const parent = filedUnder ? (topic?.parent ?? ContextGraph.parentOf(g, filedUnder.id)) : undefined;
      try {
        const edit = await this.applyEdit(g, id, change, topic, perms);
        return { ...edit, ...(topic !== undefined ? { topic } : {}), ...(parent ? { parent } : {}) };
      } catch (err) {
        if (definitelyRefused(err)) {
          // Refused outright (a racing write, a grant gone): nothing was written, so the topic made for it goes too.
          if (await this.forgetRows(created) && topic && err instanceof Error) {
            err.message += ` The new topic "${oneLine(topic.name, NAME_CHARS)}" made for it could not be removed by this connection; the user can remove it in Decoy, or file a memory under it.`;
          }
          throw err;
        }
        // No answer (a lost response, a timeout, a 5xx): it may have been saved. Keep the topic and read back.
        const now = this.recordsOf(await this.load()).find(r => r.id === id);
        const landed = now && now.rev > record.rev
          && (change.text === undefined || now.text === change.text)
          && (topic === undefined || (now.topic?.id ?? null) === (topic?.id ?? null));
        if (!landed) throw outcomeUnknown(id);
        return { record: now, rotated: false, reconciled: true, ...(topic !== undefined ? { topic } : {}), ...(parent ? { parent } : {}) };
      }
    });
  }

  private static checkRev(record: MemoryRecord, expected?: number) {
    if (expected !== undefined && expected !== record.rev) {
      throw Object.assign(new Error(`This memory changed since you read it (you read revision ${expected}; it is now ${record.rev}). ` +
        'Read it again (get_memory), re-apply your change, and retry with the new rev.'), { code: 'REV_CONFLICT', current_rev: record.rev });
    }
  }

  /** The categories and `about` a change leaves on a memory (see applyEdit). */
  private static nextLabels(record: MemoryRecord, change: MemoryChange, topic: TopicResult | null | undefined): { categories: string[]; about: string[] } {
    let categories = record.categories ?? [];
    if (change.categories) categories = [...new Set(change.categories)];
    if (change.addCategories?.length) categories = [...new Set([...categories, ...change.addCategories])];
    const current = record.topic?.id ?? (record.accountId ? `account:${record.accountId}` : 'user');
    const about = topic !== undefined && (topic?.id ?? 'user') !== current ? [topic ? topic.id : 'user'] : record.about;
    return { categories, about };
  }

  /** Labels that decide who reads a memory (`user` grants nothing). */
  private static grantLabels(categories: string[], about: string[]): string[] {
    return [...categories.map(c => `category:${c}`), ...about.filter(a => a.startsWith('topic:') || a.startsWith('account:'))];
  }

  /** This connection's own grants (GET /policies), or null when they could not be read. */
  private async policies(): Promise<ServedPermission[] | null> {
    try {
      const p = await this.deps.call<{ policies?: { permissions?: ServedPermission[] }[] }>('/policies');
      return (p.policies ?? []).flatMap(x => x.permissions ?? []);
    } catch {
      return null;
    }
  }

  /** This connection's own grants, or a refusal that nothing was changed. */
  private async ownPerms(): Promise<ServedPermission[]> {
    const perms = await this.policies();
    if (perms) return perms;
    throw Object.assign(new Error('Decoy could not read this connection\'s grants, so it could not check that the new topic or categories stay inside what it can write. Nothing was changed; try again.'),
      { code: 'GRANTS_UNREADABLE' });
  }

  /** A relabel stays inside what this connection can write, or nothing is sent (the server enforces
   *  the same on the key wraps): every label it adds or removes is one it writes, and it can still
   *  write the memory afterwards. Saving the memory gives nothing here: access is exactly the grant.
   *  Unchanged labels are not checked here: the server checks write on the memory as it is.
   *  Returns this connection's grants when it looked them up. */
  private async assertInsideWriteSet(record: MemoryRecord, next: { categories: string[]; about: string[] }, newTopics: string[] = []): Promise<ServedPermission[] | null> {
    const before = ContextGraph.grantLabels(record.categories ?? [], record.about);
    const after = ContextGraph.grantLabels(next.categories, next.about);
    // A topic this edit creates is no place anyone holds a grant on yet: filing it there widens nothing.
    const changed = [...after.filter(l => !before.includes(l) && !newTopics.includes(l)), ...before.filter(l => !after.includes(l))];
    if (!changed.length) return null;
    const perms = await this.ownPerms();
    const w = ownSelectors(perms, 'write');
    const writes = (l: string) => l.startsWith('category:') ? w.all || w.categories.includes(l.slice(9))
      : l.startsWith('topic:') ? w.all || w.topics.includes(l)
      : l.startsWith('account:') ? w.all || w.account_wildcard || w.account_ids.includes(l.slice(8)) : false;
    const facts: MemoryFacts = { row_id: record.id, kind: 'observation', categories: next.categories, about: next.about };
    const outside = changed.find(l => !writes(l));
    if (!outside && viaForSelectors(w, facts).length) return perms;
    // Ask for write on the label it can't write, else where it would go (every memory only when it
    // would have no label). Never a topic this edit creates: it is not saved yet, so no grant can name it.
    const target = outside ?? after.find(l => !newTopics.includes(l)) ?? null;
    throw Object.assign(new Error('This change would move the memory outside what this connection can write. ' +
      `Nothing was changed. To make it, ask for edit there: ${writeAsk(target)}.`), { status: 403, code: OUTSIDE_WRITE_SET });
  }

  /** Best effort: delete rows this agent just saved (a topic whose memory write failed). Saving
   *  them gave no right to delete them: the server decides by this connection's grants. Returns
   *  whether any of them is left. */
  private async forgetRows(rows: NewRow[]): Promise<boolean> {
    if (!rows.length) return false;
    try {
      return (await this.deleteRows(rows.map(r => ({ id: r.id, space: null, mine: true, via: [] })))).size > 0;
    } catch {
      return true;
    }
  }

  /** Seal and save one memory's new plaintext (see editMemory). `topic`: undefined = unchanged. */
  private async applyEdit(g: Loaded, id: string, change: MemoryChange, topic: TopicResult | null | undefined, perms: ServedPermission[] | null = null): Promise<Omit<MemoryEdit, 'topic'>> {
    const o = g.opened.find(x => x.row.id === id)!;
    const record = this.recordsOf(g).find(r => r.id === id)!;
    const ob = { ...(o.value.observation as Record<string, unknown>) };
    const value: Record<string, unknown> = { ...o.value };
    const text = change.text ?? record.text;
    ob.content = text;
    const oldCats = record.categories ?? [];
    const cats = ContextGraph.nextLabels(record, change, topic).categories;
    if (change.categories || change.addCategories?.length) value.categories = cats;
    if (topic !== undefined && (topic?.id ?? 'user') !== (record.topic?.id ?? (record.accountId ? `account:${record.accountId}` : 'user'))) {
      value.about = [topic ? topic.id : 'user'];
      ob.entityName = topic ? topic.name : USER_ENTITY;
    }
    value.observation = ob;
    const newAbout = (Array.isArray(value.about) ? value.about : []).filter((a): a is string => typeof a === 'string');
    const result = (rev: number, updatedAt: string): MemoryRecord => ({
      ...record, text, rev, updatedAt, categories: cats, about: newAbout,
      ...(topic !== undefined ? { topic: topic ? { id: topic.id, name: topic.name, type: topic.type } : null, entityName: topic ? topic.name : USER_ENTITY } : {}),
    });

    if (o.space) {
      // The older per-space store, with the space key: Read & write on it, whoever saved it (the server decides).
      const res = await this.put('/context/rows', { id, expected_rev: record.rev, ciphertext: this.deps.sealVault(value, o.key) }, record);
      return { record: result(res.rev, res.updated_at), rotated: false };
    }

    // Labels decide who reads it; `user` grants nothing, so only categories, topics and accounts count.
    const before = ContextGraph.grantLabels(oldCats, record.about), after = ContextGraph.grantLabels(cats, newAbout);
    const removed = before.filter(l => !after.includes(l)), added = after.filter(l => !before.includes(l));
    const factsOf = (c: string[], about: string[]): MemoryFacts => ({ row_id: id, kind: 'observation', categories: c, about });

    if (removed.length) {
      // Narrowed: a new key, wrapped to the owner, to itself and to every connection that reads it
      // now — except those that read it only by a removed label — swapped in atomically: every wrap
      // of the old key goes with it. The server refuses a new key that leaves a current holder out
      // (409 HOLDERS_MISSING, naming each with its key and reasons): those are wrapped and it is
      // sent once more, so a narrowing never cuts off anyone it should not.
      const keys = await this.deps.call<Grantees>('/context/memory-grantees');
      if (!keys.owner_public_key) throw new Error('The account owner has not finished key setup on a device yet, so context cannot be stored.');
      const key = randomBytes(32), kid = skidOf(key);
      const facts = factsOf(cats, newAbout);
      const wraps = keys.grantees.flatMap(t => {
        const via = viaForSelectors(t.selectors, facts);
        return via.length ? [{ token_id: t.token_id, via, wrapped_key: wrapKeyForRecipient(key, t.public_key) }] : [];
      });
      const own = perms ?? await this.ownPerms();
      const body = {
        id, expected_rev: record.rev, kid, ciphertext: this.deps.sealVault(value, key),
        owner_wrap: sealEnvelopeForOwner(key.toString('base64'), keys.owner_public_key),
        self_wrap: wrapKeyForRecipient(key, this.deps.ownPublicKey),
        self_via: viaForSelectors(ownSelectors(own, 'read'), facts),
        removed_reasons: removed,
        grantee_wraps: wraps,
      };
      let res: { rev: number; updated_at: string };
      try {
        res = await this.deps.call<{ rev: number; updated_at: string }>('/context/memories', 'PUT', body);
      } catch (err) {
        const e = err as { code?: string; missing?: unknown };
        if (e?.code !== HOLDERS_MISSING || !Array.isArray(e.missing)) this.putFailed(err, record);
        for (const h of e.missing as { token_id?: unknown; public_key?: unknown; via?: unknown }[]) {
          if (typeof h?.token_id !== 'string' || typeof h.public_key !== 'string' || !Array.isArray(h.via)) continue;
          // Never a removed label, whatever the answer names: a holder left with no reason gets no new key.
          const via = h.via.filter((v): v is string => typeof v === 'string' && v !== 'self' && !removed.includes(v)
            && !(v.startsWith('and:') && v.slice(4).split('+').some(x => removed.includes(x))));
          if (!via.length) continue;
          const at = wraps.findIndex(x => x.token_id === h.token_id);
          const wrap = { token_id: h.token_id, via: [...new Set([...(at >= 0 ? wraps[at].via : []), ...via])], wrapped_key: wrapKeyForRecipient(key, h.public_key) };
          if (at >= 0) wraps[at] = wrap; else wraps.push(wrap);
        }
        res = await this.put('/context/memories', { ...body, grantee_wraps: wraps }, record);
      }
      this.keyCache.set(`${id}:${kid}`, key);
      o.key = key; o.row.kid = kid;
      return { record: result(res.rev, res.updated_at), rotated: true };
    }

    const res = await this.put('/context/memories', { id, expected_rev: record.rev, ciphertext: this.deps.sealVault(value, o.key) }, record);
    if (added.length) {
      // Widened: same key, wrapped by this writer to every connection that now reaches it for a new
      // reason (the server keeps only reasons this writer holds write on, which the check above
      // made sure of). The edit is saved: sharing it is best effort (the edit nudged the owner's phone too).
      const keys = await this.deps.call<Grantees>('/context/memory-grantees').catch(() => ({ owner_public_key: null, grantees: [] }) as Grantees);
      const oldFacts = factsOf(oldCats, record.about), newFacts = factsOf(cats, newAbout);
      const wraps = keys.grantees.flatMap(t => {
        const was = viaForSelectors(t.selectors, oldFacts), now = viaForSelectors(t.selectors, newFacts);
        return now.some(v => !was.includes(v)) ? [{ token_id: t.token_id, via: now, wrapped_key: wrapKeyForRecipient(o.key, t.public_key) }] : [];
      });
      if (wraps.length) {
        // Best effort: the edit is saved; the owner's phone shares anything missed (the edit nudged it).
        await this.deps.call('/context/memory-wraps', 'POST', { row_id: id, kid: o.row.kid, wraps }).catch(() => {});
      }
    }
    return { record: result(res.rev, res.updated_at), rotated: false };
  }

  /** PUT an edit; a stale revision or a missing grant becomes a message an agent can act on. */
  private async put(path: string, body: Record<string, unknown>, record: MemoryRecord): Promise<{ rev: number; updated_at: string }> {
    try {
      return await this.deps.call<{ rev: number; updated_at: string }>(path, 'PUT', body);
    } catch (err) {
      return this.putFailed(err, record);
    }
  }

  private putFailed(err: unknown, record: MemoryRecord): never {
    const e = err as { status?: number; code?: string; current_rev?: number; message?: string };
    if (e?.code === MEMORY_MOVING) throw ContextGraph.moving(err);
    if (e?.code === HOLDERS_MISSING) {
      throw Object.assign(new Error('Decoy could not give the new key to every connection that reads this memory (they changed meanwhile). Nothing was changed; read it again and retry.'),
        { status: 409, code: HOLDERS_MISSING });
    }
    if (e?.code === 'REV_CONFLICT' || (e?.status === 409 && !e?.code) || /REV_CONFLICT/.test(String(e?.message))) {
      ContextGraph.checkRev({ ...record, rev: e.current_rev ?? record.rev + 1 }, record.rev);
    }
    if (!denied(err)) throw err;
    throw Object.assign(new Error(`Changing this memory needs edit on it. Ask with ${writeAsk(ContextGraph.askFor(record))}.`), { status: 403, code: 'INSUFFICIENT_GRANT' });
  }

  /** The label to ask write on for this memory: the reason this connection reads it by, else its labels. */
  static askFor(record: Pick<MemoryRecord, 'via' | 'categories' | 'about'>): string | null {
    return askLabel(record.via, ContextGraph.grantLabels(record.categories ?? [], record.about));
  }

  /** The old store's "retry while the owner's phone moves it" answer, in this bridge's words. */
  private static moving(err: unknown) {
    const wait = retryWait((err as { retry_after_seconds?: unknown } | null)?.retry_after_seconds);
    return Object.assign(new Error(movingText('changed', wait)),
      { status: 409, code: MEMORY_MOVING, retry_after_seconds: wait });
  }

  /** Delete memories by id. Delete on each is the rule, whoever saved it;
   *  the server decides. The rest come back refused, or `moving` while the owner's phone moves an
   *  older row to its own key. */
  async deleteMemories(ids: string[]): Promise<{ deleted: string[]; refused: string[]; notFound: string[]; moving?: string[]; retryAfter?: number; asks?: Record<string, string> }> {
    return this.withLock(async () => {
      const g = await this.load();
      const rows = new Map(g.opened.map(o => [o.row.id, o]));
      const records = new Map(this.recordsOf(g).map(r => [r.id, r]));
      const refused: string[] = [], notFound: string[] = [], targets: OpenRow[] = [];
      for (const id of new Set(ids)) {
        const o = rows.get(id);
        if (!o || !records.has(id)) notFound.push(id);
        else targets.push({ id, space: o.space?.id ?? null, mine: o.row.mine, via: o.row.via ?? [] });
      }
      const out = await this.deleteRowsDetailed(targets);
      const deleted = targets.map(t => t.id).filter(id => !out.refused.has(id));
      refused.push(...targets.map(t => t.id).filter(id => out.refused.has(id) && !out.moving.has(id)));
      const moving = [...out.moving];
      // For each refused memory, the request that gives delete on it.
      const asks = Object.fromEntries(refused.map(id => [id, writeRequestFor(records.get(id)!, 'delete')]));
      return { deleted, refused, notFound, ...ContextGraph.movingOf(moving, out), ...(refused.length ? { asks } : {}) };
    });
  }

  /** Follow the agent sync feed (/sync, already narrowed to this agent's grants) and call
   *  `onChange` whenever a memory row or space changed — by any agent or by the owner.
   *  Anchors at the current head, so only changes after the call count. Returns a stop. */
  watch(onChange: () => void, everyMs: number): () => void {
    type Changes = Record<string, { created?: string[]; updated?: string[]; destroyed?: string[] }>;
    let cursor: string | null = null;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        if (cursor === null) {
          cursor = (await this.deps.call<{ head: string }>('/sync/head')).head;
        } else {
          let changed = false, more = true;
          while (more && !stopped) {
            const at: string = cursor ?? '0';
            const r: { state: string; hasMore: boolean; changes: Changes } = await this.deps.call(`/sync?cursor=${encodeURIComponent(at)}`);
            cursor = r.state;
            more = r.hasMore;
            changed ||= ['context_row', 'context_space'].some(k => {
              const c = r.changes?.[k];
              return !!c && ((c.created?.length ?? 0) + (c.updated?.length ?? 0) + (c.destroyed?.length ?? 0)) > 0;
            });
          }
          if (changed && !stopped) onChange();
        }
      } catch {
        cursor = null;   // cursor too old or a network blip: re-anchor at the head
      }
      if (!stopped) { timer = setTimeout(tick, everyMs); timer.unref?.(); }
    };
    void tick();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  }

  async readGraph(): Promise<KnowledgeGraph> {
    const g = await this.load();
    return { entities: [...g.nodes.values()].map(n => n.entity), relations: g.edges.map(e => e.relation) };
  }

  async searchNodes(query: string): Promise<KnowledgeGraph> {
    const graph = await this.readGraph();
    const q = query.toLowerCase();
    const filteredEntities = graph.entities.filter(e =>
      e.name.toLowerCase().includes(q) || e.entityType.toLowerCase().includes(q) || e.observations.some(o => o.toLowerCase().includes(q)));
    const filteredEntityNames = new Set(filteredEntities.map(e => e.name));
    return { entities: filteredEntities, relations: graph.relations.filter(r => filteredEntityNames.has(r.from) || filteredEntityNames.has(r.to)) };
  }

  async openNodes(names: string[]): Promise<KnowledgeGraph> {
    const graph = await this.readGraph();
    const filteredEntities = graph.entities.filter(e => names.includes(e.name));
    const filteredEntityNames = new Set(filteredEntities.map(e => e.name));
    return { entities: filteredEntities, relations: graph.relations.filter(r => filteredEntityNames.has(r.from) || filteredEntityNames.has(r.to)) };
  }
}

// ── The nine MCP Memory server tools ──────────────────────────────────────────
// Names, titles, descriptions, input/output schemas, annotations and result text are the
// reference server's (modelcontextprotocol/servers src/memory/index.ts, MIT), so any agent
// already using the memory server works unchanged. The only additions are Decoy's
// "not deleted" notes when a delete would touch an account or a memory this agent can't write.


export const MEMORY_TOOLS = [
  'create_entities', 'create_relations', 'add_observations',
  'delete_entities', 'delete_observations', 'delete_relations',
  'read_graph', 'search_nodes', 'open_nodes',
] as const;

const EntitySchema = z.object({
  name: z.string().describe('The name of the entity'),
  entityType: z.string().describe('The type of the entity: reuse an existing one (device, document, event, goal, hobby, media, organization, person, pet, place, product, project, team, trip)'),
  observations: z.array(z.string()).describe('An array of observation contents associated with the entity'),
});
const RelationSchema = z.object({
  from: z.string().describe('The name of the entity where the relation starts'),
  to: z.string().describe('The name of the entity where the relation ends'),
  relationType: z.string().describe('The type of the relation: true and specific for these two, not a stock phrase; for health, money, legal or relationship subjects, no more than the topic names say'),
});
export const SEARCH_QUERY_MAX_LENGTH = 2048;

const writeHints = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const deleteHints = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };
const readHints = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const json = (v: unknown) => [{ type: 'text' as const, text: JSON.stringify(v, null, 2) }];
const notYours = (refused?: string[]) => (refused?.length ? ` Not deleted (an account, or a memory this connection may not delete): ${refused.join(', ')}` : '');
const notYet = (moving?: string[], retryAfter?: number) => (moving?.length
  ? ` Not deleted yet (still in the older store while the user's Decoy app moves it to its own key; retry in about ${retryAfter ?? 30} seconds): ${moving.join(', ')}` : '');

export const RESOURCE_URI = 'memory://knowledge-graph';

/** How often a subscribed client's graph is checked for other agents' changes. */
export const MEMORY_POLL_MS = Number(process.env.DECOY_MEMORY_POLL_MS) || 15_000;

export function registerMemoryTools(server: McpServer, graph: ContextGraph, opts: { pollMs?: number; include?: (tool: string) => boolean } = {}): { notifyGraphUpdated: () => void } {
  // The nine tools are opt-in on the default surface (what agents use); the resource
  // and its change notifications are always offered.
  const reg = gatedRegister(server, opts.include);
  // The reference server's resource: the whole graph, with notifications/resources/updated
  // sent only to a client that subscribed.
  const subscribers = new Set<string>();
  const notifyGraphUpdated = () => {
    if (subscribers.has(RESOURCE_URI)) server.server.sendResourceUpdated({ uri: RESOURCE_URI }).catch(() => {});
  };
  server.registerResource('knowledge-graph', RESOURCE_URI, {
    title: 'Knowledge Graph',
    description: 'The full knowledge graph with all entities and relations',
    mimeType: 'application/json',
  }, async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(await graph.readGraph(), null, 2) }] }));
  server.server.registerCapabilities({ resources: { subscribe: true } });
  // While a client is subscribed, follow the sync feed so changes made by other agents or by
  // the owner reach it as notifications/resources/updated too, not only this client's own.
  let stopWatching: (() => void) | null = null;
  const watch = (on: boolean) => {
    if (on && !stopWatching) stopWatching = graph.watch(notifyGraphUpdated, opts.pollMs ?? MEMORY_POLL_MS);
    if (!on && stopWatching) { stopWatching(); stopWatching = null; }
  };
  server.server.setRequestHandler(SubscribeRequestSchema, async (request) => {
    subscribers.add(request.params.uri);
    watch(subscribers.has(RESOURCE_URI));
    return {};
  });
  server.server.setRequestHandler(UnsubscribeRequestSchema, async (request) => {
    subscribers.delete(request.params.uri);
    watch(subscribers.has(RESOURCE_URI));
    return {};
  });
  const priorClose = server.server.onclose;
  server.server.onclose = () => { watch(false); priorClose?.(); };

  reg('create_entities', {
    title: 'Create Entities',
    description: 'Create multiple new entities in the knowledge graph. An entity is a topic: search_nodes first and reuse an existing name; categories are not set here. Needs memory.save (403 INSUFFICIENT_GRANT without it; ask with request_access({ permissions: ["memory.save"] })).',
    inputSchema: { entities: z.array(EntitySchema) },
    outputSchema: { entities: z.array(EntitySchema) },
    annotations: writeHints,
  }, async ({ entities }) => {
    const result = await graph.createEntities(entities);
    notifyGraphUpdated();
    return { content: json(result), structuredContent: { entities: result } };
  });

  reg('create_relations', {
    title: 'Create Relations',
    description: 'Create multiple new relations between entities in the knowledge graph. Relations should be in active voice. A relation connects topics (entities); it carries no categories. Needs memory.save (403 INSUFFICIENT_GRANT without it; ask with request_access({ permissions: ["memory.save"] })).',
    inputSchema: { relations: z.array(RelationSchema) },
    outputSchema: { relations: z.array(RelationSchema) },
    annotations: writeHints,
  }, async ({ relations }) => {
    const result = await graph.createRelations(relations);
    notifyGraphUpdated();
    return { content: json(result), structuredContent: { relations: result } };
  });

  reg('add_observations', {
    title: 'Add Observations',
    description: 'Add new observations to existing entities in the knowledge graph. Each observation is a memory filed under that entity (its topic); no categories are set here (the user\'s device adds them) — use add_memory with categories and topic to set both. Needs memory.save (403 INSUFFICIENT_GRANT without it; ask with request_access({ permissions: ["memory.save"] })).',
    inputSchema: {
      observations: z.array(z.object({
        entityName: z.string().describe('The name of the entity to add the observations to'),
        contents: z.array(z.string()).describe('An array of observation contents to add'),
      })),
    },
    outputSchema: { results: z.array(z.object({ entityName: z.string(), addedObservations: z.array(z.string()) })) },
    annotations: writeHints,
  }, async ({ observations }) => {
    const result = await graph.addObservations(observations);
    notifyGraphUpdated();
    return { content: json(result), structuredContent: { results: result } };
  });

  reg('delete_entities', {
    title: 'Delete Entities',
    description: 'Delete multiple entities and their associated relations from the knowledge graph',
    inputSchema: { entityNames: z.array(z.string()).describe('An array of entity names to delete') },
    outputSchema: { success: z.boolean(), message: z.string() },
    annotations: deleteHints,
  }, async ({ entityNames }) => {
    const { deleted, notFound, refused, moving, retryAfter } = await graph.deleteEntities(entityNames);
    notifyGraphUpdated();
    const message = deleted.length === entityNames.length
      ? 'Entities deleted successfully'
      : `Deleted ${deleted.length} of ${entityNames.length} entities.` +
        (notFound.length ? ` Not found: ${notFound.join(', ')}` : '') + notYours(refused) + notYet(moving, retryAfter);
    return { content: [{ type: 'text' as const, text: message }], structuredContent: { success: true, message } };
  });

  reg('delete_observations', {
    title: 'Delete Observations',
    description: 'Delete specific observations from entities in the knowledge graph',
    inputSchema: {
      deletions: z.array(z.object({
        entityName: z.string().describe('The name of the entity containing the observations'),
        observations: z.array(z.string()).describe('An array of observations to delete'),
      })),
    },
    outputSchema: { success: z.boolean(), message: z.string() },
    annotations: deleteHints,
  }, async ({ deletions }) => {
    const { deletedCount, missingEntities, refused, moving, retryAfter } = await graph.deleteObservations(deletions);
    notifyGraphUpdated();
    const requested = deletions.reduce((total, d) => total + d.observations.length, 0);
    const message = deletedCount === requested
      ? 'Observations deleted successfully'
      : `Deleted ${deletedCount} of ${requested} observations.` +
        (missingEntities.length ? ` Entities not found: ${missingEntities.join(', ')}` : '') + notYours(refused) + notYet(moving, retryAfter);
    return { content: [{ type: 'text' as const, text: message }], structuredContent: { success: true, message } };
  });

  reg('delete_relations', {
    title: 'Delete Relations',
    description: 'Delete multiple relations from the knowledge graph',
    inputSchema: { relations: z.array(RelationSchema).describe('An array of relations to delete') },
    outputSchema: { success: z.boolean(), message: z.string() },
    annotations: deleteHints,
  }, async ({ relations }) => {
    const { deletedCount, refused, moving, retryAfter } = await graph.deleteRelations(relations);
    notifyGraphUpdated();
    const message = deletedCount === relations.length
      ? 'Relations deleted successfully'
      : refused?.length || moving?.length
        ? `Deleted ${deletedCount} of ${relations.length} relations.${notYours(refused)}${notYet(moving, retryAfter)}`
        : `Deleted ${deletedCount} of ${relations.length} relations. The rest matched nothing.`;
    return { content: [{ type: 'text' as const, text: message }], structuredContent: { success: true, message } };
  });

  reg('read_graph', {
    title: 'Read Graph',
    description: 'Read the entire knowledge graph',
    inputSchema: {},
    outputSchema: { entities: z.array(EntitySchema), relations: z.array(RelationSchema) },
    annotations: readHints,
  }, async () => {
    const g = await graph.readGraph();
    return { content: json(g), structuredContent: { ...g } };
  });

  reg('search_nodes', {
    title: 'Search Nodes',
    description: 'Search for nodes in the knowledge graph based on a query',
    inputSchema: {
      query: z.string().max(SEARCH_QUERY_MAX_LENGTH).describe('The search query to match against entity names, types, and observation content'),
    },
    outputSchema: { entities: z.array(EntitySchema), relations: z.array(RelationSchema) },
    annotations: readHints,
  }, async ({ query }) => {
    const g = await graph.searchNodes(query);
    return { content: json(g), structuredContent: { ...g } };
  });

  reg('open_nodes', {
    title: 'Open Nodes',
    description: 'Open specific nodes in the knowledge graph by their names',
    inputSchema: { names: z.array(z.string()).describe('An array of entity names to retrieve') },
    outputSchema: { entities: z.array(EntitySchema), relations: z.array(RelationSchema) },
    annotations: readHints,
  }, async ({ names }) => {
    const g = await graph.openNodes(names);
    return { content: json(g), structuredContent: { ...g } };
  });
  return { notifyGraphUpdated };
}
