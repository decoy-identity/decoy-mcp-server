// Agent-written secret fields on an account (/api/agent/accounts/:id/fields).
//
// Each field is its own encrypted row next to the account — an API key, a token, a recovery code —
// sealed here with its own random key and wrapped to the owner, this connection and the other
// connections that can reveal the account. The server stores ciphertext and wraps only.
//
//   set     upsert by label (or field_id) among the fields this connection can open; a stale
//           revision is re-read and retried; an uncertain create is retried with the SAME id, so it
//           never makes a second field. Never returns the value.
//   get     one field's value (the read)
//   list    labels only
//   delete  one field
//   forUnlock  the fields account_unlock merges into custom_fields
//
// Every field opened here is checked against the row it was served as (lib/account-field-crypto
// openAccountField): a blob moved to another row or account is skipped, never shown.

import { waitingFromList, shownWaiting, retrySeconds, waitingLine, WaitingError, type Waiting } from './waiting.js';
import { randomUUID } from 'node:crypto';
import { recordUnreadable, RecordUnreadable, RECORD_UNREADABLE } from './api-error.js';
import {
  fieldKid, newFieldKey, sealAccountField, openAccountField, editAccountField,
  type AccountFieldPayload, type AccountFieldType,
} from './account-field-crypto.js';
import { wrapKeyForRecipient, sealEnvelopeForOwner, type ApiCall } from './context-graph.js';

export interface AccountFieldsDeps {
  call: ApiCall;
  /** Unwrap a headerless RSA-OAEP envelope with this agent's private key → raw bytes. */
  unwrap: (wrappedBase64: string) => Buffer;
  /** This agent's public key (SPKI DER, base64) — for the wrap it keeps of a key it creates. */
  ownPublicKey: string;
}

/**
 * A read of one field that found no such field among the ones this connection can open, while
 * other fields of the account are waiting on the owner's Decoy app. A field is reported as
 * waiting only when Decoy names it; a label is sealed, so Decoy cannot say whether a waiting
 * field has it. The message says both things in fixed words. `retry_after_seconds`: set for a
 * read by label while fields are `preparing` (the field may be one of them).
 */
export class NoSuchFieldError extends Error {
  constructor(message: string, public readonly retry_after_seconds?: number) { super(message); this.name = 'NoSuchFieldError'; }
}
/** How many fields are waiting, as the start of a sentence. */
function waitingFieldsSentence(waiting: Waiting[]): string {
  const known = waiting.every((w) => w.count !== undefined);
  const n = waiting.reduce((sum, w) => sum + (w.count ?? 0), 0);
  const many = !known ? 'Some' : `${waiting.some((w) => w.at_least) ? 'At least ' : ''}${n}`;
  return `${many} of this account's fields ${known && n === 1 ? 'is' : 'are'} waiting on the owner's Decoy app, and a label is read only once a field is open: account_field_list gives their state.`;
}

type Served = { id: string; kid: string; rev: number; ciphertext: string; wrapped_key: string; mine: boolean; edited_by_owner: boolean };
type Opened = { id: string; kid: string; rev: number; key: Buffer; payload: AccountFieldPayload; mine: boolean; edited_by_owner: boolean };
export type FieldSelector = { label?: string; field_id?: string };

const MAX_ATTEMPTS = 4;
const norm = (s: string) => s.trim().toLowerCase();
const errCode = (e: unknown) => (e as { code?: string } | null)?.code;
const errStatus = (e: unknown) => (e as { status?: number } | null)?.status;
/** No answer, or a server/gateway failure: the write may or may not have landed. */
const uncertain = (e: unknown) => { const s = errStatus(e); return s === undefined || s >= 500; };

export class AccountFields {
  constructor(private deps: AccountFieldsDeps) {}

  /** The fields on this account this connection can open, opened and checked. */
  async open(accountId: string): Promise<{ fields: Opened[]; unreadable: number; unreadableIds: string[]; waiting: Waiting[] }> {
    const res = await this.deps.call<{ fields?: Served[] }>(`/accounts/${accountId}/fields`);
    // Fields this connection may open and holds no key for are named by state, never left out.
    const waiting = waitingFromList('account_fields', res);
    const fields: Opened[] = [];
    const unreadableIds: string[] = [];
    for (const f of res.fields ?? []) {
      try {
        const key = this.deps.unwrap(f.wrapped_key);
        if (fieldKid(key) !== f.kid) throw new Error('kid mismatch');
        const payload = openAccountField(Buffer.from(f.ciphertext, 'base64'), key, { id: f.id, account_id: accountId });
        fields.push({ id: f.id, kid: f.kid, rev: Number(f.rev), key, payload, mine: !!f.mine, edited_by_owner: !!f.edited_by_owner });
      } catch {
        // A wrong key, a swapped blob or a bad shape is never shown.
        unreadableIds.push(String(f?.id ?? '').toLowerCase());
      }
    }
    return { fields, unreadable: unreadableIds.length, unreadableIds, waiting };
  }

  private pick(fields: Opened[], sel: FieldSelector): Opened | null {
    if (sel.field_id) return fields.find((f) => f.id.toLowerCase() === sel.field_id!.toLowerCase()) ?? null;
    if (!sel.label || !sel.label.trim()) throw new Error('Pass label or field_id.');
    const hits = fields.filter((f) => norm(f.payload.label) === norm(sel.label!));
    if (hits.length > 1) {
      throw new Error(`${hits.length} fields on this account are labelled "${sel.label.trim()}" (${hits.map((h) => h.id).join(', ')}). Pass field_id.`);
    }
    return hits[0] ?? null;
  }

  async list(accountId: string) {
    const { fields, unreadable, waiting } = await this.open(accountId);
    return {
      account_id: accountId,
      fields: fields.map((f) => ({ field_id: f.id, label: f.payload.label, secret: f.payload.fieldType === 'concealed-string', rev: f.rev, mine: f.mine, edited_by_owner: f.edited_by_owner })),
      ...(unreadable ? { unreadable } : {}),
      ...(waiting.length ? { waiting: shownWaiting(waiting) } : {}),
    };
  }

  async get(accountId: string, sel: FieldSelector) {
    const { fields, waiting } = await this.open(accountId);
    const f = this.pick(fields, sel);
    if (!f) {
      // The field Decoy names as waiting is reported as waiting, alone. Any other is not: the read
      // says that no field it can open is the one asked for, and how many fields are waiting.
      const id = sel.field_id?.toLowerCase();
      const named = id ? waiting.find((w) => w.ids?.some((x) => x.toLowerCase() === id)) : undefined;
      if (named) {
        const { at_least: _cut, ...one } = named;
        throw new WaitingError({ ...one, count: 1, ids: [sel.field_id!] });
      }
      const none = `No field ${sel.field_id ? sel.field_id : `labelled "${(sel.label ?? '').trim()}"`} that this connection can open on this account.`;
      if (!waiting.length) throw new Error(none);
      throw new NoSuchFieldError(`${none} ${waitingFieldsSentence(waiting)}`, sel.field_id ? undefined : retrySeconds(waiting) ?? undefined);
    }
    return { field_id: f.id, label: f.payload.label, value: f.payload.value, secret: f.payload.fieldType === 'concealed-string', rev: f.rev, mine: f.mine, edited_by_owner: f.edited_by_owner };
  }

  /** What account_unlock merges into custom_fields. */
  async forUnlock(accountId: string): Promise<{ field_id: string; label: string; value: string; source: 'agent_field' }[]> {
    const { fields } = await this.open(accountId);
    return fields.map((f) => ({ field_id: f.id, label: f.payload.label, value: f.payload.value, source: 'agent_field' as const }));
  }

  /** Upsert by label / field_id. Returns ids and revisions only — never the value. */
  async set(input: { account_id: string; label: string; value: string; secret?: boolean; field_id?: string }) {
    const accountId = input.account_id;
    const fieldType: AccountFieldType = input.secret === false ? 'string' : 'concealed-string';
    const label = input.label.trim();
    if (!label) throw new Error('label must not be empty.');
    // A create that may have landed is retried with the same id and key, so it is found, not doubled.
    let pending: { id: string; key: Buffer } | null = null;
    // Once a field is chosen, retries stay on it by id: an owner rename in between never makes us
    // miss it by label and create a duplicate.
    let pinned: string | null = null;
    // A PUT whose answer was lost may have landed; finding our value afterwards means it did.
    let putSent = false;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const { fields, unreadableIds, waiting } = await this.open(accountId);
      // The field named is stored and does not open here: it is never written over, and no
      // second field is made for its id. Decoy lists a stored field this connection holds no key
      // for under its state (preparing, failed, unavailable), not among the fields.
      const named = (pinned ?? pending?.id ?? input.field_id)?.toLowerCase();
      if (named && unreadableIds.includes(named)) {
        throw recordUnreadable('This field', 'is stored and could not be opened with the key this connection holds');
      }
      const held = named ? waiting.find((w) => w.ids?.some((x) => x.toLowerCase() === named)) : undefined;
      if (held) {
        const { at_least: _cut, ...one } = held;
        throw new RecordUnreadable(`${RECORD_UNREADABLE}: This field is stored and this connection holds no key that opens it, so nothing was changed. ` +
          `Nothing was written. ${waitingLine({ ...one, count: 1, ids: [named!] })}`);
      }
      let target: Opened | null;
      if (pinned) {
        target = fields.find((f) => f.id === pinned) ?? null;
        if (!target) throw new Error('The field was deleted, or this connection lost access to it, while saving. Check with account_field_list and try again.');
      } else {
        target = (pending && fields.find((f) => f.id === pending!.id)) || this.pick(fields, { field_id: input.field_id, label });
      }
      if (target && target.payload.value === input.value && target.payload.fieldType === fieldType) {
        // Already stored: an earlier attempt landed (its answer was lost), or nothing changes.
        const how = pending?.id === target.id ? { created: true } : putSent ? { updated: true } : { unchanged: true };
        return { field_id: target.id, rev: target.rev, ...how };
      }
      if (!target) {
        pending ??= { id: (input.field_id ?? randomUUID()).toLowerCase(), key: newFieldKey() };
        const { id, key } = pending;
        const g = await this.deps.call<{ owner_public_key: string | null; grantees?: { token_id: string; public_key: string }[] }>(`/accounts/${accountId}/field-grantees`);
        if (!g.owner_public_key) throw new Error('The owner has no public key yet, so a field cannot be sealed for them. Ask them to open the Decoy app once.');
        const payload: AccountFieldPayload = { id, account_id: accountId, fieldType, label, value: input.value };
        const body = {
          id, kid: fieldKid(key),
          ciphertext: sealAccountField(payload, key).toString('base64'),
          owner_wrap: sealEnvelopeForOwner(key.toString('base64'), g.owner_public_key),
          self_wrap: wrapKeyForRecipient(key, this.deps.ownPublicKey),
          grantee_wraps: (g.grantees ?? []).map((t) => ({ token_id: t.token_id, wrapped_key: wrapKeyForRecipient(key, t.public_key) })),
        };
        let r: { status: string; id: string; kid: string; rev: number };
        try {
          r = await this.deps.call(`/accounts/${accountId}/fields`, 'POST', body);
        } catch (e) {
          if (uncertain(e)) continue;   // re-read: the field may exist now
          throw e;
        }
        if (r.status === 'existing' && r.kid !== body.kid) continue;   // re-read and update it instead
        return { field_id: id, rev: Number(r.rev), created: true };
      }
      pinned = target.id;
      const next = editAccountField(target.payload, { value: input.value, fieldType });
      putSent = true;
      try {
        const r = await this.deps.call<{ rev: number }>(`/accounts/${accountId}/fields/${target.id}`, 'PUT', {
          expected_rev: target.rev, ciphertext: sealAccountField(next, target.key).toString('base64'),
        });
        return { field_id: target.id, rev: Number(r.rev), updated: true };
      } catch (e) {
        if (errCode(e) === 'REV_CONFLICT' || uncertain(e)) continue;   // someone changed it: re-read, re-apply
        throw e;
      }
    }
    throw new Error(`The field kept changing while saving (${MAX_ATTEMPTS} attempts). Read it with account_field_get and try again.`);
  }

  async delete(accountId: string, sel: FieldSelector) {
    let id = sel.field_id;
    if (!id) {
      const f = this.pick((await this.open(accountId)).fields, sel);
      if (!f) throw new Error(`No field labelled "${(sel.label ?? '').trim()}" that this connection can open on this account.`);
      id = f.id;
    }
    const r = await this.deps.call<{ id: string; deleted: boolean }>(`/accounts/${accountId}/fields/${id}`, 'DELETE');
    return { field_id: r.id ?? id, deleted: true };
  }
}
