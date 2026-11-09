/**
 * The name a person sees for each tool (MCP `title`), in the Decoy app's own words: a host shows
 * it in its tool list and on each call ("Save a memory", not `add_memory`). The tool's `name`
 * stays what an agent calls. Every tool on the default list has one.
 */
export const TOOL_TITLES: Readonly<Record<string, string>> = {
  // Accounts
  credential_get: 'Look up an account',
  credential_set: 'Save an account login',
  credential_delete: 'Delete an account login',
  account_field_set: 'Save a secret on an account',
  account_field_get: 'Read a secret on an account',
  account_field_list: 'List the secrets on an account',
  account_field_delete: 'Delete a secret on an account',
  // Decoy emails
  decoy_list: 'List Decoy emails',
  decoy_create: 'Create a Decoy email',
  decoy_burn: 'Burn a Decoy email',
  inbox_list: 'List emails',
  email_read: 'Read an email',
  email_send: 'Send an email',
  email_mark_read: 'Mark an email read or unread',
  email_reply: 'Reply to an email',
  email_delete: 'Delete an email',
  // Personal info
  identity_get: 'Read personal info',
  identity_set: 'Save personal info',
  identity_update: 'Update personal info',
  identity_delete: 'Delete personal info',
  // Access
  my_permissions: 'Check access',
  request_access: 'Ask for access',
  // Utility
  password_generate: 'Make a password',
  // Memories
  add_memory: 'Save a memory',
  search_memories: 'Search memories',
  get_memories: 'List memories',
  get_memory: 'Read a memory',
  update_memory: 'Edit a memory',
  delete_memory: 'Delete a memory',
  list_topics: 'List topics',
  read_topic: 'Read a topic',
  list_duplicate_topics: 'Find similar topics',
  connect_topics: 'Link two topics',
  disconnect_topics: 'Unlink two topics',
  set_topic_parent: 'Move a topic',
  move_memories: 'Move memories',
};

/**
 * What each tool does to the vault, for the host (MCP tool annotations): it only reads, or it can
 * delete or overwrite something, or it reaches people outside Decoy. A tool that sets its own
 * annotations (the memory tools) keeps them; every other tool on the default list has one here.
 */
const READS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const ADDS = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const OVERWRITES = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };
const DELETES = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };
const SENDS = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
export const TOOL_HINTS: Readonly<Record<string, Readonly<Record<string, boolean>>>> = {
  credential_get: READS,
  credential_set: OVERWRITES,
  credential_delete: DELETES,
  account_field_set: OVERWRITES,
  account_field_get: READS,
  account_field_list: READS,
  account_field_delete: DELETES,
  decoy_list: READS,
  decoy_create: ADDS,
  decoy_burn: DELETES,
  inbox_list: READS,
  email_read: READS,
  email_send: SENDS,
  // Read or unread is a flag on the owner's copy, set to the same value however often: nothing lost.
  email_mark_read: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  email_reply: SENDS,
  email_delete: DELETES,
  identity_get: READS,
  identity_set: ADDS,
  identity_update: OVERWRITES,
  identity_delete: DELETES,
  my_permissions: READS,
  request_access: ADDS,
  password_generate: READS,
};
