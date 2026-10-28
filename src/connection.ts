/**
 * Where this bridge's connection comes from, and where a renewed token goes.
 *
 * A connection is three secrets: the agent's private key (what Decoy seals to this agent can only
 * be opened with it), an access token, and the refresh token that renews it. Two sources:
 *
 *   files         ~/.decoy/mcp-token and ~/.decoy/mcp-agent-key.json, written at pairing
 *                 (directory 0700, files 0600). The default.
 *   environment   DECOY_AGENT_KEY + DECOY_AGENT_TOKEN (+ DECOY_AGENT_REFRESH_TOKEN), for a runtime
 *                 with no lasting disk. Used only as a complete set, and then nothing under
 *                 ~/.decoy is read for secrets or written. A refresh token is replaced every time
 *                 it is used, so it is only ever used when DECOY_CREDENTIALS_FILE names a file the
 *                 bridge may write the new pair to; once that file exists it holds the latest pair
 *                 and is read first.
 *
 * The credentials file is BOUND to the connection it was written for: it records the fingerprint
 * of the agent key and a hash of the environment access token it superseded (and the pinned client
 * id). A file that doesn't match what the environment holds now — an old one left on a volume
 * after a new pairing, or one from elsewhere — is refused, never used and never ignored: using it
 * would speak as the old connection with the new key, and ignoring it would spend a refresh token
 * the file says is already replaced.
 *
 * What is refused, always before anything is written: a partial environment set; a key from one
 * source with a token from another, unless it is the long-standing DECOY_AGENT_TOKEN + key file
 * (kept, and said out loud); and a token with no key. A key is generated only for a pairing, and
 * never when a token exists: a new key is one the connection doesn't know, so nothing sealed to
 * the agent could be opened.
 *
 * No message or log line built here contains a secret: they name variables and files only.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, randomBytes } from 'node:crypto';
import { readSecretFile, writeSecretFile, writeSecretFileIn, readSecretFileIn, removeLeftoverTemps, withFileLock, LOCK_STALE_MS, LockError, type NotHeld, SecretFileError, SecretDirError } from './secret-file.js';
import { parseSavedCredentials, parseKeyFile, serializeCredentials, savedKeyFingerprint, type AgentKeyPair, type SavedCredentials } from './credentials.js';

export const CONNECTION_ENV = {
  key: 'DECOY_AGENT_KEY',
  accessToken: 'DECOY_AGENT_TOKEN',
  refreshToken: 'DECOY_AGENT_REFRESH_TOKEN',
  credentialsFile: 'DECOY_CREDENTIALS_FILE',
  clientId: 'DECOY_CLIENT_ID',
} as const;

/** A connection that can't be opened as configured. The message is safe to print. */
export class CredentialSetupError extends Error {}

const UNCHANGED = 'Nothing was changed.';
const CLIENT_ID_OK = /^[A-Za-z0-9._:-]{1,128}$/;
const GENERATED_CLIENT_ID = /^decoy-mcp-server\.[0-9a-f-]{36}$/;
const sha256 = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');

/** How long a renewal request may take. Well inside the lock's stale threshold (secret-file
 *  LOCK_STALE_MS), so a renewal still running is never mistaken for a dead bridge's. */
export const RENEW_REQUEST_TIMEOUT_MS = 20_000;


/** The public key (SPKI DER, base64) that belongs to a private key. */
function publicKeyOf(privateKeyPem: string): string {
  return (createPublicKey(privateKeyPem).export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
}

/** SHA-256 of the SPKI public key (hex): which agent key a token belongs to. Not a secret. It is
 *  derived from the PRIVATE key, never read from the stored public half, so a key file whose
 *  private half was swapped does not keep the old fingerprint. */
export function keyFingerprint(pair: AgentKeyPair): string {
  return sha256(Buffer.from(publicKeyOf(pair.privateKeyPem), 'base64'));
}

/** The key pair for a PKCS#8 DER private key in base64 (one line). Never echoes the value. */
export function keyPairFromPkcs8(base64: string): AgentKeyPair {
  const name = CONNECTION_ENV.key;
  const text = base64.trim();
  const shape = `${name} is not a PKCS#8 DER private key in base64 (one line, no PEM header)`;
  if (text.includes('-----BEGIN')) throw new CredentialSetupError(`${shape}: it looks like a PEM. Convert it to DER and base64-encode that. ${UNCHANGED}`);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) throw new CredentialSetupError(`${shape}. ${UNCHANGED}`);
  let key;
  try {
    key = createPrivateKey({ key: Buffer.from(text, 'base64'), format: 'der', type: 'pkcs8' });
  } catch {
    // The parser's own message is dropped on purpose: only the variable is named.
    throw new CredentialSetupError(`${shape}. ${UNCHANGED}`);
  }
  if (key.asymmetricKeyType !== 'rsa') throw new CredentialSetupError(`${name} must be an RSA key (the one this connection was paired with). ${UNCHANGED}`);
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new CredentialSetupError(`${name} must be an RSA key of at least 2048 bits. ${UNCHANGED}`);
  return {
    publicKeySpki: (createPublicKey(key).export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
    privateKeyPem: key.export({ type: 'pkcs8', format: 'pem' }) as string,
  };
}

/** What DECOY_CREDENTIALS_FILE holds: the latest token pair, and what it was written for. */
export interface BoundCredentials {
  accessToken: string;
  refreshToken?: string;
  apiHost: string;
  /** The agent key in the environment when it was written. */
  keyPair: AgentKeyPair;
  /** The access token in the environment when it was written (the one this file's pair replaced). */
  supersededAccessToken: string;
  clientId?: string;
}

/** The credentials file's contents. Holds tokens; never the key (only its public fingerprint). */
export function serializeBoundCredentials(b: BoundCredentials): string {
  return JSON.stringify({
    access_token: b.accessToken,
    ...(b.refreshToken && { refresh_token: b.refreshToken }),
    api_host: b.apiHost,
    key_fingerprint: keyFingerprint(b.keyPair),
    supersedes: sha256(b.supersededAccessToken),
    ...(b.clientId && { client_id: b.clientId }),
  }) + '\n';
}

export type ConnectionSource = 'files' | 'environment' | 'environment-token' | 'none';

export interface Connection {
  /** files = ~/.decoy; environment = a complete set of variables; environment-token = the
   *  long-standing DECOY_AGENT_TOKEN with the key file; none = nothing saved, pair. */
  readonly source: ConnectionSource;
  /** The key this connection was paired with (null only when there is nothing saved yet). */
  readonly keyPair: AgentKeyPair | null;
  /** The latest tokens (null when there is nothing saved yet). Re-read on every call. */
  credentials(): SavedCredentials | null;
  /** True when an expired access token can be renewed AND the result saved. */
  canRenew(): boolean;
  /** Save a renewed access (and refresh) token where this connection keeps them. Never throws, never
   *  writes the key, and never writes environment-supplied secrets anywhere but the credentials
   *  file. `renewedFrom` is the access token the renewal started from: the save happens only if the
   *  file still holds it, and only into a file that belongs to this process's own key. */
  save(accessToken: string, refreshToken?: string, renewedFrom?: string): void;
  /** After a 401 on `failedBearer`: the token to carry on with, if the file holds a different one
   *  that belongs to THIS process's key and Decoy account; { mismatch } if it holds one for another
   *  key or account (the connection was replaced: do not retry, restart); null if there is nothing
   *  newer. The only way a running bridge ever takes a token from the file. */
  adoptable(failedBearer: string): { adopt: string } | { mismatch: true } | null;
  /** Run a renewal while holding the lock on the file the result is saved to, so two bridges on
   *  one connection don't both spend the refresh token. { held: false } = another bridge holds
   *  it and didn't finish in time: re-read instead of renewing. */
  withRenewLock<T>(fn: () => Promise<T>): Promise<{ held: true; value: T } | NotHeld>;
  /** Why the connection in use is held only in memory (an approved pairing that could not be
   *  written), or null when it is saved. While set, the connection ends when the bridge stops. */
  unsaved(): string | null;
  /** Try again to write a pairing held in memory (the same checks and lock as the commit). true = saved, or nothing to save. */
  retrySave(): Promise<boolean>;
  /** True for a --reconnect: pair again although a token is saved. The saved token is not
   *  touched until commitPairing. */
  readonly reconnecting: boolean;
  /** The key for a pairing: the saved one. A new one is made (in memory) only for a first pairing,
   *  when no token is saved; --reconnect never makes one. */
  keyPairForPairing(): AgentKeyPair;
  /** Save an approved pairing, under the renewal lock: the new pair is written to a temp file
   *  (0600, exclusive, flushed), read back and checked, then renamed over the token file. A first
   *  pairing's new key goes in just before, its client id just after. It waits out a lock that is
   *  merely recent, without blocking. Rejects, with nothing on disk changed, when the pairing must not be used here
   *  (another account, another pairing saved meanwhile). { saved: false } = it could not be
   *  written: nothing on disk changed, the pair is kept in memory for this process, and the log says why. */
  commitPairing(accessToken: string, refreshToken?: string): Promise<{ saved: boolean }>;
  /** Every token this process has held (from memory, never a file read), for cutting them out of output. */
  known(): string[];
  /** The pairing was not approved (denied, expired, stopped). Nothing was written; this says so. */
  abandonPairing(): void;
  /** The non-secret id sent at pairing (DECOY_CLIENT_ID, else ~/.decoy/mcp-client-id). An id is
   *  only ever sent with the key it was created with: a pairing that makes a new key gets a new id.
   *  A new id is written by commitPairing, never before. null for credentials from the environment. */
  clientId(): string | null;
  /** Where things live, for messages. */
  readonly paths: { tokenFile: string; keyFile: string; clientIdFile: string; credentialsFile: string | null };
}

export interface OpenConnectionOptions {
  env: Record<string, string | undefined>;
  /** The home directory the two files live under (os.homedir()). */
  home: string;
  /** The API host this bridge talks to; saved credentials are bound to the host that issued them. */
  apiHost: string;
  /** One line per call; never given a secret. */
  log: (line: string) => void;
  /** --reconnect: pair again although a token is saved. */
  reconnect?: boolean;
  /** Test seams for the commit: after the token's temp file is written, and just before it is renamed into place. */
  hooks?: { afterTempWrite?: (file: string) => void; beforeTokenRename?: () => void };
  /** How long to wait for another bridge's renewal (tests shorten it). */
  lock?: { waitMs?: number; staleMs?: number; pollMs?: number };
}

const val = (env: Record<string, string | undefined>, name: string): string | undefined => {
  const v = env[name]?.trim();
  return v ? v : undefined;
};

export function openConnection(opts: OpenConnectionOptions): Connection {
  const { env, apiHost, log } = opts;
  const E = CONNECTION_ENV;
  const dir = path.join(opts.home, '.decoy');
  const tokenFile = path.join(dir, 'mcp-token');
  const keyFile = path.join(dir, 'mcp-agent-key.json');
  const clientIdFile = path.join(dir, 'mcp-client-id');

  const envKey = val(env, E.key), envToken = val(env, E.accessToken), envRefresh = val(env, E.refreshToken);
  const sink = val(env, E.credentialsFile), pinnedClientId = val(env, E.clientId);

  if (pinnedClientId !== undefined && !CLIENT_ID_OK.test(pinnedClientId)) {
    throw new CredentialSetupError(`${E.clientId} must be 1 to 128 characters: letters, digits, and . _ : - only. ${UNCHANGED}`);
  }

  // ── Which source, decided before anything is read or written ─────────────────────────────────
  const fromEnvironment = envKey !== undefined;
  if (fromEnvironment && envToken === undefined) {
    throw new CredentialSetupError(`${E.key} is set without ${E.accessToken}: credentials from the environment are used only as a complete set ` +
      `(${E.key} and ${E.accessToken}; ${E.refreshToken} with ${E.credentialsFile} to renew). A saved file is never used to fill the gap. ` +
      `Set both, or unset ${E.key} to use the files in ${dir}. ${UNCHANGED}`);
  }
  if (!fromEnvironment && envRefresh !== undefined) {
    throw new CredentialSetupError(`${E.refreshToken} is set without ${E.key}: a refresh token is used only with the complete set ` +
      `(${E.key}, ${E.accessToken}, ${E.refreshToken}, ${E.credentialsFile}). Set them all, or unset ${E.refreshToken}. ${UNCHANGED}`);
  }
  if (!fromEnvironment && sink !== undefined) {
    throw new CredentialSetupError(`${E.credentialsFile} is set without ${E.key}: it is where a renewed token is saved for credentials that come from the ` +
      `environment. Set ${E.key} and ${E.accessToken} too, or unset ${E.credentialsFile} to use the files in ${dir}. ${UNCHANGED}`);
  }
  if (sink !== undefined && !path.isAbsolute(sink)) {
    throw new CredentialSetupError(`${E.credentialsFile} must be an absolute path to a file this process may write. ${UNCHANGED}`);
  }
  if (fromEnvironment && envRefresh !== undefined && sink === undefined) {
    throw new CredentialSetupError(`${E.refreshToken} needs ${E.credentialsFile}: a refresh token is replaced every time it is used, so the bridge only ` +
      `renews when it has a file to write the new pair to (otherwise the next start would hold a dead token). Set ${E.credentialsFile} to an absolute ` +
      `path, or unset ${E.refreshToken} and reconnect when the access token expires. ${UNCHANGED}`);
  }
  if (opts.reconnect && (fromEnvironment || envToken !== undefined)) {
    throw new CredentialSetupError(`--reconnect pairs over the files in ${dir}; credentials that come from the environment are the host's to replace. ` +
      `Unset ${E.key}, ${E.accessToken} and ${E.refreshToken}${sink ? ` (and remove the file ${E.credentialsFile} names)` : ''}, then start the bridge to pair. ${UNCHANGED}`);
  }

  // Every token this process holds or has held, kept in memory for the output scrubber.
  const seen = new Set<string>();
  const note = (...tokens: Array<string | undefined | null>) => { for (const t of tokens) if (t) seen.add(t); };
  const known = () => [...seen];
  note(envToken, envRefresh);

  // ── Client id (non-secret) ───────────────────────────────────────────────────────────────────
  // The id file holds the id and, on a second line, the fingerprint of the key it was paired with.
  let cachedClientId: string | null | undefined;
  let idToSave: string | null = null;   // made for this pairing; written by its commit, never before approval
  let storedIdForKey: () => string | null = () => null;   // set once the files are read
  const clientId = (): string | null => {
    if (pinnedClientId !== undefined) return pinnedClientId;
    if (cachedClientId !== undefined) return cachedClientId;
    // Credentials from the environment: this runtime has no lasting disk to keep an id on.
    if (fromEnvironment) return (cachedClientId = null);
    // An id never goes out with a key it was not paired with: the app would offer that pairing as
    // Reconnect for a key the connection does not know.
    return (cachedClientId = storedIdForKey() ?? (idToSave = `decoy-mcp-server.${randomUUID()}`));
  };
  /** ~-relative, for messages. */
  const tilde = (p: string) => (p.startsWith(opts.home) ? `~${p.slice(opts.home.length)}` : p);
  /** The same for a whole sentence, whatever produced it: the cause shown on /health and tool results never carries the home path. */
  const homeless = (text: string) => text.split(opts.home).join('~');

  const paths = { tokenFile, keyFile, clientIdFile, credentialsFile: sink ?? null };
  const notPairing = {
    adoptable: () => null,
    known,
    unsaved: () => null,
    retrySave: async () => true,
    reconnecting: false,
    commitPairing: async (): Promise<never> => { throw new CredentialSetupError(`This connection does not pair. ${UNCHANGED}`); },
    abandonPairing: () => { /* nothing was written */ },
  };

  // ── Environment: a complete set ──────────────────────────────────────────────────────────────
  if (fromEnvironment) {
    const keyPair = keyPairFromPkcs8(envKey!);
    const fingerprint = keyFingerprint(keyPair);
    const tokenHash = sha256(envToken!);
    const refuseFile = (why: string): never => {
      throw new CredentialSetupError(`The file ${E.credentialsFile} names can't be used: ${why}. It was neither used nor changed, and the tokens in the ` +
        `environment were not used in its place. To recover: delete that file to start from the tokens in the environment (if they have since been ` +
        `replaced, pair again with --reconnect on a machine that has this connection's key file, and choose Reconnect), or restore the secret-store values the file was written for. File: ${sink}`);
    };
    if (sink) {
      for (const left of removeLeftoverTemps(sink)) log(`[Decoy] Removed a temp file an interrupted write left beside ${E.credentialsFile}: ${left}`);
    }
    const readSink = (): SavedCredentials | null => {
      if (!sink) return null;
      let raw: string | null;
      try { raw = readSecretFileIn(sink); } catch (err) {
        if (err instanceof SecretDirError) {
          throw new CredentialSetupError(`The directory ${E.credentialsFile} is in can't be used: ${err.message}. Point ${E.credentialsFile} at a file in a ` +
            `directory that belongs to this user (or to root) and that not everyone can write to. ${UNCHANGED}`);
        }
        return refuseFile(err instanceof SecretFileError ? err.message : 'it could not be read');
      }
      if (raw === null) return null;
      let p: Record<string, unknown> | null = null;
      try { const j: unknown = JSON.parse(raw); if (j && typeof j === 'object' && !Array.isArray(j)) p = j as Record<string, unknown>; } catch { p = null; }
      if (!p || typeof p.access_token !== 'string' || !p.access_token || typeof p.api_host !== 'string') {
        return refuseFile('it is not a credentials file this bridge wrote');
      }
      if (typeof p.key_fingerprint !== 'string' || typeof p.supersedes !== 'string') {
        return refuseFile('it does not say which key and tokens it was written for');
      }
      if (p.api_host !== apiHost) return refuseFile(`it belongs to ${p.api_host}, and this bridge is set to ${apiHost}`);
      if (p.key_fingerprint !== fingerprint) {
        return refuseFile(`it was written for a different agent key than the one in ${E.key} now (an earlier connection's file, left behind after a new pairing)`);
      }
      // Its pair replaced the environment's access token, or the environment was updated to its pair.
      if (p.supersedes !== tokenHash && sha256(p.access_token) !== tokenHash) {
        return refuseFile(`it was written for different tokens than the ones in ${E.accessToken} now (the secret store was changed since, or the file is from an earlier pairing)`);
      }
      if (typeof p.client_id === 'string' && pinnedClientId !== undefined && p.client_id !== pinnedClientId) {
        return refuseFile(`it was written for a different ${E.clientId}`);
      }
      return { access_token: p.access_token, ...(typeof p.refresh_token === 'string' && p.refresh_token ? { refresh_token: p.refresh_token } : {}) };
    };
    const first = readSink();   // refuse a wrong file now, not at the first renewal
    log(first
      ? `[Decoy] Using the agent key from the environment (${E.key}) and the latest tokens from ${E.credentialsFile} (${sink}).`
      : `[Decoy] Using the agent key and token from the environment (${E.key}, ${E.accessToken}).`);
    const renewable = sink !== undefined && (envRefresh !== undefined || !!first?.refresh_token);
    if (!renewable) {
      log(`[Decoy] This connection will not be renewed: ${sink ? `no refresh token (${E.refreshToken})` : `no ${E.credentialsFile} to save a renewed token to`}. ` +
        'When the access token expires, pair again with --reconnect on a machine that has this connection\'s key file, and choose Reconnect in the Decoy app.');
    }
    let memory: SavedCredentials | null = null;   // a save with no file to write to: this process only
    note(first?.access_token, first?.refresh_token);
    return {
      source: 'environment', keyPair, paths, clientId, ...notPairing,
      credentials: () => memory ?? readSink() ?? { access_token: envToken!, ...(envRefresh && { refresh_token: envRefresh }) },
      // The credentials file is bound to this key and these tokens (readSink refuses any other), so what it holds is this connection's.
      adoptable: (failedBearer) => {
        try { const c = memory ?? readSink(); note(c?.access_token, c?.refresh_token); return c && c.access_token !== failedBearer ? { adopt: c.access_token } : null; }
        catch { return { mismatch: true as const }; }
      },
      canRenew: () => sink !== undefined && !!(readSink()?.refresh_token ?? envRefresh),
      save: (accessToken, refreshToken) => {
        note(accessToken, refreshToken);
        if (!sink) { memory = { access_token: accessToken, ...(refreshToken && { refresh_token: refreshToken }) }; return; }
        try {
          writeSecretFileIn(sink, serializeBoundCredentials({ accessToken, refreshToken, apiHost, keyPair, supersededAccessToken: envToken!, clientId: pinnedClientId }));
          log(`[Decoy] Saved the renewed token to ${E.credentialsFile} (${sink}). Keep that file: it now holds the only working refresh token.`);
        } catch {
          memory = { access_token: accessToken, ...(refreshToken && { refresh_token: refreshToken }) };
          log(`[Decoy] WARNING: could not write the renewed token to ${E.credentialsFile} (${sink}). It works until this process stops; ` +
            'the token in the environment has been replaced and will be refused at the next start. Fix the path, or pair again with --reconnect on a machine that has this connection\'s key file, and choose Reconnect.');
        }
      },
      withRenewLock: (fn) => (sink ? withFileLock(sink, fn, opts.lock) : fn().then((value) => ({ held: true as const, value }))),
      keyPairForPairing: () => { throw new CredentialSetupError(`Credentials come from the environment; this bridge does not pair over them. ${UNCHANGED}`); },
    };
  }

  // ── Files ────────────────────────────────────────────────────────────────────────────────────
  const noPairing = (): never => { throw new CredentialSetupError(`This connection is already paired. ${UNCHANGED}`); };
  const runNow = <T>(fn: () => Promise<T>) => fn().then((value) => ({ held: true as const, value }));
  /** A file in ~/.decoy. One that can't be trusted (a link, not a regular file, another user's) stops the bridge. */
  const read = (file: string): string | null => {
    try { return readSecretFile(file); }
    catch (e) {
      if (e instanceof SecretFileError) throw new CredentialSetupError(`${file} can't be used: ${e.message}. Look at what is there, then remove or replace it. ${UNCHANGED}`);
      throw e;
    }
  };
  /** A key file as it is on disk, with its public half taken from the private key (never trusted as stored). */
  const readKey = (file: string): AgentKeyPair | null => {
    const raw = read(file);
    if (raw === null) return null;
    try { const { privateKeyPem } = parseKeyFile(raw); return { privateKeyPem, publicKeySpki: publicKeyOf(privateKeyPem) }; }
    catch {
      throw new CredentialSetupError(`The agent key file ${file} is unreadable (damaged or incomplete). Restore it from a backup. Without one, run ` +
        '`npx decoy-mcp-server --logout` and then pair again: that is a new connection, and what the old connection created and was given stays with the old ' +
        `connection. ${UNCHANGED}`);
    }
  };

  // The long-standing DECOY_AGENT_TOKEN: an access token from the environment with the key file
  // from pairing. Kept as it was, and said out loud; never with a freshly made key.
  if (envToken !== undefined) {
    const keyForEnv = readKey(keyFile);
    if (!keyForEnv) {
      throw new CredentialSetupError(`${E.accessToken} is set, but there is no key for it: ${keyFile} is missing and ${E.key} is not set. ` +
        'This bridge never makes a new key for an existing connection (the connection would not know it, so nothing sealed to this agent could be opened). ' +
        `Restore the key this connection was paired with (set ${E.key}, or put the key file back), or unset ${E.accessToken} and start the bridge to pair again ` +
        `(a new connection). ${UNCHANGED}`);
    }
    log(`[Decoy] Using the access token from ${E.accessToken} with the agent key in ${keyFile}. It carries no refresh token and is not renewed.`);
    return {
      source: 'environment-token', keyPair: keyForEnv, paths, clientId, ...notPairing,
      credentials: () => ({ access_token: envToken }),
      canRenew: () => false,
      save: () => { /* an explicit token is used as given */ },
      withRenewLock: runNow,
      keyPairForPairing: noPairing,
    };
  }

  const parseToken = (raw: string | null): { credentials: SavedCredentials; keyFingerprint: string | null } | null => {
    if (raw === null) return null;
    const credentials = parseSavedCredentials(raw, apiHost);   // throws for another environment's credentials: stop rather than overwrite them
    if (credentials) return { credentials, keyFingerprint: savedKeyFingerprint(raw) };
    // A file that is there but holds no token (cut short, empty, not a token at all) is not "nothing
    // saved": pairing over it, or making a key beside it, could throw a live connection away. The
    // recovery that keeps the connection comes first; --logout, which cannot, comes last.
    const t = tilde(tokenFile);
    // What that start will send, from what is on disk now: Reconnect is only offered for an id stored for this key.
    const idForKey = ((): boolean => {
      try {
        const key = readKey(keyFile), recorded = (readSecretFile(clientIdFile) ?? '').split('\n')[1]?.trim();
        return !!key && !!recorded && recorded === keyFingerprint(key);
      } catch { return false; }
    })();
    throw new CredentialSetupError(`${t} is there but can't be read as a saved connection (it is damaged or incomplete). ` +
      (idForKey
        ? `To keep the connection: move only that file aside (rename it to ${t}.damaged) and start the bridge. It pairs again with the same key and id, so the ` +
          'Decoy app offers Reconnect. '
        : fs.existsSync(keyFile)
          ? `Move only that file aside (rename it to ${t}.damaged) and start the bridge. It pairs again with the same key, but there is no stored id for that ` +
            'key here, so the Decoy app will show it as a new connection: connections paired before 1.2.1 cannot be continued. Then remove the old one under ' +
            'Connections in the Decoy app. '
          : `Move only that file aside (rename it to ${t}.damaged) and start the bridge to pair. `) +
      'Or restore the file from a backup. Last resort: `npx decoy-mcp-server --logout` cannot revoke a token it cannot read, and it deletes the key and the id as ' +
      `well: the connection then stays live in Decoy until you remove it under Connections in the Decoy app, and the next pairing is a new connection. ${UNCHANGED}`);
  };
  // ── What is saved ─────────────────────────────────────────────────────────────────────────────
  const rm = (f: string) => fs.rmSync(f, { force: true });
  type Saved = { credentials: SavedCredentials; keyFingerprint: string | null };
  /** What a token says about itself (a JWT's tokenId and userId), read locally and not verified. */
  const claims = (accessToken: string | null | undefined): { tokenId?: string; userId?: string } => {
    try {
      const p = JSON.parse(Buffer.from((accessToken ?? '').split('.')[1] ?? '', 'base64url').toString('utf8')) as { tokenId?: unknown; userId?: unknown };
      return { ...(typeof p.tokenId === 'string' && { tokenId: p.tokenId }), ...(typeof p.userId === 'string' && { userId: p.userId }) };
    } catch { return {}; }
  };
  /** Only when both tokens say so. One key can hold several connections over time, so a key in common proves nothing. */
  const sameConnection = (a: Saved, b: Saved): boolean => {
    const ia = claims(a.credentials.access_token).tokenId;
    return !!ia && ia === claims(b.credentials.access_token).tokenId;
  };
  const readSaved = (): Saved | null => parseToken(read(tokenFile));

  // Temp files an interrupted write left: old ones only (another bridge may be mid-write).
  for (const f of [tokenFile, keyFile, clientIdFile]) removeLeftoverTemps(f);

  const savedAtOpen = readSaved();   // first: a token file that can't be read stops the bridge before anything else is decided
  const savedKey = readKey(keyFile);
  const reconnecting = !!opts.reconnect;
  note(savedAtOpen?.credentials.access_token, savedAtOpen?.credentials.refresh_token);

  // A token is never paired with a key it was not issued for, and a connection is never moved
  // to another key: both stop here, --reconnect or not, with the two ways back there are.
  const WAYS_BACK = `Two ways back: 1) Restore ${keyFile} from a backup. 2) Run \`npx decoy-mcp-server --logout\` and then pair again. That is a new connection: ` +
    `what the old connection created and was given stays with the old connection: this bridge does not continue a connection with a different key. ${UNCHANGED}`;
  if (reconnecting && !savedAtOpen && !savedKey) {
    throw new CredentialSetupError(`--reconnect pairs again with the key this installation already has, and there is none here (${keyFile}). ` +
      `If this computer was never connected, start the bridge without --reconnect to pair. ${UNCHANGED}`);
  }
  if (savedAtOpen && !savedKey) {
    throw new CredentialSetupError(`There is a saved connection but its key is missing: the token is in ${tokenFile} and the key file ${keyFile} is not there. ` +
      `This bridge never makes a new key for an existing connection: the connection would not know it, so nothing sealed to this agent could be opened. ${WAYS_BACK}`);
  }
  // Stopped only on positive evidence: both fingerprints known, and different. A token with no
  // fingerprint (an earlier version wrote it) is accepted, and bound at the next save.
  if (savedAtOpen?.keyFingerprint && savedKey && savedAtOpen.keyFingerprint !== keyFingerprint(savedKey)) {
    throw new CredentialSetupError('The agent key does not match this connection: the saved token was issued for a different key, so nothing sealed to this agent ' +
      `could be opened with the one in ${keyFile}. Token: ${tokenFile}. ${WAYS_BACK}`);
  }
  // The approval will be checked against the account the saved connection belongs to. One that
  // names none can't be checked, so it is not paired over.
  if (reconnecting && savedAtOpen && !claims(savedAtOpen.credentials.access_token).userId) {
    throw new CredentialSetupError(`This saved connection cannot be checked against the approving account (its token, ${tilde(tokenFile)}, names no account), so ` +
      `--reconnect will not pair over it. Move the token file aside and start the bridge without --reconnect: it pairs with the same key. ${UNCHANGED}`);
  }
  if (reconnecting) {
    log(`[Decoy] Pairing again with the key this installation already has. The saved connection is not touched until the new pairing is approved and saved: ` +
      `${savedAtOpen ? `${tokenFile} stays as it is, and in use, until then` : 'there is none saved now'}. If the pairing is denied, expires or is stopped before you approve, nothing changes.`);
    log('[Decoy] In the Decoy app, choose "Reconnect" to continue the earlier connection (its access and what it created carry over). Once you approve ' +
      'Reconnect, Decoy retires the previously saved token, whatever happens on this computer. Or approve it as a new connection. Reconnect is offered ' +
      'when the earlier connection was paired by this installation on 1.2.1 or later. Approve Reconnect only for a pairing you started yourself.');
  }

  // ── This process's connection: what it may take from the file, and the one place it writes it ──
  let ownKey: AgentKeyPair | null = savedKey;                                    // set by a first pairing's commit
  let memory: SavedCredentials | null = null;                                    // an approved pairing that could not be written: this process only
  let unsavedWhy: string | null = null;                                          // …and why
  let lastToken: string | null = savedAtOpen?.credentials.access_token ?? null;   // the token this process runs on
  const ownFingerprint = () => (ownKey ? keyFingerprint(ownKey) : null);
  /** Is this saved token this process's to use? It must be for this process's key (its own record
   *  says; without one, the key file on disk must still be this key) and for the same Decoy account. */
  const isOurs = (t: Saved): boolean => {
    const mine = ownFingerprint();
    if (!mine) return false;
    // The account: both tokens name the same one; or neither names one and they are the same
    // connection (token id). Anything else is not this bridge's.
    const own = claims(lastToken), theirs = claims(t.credentials.access_token);
    const sameToken = t.credentials.access_token === lastToken;   // the very token this process runs on (a save over it)
    if (!sameToken && (own.userId || theirs.userId ? own.userId !== theirs.userId : !own.tokenId || own.tokenId !== theirs.tokenId)) return false;
    if (t.keyFingerprint) return t.keyFingerprint === mine;
    try { const onDisk = readKey(keyFile); return !!onDisk && keyFingerprint(onDisk) === mine; } catch { return false; }
  };
  const adoptable = (failedBearer: string): { adopt: string } | { mismatch: true } | null => {
    let cur: Saved | null;
    try { cur = readSaved(); } catch { return { mismatch: true }; }   // another API host's token, or a file that can't be trusted
    if (!cur || cur.credentials.access_token === failedBearer) return null;
    // Running on an approved pairing that could not be saved: the file still holds the token it replaced.
    if (memory && cur.credentials.access_token === savedAtOpen?.credentials.access_token) return null;
    if (!isOurs(cur)) return { mismatch: true };
    memory = null; unsavedWhy = null;
    lastToken = cur.credentials.access_token;
    note(cur.credentials.access_token, cur.credentials.refresh_token);
    return { adopt: cur.credentials.access_token };
  };
  /** THE write of the token file. Callers hold the lock (a renewal, a commit) and have compared first. */
  const putToken = (accessToken: string, refreshToken: string | undefined, key: AgentKeyPair, check?: (tmp: string) => void) => {
    writeSecretFile(tokenFile, serializeCredentials(accessToken, refreshToken, apiHost, keyFingerprint(key)), check);
    lastToken = accessToken;
    note(accessToken, refreshToken);
  };

  // ── Pairing: one commit ──────────────────────────────────────────────────────────────────────
  let pairingKey: AgentKeyPair | null = savedKey;
  const subject = reconnecting ? 'reconnect' : 'pairing';
  /** The stored id, if it is this key's: its recorded fingerprint says so; an id file without one
   *  counts only while a token bound to this key is saved beside it. */
  storedIdForKey = () => {
    if (!savedKey) return null;
    try {
      const [id, recorded] = (readSecretFile(clientIdFile) ?? '').split('\n').map((l) => l.trim());
      if (!id || !GENERATED_CLIENT_ID.test(id)) return null;
      const mine = keyFingerprint(savedKey);
      return (recorded ? recorded === mine : savedAtOpen?.keyFingerprint === mine) ? id : null;
    } catch { return null; }   // a link, or unreadable: not used; a new id replaces it when the pairing is saved
  };
  let writableChecked = false;
  const keyPairForPairing = (): AgentKeyPair => {
    // A new key is a new connection. A pinned id belongs to the key it was first paired with, and
    // the app would offer this pairing as Reconnect for a key that connection does not know.
    if (!pairingKey && pinnedClientId !== undefined) {
      throw new CredentialSetupError(`${E.clientId} is set, but there is no agent key here (${tilde(keyFile)}): pairing now would make a new key, and with a new ` +
        `key it is a new connection, not a reconnect. Unset or change ${E.clientId} to pair as a new connection, or put the key file this id was paired with ` +
        `back first. ${UNCHANGED}`);
    }
    // Found once, before the owner is asked to approve anything: a place the result can't be written to.
    if (!writableChecked) {
      const cant = (why: string): never => { throw new CredentialSetupError(`The connection can't be written: ${why}. ${UNCHANGED}`); };
      try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { cant(`${dir} can't be made or is not a directory`); }
      const probe = path.join(dir, `.write-probe.${randomBytes(6).toString('hex')}.tmp`);
      try { fs.closeSync(fs.openSync(probe, 'wx', 0o600)); rm(probe); } catch { cant(`${dir} is not a directory this user can write to`); }
      writableChecked = true;
    }
    if (pairingKey) return pairingKey;
    // A first pairing (a saved token without its key stopped above). The key lives in memory until
    // the pairing is saved: nothing about it is on disk while the owner decides.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return (pairingKey = { publicKeySpki: (publicKey as Buffer).toString('base64'), privateKeyPem: privateKey as string });
  };
  const abandonPairing = () => {
    pairingKey = savedKey;
    log(`[Decoy] The ${subject} was not approved (denied, expired, or stopped first). Nothing was changed, on this computer or in Decoy` +
      `${savedAtOpen ? `: the saved connection (${tokenFile}) is as it was` : ''}.`);
  };

  const idLine = (id: string, key: AgentKeyPair) => `${id}\n${keyFingerprint(key)}\n`;
  /**
   * Put an approved pair in place. The caller holds the lock. Every check is made again on each
   * call: saved = written; stop = this pairing must not be written here (why); cant = the write failed (why).
   */
  const install = (key: AgentKeyPair, accessToken: string, refreshToken?: string): 'saved' | { stop: string } | { cant: string } => {
    let wroteKey = false;
    try {
      const another = (): Saved | null | 'another' => { try { return readSaved(); } catch { return 'another'; } };   // e.g. another API host's token, or a damaged file
      const cur = another();
      const unchanged = cur !== 'another' && (cur?.credentials.access_token ?? null) === (savedAtOpen?.credentials.access_token ?? null);
      // Over the token this pairing was approved over, or that token renewed since; never over another connection.
      if (!unchanged && !(cur && cur !== 'another' && savedAtOpen && sameConnection(cur, savedAtOpen))) {
        return { stop: 'another pairing was saved on this computer meanwhile, and it was not overwritten' };
      }
      if (!savedKey) {   // a first pairing: its key goes in first, and only into an empty place
        if (fs.existsSync(keyFile)) return { stop: `a key file appeared at ${tilde(keyFile)} meanwhile, and it was not replaced` };
        writeSecretFile(keyFile, JSON.stringify(key));
        wroteKey = true;
        // An id left by an earlier key goes when a new key comes: replaced by this pairing's, or removed.
        if (idToSave) writeSecretFile(clientIdFile, idLine(idToSave, key)); else rm(clientIdFile);
      }
      const wanted = serializeCredentials(accessToken, refreshToken, apiHost, keyFingerprint(key));
      putToken(accessToken, refreshToken, key, (tmp) => {
        opts.hooks?.afterTempWrite?.(tmp);
        if (fs.readFileSync(tmp, 'utf8') !== wanted) throw new Error('read back differently');
        opts.hooks?.beforeTokenRename?.();
      });
      // The id goes with the key it was made for. Without it the pairing still works (a later one is just not offered as Reconnect).
      if (idToSave) {
        try { if (!wroteKey) writeSecretFile(clientIdFile, idLine(idToSave, key)); idToSave = null; }
        catch { log(`[Decoy] Could not store the client id in ${clientIdFile}; a later pairing can't be offered as Reconnect.`); }
      }
      return 'saved';
    } catch (e) {
      if (wroteKey) { try { rm(keyFile); rm(clientIdFile); } catch { /* a key with no token: the next pairing uses it */ } }
      return { cant: e instanceof LockError ? e.message.replace(/\.$/, '') : `its token could not be written to ${tilde(dir)} and read back` };
    }
  };
  const notHeld = (why: NotHeld['why']) => (why === 'held'
    ? `another bridge holds the lock on the token file (${tilde(tokenFile)}.lock) and did not release it`
    : `the lock file could not be created (${tilde(tokenFile)}.lock): check that ${tilde(dir)} can be written to by this user`);
  /** The pairing held in memory is now on disk. */
  const nowSaved = () => {
    memory = null; unsavedWhy = null;
    log(`[Decoy] The pairing this bridge was holding in memory is now saved (${tokenFile}).`);
  };

  const commitPairing = async (accessToken: string, refreshToken?: string): Promise<{ saved: boolean }> => {
    const key = keyPairForPairing();   // the key the pairing was made with (the write check is made once, before approval)
    // The approval must be from the account the saved connection belongs to: this bridge's key,
    // its files and what it has cached are that account's.
    const was = claims(savedAtOpen?.credentials.access_token).userId;
    if (was && claims(accessToken).userId !== was) {
      throw Object.assign(new CredentialSetupError('The pairing was approved from a different Decoy account than the one the saved connection belongs to, so it ' +
        `was not saved. The saved connection (${tokenFile}) is as it was. To connect this computer to another account, run \`npx decoy-mcp-server --logout\` ` +
        'first and then pair.'), { otherAccount: true });
    }
    // Decoy has approved. From here on "nothing changed" is not true: after a Reconnect, the
    // previously saved token is already retired on Decoy's side. So this is the worst moment to
    // give up on a lock that is merely recent (a bridge that died mid-renewal): wait until it
    // would count as stale, and a little more. The wait does not block the process.
    const approvedBut = `Decoy approved the ${subject} but this computer could not save it`;
    const stale = opts.lock?.staleMs ?? LOCK_STALE_MS;
    let got: Awaited<ReturnType<typeof withFileLock<ReturnType<typeof install>>>>;
    try { got = await withFileLock(tokenFile, async () => install(key, accessToken, refreshToken), { ...opts.lock, staleMs: stale, waitMs: stale + (opts.lock?.waitMs ?? 15_000) }); }
    catch (e) { got = { held: true, value: { cant: e instanceof LockError ? e.message.replace(/\.$/, '') : `its token could not be written to ${tilde(dir)} and read back` } }; }
    const result = got.held ? got.value : { cant: notHeld(got.why) };
    if (typeof result === 'object' && 'stop' in result) {
      throw new CredentialSetupError(`${approvedBut}: ${result.stop}. ` + (savedKey
        ? 'Start the bridge to use the one that is saved. In the Decoy app, under Connections, keep the connection you want; if that is not the one saved here, run --reconnect again.'
        : 'Start the bridge to pair again. The connection this pairing made is listed under Connections in the Decoy app: remove it there.'));
    }
    ownKey = key;
    lastToken = accessToken; note(accessToken, refreshToken);
    if (result !== 'saved') {
      memory = { access_token: accessToken, ...(refreshToken && { refresh_token: refreshToken }) };
      unsavedWhy = homeless(result.cant);
      log(`[Decoy] WARNING: ${approvedBut}: ${result.cant}. Nothing on disk was changed. This bridge keeps running on the new token, in memory, until it stops, ` +
        'and tries again to save it from time to time. ' +
        (reconnecting
          ? 'If you chose Reconnect, the previously saved token no longer works, so the bridge will be refused if it is started again before this is saved. Fix the ' +
            'cause and it is saved without anything more from you. If the bridge stops first: run `npx decoy-mcp-server --reconnect` again and choose Reconnect on ' +
            'your phone. Do not remove the connection in the app.'
          : 'Fix the cause and it is saved without anything more from you. If the bridge stops first it will pair again when it is started, and the connection this ' +
            'pairing made is then left under Connections in the Decoy app: remove it there once the new one works.'));
      return { saved: false };
    }
    log(reconnecting
      ? `[Decoy] The new pairing is saved (${tokenFile}). If you approved it as Reconnect, the earlier token is retired and other running bridges on this ` +
        'connection pick up the new one on their next call. If you approved it as a new connection, the earlier one is still listed under Connections in the Decoy app: remove it there.'
      : `[Decoy] The pairing is saved (${tokenFile}).`);
    return { saved: true };
  };

  /** What a retry found: saved, or the reason it still is not (kept for unsaved()). */
  const settle = (result: ReturnType<typeof install>): boolean => {
    if (result === 'saved') { nowSaved(); return true; }
    unsavedWhy = homeless('stop' in result ? result.stop : result.cant);
    return false;
  };
  const retrySave = async (): Promise<boolean> => {
    if (!memory || !ownKey) return true;
    const held = memory, key = ownKey;
    try {
      const got = await withFileLock(tokenFile, async () => (memory === held ? install(key, held.access_token, held.refresh_token) : 'saved' as const), { ...opts.lock, waitMs: 0 });
      if (!got.held) { unsavedWhy = homeless(notHeld(got.why)); return false; }
      return memory === held ? settle(got.value) : !memory;
    } catch (e) { unsavedWhy = homeless(e instanceof LockError ? e.message.replace(/\.$/, '') : `its token could not be written to ${tilde(dir)}`); return false; }
  };

  const REPLACED = 'This bridge\'s connection was replaced by another one on this computer (the saved token belongs to a different key or account). Restart the bridge.';
  /** A renewal's result, saved only over the token it was renewed from (called inside withRenewLock). */
  const saveToFile = (accessToken: string, refreshToken?: string, renewedFrom?: string) => {
    if (memory && ownKey) {   // the file holds the token this process's pairing replaced: the renewed pair is the one to write, with every check again
      memory = { access_token: accessToken, ...(refreshToken && { refresh_token: refreshToken }) };
      lastToken = accessToken; note(accessToken, refreshToken);
      settle(install(ownKey, accessToken, refreshToken));
      return;
    }
    try {
      let cur: Saved | null;
      try { cur = readSaved(); } catch { log(`[Decoy] ${REPLACED} The renewed token was not saved.`); return; }
      if (cur && !isOurs(cur)) { log(`[Decoy] ${REPLACED} The renewed token was not saved.`); return; }
      if (!cur || !ownKey || cur.credentials.access_token !== (renewedFrom ?? lastToken)) {
        log(`[Decoy] ${tokenFile} no longer holds the token that was renewed (it was replaced or removed meanwhile); the renewed token was not saved.`);
        return;
      }
      putToken(accessToken, refreshToken, ownKey);
    } catch { log(`[Decoy] Warning: could not save the token to ${tokenFile}.`); }
  };

  const files = {
    paths, clientId, adoptable, known, retrySave,
    unsaved: () => (memory ? unsavedWhy : null),
    credentials: () => memory ?? readSaved()?.credentials ?? null,
    canRenew: () => !!(memory ?? readSaved()?.credentials)?.refresh_token,
    save: saveToFile,
    // With the pairing only in memory and no way to make a lock file, nothing on disk can be raced: the renewal runs without it.
    withRenewLock: async <T>(fn: () => Promise<T>) => {
      const got = await withFileLock(tokenFile, fn, opts.lock);
      return !got.held && got.why === 'unusable' && memory ? { held: true as const, value: await fn() } : got;
    },
  };
  if (savedAtOpen && savedKey && !reconnecting) {
    return { source: 'files', keyPair: savedKey, ...files, reconnecting: false, commitPairing: notPairing.commitPairing, abandonPairing: notPairing.abandonPairing, keyPairForPairing: noPairing };
  }
  // Nothing saved, or a --reconnect: the next step is a pairing.
  return { source: 'none', keyPair: savedKey, ...files, reconnecting, keyPairForPairing, commitPairing, abandonPairing };
}
