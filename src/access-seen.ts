// The access a saved connection was last seen to have, kept between runs of the bridge so that a
// change made in the Decoy app while no bridge was running is announced to the next session.
//
// One small file beside the token: ~/.decoy/mcp-access-seen
//   line 1  the fingerprint (src/access-summary.ts accessFingerprint): the server's access version
//           ("v:<version>") or a hash of what the connection may do ("h:<32 hex>")
//   line 2  the fingerprint of this agent's key, so a file written for another connection is ignored
// Neither is a secret. It is still written and read like the files beside it (src/secret-file.ts):
// owner-only, a temp file renamed into place, never through a link. Nothing else reads it, and the
// token, key and id files are never touched from here. A connection supplied by the environment has
// no file: what it saw lives in memory.

import fs from 'node:fs';
import path from 'node:path';
import { keyFingerprint, type Connection } from './connection.js';
import { readSecretFile, writeSecretFile } from './secret-file.js';
import type { AccessStore } from './access-summary.js';

export const ACCESS_SEEN_FILE = 'mcp-access-seen';
const FINGERPRINT = /^[hv]:[\w.:-]{1,128}$/;

export function accessSeenStore(c: Connection): AccessStore | undefined {
  if (c.source === 'environment' || c.source === 'environment-token' || !c.keyPair) return undefined;
  const file = path.join(path.dirname(c.paths.tokenFile), ACCESS_SEEN_FILE);
  const key = keyFingerprint(c.keyPair);
  return {
    load() {
      const [seen, forKey] = (readSecretFile(file) ?? '').split('\n').map((l) => l.trim());
      return seen && forKey === key && FINGERPRINT.test(seen) ? seen : null;
    },
    // Only beside a connection that is itself saved: nothing is written for one held in memory.
    save(fingerprint) {
      if (!FINGERPRINT.test(fingerprint) || c.unsaved() || !fs.existsSync(c.paths.tokenFile)) return;
      writeSecretFile(file, `${fingerprint}\n${key}\n`);
    },
  };
}
