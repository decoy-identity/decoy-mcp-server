// webauthn-bridge.ts — the page-side relay for passkey login.
//
// A passkey can't be exported and read like a password; it has to be *signed*.
// The Decoy passkey_assert MCP tool relays the browser's WebAuthn ceremony to
// the iPhone, which holds the private key and produces the assertion. This
// module is the missing browser half: it installs a shim that overrides
// navigator.credentials.get in the page, ships the ceremony params out to the
// agent (which calls passkey_assert), and resolves the page's promise with a
// synthetic PublicKeyCredential that a real @simplewebauthn/browser RP accepts.
//
// This file has NO side effects on import — call installPasskeyBridge(page, assert)
// once per page, BEFORE navigating to the login page (addInitScript must run
// before any page script touches navigator.credentials).
//
// ─── Usage (wiring it to the MCP passkey_assert tool) ───────────────────────
//
//   import { chromium } from 'playwright';
//   import { installPasskeyBridge } from './webauthn-bridge.js';
//   import { Client } from '@modelcontextprotocol/sdk/client/index.js';
//
//   const browser = await chromium.launch();
//   const page = await browser.newPage();
//
//   // `assert` calls the Decoy MCP passkey_assert tool and returns its result.
//   await installPasskeyBridge(page, async ({ rpId, credentialIdB64, credentialIdsB64, clientDataJsonB64 }, { signal }) => {
//     const res = await mcpClient.callTool({
//       name: 'passkey_assert',
//       arguments: {
//         rp_id: rpId,
//         credential_id_b64: credentialIdB64,
//         credential_ids_b64: credentialIdsB64,
//         client_data_json_b64: clientDataJsonB64,
//         reason: 'Sign in with passkey',
//       },
//     }, undefined, {
//       signal,            // the page gave up: the call is cancelled and the owner's prompt ends
//       timeout: 330_000,  // the owner has up to 5 minutes to answer; the MCP client's default is 60 s
//     });
//     // The tool returns the assertion JSON as text content.
//     return JSON.parse(res.content[0].text) as {
//       authenticator_data: string; signature: string;
//       user_handle: string | null; credential_id: string;
//     };
//   });
//
//   await page.goto('https://example.com/login');
//   await page.click('#sign-in-with-passkey'); // page calls navigator.credentials.get → bridged
//
// ────────────────────────────────────────────────────────────────────────────

/**
 * The assertion-producing callback the bridge invokes. Receives the ceremony
 * params the page asked for (relying-party id, the requested credential id, and
 * the browser-authored clientDataJSON — all that the device needs to sign), and
 * returns the WebAuthn assertion produced on-device. All byte fields are base64.
 *
 * Wire this to the Decoy `passkey_assert` MCP tool.
 */
export type PasskeyAssertFn = (p: {
  /** Relying-party id, e.g. "github.com" (options.publicKey.rpId). */
  rpId: string;
  /** The requested credential id when the page lists exactly one (allowCredentials), base64; else "". */
  credentialIdB64: string;
  /** Every credential id the page lists (allowCredentials[].id), base64; empty when it lists none. */
  credentialIdsB64: string[];
  /** The exact browser-authored clientDataJSON bytes, base64. */
  clientDataJsonB64: string;
}, opts: {
  /** Aborted when the page gives up (its timeout, or its AbortSignal): cancel the tool call with it. */
  signal: AbortSignal;
}) => Promise<{
  /** authenticatorData bytes, base64. */
  authenticator_data: string;
  /** ECDSA (DER) signature bytes, base64. */
  signature: string;
  /** userHandle bytes, base64 — or null if the device doesn't return one. */
  user_handle: string | null;
  /** The credential id the device signed with, base64. */
  credential_id: string;
}>;

// Playwright isn't a dependency of this package — the helper runs inside the
// agent's own Playwright. We keep `Page` loose so the build stays green without
// pulling in playwright. (Agents get full typing from their own import.)
import { checkClientData } from './passkey-check.js';

type Page = any; // eslint-disable-line @typescript-eslint/no-explicit-any

/**
 * Install the passkey relay on a Playwright Page.
 *
 * Overrides navigator.credentials.get so that any WebAuthn login ceremony the
 * page starts is routed through `assert` (→ the Decoy passkey_assert tool → the
 * iPhone) instead of a real authenticator. The page receives a synthetic
 * PublicKeyCredential whose response buffers are REAL fresh ArrayBuffers, which
 * @simplewebauthn/browser (and hand-rolled RP clients) accept.
 *
 * Call once per page, before navigating to the login page.
 *
 * @param page   Playwright Page (typed loosely; see note above).
 * @param assert Callback that produces the on-device assertion.
 */
export async function installPasskeyBridge(page: Page, assert: PasskeyAssertFn): Promise<void> {
  // Node ⇄ page boundary. The page shim calls window.__decoyPasskeyAssert(...); Playwright
  // marshals the JSON across to this Node-side callback along with the calling frame, whose
  // real origin page scripts can't fake: the ceremony must come from it and from the rpId.
  // One AbortController per ceremony: the page tells us when it gives up (timeout or abort), and
  // the assert callback's signal cancels the tool call, which withdraws the owner's ask.
  const ceremonies = new Map<string, AbortController>();
  const givenUp = new Set<string>(); // gave up before its ceremony reached us
  const controllerFor = (id: string) => {
    let c = ceremonies.get(id);
    if (!c) { c = new AbortController(); ceremonies.set(id, c); }
    if (givenUp.delete(id)) c.abort();
    return c;
  };
  await page.exposeBinding(
    '__decoyPasskeyAssert',
    async (source: { frame: { url(): string } }, p: { rpId: string; credentialIdB64: string; credentialIdsB64?: string[]; clientDataJsonB64: string; ceremonyId?: string }) => {
      checkClientData(p.rpId, p.clientDataJsonB64, new URL(source.frame.url()).origin);
      const id = typeof p.ceremonyId === 'string' ? p.ceremonyId : '';
      const c = id ? controllerFor(id) : new AbortController();
      try {
        return await assert(
          { rpId: p.rpId, credentialIdB64: p.credentialIdB64, credentialIdsB64: Array.isArray(p.credentialIdsB64) ? p.credentialIdsB64 : [], clientDataJsonB64: p.clientDataJsonB64 },
          { signal: c.signal },
        );
      } finally {
        if (id) ceremonies.delete(id);
      }
    },
  );
  await page.exposeBinding('__decoyPasskeyAbort', async (_source: unknown, id: unknown) => {
    if (typeof id !== 'string' || !id) return;
    const c = ceremonies.get(id);
    if (c) c.abort();
    else if (givenUp.size < 64) givenUp.add(id);
  });

  // The browser-side shim. Runs in page context via addInitScript BEFORE any
  // page script. It authors clientDataJSON itself (the canonical byte layout the
  // device must hash), ships the exact bytes to Node, and resolves a synthetic
  // PublicKeyCredential whose .response fields are real ArrayBuffers and whose
  // getClientExtensionResults() exists. Mirrors the proven spike shim.
  await page.addInitScript(() => {
    const enc = new TextEncoder();

    // ── base64 / base64url helpers (page-side; mirror the spike) ────────────
    // Bytes from the device cross the boundary as base64 (clientDataJSON is
    // base64 too, matching the passkey_assert contract). We decode/encode here.
    function b64ToBytes(s: string): Uint8Array {
      // Tolerate base64url just in case, then standard base64.
      const norm = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = norm.length % 4 === 2 ? '==' : norm.length % 4 === 3 ? '=' : '';
      const bin = atob(norm + pad);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    function bytesToB64(bytes: Uint8Array): string {
      let str = '';
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str);
    }
    function bytesToB64url(bytes: Uint8Array): string {
      return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    // bufferSource (ArrayBuffer | TypedArray) -> Uint8Array
    function toBytes(bs: ArrayBuffer | ArrayBufferView): Uint8Array {
      if (bs instanceof ArrayBuffer) return new Uint8Array(bs);
      if (ArrayBuffer.isView(bs)) return new Uint8Array(bs.buffer, bs.byteOffset, bs.byteLength);
      return new Uint8Array(bs as ArrayBuffer);
    }
    // Return a fresh, exact-length ArrayBuffer copy (no slack from pooled buffers).
    function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
      const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const ab = new ArrayBuffer(u8.byteLength);
      new Uint8Array(ab).set(u8);
      return ab;
    }

    // Author the canonical clientDataJSON. WebAuthn requires UTF-8 JSON with
    // type, challenge (base64url, no padding), origin; we also include
    // crossOrigin:false. Key ORDER is the contract the device re-hashes:
    // type, challenge, origin, crossOrigin. JSON.stringify preserves insertion
    // order for string keys, so this layout is stable.
    function buildClientDataJSON(challengeBytes: Uint8Array, origin: string): Uint8Array {
      const obj = {
        type: 'webauthn.get',
        challenge: bytesToB64url(challengeBytes),
        origin,
        crossOrigin: false,
      };
      return enc.encode(JSON.stringify(obj));
    }

    // We can't construct a real PublicKeyCredential; we forge a duck-typed
    // object. @simplewebauthn/browser reads: id, rawId, response.{...}, type,
    // getClientExtensionResults(), authenticatorAttachment. This is the exact
    // synthetic shape the spike proved a real RP client accepts.
    function makeSyntheticCredential(args: {
      id: string;
      rawId: ArrayBuffer;
      type: string;
      response: unknown;
      authenticatorAttachment: string;
    }) {
      const { id, rawId, type, response, authenticatorAttachment } = args;
      const cred: Record<string, unknown> = {
        id,
        rawId, // ArrayBuffer
        type,
        response,
        authenticatorAttachment,
        getClientExtensionResults() {
          return {};
        },
        // Real creds have toJSON(); provide it for completeness (lib won't call it).
        toJSON() {
          return { id, type };
        },
      };
      // Make instanceof / toString checks less likely to surprise an RP.
      Object.defineProperty(cred, Symbol.toStringTag, { value: 'PublicKeyCredential' });
      return cred;
    }

    const realGet = navigator.credentials.get.bind(navigator.credentials);

    navigator.credentials.get = async (options?: CredentialRequestOptions) => {
      // Non-WebAuthn requests (e.g. password credentials) pass through untouched.
      if (!options || !(options as { publicKey?: unknown }).publicKey) {
        return realGet(options);
      }
      // A background request the page makes on load (passkey autofill, mediation "conditional")
      // is never sent to the owner's phone: only a sign-in the agent starts is. The browser
      // handles it as if Decoy were not there.
      if ((options as { mediation?: string }).mediation === 'conditional') {
        return realGet(options);
      }
      const pk = (options as { publicKey: PublicKeyCredentialRequestOptions }).publicKey;

      // Honor an already-aborted signal up front, and reject if it aborts later.
      const signal = options.signal;
      if (signal?.aborted) {
        throw new DOMException('The operation was aborted.', 'AbortError');
      }

      const challengeBytes = toBytes(pk.challenge as ArrayBuffer);
      const origin = window.location.origin;
      // rpId defaults to the effective domain when the page omits it.
      const rpId = pk.rpId || window.location.hostname;

      // Every credential id the page lists (Decoy signs with the one it holds), and the one id
      // when it lists exactly one. With none, Decoy finds the passkey by site.
      const allow = pk.allowCredentials || [];
      const credentialIdsB64 = allow.map((c) => bytesToB64(toBytes(c.id as ArrayBuffer)));
      const credentialIdB64 = credentialIdsB64.length === 1 ? credentialIdsB64[0] : '';
      const ceremonyId = Math.random().toString(36).slice(2) + Date.now().toString(36);

      // Author the exact clientDataJSON bytes the device must hash.
      const clientDataJSON = buildClientDataJSON(challengeBytes, origin);

      // Race the relay against timeout / abort so the page's promise can settle.
      const relay = (
        window as unknown as {
          __decoyPasskeyAssert: (p: {
            rpId: string;
            credentialIdB64: string;
            credentialIdsB64: string[];
            clientDataJsonB64: string;
            ceremonyId: string;
          }) => Promise<{
            authenticator_data: string;
            signature: string;
            user_handle: string | null;
            credential_id: string;
          }>;
        }
      ).__decoyPasskeyAssert({
        rpId,
        credentialIdB64,
        credentialIdsB64,
        clientDataJsonB64: bytesToB64(clientDataJSON),
        ceremonyId,
      });

      const racers: Promise<unknown>[] = [relay];
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      if (typeof pk.timeout === 'number' && pk.timeout > 0) {
        racers.push(
          new Promise((_resolve, reject) => {
            timeoutId = setTimeout(
              () => reject(new DOMException('The operation timed out.', 'TimeoutError')),
              pk.timeout,
            );
          }),
        );
      }
      if (signal) {
        racers.push(
          new Promise((_resolve, reject) => {
            signal.addEventListener(
              'abort',
              () => reject(new DOMException('The operation was aborted.', 'AbortError')),
              { once: true },
            );
          }),
        );
      }

      let out: {
        authenticator_data: string;
        signature: string;
        user_handle: string | null;
        credential_id: string;
      };
      try {
        out = (await Promise.race(racers)) as typeof out;
      } catch (e) {
        // The page gave up (timeout or abort): the owner's prompt ends.
        if (e instanceof DOMException && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
          void (window as unknown as { __decoyPasskeyAbort?: (id: string) => Promise<void> }).__decoyPasskeyAbort?.(ceremonyId)?.catch?.(() => {});
        }
        throw e;
      } finally {
        if (timeoutId !== undefined) clearTimeout(timeoutId);
      }

      // Decode the device's assertion (base64) back into real ArrayBuffers.
      const authDataBytes = b64ToBytes(out.authenticator_data);
      const signatureBytes = b64ToBytes(out.signature);
      const userHandleBytes = out.user_handle ? b64ToBytes(out.user_handle) : null;
      // The device tells us which credential it signed with; prefer that, else echo.
      const credIdB64 = out.credential_id || credentialIdB64;
      const rawIdBytes = credIdB64 ? b64ToBytes(credIdB64) : new Uint8Array(0);

      const response = {
        clientDataJSON: toArrayBuffer(clientDataJSON),
        authenticatorData: toArrayBuffer(authDataBytes),
        signature: toArrayBuffer(signatureBytes),
        userHandle: userHandleBytes ? toArrayBuffer(userHandleBytes) : null,
      };

      // RP libs read credential.id as base64url; emit that form.
      return makeSyntheticCredential({
        id: bytesToB64url(rawIdBytes),
        rawId: toArrayBuffer(rawIdBytes),
        type: 'public-key',
        response,
        authenticatorAttachment: 'platform',
      }) as unknown as Credential;
    };
  });
}
