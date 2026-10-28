/**
 * Binds a passkey ceremony to its real origin before the phone is asked to sign: the
 * clientDataJSON must be a webauthn.get, not cross-origin, from https on the relying party
 * (or a subdomain), and, when the browser relay knows the calling frame, from that frame.
 */
export function checkClientData(rpId: string, clientDataJsonB64: string, frameOrigin?: string): void {
  const rp = rpId.trim().toLowerCase();
  if (!rp.includes('.') || rp.startsWith('.') || rp.endsWith('.')) throw new Error(`rp_id "${rpId}" is not a site's domain.`);
  let cd: { type?: unknown; origin?: unknown; crossOrigin?: unknown };
  try { cd = JSON.parse(Buffer.from(clientDataJsonB64, 'base64').toString('utf8')); } catch { throw new Error('clientDataJSON is not valid base64 JSON.'); }
  if (!cd || typeof cd !== 'object') throw new Error('clientDataJSON is not valid base64 JSON.');
  if (cd.type !== 'webauthn.get') throw new Error('clientDataJSON must be a login ceremony (type "webauthn.get").');
  if (cd.crossOrigin === true) throw new Error('A cross-origin passkey ceremony is not allowed.');
  let origin: URL;
  try { origin = new URL(String(cd.origin)); } catch { throw new Error('clientDataJSON has no valid origin.'); }
  if (origin.protocol !== 'https:') throw new Error('A passkey ceremony origin must use https.');
  const host = origin.hostname.toLowerCase();
  if (host !== rp && !host.endsWith(`.${rp}`)) throw new Error(`The ceremony origin ${origin.origin} is not ${rp} or one of its subdomains.`);
  if (frameOrigin !== undefined && frameOrigin !== origin.origin) {
    throw new Error(`The ceremony origin ${origin.origin} is not the frame that asked (${frameOrigin}).`);
  }
}
