/**
 * Does a credential saved for `saved` serve a request for `asked`? Exactly, when asked is a
 * subdomain of the saved site, or when the saved site is asked's www. Never by a bare suffix
 * ("com"), and asking for a parent never reaches a child site's credential.
 */
export function hostMatches(saved: string, asked: string): boolean {
  const s = saved.trim().toLowerCase(), a = asked.trim().toLowerCase();
  if (!s.includes('.') || !a.includes('.')) return false;
  return s === a || a.endsWith(`.${s}`) || s === `www.${a}`;
}

/** A saved URL or bare host as a lowercase hostname (null when there is none). */
export function hostOf(u: unknown): string | null {
  if (typeof u !== 'string' || !u) return null;
  try { return new URL(u.includes('://') ? u : `https://${u}`).hostname.toLowerCase(); }
  catch { return u.toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0] || null; }
}

/** Does a credential saved under this URL serve a request for `asked`? */
export function urlHostMatches(savedUrl: unknown, asked: string): boolean {
  const saved = hostOf(savedUrl);
  return !!saved && hostMatches(saved, asked);
}

/**
 * Whether a value an account envelope gives as its site may be passed on as one. Only what the
 * guard is for is refused: a value shaped like a 2FA secret (16 or more base32 characters, with
 * a digit, no dot), an otpauth URI, a URL or path, an address, text with spaces, an overlong
 * value. Every other name a site can have is accepted: letters of any alphabet, underscores, a
 * port, a bracketed IPv6 address, a final dot, a single long label.
 */
export function looksLikeHost(v: unknown): v is string {
  if (typeof v !== 'string' || v.length === 0 || v.length > 253) return false;
  if (/\s/.test(v) || v.includes('://') || v.includes('/') || v.includes('@') || /^otpauth/i.test(v)) return false;
  const seedShaped = /^[a-z2-7]{16,}=*$/i.test(v) && /[2-7]/.test(v); // no dot can match: the class has none
  return !seedShaped;
}

const SITE_HOST = /^(?:[a-z0-9-]{1,63}\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$/;

/**
 * The site of an account as a host, for a list that must hold no secret (list_topics `accounts`).
 * The stored value is shown only when it is a web address or a bare host, and the host is in it
 * letter for letter: an optional http(s)://, then the host, then an optional port and an optional
 * path. The host has at least one dot and at most 253 characters; each label is 1 to 63 letters
 * a-z, digits and hyphens; and the last label is what a top-level domain is: 2 to 24 letters and
 * nothing else, or punycode (xn--…). So an IP address is not one, and nor is a value that only
 * has a dot in it ("MyDog.Rex2019", "SG.x.y", a three-part token). Anything else gives null: a
 * value with any other character in the host's place (a password, a key, a 2FA secret, a number,
 * a name in another alphabet, a user name and password before the host), and any other scheme.
 */
export function siteHost(stored: unknown): string | null {
  if (typeof stored !== 'string') return null;
  const value = stored.trim();
  if (!value || value.length > 2048) return null;
  const m = /^(?:https?:\/\/)?([^/?#:@\s]+)(?::\d{1,5})?(?:[/?#].*)?$/is.exec(value);
  if (!m) return null;
  const host = m[1].toLowerCase();
  if (host.length > 253 || !SITE_HOST.test(host)) return null;
  // What a URL parser makes of the stored value is that same host, unchanged.
  try { return new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`).hostname === host ? host : null; } catch { return null; }
}
