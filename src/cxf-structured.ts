import { randomUUID } from 'node:crypto';

// Multi-part typed fields (address, credit-card) ⇄ StructuredFieldBlob[].
//
// This is the MCP-server inverse of the iOS AccountMetadataBlob.toCXFItem mapping
// (CryptoService.swift). Each such CXF credential carries its members as
// EditableFields whose `designation` IS the CXF member name (= the
// StructuredFieldBlob `values` key), e.g. address → streetAddress/city/postalCode/…,
// credit-card → number/fullName/expiryDate/verificationNumber.
//
// CRITICAL: every emitted entry MUST have a string `id`. iOS StructuredFieldBlob.id
// is a required Codable key with no custom decoder, so a missing id makes the entire
// `structured` array silently decode to nil on the device → the user's address/card
// vanishes. The id is ephemeral (iOS regenerates it on its own CXF reads), so a fresh
// uuid per reconstruction is correct.

export const STRUCTURED_CXF_TYPES = new Set(['address', 'credit-card']);

export interface StructuredFieldBlob {
  id: string;
  kind: string;
  label: string | null;
  values: Record<string, string>;
}

/**
 * Reconstruct StructuredFieldBlob[] from a CXF Item's address/credit-card
 * credentials. Returns [] when there are none. `genId` is injectable for tests.
 */
export function cxfItemToStructured(
  item: any,
  genId: () => string = randomUUID,
): StructuredFieldBlob[] {
  const creds: any[] = (item && item.credentials) || [];
  return creds
    .filter((c: any) => STRUCTURED_CXF_TYPES.has(c?.type))
    .map((c: any): StructuredFieldBlob => {
      const values: Record<string, string> = {};
      for (const f of (c.fields || [])) {
        if (f?.designation) values[f.designation] = f.value;
      }
      return { id: genId(), kind: c.type, label: c.label ?? null, values };
    })
    .filter((s) => Object.keys(s.values).length > 0);
}
