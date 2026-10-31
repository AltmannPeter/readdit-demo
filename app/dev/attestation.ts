// What the nym_auth attestation looks like in each encoding, in the demo profile's rulebook version
// (v0.4: birth_date, ssc and psc; v0.5: bsc and psc as items; v0.6: bsc and psc as the MSO's
// valueDigests, the decoy-digest layout, no items), with the values of the demo's own credentials
// (app/wallet/demo-wallet*.json, decoded by app/wallet/holder.ts).
import { findScheme } from '#shared/registry/circuits'
import type { CredentialView } from '~/wallet/holder'

export interface AttestationRow {
  id: string
  type: string
  presence?: string
  value: string
  note?: string
}

export interface AttestationView {
  encoding: 'mso_mdoc' | 'bbs_cd'
  title: string
  typeLabel: string
  typeValue: string
  rows: AttestationRow[]
  secrets: AttestationRow[]
  notes: string[]
  structure: Record<string, unknown>
}

const short = (hex: string) => (hex.length > 20 ? `h'${hex.slice(0, 8)}…${hex.slice(-8)}'` : `h'${hex}'`)
/** date-packed = (Y − 1900)·372 + (M − 1)·31 + (D − 1) */
const packed = (iso: string) => {
  const [y, m, d] = iso.split('-').map(Number) as [number, number, number]
  return (y - 1900) * 372 + (m - 1) * 31 + (d - 1)
}

/** The mdoc's IssuerSignedItem values and its MSO, for the full structure; the MSO's members in
 *  the order the credential has them (v0.5's compact profile puts docType second after the
 *  algorithm). */
function mdocStructure(c: CredentialView, value: Record<string, string>): Record<string, unknown> {
  const ns = c.namespace || c.docType
  const msoBody = {
    version: c.mso.version,
    digestAlgorithm: c.mso.digestAlgorithm,
    ...(c.rulebook === '0.5' && { docType: c.docType }),
    valueDigests: { [ns]: Object.fromEntries(c.elements.map((e) => [e.digestID, "h'…'"])) },
    deviceKeyInfo: { deviceKey: { kty: 'EC2', crv: c.deviceKey.crv, jwk_thumbprint: c.deviceKey.jwkThumbprint } },
    ...(c.rulebook !== '0.5' && { docType: c.docType }),
    validityInfo: c.validity,
  }
  return {
    docType: c.docType,
    issuerSigned: {
      nameSpaces: { [ns]: c.elements.map((e) => ({ digestID: e.digestID, random: "h'…' (16 bytes)", elementIdentifier: e.id, elementValue: value[e.id] ?? '…' })) },
      issuerAuth: {
        COSE_Sign1: {
          protected: { alg: c.mso.signatureAlgorithm },
          unprotected: { '33 (x5chain)': c.issuer.documentSigner },
          payload: { MobileSecurityObject: msoBody },
          signature: `h'…' (${c.mso.signatureAlgorithm})`,
        },
      },
    },
  }
}

/** Rulebook v0.5: bsc = SHA-256(secret_seed ‖ birth_date) and psc = SHA-256(private_seed) (or 32
 *  zero bytes); birth_date is not a data element, the wallet holds it beside the attestation. */
function mdocV05(c: CredentialView): AttestationView {
  const bsc = c.attributes.bsc ?? ''
  const psc = c.attributes.psc
  const zeroPsc = !psc || /^0+$/.test(psc)
  const digest = (id: string) => c.elements.find((e) => e.id === id)?.digestID
  return {
    encoding: 'mso_mdoc',
    title: 'nym_auth attestation v0.5, ISO/IEC 18013-5 (mso_mdoc)',
    typeLabel: 'docType and namespace',
    typeValue: c.docType,
    rows: [
      { id: 'bsc', type: 'bstr .size 32', presence: 'REQ', value: short(bsc), note: 'SHA-256(secret_seed ‖ birth_date), birth_date as the 10-byte full-date. Input to pseudonym and age_check' },
      { id: 'psc', type: 'bstr .size 32', presence: 'REQ', value: psc ? short(psc) : 'not in this credential', note: zeroPsc ? '32 zero bytes: no private seed' : 'SHA-256(private_seed), or 32 zero bytes without a private seed' },
    ],
    secrets: [
      { id: 'secret_seed', type: '16 bytes', value: 'held by the wallet and the issuer', note: 'Opens bsc with birth_date; input to the pseudonym' },
      { id: 'birth_date', type: 'full-date, 10 bytes', value: c.attributes.birth_date, note: 'Opens bsc with secret_seed; input to age_check' },
      ...(zeroPsc ? [] : [{ id: 'private_seed', type: '16 bytes', value: 'held by the wallet only', note: 'Opens psc' }]),
    ],
    notes: [
      `Each data element is a separate IssuerSignedItem: bsc (digestID ${digest('bsc') ?? '–'}) and psc (digestID ${digest('psc') ?? '–'}).`,
      'birth_date is not a data element: it is carried only inside bsc.',
      'bsc and psc are never disclosed; only zkp_req presentations are allowed.',
      'A proof establishes validFrom ≤ proof_time ≤ validUntil, both bounds included.',
      'issuerAuth carries x5chain (label 33); the circuit checks the signature.',
      `Compact profile: ${c.compactProfile ? 'yes' : 'no'}. Issuer: ${c.issuer.name}. ${c.sizes.issuerSigned} bytes of IssuerSigned.`,
    ],
    structure: mdocStructure(c, { bsc: `${short(bsc)} (32 bytes)`, ...(psc && { psc: `${short(psc)} (32 bytes)` }) }),
  }
}

/** Rulebook v0.6, the decoy-digest layout (nym-auth-longfellow-decoy-v1, INTEGRATION.md §5): the
 *  MSO's valueDigests hold bsc (digestID 0) and psc (digestID 1) themselves, so the credential has
 *  no IssuerSignedItems and no nameSpaces, only issuerAuth; the MSO contains no claims. */
function mdocV06(c: CredentialView): AttestationView {
  const bsc = c.attributes.bsc ?? ''
  const psc = c.attributes.psc ?? ''
  const zeroPsc = !psc || /^0+$/.test(psc)
  const ns = c.namespace || c.docType
  return {
    encoding: 'mso_mdoc',
    title: 'nym_auth attestation v0.6, ISO/IEC 18013-5 (mso_mdoc), decoy-digest layout',
    typeLabel: 'docType and namespace',
    typeValue: c.docType,
    rows: [
      { id: 'bsc', type: 'bstr .size 32', presence: 'REQ', value: short(bsc), note: 'valueDigests digestID 0, the commitment itself: SHA-256(secret_seed ‖ birth_date). Input to pseudonym and age_check' },
      { id: 'psc', type: 'bstr .size 32', presence: 'REQ', value: short(psc), note: `valueDigests digestID 1, the commitment itself: ${zeroPsc ? '32 zero bytes, no private seed' : 'SHA-256(private_seed)'}` },
    ],
    secrets: [
      { id: 'secret_seed', type: '16 bytes', value: 'held by the wallet and the issuer', note: 'Opens bsc with birth_date; input to the pseudonym' },
      { id: 'birth_date', type: 'full-date, 10 bytes', value: c.attributes.birth_date, note: 'Opens bsc with secret_seed; input to age_check' },
      ...(zeroPsc ? [] : [{ id: 'private_seed', type: '16 bytes', value: 'held by the wallet only', note: 'Opens psc' }]),
    ],
    notes: [
      'The MSO contains no claims: there are no IssuerSignedItems and no nameSpaces. IssuerSigned holds issuerAuth only.',
      'valueDigests holds bsc (digestID 0) and psc (digestID 1) themselves, not digests of items.',
      'birth_date is not in the credential: it is carried only inside bsc.',
      'The MSO is a fixed 398-byte form, so the signed Sig_structure is 423 bytes with every field at a fixed offset; the circuits start SHA-256 after its constant first 128 bytes.',
      'bsc and psc are never disclosed; only zkp_req presentations are allowed.',
      'A proof establishes validFrom ≤ proof_time ≤ validUntil, both bounds included.',
      `issuerAuth carries x5chain (label 33); the circuit checks the signature. Issuer: ${c.issuer.name}. ${c.sizes.issuerSigned} bytes of IssuerSigned.`,
    ],
    structure: {
      docType: c.docType,
      issuerSigned: {
        issuerAuth: {
          COSE_Sign1: {
            protected: { alg: c.mso.signatureAlgorithm },
            unprotected: { '33 (x5chain)': c.issuer.documentSigner },
            payload: {
              MobileSecurityObject: {
                version: c.mso.version,
                digestAlgorithm: c.mso.digestAlgorithm,
                docType: c.docType,
                valueDigests: { [ns]: { 0: `${short(bsc)} (bsc)`, 1: `${short(psc)} (psc)` } },
                deviceKeyInfo: { deviceKey: { kty: 'EC2', crv: c.deviceKey.crv, jwk_thumbprint: c.deviceKey.jwkThumbprint } },
                validityInfo: c.validity,
              },
            },
            signature: `h'…' (${c.mso.signatureAlgorithm})`,
          },
        },
      },
    },
  }
}

function mdoc(c: CredentialView): AttestationView {
  const birth = c.attributes.birth_date
  const value: Record<string, string> = { birth_date: `1004("${birth}")`, ssc: `${short(c.attributes.ssc)} (32 bytes)`, ...(c.attributes.psc && { psc: `${short(c.attributes.psc)} (32 bytes)` }) }
  return {
    encoding: 'mso_mdoc',
    title: 'nym_auth attestation v0.4, ISO/IEC 18013-5 (mso_mdoc)',
    typeLabel: 'docType and namespace',
    typeValue: c.docType,
    rows: [
      { id: 'birth_date', type: '#6.1004(tstr) full-date', presence: 'REQ', value: value.birth_date!, note: 'Input to age_check' },
      { id: 'ssc', type: 'bstr .size 32', presence: 'REQ', value: short(c.attributes.ssc), note: 'SHA-256(secret_seed), the issuer-known seed commitment' },
      { id: 'psc', type: 'bstr .size 32', presence: 'OPT', value: c.attributes.psc ? short(c.attributes.psc) : 'not in this credential', note: 'SHA-256(private_seed), the issuer-unknown seed commitment' },
    ],
    secrets: [
      { id: 'secret_seed', type: '16 bytes', value: 'held by the wallet and the issuer', note: 'Opening of ssc; input to the pseudonym' },
      ...(c.attributes.psc ? [{ id: 'private_seed', type: '16 bytes', value: 'held by the wallet only', note: 'Opening of psc' }] : []),
    ],
    notes: [
      'Each data element is a separate IssuerSignedItem.',
      'ssc, psc and birth_date are never disclosed; only zkp_req presentations are allowed.',
      'issuerAuth carries x5chain (label 33); the circuit checks the signature.',
      `Compact profile: ${c.compactProfile ? 'yes' : 'no'}. Issuer: ${c.issuer.name}. ${c.sizes.issuerSigned} bytes of IssuerSigned.`,
    ],
    structure: mdocStructure(c, value),
  }
}

function bbs(c: CredentialView, rulebook: string): AttestationView {
  const birth = c.attributes.birth_date
  const scheme = findScheme('urn:mms:bbs-cd:nym_auth:v1')
  const notes: Record<string, string> = {
    device_key: 'Hashed-ECDSA proof of possession (ecdsa-pop plugin)',
    birth_date: '(Y − 1900)·372 + (M − 1)·31 + (D − 1); order-preserving (date-range plugin)',
    secret_seed: 'hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed"); the pseudonym seed (pseudonym plugin)',
  }
  const values: Record<string, string> = {
    device_key: '(x, y) of the P-256 device key',
    birth_date: `${packed(birth)}  (${birth})`,
    secret_seed: 'a scalar in BLS12-381 Fr \\ {0}',
  }
  const attributes = c.bbs?.attributes ?? []
  return {
    encoding: 'bbs_cd',
    title: `nym_auth attestation v${rulebook}, BBS committed disclosures (bbs_cd)`,
    typeLabel: 'schema',
    typeValue: c.bbs?.schemaId ?? c.docType,
    rows: attributes.map((a) => ({ id: a.name, type: a.type, presence: `${a.messages} message${a.messages === 1 ? '' : 's'}`, value: values[a.name] ?? '…', note: notes[a.name] })),
    secrets: [],
    notes: [
      'The issuer signs the seed itself (not a commitment) and the device key as attributes.',
      'No attribute is disclosable: a presentation commits to what it uses and hides the rest.',
      'No validity period and no psc in this version.',
      ...(scheme ? [`Schema digest ${scheme.schema.digest}.`] : []),
    ],
    structure: {
      schema_id: c.bbs?.schemaId,
      ...(scheme && { schema_digest: scheme.schema.digest }),
      ciphersuite: 'BLS12-381-SHA-256 (bbs-cd-plugins 0.1)',
      messages: attributes.map((a) => ({ attribute: a.name, type: a.type, count: a.messages, value: a.name === 'birth_date' ? packed(birth) : 'hidden' })),
      signature: "BBS signature: h'…'",
      issuer_public_key: c.bbs ? `${short(c.bbs.issuerKey)} (${c.bbs.issuerKey.length / 2} bytes)` : '…',
    },
  }
}

/** The view of one credential, by its encoding, in rulebook version `rulebook` (the demo
 *  profile's): an mdoc shows the holder's v0.5 mdoc under v0.5 and its v0.6 mdoc under v0.6. */
export function attestationFor(c: CredentialView, rulebook = '0.4'): AttestationView {
  if (c.format === 'bbs_cd') return bbs(c, rulebook)
  if (rulebook === '0.6' && c.v06) return mdocV06(c.v06)
  return rulebook === '0.5' && c.v05 ? mdocV05(c.v05) : mdoc(c)
}
