// What the nym_auth attestation looks like in each encoding (rulebook v0.4), with the values of the
// demo's own credentials (app/wallet/demo-wallet*.json, decoded by app/wallet/holder.ts).
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

function mdoc(c: CredentialView): AttestationView {
  const birth = c.attributes.birth_date
  const ns = c.namespace || c.docType
  const value: Record<string, string> = { birth_date: `1004("${birth}")`, ssc: `${short(c.attributes.ssc)} (32 bytes)`, ...(c.attributes.psc && { psc: `${short(c.attributes.psc)} (32 bytes)` }) }
  return {
    encoding: 'mso_mdoc',
    title: 'nym_auth attestation, ISO/IEC 18013-5 (mso_mdoc)',
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
    structure: {
      docType: c.docType,
      issuerSigned: {
        nameSpaces: { [ns]: c.elements.map((e) => ({ digestID: e.digestID, random: "h'…' (16 bytes)", elementIdentifier: e.id, elementValue: value[e.id] ?? '…' })) },
        issuerAuth: {
          COSE_Sign1: {
            protected: { alg: c.mso.signatureAlgorithm },
            unprotected: { '33 (x5chain)': c.issuer.documentSigner },
            payload: {
              MobileSecurityObject: {
                version: c.mso.version,
                digestAlgorithm: c.mso.digestAlgorithm,
                valueDigests: { [ns]: Object.fromEntries(c.elements.map((e) => [e.digestID, "h'…'"])) },
                deviceKeyInfo: { deviceKey: { kty: 'EC2', crv: c.deviceKey.crv, jwk_thumbprint: c.deviceKey.jwkThumbprint } },
                docType: c.docType,
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

function bbs(c: CredentialView): AttestationView {
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
    title: 'nym_auth attestation, BBS committed disclosures (bbs_cd)',
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

/** The view of one credential, by its encoding. */
export function attestationFor(c: CredentialView): AttestationView {
  return c.format === 'bbs_cd' ? bbs(c) : mdoc(c)
}
