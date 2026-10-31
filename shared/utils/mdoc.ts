// Reads an ISO/IEC 18013-5 IssuerSigned (base64url) of the nym_auth attestation: the wallet shows
// its own credential from it. It does not check the issuer's signature; the prover does
// (native/vega/nym-vega/src/prover.rs).
//
// Rulebook v0.6's decoy-digest layout (nym-auth-longfellow-decoy-v1, INTEGRATION.md §5) has no
// `nameSpaces`: the MSO's valueDigests hold bsc (digestID 0) and psc (1) themselves, so the
// credential carries no IssuerSignedItem and the MSO no claim. Read as `layout: 'decoy'`.

import { Decoder, Tag } from 'cbor-x'
import { NYM_DOCTYPE } from '../types/oid4vp'

const cbor = new Decoder({ mapsAsObjects: false, useRecords: false })

export interface IssuerSignedView {
  /** `decoy`: rulebook v0.6's decoy-digest layout (no nameSpaces; bsc and psc as valueDigests 0 and 1). */
  layout: 'items' | 'decoy'
  docType: string
  namespace: string
  /** The items in the order issued (none in the decoy-digest layout). */
  items: Array<{ digestID: number; elementIdentifier: string; value: unknown; bytes: number }>
  /** v0.4: the birth_date item; v0.5 and v0.6 commit to it in bsc, so null. */
  birthDate: string | null
  /** v0.4's ssc, v0.5's and v0.6's bsc (null when the credential has none). */
  ssc: Uint8Array | null
  bsc: Uint8Array | null
  psc: Uint8Array | null
  /** DER Document Signer certificate from x5chain. */
  documentSigner: Uint8Array
  validity: { signed: string; validFrom: string; validUntil: string }
  deviceKey: { x: Uint8Array; y: Uint8Array }
  digestAlgorithm: string
  /** COSE alg of issuerAuth's protected header: -7 is ES256. */
  signatureAlgorithm: string
  version: string
  /** Sizes, for the compact-profile view. */
  bytes: { issuerSigned: number }
}

export function fromBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

export function toBase64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fail(what: string): never {
  throw new Error(`IssuerSigned: ${what}`)
}

function map(v: unknown, what: string): Map<unknown, unknown> {
  return v instanceof Map ? v : fail(`${what} is not a map`)
}

function bytes(v: unknown, what: string): Uint8Array {
  return v instanceof Uint8Array ? v : fail(`${what} is not a byte string`)
}

function embedded(v: unknown, what: string): unknown {
  if (!(v instanceof Tag) || v.tag !== 24) fail(`${what} is not tag 24`)
  return cbor.decode(bytes(v.value, what))
}

/** A tdate (tag 0) as written, YYYY-MM-DDThh:mm:ssZ. */
function tdate(v: unknown, what: string): string {
  if (v instanceof Date) return v.toISOString().replace(/\.\d{3}Z$/, 'Z')
  if (v instanceof Tag && v.tag === 0 && typeof v.value === 'string') return v.value
  if (typeof v === 'string') return v
  return fail(`${what} is not a tdate`)
}

const COSE_ALGS: Record<number, string> = { [-7]: 'ES256', [-35]: 'ES384', [-36]: 'ES512' }

export function readIssuerSigned(issuerSigned: string): IssuerSignedView {
  const raw = fromBase64url(issuerSigned)
  const root = map(cbor.decode(raw), 'IssuerSigned')
  const auth = root.get('issuerAuth')
  if (!Array.isArray(auth) || auth.length !== 4) fail('issuerAuth is not a COSE_Sign1')
  const [protectedBytes, unprotected, payload] = auth as [unknown, unknown, unknown, unknown]
  const protectedHeader = map(cbor.decode(bytes(protectedBytes, 'protected header')), 'protected header')
  const x5chain = map(unprotected, 'unprotected header').get(33)
  const documentSigner = Array.isArray(x5chain) ? bytes(x5chain[0], 'x5chain') : bytes(x5chain, 'x5chain')
  const mso = map(embedded(cbor.decode(bytes(payload, 'payload')), 'payload'), 'MSO')
  const validity = map(mso.get('validityInfo'), 'validityInfo')
  const deviceKey = map(map(mso.get('deviceKeyInfo'), 'deviceKeyInfo').get('deviceKey'), 'deviceKey')

  const common = {
    docType: String(mso.get('docType')),
    namespace: NYM_DOCTYPE,
    documentSigner,
    validity: {
      signed: tdate(validity.get('signed'), 'signed'),
      validFrom: tdate(validity.get('validFrom'), 'validFrom'),
      validUntil: tdate(validity.get('validUntil'), 'validUntil'),
    },
    deviceKey: { x: bytes(deviceKey.get(-2), 'deviceKey x'), y: bytes(deviceKey.get(-3), 'deviceKey y') },
    digestAlgorithm: String(mso.get('digestAlgorithm')),
    signatureAlgorithm: COSE_ALGS[Number(protectedHeader.get(1))] ?? `COSE ${protectedHeader.get(1)}`,
    version: String(mso.get('version')),
    bytes: { issuerSigned: raw.length },
  }

  if (!root.has('nameSpaces')) {
    // The decoy-digest layout: valueDigests holds exactly digestIDs 0 (bsc) and 1 (psc), each a
    // 32-byte commitment itself, and there are no items.
    const digests = map(map(mso.get('valueDigests'), 'valueDigests').get(NYM_DOCTYPE), `valueDigests ${NYM_DOCTYPE}`)
    const ids = [...digests.keys()].map(Number).sort()
    if (ids.length !== 2 || ids[0] !== 0 || ids[1] !== 1) fail('no nameSpaces, and valueDigests is not exactly digestIDs 0 and 1')
    const commitment = (id: number, what: string) => {
      const b = bytes(digests.get(id), what)
      return b.length === 32 ? b : fail(`${what} is not 32 bytes`)
    }
    return { layout: 'decoy', ...common, items: [], birthDate: null, ssc: null, bsc: commitment(0, 'bsc'), psc: commitment(1, 'psc') }
  }

  const nameSpaces = map(root.get('nameSpaces'), 'nameSpaces')
  const list = nameSpaces.get(NYM_DOCTYPE)
  if (!Array.isArray(list)) fail(`no namespace ${NYM_DOCTYPE}`)
  const items = list.map((entry: unknown) => {
    const item = map(embedded(entry, 'IssuerSignedItemBytes'), 'IssuerSignedItem')
    return {
      digestID: Number(item.get('digestID')),
      elementIdentifier: String(item.get('elementIdentifier')),
      value: item.get('elementValue'),
      bytes: (entry as Tag).value instanceof Uint8Array ? ((entry as Tag).value as Uint8Array).length : 0,
    }
  })
  const value = (id: string) => items.find((i) => i.elementIdentifier === id)?.value
  const birth = value('birth_date')
  if (birth !== undefined && (!(birth instanceof Tag) || birth.tag !== 1004 || typeof birth.value !== 'string')) fail('birth_date is not tag 1004')
  const opt = (id: string) => (value(id) === undefined ? null : bytes(value(id), id))

  return {
    layout: 'items',
    ...common,
    items,
    birthDate: birth instanceof Tag ? (birth.value as string) : null,
    ssc: opt('ssc'),
    bsc: opt('bsc'),
    psc: opt('psc'),
  }
}
