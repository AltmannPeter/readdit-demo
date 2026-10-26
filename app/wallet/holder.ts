// The holders' material, which the mocked SIROS ID wallet carries outright: for each nym_auth
// credential, the mdoc, its device key pair and its secret_seed, issued by native/vega/issuer
// (nym-issuer) into demo-wallet.json under one Document Signer; and the BBS credential
// (bbs_cd, docs/bbs_cd.md) with the device key and secret_seed of the mdoc holder it was issued
// for, issued by native/bbs/issuer (bbs-issuer) into demo-wallet-bbs.json. The demo has no true holder
// binding: a real wallet keeps the device key in secure hardware and never shows the seed. The
// wallet sends each native step only what it needs (app/wallet/prover.ts), from the credential
// the person chose, and decodes its own credentials for the screens below.

import walletFile from './demo-wallet.json'
import bbsWalletFile from './demo-wallet-bbs.json'
import { readIssuerSigned, type IssuerSignedView } from '#shared/utils/mdoc'
import { fromHex, toHex, utf8, sha256 } from '#shared/utils/bytes'
import { fromBase64url, toBase64url } from '#shared/utils/mdoc'
import { findScheme, SCHEME_REGISTRY } from '#shared/registry/circuits'
import type { SourceFormat } from '#shared/types/oid4vp'

export interface WalletCredential {
  format: 'mso_mdoc'
  doctype: string
  /** base64url IssuerSigned */
  issuer_signed: string
}

/** P-256 JWK with its private part. */
export interface DeviceKeyJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  d: string
}

export interface MdocMaterial {
  credential: WalletCredential
  device_key: DeviceKeyJwk
  /** 16 bytes, hex: the opening of the credential's ssc. */
  secret_seed: string
}

/** The BBS credential as bbs-issuer writes it (native/bbs/nym-bbs/src/credential.rs). */
export interface BbsWalletCredential {
  format: 'bbs_cd'
  schema_id: string
  /** base64url IssuerParams: var8(pk) ‖ var16(schema). */
  issuer_params: string
  signature: string
  /** Scalars as 64 hex digits; OCTETS as "o:" and base64url. */
  messages: string[]
}

export interface BbsMaterial {
  credential: BbsWalletCredential
  device_key: DeviceKeyJwk
}

export type WalletMaterial = MdocMaterial | BbsMaterial

export const isMdoc = (m: WalletMaterial): m is MdocMaterial => m.credential.format === 'mso_mdoc'

/** Each credential's material: demo-wallet.json's, then demo-wallet-bbs.json's. A phone holds some of them (PHONES). */
export const holders: WalletMaterial[] = [
  ...walletFile.holders.map((h) => ({
    credential: h.credential as WalletCredential,
    device_key: h.device_key as DeviceKeyJwk,
    secret_seed: h.secret_seed,
  })),
  ...bbsWalletFile.holders.map((h) => ({ credential: h.credential as BbsWalletCredential, device_key: h.device_key as DeviceKeyJwk })),
]

/** The mdoc material of a credential (index into holders); throws for a BBS credential. */
export function mdocMaterial(index: number): MdocMaterial {
  const m = holders[index]
  if (!m || !isMdoc(m)) throw new Error(`credential ${index} is not an mdoc`)
  return m
}

/** The credential as the wallet's screens show it. Everything comes from the mdoc itself. */
export interface CredentialView {
  /** Position in the wallet (holders[index]). */
  index: number
  /** The attestation's encoding (a zkp_req query's source_format): the mdoc, or the BBS credential. */
  format: SourceFormat
  /** The mdoc's docType, or the BBS credential's schema id. */
  docType: string
  namespace: string
  title: string
  encoding: string
  /** Rulebook "Compact profile": only the defined elements, digestIDs from 0, 20-character dates, P-256 keys. */
  compactProfile: boolean
  issuer: { name: string; country?: string; documentSigner: string; certificateValidUntil: string }
  validity: { signed: string; validFrom: string; validUntil: string }
  attributes: { birth_date: string; ssc: string; psc: string | null }
  elements: Array<{ id: string; digestID: number }>
  mso: { version: string; digestAlgorithm: string; signatureAlgorithm: string }
  deviceKey: { kty: string; crv: string; jwkThumbprint: string }
  sizes: { issuerSigned: number }
  /** bbs_cd only: the BBS issuer key, the schema and its attributes. */
  bbs?: { issuerKey: string; schemaId: string; attributes: Array<{ name: string; type: string; messages: number }>; messages: number }
}

/**
 * The demo's phones, one credential each (indexes into holders): the teen's mdoc, the adult's
 * mdoc, and the teen's BBS credential on a phone of its own, so which encoding answers a request
 * is the phone's, not a choice between cards. The site's dialog shows one phone at a time and
 * can swap them, so the audience sees someone try another person's phone. Colours match the
 * credential cards.
 */
export interface PhoneDef {
  id: 'teen' | 'adult' | 'teen-bbs'
  label: string
  credentials: number[]
  /** The phone frame's colour, and the credential cards' (CARD_COLOURS). */
  bezel: string
  tone: string
}

export const PHONES: PhoneDef[] = [
  { id: 'teen', label: "Teen's phone", credentials: [0], bezel: '#3c434e', tone: '#5B6573' },
  { id: 'adult', label: "Adult's phone", credentials: [1], bezel: '#5c1d25', tone: '#8C2F39' },
  { id: 'teen-bbs', label: "Teen's BBS phone", credentials: [2], bezel: '#1d3b45', tone: '#2E5E6E' },
]

export const findPhone = (id: string) => PHONES.find((p) => p.id === id) ?? PHONES[0]!

/** Whole years from a birth date (YYYY-MM-DD) to a day. */
export function ageOn(birthDate: string, today: string): number {
  const [by, bm, bd] = birthDate.split('-').map(Number) as [number, number, number]
  const [ty, tm, td] = today.split('-').map(Number) as [number, number, number]
  return ty - by - (tm < bm || (tm === bm && td < bd) ? 1 : 0)
}

/** The credential's display name (the issuer gives no display metadata, so the wallet names the type). */
export const NYM_TITLE = 'Age and pseudonym'
export const NYM_BBS_TITLE = 'Age and pseudonym (BBS)'

function compact(v: IssuerSignedView): boolean {
  const known = ['birth_date', 'ssc', 'psc']
  const ids = v.items.map((i) => i.digestID).sort((a, b) => a - b)
  return (
    v.items.every((i) => known.includes(i.elementIdentifier)) &&
    ids.every((id, k) => id === k) &&
    [v.validity.signed, v.validity.validFrom, v.validity.validUntil].every((t) => t.length === 20) &&
    v.deviceKey.x.length === 32 &&
    v.deviceKey.y.length === 32 &&
    v.signatureAlgorithm === 'ES256'
  )
}

/** RFC 7638 thumbprint of the device key, base64url. */
async function thumbprint(k: DeviceKeyJwk): Promise<string> {
  return toBase64url(await sha256(utf8(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x, y: k.y }))))
}

let cached: Promise<CredentialView[]> | undefined

/** Decodes the wallet's credentials once. */
export function loadCredentials(): Promise<CredentialView[]> {
  cached ??= Promise.all(holders.map((h, index) => (isMdoc(h) ? decode(h, index) : decodeBbs(h, index))))
  return cached
}

/** IssuerParams = var8(pk) ‖ var16(schema); schema = var8(id) ‖ u8 n ‖ attribute*n (docs/ENVELOPE.md §2–3). */
export function readIssuerParams(b: Uint8Array) {
  let o = 0
  const u8 = () => b[o++]!
  const u16 = () => (o += 2, (b[o - 2]! << 8) | b[o - 1]!)
  const take = (n: number) => b.slice(o, (o += n))
  const text = (n: number) => new TextDecoder().decode(take(n))
  const pk = take(u8())
  const schemaLen = u16()
  const end = o + schemaLen
  const id = text(u8())
  const attributes: Array<{ name: string; type: string; count: number; bits: number }> = []
  for (let n = u8(); n > 0; n--) {
    const name = text(u8())
    if (u8() === 0) attributes.push({ name, type: 'octets', count: 1, bits: 0 })
    else {
      const type = text(u8())
      const count = u16()
      const bits = u16()
      u8() // blind
      attributes.push({ name, type, count, bits })
    }
  }
  if (o !== end || o !== b.length) throw new Error('issuer_params: unexpected length')
  return { pk, schemaId: id, attributes }
}

/** pack(Y, M, D) = (Y − 1900)·372 + (M − 1)·31 + (D − 1), back to YYYY-MM-DD (date-range plugin). */
function unpackDate(v: number): string {
  const y = Math.floor(v / 372) + 1900
  const m = Math.floor((v % 372) / 31) + 1
  const d = (v % 31) + 1
  return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`
}

async function decodeBbs(holder: BbsMaterial, index: number): Promise<CredentialView> {
  const c = holder.credential
  const params = readIssuerParams(fromBase64url(c.issuer_params))
  const scheme = SCHEME_REGISTRY.find((s) => s.schema.id === params.schemaId) ?? findScheme('urn:mms:bbs-cd:nym_auth:v1')!
  let at = 0
  const offsets = params.attributes.map((a) => ((at += a.count), at - a.count))
  const birthAt = offsets[params.attributes.findIndex((a) => a.name === 'birth_date')]!
  const birth = unpackDate(Number(BigInt(`0x${c.messages[birthAt]}`)))
  const bytes = fromBase64url(c.issuer_params).length + fromBase64url(c.signature).length + c.messages.reduce((n, m) => n + (m.startsWith('o:') ? fromBase64url(m.slice(2)).length : fromHex(m).length), 0)
  return {
    index,
    format: 'bbs_cd',
    docType: params.schemaId,
    namespace: '',
    title: NYM_BBS_TITLE,
    encoding: 'BBS with committed disclosures (ETSI draft v0.7), BLS12-381-SHA-256',
    compactProfile: false,
    issuer: { name: scheme.issuer.name, country: scheme.issuer.country, documentSigner: `BBS issuer key ${toHex(params.pk).slice(0, 16)}…`, certificateValidUntil: '9999-12-31T23:59:59Z' },
    validity: { signed: '', validFrom: '', validUntil: '9999-12-31T23:59:59Z' },
    attributes: { birth_date: birth, ssc: '', psc: null },
    elements: params.attributes.map((a, i) => ({ id: a.name, digestID: i })),
    mso: { version: '', digestAlgorithm: '', signatureAlgorithm: 'BBS' },
    deviceKey: { kty: holder.device_key.kty, crv: holder.device_key.crv, jwkThumbprint: await thumbprint(holder.device_key) },
    sizes: { issuerSigned: bytes },
    bbs: {
      issuerKey: toHex(params.pk),
      schemaId: params.schemaId,
      attributes: params.attributes.map((a) => ({ name: a.name, type: a.type, messages: a.count })),
      messages: c.messages.length,
    },
  }
}

async function decode(holder: MdocMaterial, index: number): Promise<CredentialView> {
  const v = readIssuerSigned(holder.credential.issuer_signed)
  // @peculiar/x509 needs the Reflect metadata polyfill loaded first.
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  const cert = new x509.X509Certificate(v.documentSigner as BufferSource)
  const field = (name: string) => cert.subjectName.getField(name)[0]
  return {
    index,
    format: 'mso_mdoc',
    docType: v.docType,
    namespace: v.namespace,
    title: NYM_TITLE,
    encoding: 'ISO/IEC 18013-5 mdoc',
    compactProfile: compact(v),
    issuer: {
      name: field('O') ?? field('CN') ?? cert.subject,
      country: field('C'),
      documentSigner: cert.subject,
      certificateValidUntil: cert.notAfter.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    },
    validity: v.validity,
    attributes: { birth_date: v.birthDate, ssc: toHex(v.ssc), psc: v.psc ? toHex(v.psc) : null },
    elements: v.items.map((i) => ({ id: i.elementIdentifier, digestID: i.digestID })),
    mso: { version: v.version, digestAlgorithm: v.digestAlgorithm, signatureAlgorithm: v.signatureAlgorithm },
    deviceKey: {
      kty: holder.device_key.kty,
      crv: holder.device_key.crv,
      jwkThumbprint: await thumbprint(holder.device_key),
    },
    sizes: { issuerSigned: v.bytes.issuerSigned },
  }
}

/** validUntil 9999-12-31T23:59:59Z, the farthest a tdate holds: the credential does not expire. */
export const neverExpires = (validUntil: string) => validUntil.startsWith('9999-12-31')

/** A credential in the guide's words: its type and birth date, which tell the two apart, and its expiry if it has one. */
export function credentialLabel(c: CredentialView): string {
  const d = (iso: string) => new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })
  return `${c.title}, born ${d(c.attributes.birth_date)}${neverExpires(c.validity.validUntil) ? '' : `, expires ${d(c.validity.validUntil)}`}`
}

export interface DisplayCredential {
  title: string
  issuer: string
  /** Card colour; the issuer gives no display metadata, so the wallet picks one per credential. */
  background: string
  text: string
  /** The holder's birth date (YYYY-MM-DD), on the holder's own screens; the tell between two credentials. */
  birthDate?: string
  /** Absent when the credential does not expire. */
  validUntil?: string
}

/** DD/MM/YYYY, as the SIROS ID wallet shows dates. */
export const sidDate = (iso: string) =>
  new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' })

/** Card colour per credential (holders[index]), so the cards are easy to tell apart: the mdocs'
 *  (teen grey, adult red), then the BBS credential's (teal). */
const CARD_COLOURS = ['#5B6573', '#8C2F39', '#2E5E6E'] as const

export function nymCard(c: CredentialView | null): DisplayCredential {
  return {
    title: c?.title ?? NYM_TITLE,
    issuer: c?.issuer.name ?? '',
    background: CARD_COLOURS[(c?.index ?? 0) % CARD_COLOURS.length]!,
    text: '#FFFFFF',
    birthDate: c?.attributes.birth_date,
    validUntil: c && !neverExpires(c.validity.validUntil) ? c.validity.validUntil : undefined,
  }
}
