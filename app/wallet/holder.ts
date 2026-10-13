// The holders' material, which the mocked SIROS ID wallet carries outright: for each nym_auth
// credential, the mdoc, its device key pair and its secret_seed, issued by native/vega/issuer
// (nym-issuer) into demo-wallet.json under one Document Signer. The demo has no true holder
// binding: a real wallet keeps the device key in secure hardware and never shows the seed. The
// wallet sends each native step only what it needs (app/wallet/prover.ts), from the credential
// the person chose, and decodes its own credentials for the screens below.

import walletFile from './demo-wallet.json'
import { readIssuerSigned, type IssuerSignedView } from '#shared/utils/mdoc'
import { toHex, utf8, sha256 } from '#shared/utils/bytes'
import { toBase64url } from '#shared/utils/mdoc'

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

export interface WalletMaterial {
  credential: WalletCredential
  device_key: DeviceKeyJwk
  /** 16 bytes, hex: the opening of the credential's ssc. */
  secret_seed: string
}

/** Each credential's material, in the wallet's order (the first is the default for a request). */
export const holders: WalletMaterial[] = walletFile.holders.map((h) => ({
  credential: h.credential as WalletCredential,
  device_key: h.device_key as DeviceKeyJwk,
  secret_seed: h.secret_seed,
}))

/** The credential as the wallet's screens show it. Everything comes from the mdoc itself. */
export interface CredentialView {
  /** Position in the wallet (holders[index]). */
  index: number
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
}

/** The credential's display name (the issuer gives no display metadata, so the wallet names the type). */
export const NYM_TITLE = 'Age and pseudonym'

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
  cached ??= Promise.all(holders.map((h, index) => decode(h, index)))
  return cached
}

async function decode(holder: WalletMaterial, index: number): Promise<CredentialView> {
  const v = readIssuerSigned(holder.credential.issuer_signed)
  // @peculiar/x509 needs the Reflect metadata polyfill loaded first.
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  const cert = new x509.X509Certificate(v.documentSigner as BufferSource)
  const field = (name: string) => cert.subjectName.getField(name)[0]
  return {
    index,
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

/** A credential in the guide's words: its type, birth date and expiry, which tell the two apart. */
export function credentialLabel(c: CredentialView): string {
  const d = (iso: string) => new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })
  return `${c.title}, born ${d(c.attributes.birth_date)}, expires ${d(c.validity.validUntil)}`
}

export interface DisplayCredential {
  title: string
  issuer: string
  /** Card colour; the issuer gives no display metadata, so the wallet uses its brand colour. */
  background: string
  text: string
  validUntil?: string
}

/** Static card shown next to nym_auth so the wallet looks lived-in. Not used in any flow. */
export const pidCard: DisplayCredential = { title: 'Personal ID', issuer: 'Demo Issuer', background: '#D3D3D3', text: '#000000' }

export function nymCard(c: CredentialView | null): DisplayCredential {
  return { title: c?.title ?? NYM_TITLE, issuer: c?.issuer.name ?? '', background: '#1C4587', text: '#FFFFFF', validUntil: c?.validity.validUntil }
}
