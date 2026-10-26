// Trusted issuers beyond the configured ones (/tech's "Trust new issuers").
//
// The circuit verifiers trust a Document Signer certificate when it is one of their configured
// trust anchors (runtime config vegaTrustAnchors, longfellowTrustAnchors: the demo issuer), and the
// BBS verifier the issuer key of its configured issuer parameters (bbsIssuerParams). With "Trust
// new issuers" on (the default; a demo reset restores runtime config trustNewIssuers), a
// presentation from an unknown issuer is verified with that issuer trusted for the one call, and
// when the presentation is accepted the issuer is added to the trusted issuers: kept in a JSON file
// (runtime config trustedIssuersFile) and passed to every later verification of its format
// (`learned_issuers`). So another wallet's issuer is trusted from its first verified presentation
// on. A demo verifier: in production the trust list comes from the trust framework. /tech lists the
// added issuers and removes one on request.
//
// mso_mdoc: the issuer is the Document Signer certificate (base64 DER). bbs_cd: the issuer's
// 96-byte public key (base64), which the verifier trusts with the profile's schema, so an issuer
// whose credentials use another schema still fails, at the proof.
import { X509Certificate, createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { Decoder } from 'cbor-x'

export type IssuerFormat = 'mso_mdoc' | 'bbs_cd'

export interface LearnedIssuer {
  /** The format of the presentations it signs. Absent in files written before BBS: mso_mdoc. */
  format: IssuerFormat
  /** mso_mdoc: the Document Signer certificate, base64 DER. bbs_cd: the issuer's public key, base64. */
  key: string
  /** SHA-256 of the key's bytes, hex. */
  fingerprint: string
  /** mso_mdoc: the certificate's subject and issuer; bbs_cd: empty. */
  subject: string
  issuer: string
  not_after: string | null
  added_at: string
  /** The system of the presentation that brought it. */
  system_id: string
}

const g = globalThis as unknown as { __communityIssuers?: LearnedIssuer[]; __communityAnchors?: Set<string> }

function file(): string {
  return resolve(process.cwd(), String(useRuntimeConfig().trustedIssuersFile))
}

/** The added issuers, read from the file once. */
export async function learnedIssuers(): Promise<LearnedIssuer[]> {
  if (g.__communityIssuers) return g.__communityIssuers
  let list: LearnedIssuer[] = []
  try {
    if (existsSync(file())) list = JSON.parse(await readFile(file(), 'utf8')) as LearnedIssuer[]
  } catch (e) {
    console.warn(`[issuers] cannot read ${file()}: ${(e as Error).message}`)
  }
  // Entries written before BBS: { der, … }, all mso_mdoc.
  type Old = Partial<LearnedIssuer> & { der?: string }
  g.__communityIssuers = (Array.isArray(list) ? (list as Old[]) : [])
    .map(({ der, ...i }) => ({ ...i, format: i.format ?? 'mso_mdoc', key: i.key ?? der ?? '' }) as LearnedIssuer)
    .filter((i) => i.key)
  return g.__communityIssuers
}

async function save(list: LearnedIssuer[]) {
  g.__communityIssuers = list
  try {
    await mkdir(dirname(file()), { recursive: true })
    await writeFile(file(), `${JSON.stringify(list, null, 2)}\n`)
  } catch (e) {
    console.warn(`[issuers] cannot write ${file()}: ${(e as Error).message}`)
  }
}

/** The configured trust anchors of the circuit verifiers, base64 DER. */
async function configuredAnchors(): Promise<Set<string>> {
  if (g.__communityAnchors) return g.__communityAnchors
  const cfg = useRuntimeConfig()
  const out = new Set<string>()
  for (const path of new Set([String(cfg.vegaTrustAnchors), String(cfg.longfellowTrustAnchors)])) {
    try {
      const pem = await readFile(resolve(process.cwd(), path), 'utf8')
      for (const m of pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)) out.add(m[1]!.replace(/\s+/g, ''))
    } catch {
      /* the verifier reports a missing file itself */
    }
  }
  g.__communityAnchors = out
  return out
}

/** The Document Signer certificate a ZkpPresentation carries (`issuer_key_set`, one entry), base64 DER. */
export function presentedIssuer(presentation: string): string | null {
  try {
    const m = new Decoder({ mapsAsObjects: false, useRecords: false }).decode(Buffer.from(presentation, 'base64url')) as unknown
    const set = m instanceof Map ? m.get('issuer_key_set') : undefined
    const first = Array.isArray(set) && set.length === 1 ? set[0] : undefined
    return first instanceof Uint8Array ? Buffer.from(first).toString('base64') : null
  } catch {
    return null
  }
}

/** An issuer for the log and the trace: a certificate's subject, or a BBS key's first bytes, and
 *  the start of its SHA-256. `key`: base64 (DER for mso_mdoc). */
export function issuerName(key: string, format: IssuerFormat = 'mso_mdoc'): string {
  const bytes = Buffer.from(key, 'base64')
  const fp = createHash('sha256').update(bytes).digest('hex').slice(0, 16)
  if (format === 'bbs_cd') return `BBS issuer key ${bytes.subarray(0, 8).toString('hex')}… (sha-256 ${fp}…)`
  try {
    return `${new X509Certificate(bytes).subject.replace(/\n/g, ', ')} (sha-256 ${fp}…)`
  } catch {
    return `sha-256 ${fp}…`
  }
}

/** Whether the circuit verifiers trust `der` already: a configured anchor or an added issuer. */
export async function isTrusted(der: string): Promise<boolean> {
  return (await configuredAnchors()).has(der) || (await learnedIssuers()).some((i) => i.format === 'mso_mdoc' && i.key === der)
}

/** The added issuers of one format, for the verifier call: certificates (mso_mdoc) or keys (bbs_cd). */
export async function learnedKeys(format: IssuerFormat): Promise<string[]> {
  return (await learnedIssuers()).filter((i) => i.format === format).map((i) => i.key)
}

/** The name the trace gives an added issuer. */
export const addedName = (i: LearnedIssuer) => i.subject || issuerName(i.key, i.format)

/** Adds an issuer (after a presentation it signed was accepted). `key`: base64, see LearnedIssuer. */
export async function learnIssuer(key: string, systemId: string, format: IssuerFormat = 'mso_mdoc'): Promise<LearnedIssuer> {
  const list = await learnedIssuers()
  const have = list.find((i) => i.format === format && i.key === key)
  if (have) return have
  let subject = '', issuer = '', notAfter: string | null = null
  if (format === 'mso_mdoc') {
    await import('reflect-metadata')
    const x509 = await import('@peculiar/x509')
    try {
      const c = new x509.X509Certificate(Buffer.from(key, 'base64'))
      subject = c.subject
      issuer = c.issuer
      notAfter = c.notAfter.toISOString()
    } catch {
      /* the verifier read it; the names are for display only */
    }
  }
  const entry: LearnedIssuer = {
    format,
    key,
    fingerprint: createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex'),
    subject,
    issuer,
    not_after: notAfter,
    added_at: new Date().toISOString(),
    system_id: systemId,
  }
  await save([...list, entry])
  console.log(`[issuers] trusted from now on: ${addedName(entry)} (from a verified ${systemId} presentation)`)
  return entry
}

/** Removes an added issuer; false when there is none with this fingerprint. */
export async function forgetIssuer(fingerprint: string): Promise<boolean> {
  const list = await learnedIssuers()
  const rest = list.filter((i) => i.fingerprint !== fingerprint)
  if (rest.length === list.length) return false
  await save(rest)
  return true
}
