// Trusted issuers beyond the configured trust anchors (/tech's "Trust new issuers").
//
// The circuit verifiers trust a Document Signer certificate when it is one of their configured
// trust anchors (runtime config vegaTrustAnchors, longfellowTrustAnchors: the demo issuer). With
// "Trust new issuers" on (the default; a demo reset restores runtime config trustNewIssuers), an
// mdoc presentation from an unknown Document Signer is verified with that certificate trusted for
// the one call, and when the presentation is accepted the certificate is added to the trusted
// issuers: kept in a JSON file (runtime config trustedIssuersFile) and passed to every later
// verification (`learned_issuers`). So another wallet's issuer is trusted from its first verified
// presentation on. A demo verifier: in production the trust list comes from the trust framework.
// /tech lists the added issuers and removes one on request. mso_mdoc only; the BBS verifier trusts
// its one configured issuer.
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { Decoder } from 'cbor-x'

export interface LearnedIssuer {
  /** The Document Signer certificate, base64 DER. */
  der: string
  /** SHA-256 of the DER, hex. */
  fingerprint: string
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
  g.__communityIssuers = Array.isArray(list) ? list : []
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

/** Whether the circuit verifiers trust `der` already: a configured anchor or an added issuer. */
export async function isTrusted(der: string): Promise<boolean> {
  return (await configuredAnchors()).has(der) || (await learnedIssuers()).some((i) => i.der === der)
}

/** The added issuers' certificates, for the verifier call. */
export async function learnedDers(): Promise<string[]> {
  return (await learnedIssuers()).map((i) => i.der)
}

/** Adds `der` to the trusted issuers (after a presentation it signed was accepted). */
export async function learnIssuer(der: string, systemId: string): Promise<LearnedIssuer> {
  const list = await learnedIssuers()
  const have = list.find((i) => i.der === der)
  if (have) return have
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  let subject = '', issuer = '', notAfter: string | null = null
  try {
    const c = new x509.X509Certificate(Buffer.from(der, 'base64'))
    subject = c.subject
    issuer = c.issuer
    notAfter = c.notAfter.toISOString()
  } catch {
    /* the verifier read it; the names are for display only */
  }
  const entry: LearnedIssuer = {
    der,
    fingerprint: createHash('sha256').update(Buffer.from(der, 'base64')).digest('hex'),
    subject,
    issuer,
    not_after: notAfter,
    added_at: new Date().toISOString(),
    system_id: systemId,
  }
  await save([...list, entry])
  console.log(`[issuers] trusted from now on: ${subject || entry.fingerprint} (from a verified ${systemId} presentation)`)
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
