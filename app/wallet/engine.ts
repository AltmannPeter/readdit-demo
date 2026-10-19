import type { AgeCheckReq, CredentialQuery, PseudonymConfig, RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'
import type { CircuitEntry, SchemeEntry } from '#shared/registry/circuits'
import { selectCircuit, selectScheme } from '#shared/utils/negotiation'
import { derivePseudonym } from '#shared/utils/pseudonym'
import { fromHex } from '#shared/utils/bytes'
import type { CredentialView } from './holder'
import { credentialLabel, mdocMaterial } from './holder'
import { CONFIG_PROPERTIES } from './rulebook'

/** What the wallet can prove: the circuits (circuit_zk) and schemes (mms_zk) of /api/wallet/capabilities. */
export interface WalletCaps {
  circuitIds: string[]
  schemeIds: string[]
}

/** The request format a credential answers. */
export const formatOf = (c: CredentialView) => (c.format === 'mms_zk' ? 'mms_zk' : 'circuit_zk')

/** The credential query of `req` that `cred` can answer: the same format and document type or schema. */
export function queryFor(req: RequestObject, cred: CredentialView): CredentialQuery | undefined {
  return (req.dcql_query?.credentials ?? []).find((q) =>
    q.format === 'circuit_zk' ? cred.format === 'mso_mdoc' && q.meta?.doctype_value === cred.docType : q.format === 'mms_zk' && cred.format === 'mms_zk' && q.meta?.schema_id_value === cred.docType,
  )
}

export type RequestItemView =
  | { kind: 'pseudonym'; handle: string; config: PseudonymConfig; verifierIdType?: string; verifierContext?: string; function: 'pseudonym-v1-sha256' | 'pseudonym-bbs-v1' }
  | { kind: 'age'; handle: string; ge?: string; le?: string; minAge?: number; maxAge?: number }

export interface RequestView {
  verifierName: string
  verifierHost: string
  clientId: string
  items: RequestItemView[]
  /** false: the wallet cannot produce a presentation. */
  satisfiable: boolean
  /** age: holder data does not meet the predicate (-> access_denied).
   *  unsupported / no_circuit: independent of holder data (-> invalid_request). */
  problem?: 'age' | 'unsupported' | 'no_circuit'
  /** For unsupported / no_circuit: the rule the request breaks, for the guide. */
  reason?: string
  /** The credential query the wallet answers, and the circuit (circuit_zk) or scheme (mms_zk). */
  query?: CredentialQuery
  circuit?: CircuitEntry
  scheme?: SchemeEntry
}

/** Whole years between a birth date and `today`. */
export function ageOn(birth: string, today: string): number {
  const [by, bm, bd] = birth.split('-').map(Number) as [number, number, number]
  const [ty, tm, td] = today.split('-').map(Number) as [number, number, number]
  return ty - by - (tm < bm || (tm === bm && td < bd) ? 1 : 0)
}

function daysBetween(a: string, b: string): number {
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86_400_000)
}

function ageItem(r: AgeCheckReq, today: string): RequestItemView {
  return {
    kind: 'age',
    handle: r.return,
    ...(r.params.ge && { ge: r.params.ge, maxAge: ageOn(r.params.ge, today) }),
    ...(r.params.le && { le: r.params.le, minAge: ageOn(r.params.le, today) }),
  }
}

/** Parse "openid4vp://?client_id=...&request_uri=...&request_uri_method=post" */
export function parseAuthorizationUrl(url: string): { clientId: string; requestUri: string; method: 'get' | 'post' } | null {
  const q = url.indexOf('?')
  if (!url.startsWith('openid4vp://') || q < 0) return null
  const p = new URLSearchParams(url.slice(q + 1))
  const clientId = p.get('client_id')
  const requestUri = p.get('request_uri')
  const method = p.get('request_uri_method') === 'post' ? 'post' : 'get'
  return clientId && requestUri ? { clientId, requestUri, method } : null
}

const ID_TYPE_CONFIGS = new Set(['known-offender-matching-ssc', 'known-offender-matching-psc', 'account-recovery-ssc'])

/**
 * Checks the request against the rulebook (circuit_zk) or the mms_zk profile, the credential and
 * what the wallet can run. With several credential queries, they must be alternatives in one
 * credential set (each option one query); the wallet answers the one its credential fits.
 */
export function analyzeRequest(req: RequestObject, cred: CredentialView, today: string, caps: WalletCaps): RequestView {
  const host = req.client_id.startsWith('x509_san_dns:') ? req.client_id.slice('x509_san_dns:'.length) : ''
  const view: RequestView = {
    verifierName: req.client_metadata.client_name ?? host,
    verifierHost: host,
    clientId: req.client_id,
    items: [],
    satisfiable: true,
  }
  const reject = (problem: 'unsupported' | 'no_circuit', reason: string): RequestView => ({ ...view, satisfiable: false, problem, reason })

  const queries = req.dcql_query?.credentials ?? []
  const sets = req.dcql_query?.credential_sets
  if (!queries.length) return reject('unsupported', 'no credential query')
  if (sets) {
    const ids = queries.map((q) => q.id)
    const options = sets.length === 1 ? sets[0]!.options : []
    if (!options.length || options.some((o) => o.length !== 1 || !ids.includes(o[0]!)) || new Set(options.map((o) => o[0])).size !== ids.length) {
      return reject('unsupported', 'credential_sets: the wallet answers one set whose options are single queries')
    }
  } else if (queries.length !== 1) {
    return reject('unsupported', `${queries.length} credential queries without credential_sets; the wallet answers exactly one`)
  }
  const q = queryFor(req, cred)
  if (!q) {
    const asked = queries.map((x) => `${x.format} ${x.format === 'circuit_zk' ? x.meta?.doctype_value : x.meta?.schema_id_value}`).join(', ')
    return reject('unsupported', `the request asks for ${asked}; this credential is ${cred.format} ${cred.docType}`)
  }
  view.query = q
  if ((q as { require_cryptographic_holder_binding?: boolean }).require_cryptographic_holder_binding === false) return reject('unsupported', 'require_cryptographic_holder_binding is false')
  if (!q.req?.length) return reject('unsupported', 'req is empty')

  let nyms = 0
  let ages = 0
  let ageFails = false
  for (const r of q.req) {
    if (r.id === 'pseudonym-v1-sha256' && q.format === 'circuit_zk') {
      nyms++
      const { config, verifier_id_type: idType, verifier_context: ctx } = r.params
      if (!(config in CONFIG_PROPERTIES)) return reject('unsupported', `pseudonym configuration ${config} is not defined by the rulebook`)
      const usesVerifierInput = ID_TYPE_CONFIGS.has(config)
      if (usesVerifierInput !== !!idType) return reject('unsupported', `${config} ${usesVerifierInput ? 'needs' : 'takes no'} verifier_id_type`)
      if (idType && idType !== 'x509_san_dns' && idType !== 'semantic') return reject('unsupported', `verifier_id_type ${idType} is not defined by the rulebook`)
      if (idType === 'x509_san_dns' && !host) return reject('unsupported', `verifier_id_type x509_san_dns with client_id ${req.client_id}`)
      if (idType === 'semantic') return reject('unsupported', "verifier_id_type semantic needs the verifier's registration certificate, which this demo does not have")
      if ((config === 'account-recovery-ssc') !== (ctx != null)) return reject('unsupported', `verifier_context is ${ctx != null ? 'only for' : 'required by'} account-recovery-ssc`)
      if (ctx != null && (new TextEncoder().encode(ctx).length < 1 || new TextEncoder().encode(ctx).length > 64)) return reject('unsupported', 'verifier_context must be 1 to 64 bytes')
      if (config === 'known-offender-matching-psc' && !cred.attributes.psc) return reject('unsupported', 'known-offender-matching-psc needs psc, which the credential does not contain')
      view.items.push({ kind: 'pseudonym', function: 'pseudonym-v1-sha256', handle: r.return, config, ...(idType && { verifierIdType: idType }), ...(ctx != null && { verifierContext: ctx }) })
    } else if (r.id === 'pseudonym-bbs-v1' && q.format === 'mms_zk') {
      nyms++
      const { config, verifier_id_type: idType } = r.params
      if (config !== 'known-offender-matching-ssc') return reject('unsupported', `pseudonym-bbs-v1 configuration ${config}; the profile defines known-offender-matching-ssc`)
      if (idType !== 'x509_san_dns' || !host) return reject('unsupported', `pseudonym-bbs-v1 needs verifier_id_type x509_san_dns and an x509_san_dns client_id`)
      view.items.push({ kind: 'pseudonym', function: 'pseudonym-bbs-v1', handle: r.return, config, verifierIdType: idType })
    } else if (r.id === 'age_check') {
      ages++
      const { ge, le } = r.params
      if (!ge && !le) return reject('unsupported', 'age_check without ge or le')
      if (ge && le && (le < ge || daysBetween(ge, le) + 1 < 365)) return reject('unsupported', 'age_check bounds span less than 365 days')
      view.items.push(ageItem(r, today))
      if (!((!ge || cred.attributes.birth_date >= ge) && (!le || cred.attributes.birth_date <= le))) ageFails = true
    } else {
      return reject('unsupported', `function ${(r as { id: string }).id} is not defined for ${q.format}`)
    }
  }
  if (nyms > 1 || ages > 1) return reject('unsupported', 'more than one pseudonym or age_check in req')

  if (q.format === 'circuit_zk') {
    const offer = req.client_metadata?.vp_formats_supported?.circuit_zk ?? {}
    const circuit = selectCircuit({ offer, walletCircuitIds: caps.circuitIds, query: q })
    if (!circuit) {
      return reject('no_circuit', `the request offers ${offer.circuit_id_values?.join(', ') || 'no circuit id'}; the wallet runs ${caps.circuitIds.join(', ') || 'none'}`)
    }
    view.circuit = circuit
  } else {
    const offer = req.client_metadata?.vp_formats_supported?.mms_zk ?? {}
    const scheme = selectScheme({ offer, walletSchemeIds: caps.schemeIds, query: q })
    if (!scheme) {
      return reject('no_circuit', `the request offers ${offer.scheme_id_values?.join(', ') || 'no scheme id'}; the wallet runs ${caps.schemeIds.join(', ') || 'none'}`)
    }
    view.scheme = scheme
  }

  if (ageFails) return { ...view, satisfiable: false, problem: 'age' }
  return view
}

/** "13–17", "18+", "under 18": the age range in a request screen title. */
export function ageShort(item: { minAge?: number; maxAge?: number }): string {
  if (item.minAge != null && item.maxAge != null) return `${item.minAge}–${item.maxAge}`
  if (item.minAge != null) return `${item.minAge}+`
  return `under ${item.maxAge! + 1}`
}

/** "between 13 and 17", "18 or older", "under 18". */
export function ageText(item: { minAge?: number; maxAge?: number }): string {
  if (item.minAge != null && item.maxAge != null) return `between ${item.minAge} and ${item.maxAge}`
  if (item.minAge != null) return `${item.minAge} or older`
  return `under ${item.maxAge! + 1}`
}


export function fmtDate(iso: string): string {
  return new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })
}

/** "Born between 14 Oct 2008 and 13 Oct 2013", "Born on or before 13 Oct 2008". */
export function birthRangeText(item: { ge?: string; le?: string }): string {
  if (item.ge && item.le) return `Born between ${fmtDate(item.ge)} and ${fmtDate(item.le)}`
  if (item.le) return `Born on or before ${fmtDate(item.le)}`
  return `Born on or after ${fmtDate(item.ge!)}`
}

/**
 * A request, in two forms, both derived from the request, the circuit's registry entry and the
 * credential: `fields` is what the wallet's request screen lists; the rest is the technical
 * account of the same request, which the guide panel shows.
 */
export interface ConsentView {
  verifier: { name: string; host: string; clientId: string; certificate?: string }
  /** The credential the presentation is made from: its position in the wallet and its label. */
  credential: { index: number; label: string }
  /** The request screen's "Requested Information", in product wording. */
  fields: Array<{ kind: 'pseudonym' | 'age'; name: string; value?: string; notes?: string[] }>
  /** The pseudonym this request discloses, computed by the wallet as the circuit will, with the
   *  rulebook's properties of the requested configuration. */
  pseudonym?: { handle: string; config: PseudonymConfig; function: 'pseudonym-v1-sha256' | 'pseudonym-bbs-v1'; verifierId: string; value?: string; properties: string[] }
  age?: { handle: string; text: string; range: string; ge?: string; le?: string }
  /** The other values the verifier receives, from the circuit's registry entry. */
  alsoSent: Array<{ label: string; value: string }>
  notShared: Array<{ label: string; value?: string }>
}

const ELEMENT_LABELS: Record<string, string> = {
  birth_date: 'Birth date',
  ssc: 'Seed commitment (ssc)',
  psc: 'Private seed commitment (psc)',
}

export async function consentFor(view: RequestView, cred: CredentialView, certificate?: string): Promise<ConsentView> {
  const host = view.verifierHost || view.clientId
  const out: ConsentView = {
    verifier: { name: view.verifierName, host, clientId: view.clientId, ...(certificate && { certificate }) },
    credential: { index: cred.index, label: credentialLabel(cred) },
    fields: [],
    alsoSent: [],
    notShared: [],
  }

  for (const item of view.items) {
    if (item.kind === 'pseudonym') {
      const verifierId = view.clientId
      // pseudonym-v1-sha256: the wallet computes it as the circuit will. pseudonym-bbs-v1
      // (SHA-256(seed·OP), a BLS12-381 point) comes out of the proof.
      const value =
        item.function === 'pseudonym-v1-sha256'
          ? await derivePseudonym({ config: item.config, seed: fromHex(mdocMaterial(cred.index).secret_seed), verifierId, verifierContext: item.verifierContext })
          : undefined
      const p = CONFIG_PROPERTIES[item.config]
      const properties = [`The same at every visit to ${host}.`]
      if (p.distinctPerVerifier) properties.push(`Different for every site: it is derived from the verifier_id ${verifierId}.`)
      if (p.sameAcrossVerifiers) properties.push('The same value at every site that receives it.')
      if (p.knownOffenderMatching) properties.push(`${host} recognises it at a new sign-up, for example after a ban.`)
      properties.push(
        p.issuerCanLink
          ? `The issuer, ${cred.issuer.name}, knows the seed and can link the pseudonym to the holder.`
          : `The issuer, ${cred.issuer.name}, cannot link the pseudonym to the holder.`,
      )
      out.pseudonym = { handle: item.handle, config: item.config, function: item.function, verifierId, ...(value && { value }), properties }
      // What the configuration means for the person (rulebook properties, CONFIG_PROPERTIES).
      // Each fits on one line at the phone's width.
      const notes = ['Your personal data will not be shared']
      if (p.distinctPerVerifier) notes.push('You cannot be tracked across sites')
      if (p.sameAcrossVerifiers) notes.push('Sites that receive it can link your visits')
      notes.push('The site can recognize your account')
      // The issuer can link only if it kept the seed or its mapping to the holder.
      notes.push(p.issuerCanLink ? 'The issuer may be able to reveal your identity' : 'The issuer cannot reveal your identity')
      out.fields.push({ kind: 'pseudonym', name: 'Pseudonym', value: p.distinctPerVerifier ? `Specific to ${host}` : 'The same for every site', notes })
    } else {
      const text = ageText(item)
      out.age = { handle: item.handle, text, range: birthRangeText(item), ...(item.ge && { ge: item.ge }), ...(item.le && { le: item.le }) }
      out.fields.push({ kind: 'age', name: `Age proof: ${ageShort(item)}` })
    }
  }

  // The age proof first, then the pseudonym.
  out.fields.sort((a, b) => (a.kind === 'age' ? 0 : 1) - (b.kind === 'age' ? 0 : 1))

  for (const input of view.circuit?.public_inputs ?? []) {
    if (input.name === 'issuer_key_set') out.alsoSent.push({ label: 'Issuer certificate', value: cred.issuer.documentSigner })
    if (input.name === 'proof_time') out.alsoSent.push({ label: 'Proof time', value: 'The time of the presentation, to the second' })
  }
  if (view.circuit) out.alsoSent.push({ label: 'Circuit', value: `${view.circuit.label} (${view.circuit.proof_system})` })
  if (view.scheme && cred.bbs) {
    out.alsoSent.push(
      { label: 'Issuer key', value: `${cred.bbs.issuerKey.slice(0, 16)}… (BLS12-381), the same for every holder of this issuer` },
      { label: 'Schema', value: `${view.scheme.schema.id}, the same for every holder` },
      { label: 'Commitments', value: 'Fresh Pedersen commitments to the committed attributes, new in every presentation' },
      { label: 'Scheme', value: `${view.scheme.label} (${view.scheme.proof_system})` },
    )
  }

  for (const e of cred.elements) {
    const label = ELEMENT_LABELS[e.id] ?? (e.id === 'nym_seed' ? 'Pseudonym seed' : e.id === 'device_key' ? 'Device key' : e.id)
    if (e.id === 'device_key') continue
    out.notShared.push(e.id === 'birth_date' ? { label, value: fmtDate(cred.attributes.birth_date) } : { label })
  }
  if (cred.format === 'mms_zk') out.notShared.push({ label: 'Device key' }, { label: 'The credential itself: the BBS signature' })
  else out.notShared.push({ label: 'Secret seed' }, { label: 'Device key' }, { label: 'The credential itself: issuer signature and validity dates' })
  return out
}
