import type { AgeCheckReq, PseudonymConfig, RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'
import type { CircuitEntry } from '#shared/registry/circuits'
import { selectCircuit } from '#shared/utils/negotiation'
import { derivePseudonym } from '#shared/utils/pseudonym'
import { fromHex } from '#shared/utils/bytes'
import type { CredentialView } from './holder'
import { holder } from './holder'
import { CONFIG_PROPERTIES } from './rulebook'

export type RequestItemView =
  | { kind: 'pseudonym'; handle: string; config: PseudonymConfig; verifierIdType?: string; verifierContext?: string }
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
  circuit?: CircuitEntry
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

/** Checks the request against the rulebook, the credential and the circuits this wallet can run. */
export function analyzeRequest(req: RequestObject, cred: CredentialView, today: string, walletCircuitIds: string[]): RequestView {
  const host = req.client_id.startsWith('x509_san_dns:') ? req.client_id.slice('x509_san_dns:'.length) : ''
  const view: RequestView = {
    verifierName: req.client_metadata.client_name ?? host,
    verifierHost: host,
    clientId: req.client_id,
    items: [],
    satisfiable: true,
  }
  const reject = (problem: 'unsupported' | 'no_circuit') => ({ ...view, satisfiable: false, problem })

  const queries = req.dcql_query.credentials
  if (queries.length !== 1) return reject('unsupported')
  const q = queries[0]!
  if (q.format !== 'circuit_zk' || q.meta.doctype_value !== NYM_DOCTYPE || q.meta.doctype_value !== cred.docType) return reject('unsupported')
  if ((q as { require_cryptographic_holder_binding?: boolean }).require_cryptographic_holder_binding === false) return reject('unsupported')
  if (!q.req.length) return reject('unsupported')

  let nyms = 0
  let ages = 0
  let ageFails = false
  for (const r of q.req) {
    if (r.id === 'pseudonym-v1-sha256') {
      nyms++
      const { config, verifier_id_type: idType, verifier_context: ctx } = r.params
      const usesVerifierInput = ID_TYPE_CONFIGS.has(config)
      if (usesVerifierInput !== !!idType) return reject('unsupported')
      if (idType && idType !== 'x509_san_dns' && idType !== 'semantic') return reject('unsupported')
      if (idType === 'x509_san_dns' && !host) return reject('unsupported')
      if (idType === 'semantic') return reject('unsupported') // no registration certificate in this demo
      if ((config === 'account-recovery-ssc') !== (ctx != null)) return reject('unsupported')
      if (ctx != null && (new TextEncoder().encode(ctx).length < 1 || new TextEncoder().encode(ctx).length > 64)) return reject('unsupported')
      if (config === 'known-offender-matching-psc' && !cred.attributes.psc) return reject('unsupported')
      view.items.push({ kind: 'pseudonym', handle: r.return, config, ...(idType && { verifierIdType: idType }), ...(ctx != null && { verifierContext: ctx }) })
    } else if (r.id === 'age_check') {
      ages++
      const { ge, le } = r.params
      if (!ge && !le) return reject('unsupported')
      if (ge && le && (le < ge || daysBetween(ge, le) + 1 < 365)) return reject('unsupported')
      view.items.push(ageItem(r, today))
      if (!((!ge || cred.attributes.birth_date >= ge) && (!le || cred.attributes.birth_date <= le))) ageFails = true
    } else {
      return reject('unsupported')
    }
  }
  if (nyms > 1 || ages > 1) return reject('unsupported')

  const circuit = selectCircuit({ offer: req.client_metadata.vp_formats_supported.circuit_zk, walletCircuitIds, query: q })
  if (!circuit) return reject('no_circuit')
  view.circuit = circuit

  if (ageFails) return { ...view, satisfiable: false, problem: 'age' }
  return view
}

/** "between 13 and 17", "18 or older", "under 18". */
export function ageText(item: { minAge?: number; maxAge?: number }): string {
  if (item.minAge != null && item.maxAge != null) return `between ${item.minAge} and ${item.maxAge}`
  if (item.minAge != null) return `${item.minAge} or older`
  return `under ${item.maxAge! + 1}`
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

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
  /** The request screen's "Requested Information", in product wording. */
  fields: Array<{ name: string; value: string }>
  /** The pseudonym this request discloses, computed by the wallet as the circuit will, with the
   *  rulebook's properties of the requested configuration. */
  pseudonym?: { handle: string; config: PseudonymConfig; verifierId: string; value: string; properties: string[] }
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
    fields: [],
    alsoSent: [],
    notShared: [],
  }

  for (const item of view.items) {
    if (item.kind === 'pseudonym') {
      const verifierId = view.clientId
      const value = await derivePseudonym({ config: item.config, seed: fromHex(holder.secret_seed), verifierId, verifierContext: item.verifierContext })
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
      out.pseudonym = { handle: item.handle, config: item.config, verifierId, value, properties }
      out.fields.push({ name: 'Pseudonym', value: p.distinctPerVerifier ? `Specific to ${host}` : 'The same for every site' })
    } else {
      const text = ageText(item)
      out.age = { handle: item.handle, text, range: birthRangeText(item), ...(item.ge && { ge: item.ge }), ...(item.le && { le: item.le }) }
      out.fields.push({ name: 'Age', value: capitalize(text) })
    }
  }

  for (const input of view.circuit?.public_inputs ?? []) {
    if (input.name === 'issuer_key_set') out.alsoSent.push({ label: 'Issuer certificate', value: cred.issuer.documentSigner })
    if (input.name === 'proof_time') out.alsoSent.push({ label: 'Proof time', value: 'The time of the presentation, to the second' })
  }
  if (view.circuit) out.alsoSent.push({ label: 'Circuit', value: `${view.circuit.label} (${view.circuit.proof_system})` })

  for (const e of cred.elements) {
    const label = ELEMENT_LABELS[e.id] ?? e.id
    out.notShared.push(e.id === 'birth_date' ? { label, value: fmtDate(cred.attributes.birth_date) } : { label })
  }
  out.notShared.push({ label: 'Secret seed' }, { label: 'Device key' }, { label: 'The credential itself: issuer signature and validity dates' })
  return out
}
