import type { AgeCheckReq, RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'
import type { CircuitEntry } from '#shared/registry/circuits'
import { selectCircuit } from '#shared/utils/negotiation'
import type { CredentialView } from './holder'

export type RequestItemView =
  | { kind: 'pseudonym' }
  | { kind: 'age'; minAge?: number; maxAge?: number }

export interface RequestView {
  verifierName: string
  verifierHost: string
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
    ...(r.params.le && { minAge: ageOn(r.params.le, today) }),
    ...(r.params.ge && { maxAge: ageOn(r.params.ge, today) }),
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
      view.items.push({ kind: 'pseudonym' })
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

export function ageText(item: { minAge?: number; maxAge?: number }): string {
  if (item.minAge != null && item.maxAge != null) return `${item.minAge}–${item.maxAge}`
  if (item.minAge != null) return `${item.minAge} or older`
  return `under ${item.maxAge! + 1}`
}
