// Capability negotiation: circuit_zk (rulebook, "Metadata parameters" and "Capability
// negotiation"), and mms_zk the same way over schemes (docs/mms_zk.md).
import { CIRCUIT_REGISTRY, SCHEME_REGISTRY, type CircuitEntry, type SchemeEntry } from '../registry/circuits'
import type { CircuitZkCredentialQuery, CircuitZkFormats, MmsZkCredentialQuery, MmsZkFormats, VpFormats } from '../types/oid4vp'

const intersect = (a?: string[], b?: string[]) => (a && b ? a.filter((x) => b.includes(x)) : (a ?? b))

/**
 * Verifier side: tailor the offer to the wallet's `wallet_metadata` (request_uri_method=post).
 * If nothing overlaps, keep the full offer so the wallet reports the request as unsatisfiable.
 */
export function tailorCircuitZk(offer: CircuitZkFormats, wallet?: CircuitZkFormats): { formats: CircuitZkFormats; tailored: boolean } {
  if (!wallet) return { formats: offer, tailored: false }
  const ids = intersect(offer.circuit_id_values, wallet.circuit_id_values)
  const systems = intersect(offer.circuit_proof_system_values, wallet.circuit_proof_system_values)
  if ((ids && !ids.length) || (systems && !systems.length)) return { formats: offer, tailored: false }
  return {
    formats: {
      ...(systems && { circuit_proof_system_values: systems }),
      ...(ids && { circuit_id_values: ids }),
    },
    tailored: true,
  }
}

/** mms_zk, as circuit_zk: tailor scheme ids and proof systems to the wallet's. */
export function tailorMmsZk(offer: MmsZkFormats, wallet?: MmsZkFormats): { formats: MmsZkFormats; tailored: boolean } {
  if (!wallet) return { formats: offer, tailored: false }
  const ids = intersect(offer.scheme_id_values, wallet.scheme_id_values)
  const systems = intersect(offer.proof_system_values, wallet.proof_system_values)
  if ((ids && !ids.length) || (systems && !systems.length)) return { formats: offer, tailored: false }
  return {
    formats: { ...(systems && { proof_system_values: systems }), ...(ids && { scheme_id_values: ids }) },
    tailored: true,
  }
}

/**
 * Verifier side: tailor each offered format to the wallet's `wallet_metadata`. A format the wallet
 * does not list keeps the full offer.
 */
export function tailorFormats(offer: VpFormats, wallet?: VpFormats): { formats: VpFormats; tailored: boolean } {
  const zk = offer.circuit_zk ? tailorCircuitZk(offer.circuit_zk, wallet?.circuit_zk) : undefined
  const mms = offer.mms_zk ? tailorMmsZk(offer.mms_zk, wallet?.mms_zk) : undefined
  return {
    formats: { ...(zk && { circuit_zk: zk.formats }), ...(mms && { mms_zk: mms.formats }) },
    tailored: !!(zk?.tailored || mms?.tailored),
  }
}

/** Does the scheme support every item in `req`? */
export function schemeSupportsQuery(s: SchemeEntry, q: MmsZkCredentialQuery): boolean {
  if (q.meta.schema_id_value !== s.schema.id) return false
  if (!q.req.some((r) => r.id === 'pseudonym-bbs-v1')) return false
  return q.req.every((r) => {
    if (r.id === 'pseudonym-bbs-v1') {
      const f = s.functions['pseudonym-bbs-v1']
      return f.configs.includes(r.params.config) && f.verifier_id_types.includes(r.params.verifier_id_type)
    }
    if (r.id === 'age_check') return Object.keys(r.params).every((k) => s.functions.age_check.params.includes(k as 'ge' | 'le'))
    return false
  })
}

/** Wallet side, mms_zk: a scheme the request offers, the wallet runs and that supports the query. */
export function selectScheme(o: { offer: MmsZkFormats; walletSchemeIds: string[]; query: MmsZkCredentialQuery; registry?: SchemeEntry[] }): SchemeEntry | null {
  const reg = o.registry ?? SCHEME_REGISTRY
  const order = o.offer.scheme_id_values ?? reg.map((s) => s.scheme_id)
  for (const id of order) {
    const s = reg.find((e) => e.scheme_id === id)
    if (
      s &&
      (!o.offer.proof_system_values || o.offer.proof_system_values.includes(s.proof_system)) &&
      o.walletSchemeIds.includes(s.scheme_id) &&
      schemeSupportsQuery(s, o.query)
    )
      return s
  }
  return null
}

/** Does the circuit support every item in `req` with the given parameters? */
export function circuitSupportsQuery(c: CircuitEntry, q: CircuitZkCredentialQuery): boolean {
  if (q.meta.doctype_value !== c.doctype) return false
  if (c.functions['pseudonym-v1-sha256']?.required && !q.req.some((r) => r.id === 'pseudonym-v1-sha256')) return false
  return q.req.every((r) => {
    if (r.id === 'pseudonym-v1-sha256') {
      const f = c.functions['pseudonym-v1-sha256']
      if (!f || !f.configs.includes(r.params.config)) return false
      return !r.params.verifier_id_type || f.verifier_id_types.includes(r.params.verifier_id_type)
    }
    if (r.id === 'age_check') {
      const f = c.functions.age_check
      return !!f && Object.keys(r.params).every((k) => f.params.includes(k as 'ge' | 'le'))
    }
    return false
  })
}

/**
 * Wallet side: pick an approved circuit whose proof system and id are both listed
 * by the verifier, that the wallet can run, and that supports every req item.
 * Verifier order of circuit_id_values is treated as preference.
 */
export function selectCircuit(o: {
  offer: CircuitZkFormats
  walletCircuitIds: string[]
  query: CircuitZkCredentialQuery
  registry?: CircuitEntry[]
}): CircuitEntry | null {
  const reg = o.registry ?? CIRCUIT_REGISTRY
  const ok = (c: CircuitEntry) =>
    (!o.offer.circuit_id_values || o.offer.circuit_id_values.includes(c.circuit_id)) &&
    (!o.offer.circuit_proof_system_values || o.offer.circuit_proof_system_values.includes(c.proof_system)) &&
    o.walletCircuitIds.includes(c.circuit_id) &&
    circuitSupportsQuery(c, o.query)
  const order = o.offer.circuit_id_values ?? reg.map((c) => c.circuit_id)
  for (const id of order) {
    const c = reg.find((e) => e.circuit_id === id)
    if (c && ok(c)) return c
  }
  return null
}
