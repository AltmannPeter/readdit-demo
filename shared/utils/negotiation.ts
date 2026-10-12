// circuit_zk capability negotiation (rulebook, "Metadata parameters" and "Capability negotiation").
import { CIRCUIT_REGISTRY, type CircuitEntry } from '../registry/circuits'
import type { CircuitZkCredentialQuery, CircuitZkFormats } from '../types/oid4vp'

const intersect = (a?: string[], b?: string[]) => (a && b ? a.filter((x) => b.includes(x)) : (a ?? b))

/**
 * Verifier side: tailor the offer to the wallet's `wallet_metadata` (request_uri_method=post).
 * If nothing overlaps, keep the full offer so the wallet reports the request as unsatisfiable.
 */
export function tailorFormats(offer: CircuitZkFormats, wallet?: CircuitZkFormats): { formats: CircuitZkFormats; tailored: boolean } {
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

/** Does the circuit support every item in `req` with the given parameters? */
export function circuitSupportsQuery(c: CircuitEntry, q: CircuitZkCredentialQuery): boolean {
  if (q.meta.doctype_value !== c.doctype) return false
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
