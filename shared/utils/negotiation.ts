// Capability negotiation for zkp_req (rulebook v0.4, "Metadata parameters" and "Capability
// negotiation"): one set of proof systems and system ids (circuits and schemes) for both source
// formats.
import { SYSTEM_REGISTRY, typeValueOfSystem, type SystemEntry } from '../registry/circuits'
import { typeValueOf, type VpFormats, type ZkpReqCredentialQuery, type ZkpReqFormats } from '../types/oid4vp'

const intersect = (a?: string[], b?: string[]) => (a && b ? a.filter((x) => b.includes(x)) : (a ?? b))

/**
 * Verifier side: tailor the offer to the wallet's `wallet_metadata` (request_uri_method=post).
 * If nothing overlaps, keep the full offer so the wallet reports the request as unsatisfiable.
 */
export function tailorZkpReq(offer: ZkpReqFormats, wallet?: ZkpReqFormats): { formats: ZkpReqFormats; tailored: boolean } {
  if (!wallet) return { formats: offer, tailored: false }
  const ids = intersect(offer.system_id_values, wallet.system_id_values)
  const systems = intersect(offer.proof_system_values, wallet.proof_system_values)
  if ((ids && !ids.length) || (systems && !systems.length)) return { formats: offer, tailored: false }
  return {
    formats: { ...(systems && { proof_system_values: systems }), ...(ids && { system_id_values: ids }) },
    tailored: true,
  }
}

/** Verifier side: tailor the offered formats to the wallet's `wallet_metadata`. */
export function tailorFormats(offer: VpFormats, wallet?: VpFormats): { formats: VpFormats; tailored: boolean } {
  if (!offer.zkp_req) return { formats: offer, tailored: false }
  const t = tailorZkpReq(offer.zkp_req, wallet?.zkp_req)
  return { formats: { zkp_req: t.formats }, tailored: t.tailored }
}

/** Does the system support the query: its source format and type value, and every `_req` item
 *  with the given parameters? */
export function systemSupportsQuery(e: SystemEntry, q: ZkpReqCredentialQuery): boolean {
  if (q.meta?.source_format !== e.source_format || typeValueOf(q.meta) !== typeValueOfSystem(e)) return false
  const nym = e.functions.pseudonym
  if (nym?.required && !q._req.some((r) => r.fn_id === 'pseudonym')) return false
  return q._req.every((r) => {
    if (r.fn_id === 'pseudonym') return !!nym && nym.configs.includes(r.params.config) && nym.prf.includes(r.params.prf) && nym.ver.includes(r.params.ver)
    if (r.fn_id === 'age_check') {
      const f = e.functions.age_check
      return !!f && Object.keys(r.params).every((k) => f.params.includes(k as 'ge' | 'le' | 'range'))
    }
    return false
  })
}

/**
 * Wallet side: an approved system whose proof system and id are both listed by the verifier, that
 * the wallet can run, and that supports the query. The order of system_id_values is the
 * verifier's preference.
 */
export function selectSystem(o: { offer: ZkpReqFormats; walletSystemIds: string[]; query: ZkpReqCredentialQuery; registry?: SystemEntry[] }): SystemEntry | null {
  const reg = o.registry ?? SYSTEM_REGISTRY
  const order = o.offer.system_id_values ?? reg.map((e) => e.system_id)
  for (const id of order) {
    const e = reg.find((x) => x.system_id === id)
    if (
      e &&
      (!o.offer.proof_system_values || o.offer.proof_system_values.includes(e.proof_system)) &&
      o.walletSystemIds.includes(e.system_id) &&
      systemSupportsQuery(e, o.query)
    )
      return e
  }
  return null
}
