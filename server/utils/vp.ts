import type { H3Event } from 'h3'
import type { CircuitZkFormats } from '#shared/types/oid4vp'
import { findCircuit } from '#shared/registry/circuits'

/**
 * The site's circuit_zk offer: accepted circuits (config order) that are in the
 * approved registry and that the verifier service can verify.
 */
export async function verifierOffer(): Promise<CircuitZkFormats> {
  const cfg = useRuntimeConfig()
  const accepted = String(cfg.acceptedCircuits)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  const info = await verifier.info()
  const supported = new Set(info.circuits.map((c) => c.circuit_id))
  const ids = accepted.filter((id) => findCircuit(id) && supported.has(id))
  const systems = [...new Set(ids.map((id) => findCircuit(id)!.proof_system))]
  return { circuit_proof_system_values: systems, circuit_id_values: ids }
}

export function getVpSession(id: string) {
  const s = store().sessions.get(id)
  if (!s) throw createError({ statusCode: 404, statusMessage: 'unknown session' })
  if (Date.now() > s.expiresAt && s.status !== 'completed' && s.status !== 'failed') {
    s.status = 'failed'
    s.outcome = { ok: false, reason: 'expired' }
  }
  return s
}

/** Session owned by the calling browser. */
export async function getOwnedVpSession(event: H3Event, id: string) {
  const s = getVpSession(id)
  const b = await browserSession(event)
  if (s.ownerSid !== b.data.sid) throw createError({ statusCode: 403, statusMessage: 'not your session' })
  return { s, b }
}

export function handoverFor(s: { request?: { client_id: string; nonce: string; response_uri: string } }) {
  const r = s.request!
  return { client_id: r.client_id, nonce: r.nonce, response_uri: r.response_uri, jwk_thumbprint: null }
}
