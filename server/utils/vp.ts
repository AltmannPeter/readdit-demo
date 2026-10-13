import type { H3Event } from 'h3'
import type { CircuitZkFormats } from '#shared/types/oid4vp'
import { findCircuit } from '#shared/registry/circuits'

/**
 * The site's circuit_zk offer: accepted circuits (config order) that are in the approved registry
 * and that the verifier can verify. A circuit the verifier lists must be the registry's: the same
 * proof system, the same public inputs in the same order and, where the registry pins one, the same
 * hash of the circuits as data. A mismatch is a configuration error and fails the offer.
 */
export async function verifierOffer(): Promise<CircuitZkFormats> {
  const cfg = useRuntimeConfig()
  const accepted = String(cfg.acceptedCircuits)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  const info = await verifier.info()
  const ids = accepted.filter((id) => {
    const entry = findCircuit(id)
    const listed = info.circuits.find((c) => c.circuit_id === id)
    if (!entry || !listed) return false
    const names = entry.public_inputs.map((p) => p.name).join()
    if (listed.proof_system !== entry.proof_system) throw new Error(`verifier circuit ${id}: proof system ${listed.proof_system}, registry ${entry.proof_system}`)
    if (listed.public_inputs && listed.public_inputs.join() !== names) {
      throw new Error(`verifier circuit ${id}: public inputs ${listed.public_inputs.join()} do not match the registry's ${names}`)
    }
    if (entry.artifact && listed.shapes_sha256 !== entry.artifact.sha256) {
      throw new Error(`verifier circuit ${id}: ${entry.artifact.name} SHA-256 ${listed.shapes_sha256} is not the registry's ${entry.artifact.sha256}`)
    }
    return true
  })
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
