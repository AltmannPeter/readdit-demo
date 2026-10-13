import type { H3Event } from 'h3'
import type { CircuitZkFormats } from '#shared/types/oid4vp'
import { findCircuit } from '#shared/registry/circuits'
import type { VpSessionRecord } from './store'

/**
 * The site's circuit_zk offer: accepted circuits (config order) that are in the approved registry
 * and that the verifier can verify. A circuit the verifier lists must be the registry's: the same
 * proof system, the same public inputs in the same order and, where the registry pins one, the same
 * hash of the circuits as data. A mismatch is a configuration error and fails the offer, and so
 * does an offer without any circuit.
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
  if (!ids.length) throw new Error(`none of the accepted circuits (${accepted.join(', ')}) is in the registry and the verifier`)
  const systems = [...new Set(ids.map((id) => findCircuit(id)!.proof_system))]
  return { circuit_proof_system_values: systems, circuit_id_values: ids }
}

/** A session by id; one past its time ends as failed with reason `expired`. 404 unknown_session. */
export function getVpSession(id: string) {
  const s = store().sessions.get(id)
  if (!s) throw refusal(404, 'unknown_session', 'Unknown session.')
  if (Date.now() > s.expiresAt && s.status !== 'completed' && s.status !== 'failed') {
    s.status = 'failed'
    s.outcome = { ok: false, reason: 'expired' }
    addTrace(s, 'failed', 'Expired', { reason: 'expired' })
  }
  return s
}

/** The session ended without an answer from the wallet: expired, or cancelled by the site. */
export function endedReason(s: VpSessionRecord): 'expired' | 'cancelled' | null {
  if (s.status !== 'failed' || !s.outcome || s.outcome.ok) return null
  return s.outcome.reason === 'expired' || s.outcome.reason === 'cancelled' ? s.outcome.reason : null
}

/** 410 for a session that expired or that the site cancelled. */
export function goneRefusal(reason: 'expired' | 'cancelled') {
  return reason === 'expired' ? refusal(410, 'expired', 'This request has expired.') : refusal(410, 'cancelled', 'This request was cancelled.')
}

/** Session owned by the calling browser. */
export async function getOwnedVpSession(event: H3Event, id: string) {
  const s = getVpSession(id)
  const b = await browserSession(event)
  if (s.ownerSid !== b.data.sid) throw refusal(403, 'other_browser', 'This session belongs to another browser.')
  return { s, b }
}

export function handoverFor(s: { request?: { client_id: string; nonce: string; response_uri: string } }) {
  const r = s.request!
  return { client_id: r.client_id, nonce: r.nonce, response_uri: r.response_uri, jwk_thumbprint: null }
}
