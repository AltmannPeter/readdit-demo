import type { H3Event } from 'h3'
import type { CircuitZkFormats, MmsZkFormats, VpFormats } from '#shared/types/oid4vp'
import { findCircuit, findScheme } from '#shared/registry/circuits'
import type { VpSessionRecord } from './store'

const list = (v: unknown) =>
  String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

/**
 * circuit_zk: the accepted circuits (config order) that are in the approved registry and that the
 * Vega verifier can verify. A circuit the verifier lists must be the registry's: the same proof
 * system, the same public inputs in the same order and, where the registry pins one, the same hash
 * of the circuits as data. A mismatch is a configuration error and fails the offer.
 */
async function circuitZkOffer(): Promise<CircuitZkFormats | undefined> {
  const accepted = list(useRuntimeConfig().acceptedCircuits)
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
  if (!ids.length) return undefined
  return { circuit_proof_system_values: [...new Set(ids.map((id) => findCircuit(id)!.proof_system))], circuit_id_values: ids }
}

/** mms_zk, likewise: the accepted schemes that are in the registry and that the BBS verifier
 *  reports with the same proof system, schema and plugins. */
async function mmsZkOffer(): Promise<MmsZkFormats | undefined> {
  const accepted = list(useRuntimeConfig().acceptedSchemes)
  const info = await bbsVerifier.info()
  const ids = accepted.filter((id) => {
    const entry = findScheme(id)
    const listed = info.schemes.find((s) => s.scheme_id === id)
    if (!entry || !listed) return false
    if (listed.proof_system !== entry.proof_system) throw new Error(`verifier scheme ${id}: proof system ${listed.proof_system}, registry ${entry.proof_system}`)
    if (listed.schema_id !== entry.schema.id || listed.schema_digest !== entry.schema.digest) {
      throw new Error(`verifier scheme ${id}: schema ${listed.schema_id} ${listed.schema_digest} is not the registry's ${entry.schema.id} ${entry.schema.digest}`)
    }
    if (listed.plugins.join() !== entry.plugins.map((p) => p.id).join()) throw new Error(`verifier scheme ${id}: plugins ${listed.plugins.join()} are not the registry's`)
    return true
  })
  if (!ids.length) return undefined
  return { proof_system_values: [...new Set(ids.map((id) => findScheme(id)!.proof_system))], scheme_id_values: ids }
}

/**
 * The site's offer: for each proof system the site accepts now (store().acceptedProofSystems,
 * switched in /tech), its format, when its backend is loaded. circuit_zk first, then mms_zk: the
 * order of preference. A backend that is not loaded leaves its format out; an offer with no format
 * fails, and so does a configuration mismatch.
 */
export async function verifierOffer(): Promise<VpFormats> {
  const accepted = store().acceptedProofSystems
  const offer: VpFormats = {}
  const missing: string[] = []
  const take = async <T>(system: string, make: () => Promise<T | undefined>): Promise<T | undefined> => {
    if (!accepted.includes(system)) return undefined
    try {
      return await make()
    } catch (e) {
      if (e instanceof ServiceError) {
        missing.push(`${system}: ${e.code}`)
        return undefined
      }
      throw e
    }
  }
  const zk = await take('vega-v1', circuitZkOffer)
  if (zk) offer.circuit_zk = zk
  const mms = await take('bbs-cd-plugins-v0.1', mmsZkOffer)
  if (mms) offer.mms_zk = mms
  if (!offer.circuit_zk && !offer.mms_zk) {
    throw new Error(`no format to offer: the site accepts ${accepted.join(', ') || 'no proof system'}${missing.length ? `; ${missing.join('; ')}` : ''}`)
  }
  return offer
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
