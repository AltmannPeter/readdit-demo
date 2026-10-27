import type { H3Event } from 'h3'
import type { VpFormats } from '#shared/types/oid4vp'
import { PROOF_SYSTEMS, findCircuit, findScheme, findSystem } from '#shared/registry/circuits'
import { systemAvailable } from '#shared/profiles'
import type { VpSessionRecord } from './store'

const list = (v: unknown) =>
  String(v)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

/**
 * mso_mdoc: the accepted circuits (config order) whose proof system the site accepts now, that
 * are in the approved registry, and that a loaded verifier (Vega, Longfellow) can verify. A circuit
 * a verifier lists must be the registry's: the same proof system, the same public inputs in the
 * same order and, where the registry pins one, the same hash of the circuits as data. A mismatch
 * is a configuration error and fails the offer.
 */
async function circuitOffer(systems: string[]): Promise<string[]> {
  const accepted = list(useRuntimeConfig().acceptedCircuits).filter((id) => systems.includes(findCircuit(id)?.proof_system ?? ''))
  if (!accepted.length) return []
  const info = await verifier.info()
  const ids = accepted.filter((id) => {
    const entry = findCircuit(id)
    const listed = info.circuits.find((c) => c.system_id === id)
    if (!entry || !listed) return false
    const names = entry.public_inputs.map((p) => p.name).join()
    if (listed.proof_system !== entry.proof_system) throw new Error(`verifier circuit ${id}: proof system ${listed.proof_system}, registry ${entry.proof_system}`)
    if (listed.public_inputs && listed.public_inputs.join() !== names) {
      throw new Error(`verifier circuit ${id}: public inputs ${listed.public_inputs.join()} do not match the registry's ${names}`)
    }
    const sha = listed.artifact_sha256 ?? listed.shapes_sha256
    if (entry.artifact && sha !== entry.artifact.sha256) {
      throw new Error(`verifier circuit ${id}: ${entry.artifact.name} SHA-256 ${sha} is not the registry's ${entry.artifact.sha256}`)
    }
    return true
  })
  return ids
}

/** bbs_cd, likewise: the accepted schemes that are in the registry and that the BBS verifier
 *  reports with the same proof system, schema and plugins. */
async function schemeOffer(): Promise<string[]> {
  const accepted = list(useRuntimeConfig().acceptedSchemes)
  const info = await bbsVerifier.info()
  const ids = accepted.filter((id) => {
    const entry = findScheme(id)
    const listed = info.schemes.find((s) => s.system_id === id)
    if (!entry || !listed) return false
    if (listed.proof_system !== entry.proof_system) throw new Error(`verifier scheme ${id}: proof system ${listed.proof_system}, registry ${entry.proof_system}`)
    if (listed.schema_id !== entry.schema.id || listed.schema_digest !== entry.schema.digest) {
      throw new Error(`verifier scheme ${id}: schema ${listed.schema_id} ${listed.schema_digest} is not the registry's ${entry.schema.id} ${entry.schema.digest}`)
    }
    if (listed.plugins.join() !== entry.plugins.map((p) => p.id).join()) throw new Error(`verifier scheme ${id}: plugins ${listed.plugins.join()} are not the registry's`)
    return true
  })
  return ids
}

/** No proof system is accepted (the demo's start): there is nothing to ask the wallet for. */
export class NothingAccepted extends Error {
  constructor() {
    super('the site accepts no proof system')
  }
}

/**
 * The site's offer, `vp_formats_supported.zkp_req`: the systems of the proof systems the site
 * accepts now (store().acceptedProofSystems, switched in /tech), when their backend is loaded.
 * Circuits first (Vega, then Longfellow), then the BBS scheme: the order of preference. A backend
 * that is not loaded leaves its systems out; an offer with no system fails, and so does a
 * configuration mismatch. With nothing accepted, NothingAccepted.
 */
export async function verifierOffer(): Promise<VpFormats> {
  // A proof system the demo profile cannot use yet (status pending) is not offered.
  const profile = activeProfile()
  const accepted = store().acceptedProofSystems.filter((x) => systemAvailable(profile, x))
  if (!accepted.length) throw new NothingAccepted()
  const missing: string[] = []
  const take = async (systems: string[], make: () => Promise<string[]>): Promise<string[]> => {
    if (!systems.some((x) => accepted.includes(x))) return []
    try {
      return await make()
    } catch (e) {
      if (e instanceof ServiceError) {
        missing.push(`${systems.join(', ')}: ${e.code}`)
        return []
      }
      throw e
    }
  }
  const circuitSystems = PROOF_SYSTEMS.filter((p) => p.source_format === 'mso_mdoc').map((p) => p.id as string)
  const ids = [
    ...(await take(circuitSystems, () => circuitOffer(circuitSystems.filter((x) => accepted.includes(x))))),
    ...(await take(['bbs-cd-plugins-v0.1'], schemeOffer)),
  ]
  if (!ids.length) {
    throw new Error(`no system to offer: the site accepts ${accepted.join(', ') || 'no proof system'}${missing.length ? `; ${missing.join('; ')}` : ''}`)
  }
  const offer: VpFormats = { zkp_req: { proof_system_values: [...new Set(ids.map((id) => findSystem(id)!.proof_system))], system_id_values: ids } }
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

/** The handover the verifier checks the proof against: from the session's own request and key. */
export function handoverFor(s: VpSessionRecord) {
  const r = s.request!
  return { client_id: r.client_id, nonce: r.nonce, response_uri: r.response_uri, jwk_thumbprint: s.responseKey.thumbprint }
}
