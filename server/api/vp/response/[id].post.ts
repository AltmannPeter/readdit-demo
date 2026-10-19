import { RETURN_AGE, RETURN_PSEUDONYM } from '#shared/utils/dcql'
import { PROOF_SYSTEMS, findCircuit, findScheme } from '#shared/registry/circuits'
import type { FailReason } from '../../../utils/store'

/**
 * response_uri (direct_post). Form fields: vp_token (JSON) + state, or error + state.
 * Verification runs here, with the request and session values from the site's own store.
 *
 * Refused before anything is processed: 404 unknown_session, 400 state_mismatch (checked first, so
 * a caller without the request's state learns nothing about the session), 410 expired or cancelled,
 * 400 not_requested (the request was never fetched) and 400 already_answered (a second response:
 * a replay). A response that was processed answers 200, whether the presentation was accepted or
 * refused; the refusal's rule goes to the server log and the session trace (/tech), not to the
 * caller. 503 unavailable when the verifier failed and nothing could be decided.
 */
export default defineEventHandler(async (event) => {
  const s = getVpSession(getRouterParam(event, 'id')!)
  const raw = (await readRawBody(event, 'utf8')) ?? ''
  const form = Object.fromEntries(new URLSearchParams(raw))

  if (form.state !== s.state) throw refusal(400, 'state_mismatch', 'state does not match this session.')
  const ended = endedReason(s)
  if (ended) throw goneRefusal(ended)
  if (s.status === 'waiting' || !s.request) throw refusal(400, 'not_requested', 'This session is not waiting for a response.')
  if (s.status !== 'scanned') {
    console.warn(`[vp] ${s.id}: refused a second response (already_answered)`)
    addTrace(s, 'refused', 'Second response refused', { code: 'already_answered', bytes: raw.length })
    throw refusal(400, 'already_answered', 'This session has already received a response.')
  }
  s.status = 'responded'

  const fail = (reason: FailReason, detail?: string) => {
    s.status = 'failed'
    s.outcome = { ok: false, reason, ...(detail && { detail }) }
    addTrace(s, 'failed', 'Not completed', { reason, ...(detail && { detail }) })
    return {}
  }
  /** A presentation that does not pass: logged with its rule, answered 200 (processed). */
  const reject = (code: string, reason: string, data?: Record<string, unknown>) => {
    console.warn(`[vp] ${s.id}: presentation refused: ${code}${data?.input ? ` (${String(data.input)})` : ''}: ${reason}`)
    addTrace(s, 'verify', 'Proof rejected', { code, reason, ...data })
    return fail('invalid', `${code}: ${reason}`)
  }

  if (form.error) {
    addTrace(s, 'response', 'Error response received', { error: form.error, bytes: raw.length })
    return fail(form.error === 'access_denied' ? 'denied' : 'invalid_request', form.error)
  }

  let vpToken: unknown
  try {
    vpToken = JSON.parse(form.vp_token ?? '')
  } catch {
    addTrace(s, 'response', 'Presentation received', { bytes: raw.length, presentations: 0 })
    return reject('vp_token', 'vp_token is not JSON')
  }
  // Exactly one of the request's credential queries is answered (credential_sets: one option).
  const token = vpToken && typeof vpToken === 'object' && !Array.isArray(vpToken) ? (vpToken as Record<string, unknown>) : {}
  const answeredIds = Object.keys(token)
  const query = answeredIds.length === 1 ? s.dcql.credentials.find((q) => q.id === answeredIds[0]) : undefined
  const list = query ? token[query.id] : undefined
  addTrace(s, 'response', 'Presentation received', {
    bytes: raw.length,
    ...(query && { query: query.id, format: query.format }),
    presentations: Array.isArray(list) ? list.map((p) => (typeof p === 'string' ? p.length : 0)) : 0,
  })
  if (!query) return reject('vp_token', `expected a presentation for exactly one of ${s.dcql.credentials.map((q) => q.id).join(', ')}`)
  if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== 'string') return reject('vp_token', `expected one presentation for ${query.id}`)
  s.answered = query.id
  // The site accepts the format at the moment of the response too (/tech's switches); for
  // circuit_zk, the circuit's proof system is checked once the presentation names it, below.
  const systems = PROOF_SYSTEMS.filter((p) => p.format === query.format)
  if (!systems.some((p) => store().acceptedProofSystems.includes(p.id))) {
    return reject('format', `${query.format} (${systems.map((p) => p.id).join(', ') || 'unknown'}) is no longer accepted`)
  }

  const t0 = Date.now()
  let result: { ok: true; proofId: string; results: Record<string, string | true>; metrics?: VerifyMetrics } | { ok: false; code?: string; reason: string; input?: string | null; metrics?: VerifyMetrics }
  try {
    const call = { request: s.request, credential_query_id: query.id, presentation: list[0], handover: handoverFor(s) }
    if (query.format === 'circuit_zk') {
      const r = await verifier.verify({ ...call, now: new Date().toISOString() })
      result = r.ok ? { ok: true, proofId: r.circuit_id, results: r.results, metrics: r.metrics } : r
    } else {
      const r = await bbsVerifier.verify(call)
      result = r.ok ? { ok: true, proofId: r.scheme_id, results: r.results, metrics: r.metrics } : r
    }
  } catch (e) {
    const detail = e instanceof ServiceError ? `${e.code}: ${e.detail ?? ''}` : String(e)
    console.error(`[vp] ${s.id}: the verifier failed: ${detail}`)
    if (s.status === 'responded') fail('unavailable', `verifier ${detail}`)
    throw refusal(503, 'unavailable', 'The verifier is not available.')
  }
  const roundTripMs = Date.now() - t0
  // The session ended while the proof was being verified: the dialog was closed, or it expired.
  if (s.status !== 'responded') throw goneRefusal(endedReason(s) ?? 'cancelled')
  const m = result.metrics
  s.verification = { decode_ms: m?.decode_ms, verify_ms: m?.verify_ms, total_ms: m?.total_ms, round_trip_ms: roundTripMs }

  if (!result.ok) return reject(result.code ?? 'refused', result.reason, { input: result.input, metrics: result.metrics, round_trip_ms: roundTripMs })

  // Defence in depth on top of the verifier services.
  const formats = s.request.client_metadata.vp_formats_supported
  const offered = query.format === 'circuit_zk' ? formats.circuit_zk?.circuit_id_values : formats.mms_zk?.scheme_id_values
  if (offered && !offered.includes(result.proofId)) return reject('circuit', `${query.format === 'circuit_zk' ? 'circuit' : 'scheme'} not offered`)
  const proofSystem = query.format === 'circuit_zk' ? findCircuit(result.proofId)?.proof_system : findScheme(result.proofId)?.proof_system
  if (!proofSystem || !store().acceptedProofSystems.includes(proofSystem)) return reject('format', `${proofSystem ?? result.proofId} is no longer accepted`)
  const expected = query.req.map((r) => r.return).sort().join()
  if (Object.keys(result.results).sort().join() !== expected) return reject('results', 'results keys do not match req')
  const pseudonym = result.results[RETURN_PSEUDONYM]
  if (typeof pseudonym !== 'string' || !/^[0-9a-f]{64}$/.test(pseudonym)) return reject('results', 'bad pseudonym')
  const hasAge = query.req.some((r) => r.id === 'age_check')
  if (hasAge && result.results[RETURN_AGE] !== true) return reject('results', 'bad predicate')

  s.status = 'verified'
  s.outcome = { ok: true, format: query.format, proofId: result.proofId, pseudonym, ...(hasAge && { age: true as const }) }
  await recordMeasurement(s, query.format, result.proofId, result.metrics as Record<string, unknown> | undefined, hasAge)
  addTrace(s, 'verify', 'Proof verified', {
    format: query.format,
    [query.format === 'circuit_zk' ? 'circuit_id' : 'scheme_id']: result.proofId,
    results: result.results,
    metrics: result.metrics,
    round_trip_ms: roundTripMs,
  })
  return {}
})
