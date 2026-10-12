import type { VpToken } from '#shared/types/oid4vp'
import { RETURN_AGE, RETURN_PSEUDONYM } from '#shared/utils/dcql'

/**
 * response_uri (direct_post). Form fields: vp_token (JSON) + state, or error + state.
 * Verification runs here, with the request and session values from the site's own store.
 */
export default defineEventHandler(async (event) => {
  const s = getVpSession(getRouterParam(event, 'id')!)
  const raw = (await readRawBody(event, 'utf8')) ?? ''
  const form = Object.fromEntries(new URLSearchParams(raw))

  if (s.status !== 'scanned' || !s.request) throw createError({ statusCode: 400, statusMessage: 'unexpected response' })
  if (form.state !== s.state) throw createError({ statusCode: 400, statusMessage: 'state mismatch' })
  s.status = 'responded'

  const fail = (reason: 'denied' | 'invalid_request' | 'invalid' | 'unavailable', detail?: string) => {
    s.status = 'failed'
    s.outcome = { ok: false, reason, ...(detail && { detail }) }
    addTrace(s, 'failed', 'Not completed', { reason, ...(detail && { detail }) })
    return {}
  }

  if (form.error) {
    addTrace(s, 'response', 'Error response received', { error: form.error, bytes: raw.length })
    return fail(form.error === 'access_denied' ? 'denied' : 'invalid_request')
  }

  let vpToken: VpToken
  try {
    vpToken = JSON.parse(form.vp_token ?? '')
  } catch {
    return fail('invalid', 'vp_token is not JSON')
  }
  const list = vpToken[s.query.id]
  addTrace(s, 'response', 'Presentation received', {
    bytes: raw.length,
    presentations: Array.isArray(list) ? list.map((p) => p.length) : 0,
  })
  if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== 'string') return fail('invalid', 'expected one presentation')

  const t0 = Date.now()
  let result
  try {
    result = await verifier.verify({
      request: s.request,
      credential_query_id: s.query.id,
      presentation: list[0],
      handover: handoverFor(s),
      now: new Date().toISOString(),
    })
  } catch {
    return fail('unavailable', 'verifier service')
  }
  const roundTripMs = Date.now() - t0

  if (!result.ok) {
    addTrace(s, 'verify', 'Proof rejected', { reason: result.reason, metrics: result.metrics, round_trip_ms: roundTripMs })
    return fail('invalid', result.reason)
  }

  // Defence in depth on top of the verifier service.
  const offered = s.request.client_metadata.vp_formats_supported.circuit_zk.circuit_id_values
  if (offered && !offered.includes(result.circuit_id)) return fail('invalid', 'circuit not offered')
  const expected = s.query.req.map((r) => r.return).sort().join()
  if (Object.keys(result.results).sort().join() !== expected) return fail('invalid', 'results keys do not match req')
  const pseudonym = result.results[RETURN_PSEUDONYM]
  if (typeof pseudonym !== 'string' || !/^[0-9a-f]{64}$/.test(pseudonym)) return fail('invalid', 'bad pseudonym')
  const hasAge = s.query.req.some((r) => r.id === 'age_check')
  if (hasAge && result.results[RETURN_AGE] !== true) return fail('invalid', 'bad predicate')

  s.status = 'verified'
  s.outcome = { ok: true, circuitId: result.circuit_id, pseudonym, ...(hasAge && { age: true as const }) }
  addTrace(s, 'verify', 'Proof verified', {
    circuit_id: result.circuit_id,
    results: result.results,
    metrics: result.metrics,
    round_trip_ms: roundTripMs,
  })
  return {}
})
