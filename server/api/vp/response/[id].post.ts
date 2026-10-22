import { compactDecrypt, decodeProtectedHeader } from 'jose'
import { RETURN_AGE, RETURN_PSEUDONYM } from '#shared/utils/dcql'
import { PROOF_SYSTEMS, findSystem } from '#shared/registry/circuits'
import type { FailReason } from '../../../utils/store'

/**
 * response_uri (direct_post.jwt). Form field `response`: a JWE (ECDH-ES, A128GCM) to the session's
 * key, whose payload holds the response parameters: vp_token (a JSON object) and state, or error
 * and state. An unencrypted error response (error + state as form fields) is accepted too, as
 * OpenID4VP allows a wallet that cannot encrypt; an unencrypted vp_token is refused.
 * Verification runs here, with the request and session values from the site's own store.
 *
 * Refused before anything is processed: 404 unknown_session, 400 invalid_response (not a JWE to
 * this session's key, or a payload that is not a JSON object), 400 state_mismatch (checked first
 * after decryption, so a caller without the request's state learns nothing about the session),
 * 400 unencrypted, 410 expired or cancelled, 400 not_requested (the request was never fetched)
 * and 400 already_answered (a second response: a replay). None of these changes the session. A
 * response that was processed answers 200, whether the presentation was accepted or refused; the
 * refusal's rule goes to the server log and the session trace (/tech), not to the caller.
 * 503 unavailable when the verifier failed and nothing could be decided.
 */
export default defineEventHandler(async (event) => {
  const s = getVpSession(getRouterParam(event, 'id')!)
  const raw = (await readRawBody(event, 'utf8')) ?? ''
  const posted = Object.fromEntries(new URLSearchParams(raw))

  let form: Record<string, unknown>
  let jwe: { header: Record<string, unknown>; bytes: number; decrypt_ms: number } | undefined
  if (typeof posted.response === 'string') {
    const t0 = performance.now()
    try {
      const header = decodeProtectedHeader(posted.response)
      if (header.alg !== RESPONSE_ALG || header.enc !== RESPONSE_ENC) throw new Error(`alg ${String(header.alg)}, enc ${String(header.enc)}`)
      if (header.kid !== undefined && header.kid !== s.responseKey.jwk.kid) throw new Error('kid is not the session key')
      const { plaintext } = await compactDecrypt(posted.response, s.responseKey.privateKey, { keyManagementAlgorithms: [RESPONSE_ALG], contentEncryptionAlgorithms: [RESPONSE_ENC] })
      const payload = JSON.parse(new TextDecoder().decode(plaintext)) as unknown
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('the payload is not a JSON object')
      form = payload as Record<string, unknown>
      jwe = { header: header as Record<string, unknown>, bytes: posted.response.length, decrypt_ms: Math.round((performance.now() - t0) * 100) / 100 }
    } catch (e) {
      console.warn(`[vp] ${s.id}: refused a response that does not decrypt: ${(e as Error).message}`)
      throw refusal(400, 'invalid_response', 'response is not a JWE to this session\'s key.')
    }
  } else {
    form = posted
  }

  if (form.state !== s.state) throw refusal(400, 'state_mismatch', 'state does not match this session.')
  if (!jwe && form.error === undefined) {
    console.warn(`[vp] ${s.id}: refused an unencrypted response`)
    addTrace(s, 'refused', 'Unencrypted response refused', { code: 'unencrypted', bytes: raw.length })
    throw refusal(400, 'unencrypted', 'The response must be encrypted (direct_post.jwt).')
  }
  const ended = endedReason(s)
  if (ended) throw goneRefusal(ended)
  if (s.status === 'waiting' || !s.request) throw refusal(400, 'not_requested', 'This session is not waiting for a response.')
  if (s.status !== 'scanned') {
    console.warn(`[vp] ${s.id}: refused a second response (already_answered)`)
    addTrace(s, 'refused', 'Second response refused', { code: 'already_answered', bytes: raw.length })
    throw refusal(400, 'already_answered', 'This session has already received a response.')
  }
  s.status = 'responded'
  if (jwe) {
    s.response = { jwe: { header: jwe.header, bytes: jwe.bytes } }
    addTrace(s, 'decrypt', 'Response decrypted', { header: jwe.header, bytes: jwe.bytes, decrypt_ms: jwe.decrypt_ms })
  }

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

  if (form.error !== undefined) {
    const error = String(form.error)
    addTrace(s, 'response', 'Error response received', { error, encrypted: !!jwe, bytes: raw.length })
    return fail(error === 'access_denied' ? 'denied' : 'invalid_request', error)
  }

  const vpToken = form.vp_token
  // Exactly one of the request's credential queries is answered (credential_sets: one option).
  const token = vpToken && typeof vpToken === 'object' && !Array.isArray(vpToken) ? (vpToken as Record<string, unknown>) : {}
  const answeredIds = Object.keys(token)
  const query = answeredIds.length === 1 ? s.dcql.credentials.find((q) => q.id === answeredIds[0]) : undefined
  const list = query ? token[query.id] : undefined
  if (query && Array.isArray(list) && typeof list[0] === 'string') s.response!.presentation = list[0]
  addTrace(s, 'response', 'Presentation received', {
    bytes: raw.length,
    encrypted: true,
    ...(query && { query: query.id, format: query.meta.source_format }),
    presentations: Array.isArray(list) ? list.map((p) => (typeof p === 'string' ? p.length : 0)) : 0,
  })
  if (!query) return reject('vp_token', `expected a presentation for exactly one of ${s.dcql.credentials.map((q) => q.id).join(', ')}`)
  if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== 'string') return reject('vp_token', `expected one presentation for ${query.id}`)
  s.answered = query.id
  // The site accepts the source format at the moment of the response too (/tech's switches); the
  // system's proof system is checked once the presentation names it, below.
  const source = query.meta.source_format
  const systems = PROOF_SYSTEMS.filter((p) => p.source_format === source)
  if (!systems.some((p) => store().acceptedProofSystems.includes(p.id))) {
    return reject('format', `${source} (${systems.map((p) => p.id).join(', ') || 'unknown'}) is no longer accepted`)
  }

  const t0 = Date.now()
  let result: { ok: true; proofId: string; results: Record<string, string | true>; metrics?: VerifyMetrics } | { ok: false; code?: string; reason: string; input?: string | null; metrics?: VerifyMetrics }
  try {
    const call = { request: s.request, credential_query_id: query.id, presentation: list[0], handover: handoverFor(s) }
    if (source === 'mso_mdoc') {
      const r = await verifier.verify({ ...call, now: new Date().toISOString() })
      result = r.ok ? { ok: true, proofId: r.system_id, results: r.results, metrics: r.metrics } : r
    } else {
      const r = await bbsVerifier.verify(call)
      result = r.ok ? { ok: true, proofId: r.system_id, results: r.results, metrics: r.metrics } : r
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
  const offered = s.request.client_metadata.vp_formats_supported.zkp_req?.system_id_values
  const system = findSystem(result.proofId)
  if (!system || system.source_format !== source) return reject('circuit', `${result.proofId} is not a ${source} system`)
  if (offered && !offered.includes(result.proofId)) return reject('circuit', `${result.proofId} not offered`)
  if (!store().acceptedProofSystems.includes(system.proof_system)) return reject('format', `${system.proof_system} is no longer accepted`)
  const expected = query._req.map((r) => r.return).sort().join()
  if (Object.keys(result.results).sort().join() !== expected) return reject('results', 'results keys do not match _req')
  // 32 bytes (sha-256) or a 48-byte G1 point (hashdh-bls12381g1).
  const pseudonym = result.results[RETURN_PSEUDONYM]
  const nymHex = source === 'mso_mdoc' ? /^[0-9a-f]{64}$/ : /^[0-9a-f]{96}$/
  if (typeof pseudonym !== 'string' || !nymHex.test(pseudonym)) return reject('results', 'bad pseudonym')
  const hasAge = query._req.some((r) => r.fn_id === 'age_check')
  if (hasAge && result.results[RETURN_AGE] !== true) return reject('results', 'bad predicate')

  s.status = 'verified'
  s.outcome = { ok: true, format: source, proofId: result.proofId, pseudonym, ...(hasAge && { age: true as const }) }
  await recordMeasurement(s, source, result.proofId, result.metrics as Record<string, unknown> | undefined, hasAge)
  addTrace(s, 'verify', 'Proof verified', {
    format: source,
    system_id: result.proofId,
    results: result.results,
    metrics: result.metrics,
    round_trip_ms: roundTripMs,
  })
  return {}
})
