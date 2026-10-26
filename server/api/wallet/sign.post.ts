import type { RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'

/**
 * Mock phone, native step 1: the device key signs DeviceAuthentication over the SessionTranscript
 * of this request. The phone unlocked the key with its PIN screen, where any PIN does; no PIN
 * reaches the server. The phone sends its device key with the call; the prover keeps nothing.
 * `system_id`, the circuit the wallet chose, picks the addon (Vega or Longfellow); the message
 * is the same for both.
 */
export default defineEventHandler(async (event) => {
  const { request, device_key, system_id } = await readObject<{ request: RequestObject; device_key: DeviceKeyJwk; system_id?: unknown }>(event)
  if (
    typeof request?.client_id !== 'string' ||
    typeof request.nonce !== 'string' ||
    typeof request.response_uri !== 'string' ||
    typeof device_key !== 'object' ||
    !device_key
  ) {
    throw refusal(400, 'bad_request', proverMessage('bad_request'))
  }

  // Session for the tech trace, if this request came from Community.
  const sid = typeof request.state === 'string' ? store().byState.get(request.state) : undefined
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const { profile, ...result } = await prover.sign(
      {
        device_key,
        doc_type: NYM_DOCTYPE,
        handover: await handoverOf(request),
      },
      typeof system_id === 'string' ? system_id : undefined,
    )
    keepProfile(s, 'sign', profile)
    if (s) {
      addTrace(s, 'sign', 'Device key signed', {
        metrics: result.metrics,
        challenge_digest: result.challenge_digest,
        session_transcript: result.session_transcript,
        round_trip_ms: Date.now() - t0,
      })
    }
    return result
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'sign', 'Device key did not sign', { error: code, ...(e instanceof ServiceError && e.detail && { detail: e.detail }) })
    throw refusal(e instanceof ServiceError ? e.status : 500, code, proverMessage(code))
  }
})
