import type { RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'

/**
 * Mock phone, native step 1: the PIN unlocks the device key, which signs DeviceAuthentication
 * over the SessionTranscript of this request. The phone sends its device key with the call; the
 * prover keeps nothing.
 */
export default defineEventHandler(async (event) => {
  const { request, pin, device_key } = await readBody<{ request: RequestObject; pin: string; device_key: DeviceKeyJwk }>(event)
  if (!request?.client_id || !pin || !device_key) throw createError({ statusCode: 400 })

  // Session for the tech trace, if this request came from Readdit.
  const sid = store().byState.get(request.state)
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const result = await prover.sign({
      pin,
      device_key,
      doc_type: NYM_DOCTYPE,
      handover: { client_id: request.client_id, nonce: request.nonce, response_uri: request.response_uri, jwk_thumbprint: null },
    })
    if (s) {
      addTrace(s, 'sign', 'PIN checked, device key signed', {
        metrics: result.metrics,
        challenge_digest: result.challenge_digest,
        session_transcript: result.session_transcript,
        round_trip_ms: Date.now() - t0,
      })
    }
    return result
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'sign', code === 'invalid_pin' ? 'Wrong PIN, device key locked' : 'Device key did not sign', { error: code })
    throw createError({ statusCode: e instanceof ServiceError ? e.status : 500, statusMessage: code, data: { error: code } })
  }
})
