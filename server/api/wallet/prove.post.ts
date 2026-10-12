import type { RequestObject } from '#shared/types/oid4vp'

/**
 * Mock phone: build the presentation. The prover service stands in for the
 * phone's secure parts: it holds the credential, the device key and the seed,
 * and it checks the PIN before the device key signs.
 */
export default defineEventHandler(async (event) => {
  const { request, circuit_id, pin } = await readBody<{ request: RequestObject; circuit_id: string; pin: string }>(event)
  if (!request?.dcql_query?.credentials?.[0] || !circuit_id || !pin) throw createError({ statusCode: 400 })

  // Session for the tech trace, if this request came from Readdit.
  const sid = store().byState.get(request.state)
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const result = await prover.prove({
      holder: String(useRuntimeConfig().demoHolder),
      pin,
      circuit_id,
      credential_query_id: request.dcql_query.credentials[0].id,
      request,
      handover: { client_id: request.client_id, nonce: request.nonce, response_uri: request.response_uri, jwk_thumbprint: null },
    })
    if (s) {
      addTrace(s, 'prove', 'Proof created', {
        circuit_id: result.circuit_id,
        metrics: result.metrics,
        presentation_bytes: result.presentation.length,
        round_trip_ms: Date.now() - t0,
      })
    }
    return result
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'prove', 'Proof not created', { error: code })
    throw createError({ statusCode: e instanceof ServiceError ? e.status : 500, statusMessage: code, data: { error: code } })
  }
})
