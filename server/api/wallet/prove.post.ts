import type { RequestObject } from '#shared/types/oid4vp'

/**
 * Mock phone, native steps 2 and 3: the witness from the credential, then the proof. The phone
 * sends its credential, its secret_seed and the device signature of step 1; the prover keeps none
 * of them, and the witness lives only for this call.
 */
export default defineEventHandler(async (event) => {
  const { request, circuit_id, credential, secret_seed, device_signature } = await readBody<{
    request: RequestObject
    circuit_id: string
    credential: WalletCredential
    secret_seed: string
    device_signature: string
  }>(event)
  if (!request?.dcql_query?.credentials?.[0] || !circuit_id || !credential || !secret_seed || !device_signature) {
    throw createError({ statusCode: 400 })
  }

  // Session for the tech trace, if this request came from Readdit.
  const sid = store().byState.get(request.state)
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const result = await prover.prove({
      circuit_id,
      credential_query_id: request.dcql_query.credentials[0].id,
      request,
      handover: { client_id: request.client_id, nonce: request.nonce, response_uri: request.response_uri, jwk_thumbprint: null },
      credential,
      secret_seed,
      device_signature,
    })
    if (s) {
      if (result.witness) addTrace(s, 'witness', 'Witness built', { ...result.witness })
      addTrace(s, 'prove', 'Proof created', {
        circuit_id: result.circuit_id,
        metrics: result.metrics,
        presentation_bytes: result.presentation.length,
        round_trip_ms: Date.now() - t0,
      })
    }
    const { witness, ...out } = result
    return { ...out, witness_ms: witness?.metrics.witness_ms }
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'prove', 'Proof not created', { error: code, ...(e instanceof ServiceError && e.detail && { detail: e.detail }) })
    throw createError({ statusCode: e instanceof ServiceError ? e.status : 500, statusMessage: proverMessage(code), data: { error: code } })
  }
})
