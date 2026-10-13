import type { RequestObject } from '#shared/types/oid4vp'

/**
 * Mock phone, native steps 2 and 3: the witness from the credential, then the proof. The phone
 * sends its credential, its secret_seed and the device signature of step 1; the prover keeps none
 * of them, and the witness lives only for this call.
 */
export default defineEventHandler(async (event) => {
  const { request, circuit_id, credential, secret_seed, device_signature } = await readObject<{
    request: RequestObject
    circuit_id: unknown
    credential: WalletCredential
    secret_seed: unknown
    device_signature: unknown
  }>(event)
  const query = Array.isArray(request?.dcql_query?.credentials) ? request.dcql_query.credentials[0] : undefined
  if (
    typeof query?.id !== 'string' ||
    typeof request?.client_id !== 'string' ||
    typeof request.nonce !== 'string' ||
    typeof request.response_uri !== 'string' ||
    typeof circuit_id !== 'string' ||
    typeof credential !== 'object' ||
    !credential ||
    typeof secret_seed !== 'string' ||
    typeof device_signature !== 'string'
  ) {
    throw refusal(400, 'bad_request', proverMessage('bad_request'))
  }

  // Session for the tech trace, if this request came from Readdit.
  const sid = typeof request.state === 'string' ? store().byState.get(request.state) : undefined
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const result = await prover.prove({
      circuit_id,
      credential_query_id: query.id,
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
    throw refusal(e instanceof ServiceError ? e.status : 500, code, proverMessage(code))
  }
})
