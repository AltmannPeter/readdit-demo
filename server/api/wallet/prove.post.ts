import type { RequestObject } from '#shared/types/oid4vp'

/**
 * Mock phone, the proof.
 * mso_mdoc (Vega or Longfellow, by `system_id`), native steps 2 and 3: the witness from the credential, then the proof. The
 * phone sends its credential, its secret_seed and the device signature of step 1; the prover keeps
 * none of them, and the witness lives only for this call.
 * bbs_cd (BBS): one step. The phone sends its BBS credential and its device key, which signs inside
 * the ecdsa-pop plugin; the prover keeps neither.
 * `credential_query_id` names the query the wallet answers (DCQL credential_sets: one of them).
 * `rulebook`: the rulebook version the wallet reads the request under ("0.4" when absent; the demo
 * wallet picks it from the request, shared/protocol/request.ts).
 */
export default defineEventHandler(async (event) => {
  const { request, system_id, credential, secret_seed, device_signature, device_key, credential_query_id, rulebook } = await readObject<{
    request: RequestObject
    system_id: unknown
    credential: WalletCredential | BbsCredential
    secret_seed: unknown
    device_signature: unknown
    device_key: DeviceKeyJwk
    credential_query_id: unknown
    rulebook: unknown
  }>(event)
  if (rulebook !== undefined && (typeof rulebook !== 'string' || !/^\d+\.\d+$/.test(rulebook))) throw refusal(400, 'bad_request', proverMessage('bad_request'))
  const version = typeof rulebook === 'string' ? rulebook : undefined
  const queries = Array.isArray(request?.dcql_query?.credentials) ? request.dcql_query.credentials : []
  const query = typeof credential_query_id === 'string' ? queries.find((q) => q.id === credential_query_id) : queries[0]
  if (credential?.format === 'bbs_cd') return proveBbs(request as RequestObject, query?.id, credential as BbsCredential, device_key as DeviceKeyJwk, version)
  if (
    typeof query?.id !== 'string' ||
    typeof request?.client_id !== 'string' ||
    typeof request.nonce !== 'string' ||
    typeof request.response_uri !== 'string' ||
    typeof system_id !== 'string' ||
    typeof credential !== 'object' ||
    !credential ||
    typeof secret_seed !== 'string' ||
    typeof device_signature !== 'string'
  ) {
    throw refusal(400, 'bad_request', proverMessage('bad_request'))
  }

  // Session for the tech trace, if this request came from Community.
  const sid = typeof request.state === 'string' ? store().byState.get(request.state) : undefined
  const s = sid ? store().sessions.get(sid) : undefined

  const t0 = Date.now()
  try {
    const result = await prover.prove({
      system_id,
      credential_query_id: query.id,
      request,
      handover: await handoverOf(request),
      credential: credential as WalletCredential,
      secret_seed,
      device_signature,
      ...(version && { rulebook: version }),
    })
    keepProfile(s, 'witness', result.profiles.witness)
    keepProfile(s, 'prove', result.profiles.prove)
    keepParts(s, result.presentation, result.proof_parts)
    if (s) {
      if (result.witness) addTrace(s, 'witness', 'Witness built', { ...result.witness })
      addTrace(s, 'prove', 'Proof created', {
        format: 'mso_mdoc',
        system_id: result.system_id,
        backend: result.backend,
        metrics: result.metrics,
        presentation_bytes: result.presentation.length,
        round_trip_ms: Date.now() - t0,
      })
    }
    const { witness, backend: _backend, profiles: _profiles, proof_parts: _parts, ...out } = result
    return { ...out, witness_ms: witness?.metrics.witness_ms }
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'prove', 'Proof not created', { error: code, ...(e instanceof ServiceError && e.detail && { detail: e.detail }) })
    throw refusal(e instanceof ServiceError ? e.status : 500, code, proverMessage(code))
  }
})

/** bbs_cd: one call to the BBS prover. */
async function proveBbs(request: RequestObject, queryId: string | undefined, credential: BbsCredential, deviceKey: DeviceKeyJwk, rulebook?: string) {
  if (
    typeof queryId !== 'string' ||
    typeof request?.client_id !== 'string' ||
    typeof request.nonce !== 'string' ||
    typeof request.response_uri !== 'string' ||
    typeof deviceKey !== 'object' ||
    !deviceKey
  ) {
    throw refusal(400, 'bad_request', proverMessage('bad_request'))
  }
  const sid = typeof request.state === 'string' ? store().byState.get(request.state) : undefined
  const s = sid ? store().sessions.get(sid) : undefined
  const t0 = Date.now()
  try {
    const { profile, proof_parts, ...result } = await bbsProver.prove({
      request,
      credential_query_id: queryId,
      handover: await handoverOf(request),
      credential,
      device_key: deviceKey,
      ...(rulebook && { rulebook }),
    })
    keepProfile(s, 'prove', profile)
    keepParts(s, result.presentation, proof_parts)
    if (s) {
      addTrace(s, 'prove', 'Presentation created', {
        format: 'bbs_cd',
        system_id: result.system_id,
        statement: result.statement,
        metrics: result.metrics,
        presentation_bytes: result.presentation.length,
        round_trip_ms: Date.now() - t0,
      })
    }
    return result
  } catch (e) {
    const code = e instanceof ServiceError ? e.code : 'error'
    if (s) addTrace(s, 'prove', 'Presentation not created', { format: 'bbs_cd', error: code, ...(e instanceof ServiceError && e.detail && { detail: e.detail }) })
    throw refusal(e instanceof ServiceError ? e.status : 500, code, proverMessage(code))
  }
}
