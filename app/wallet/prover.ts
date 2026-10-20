import type { RequestObject } from '#shared/types/oid4vp'
import { holders, mdocMaterial } from './holder'

// The phone's native steps, through the site's /api/wallet/* routes to the provers (the Vega,
// Longfellow and BBS addons). Each call carries the holder material that step needs; the prover keeps none of it.

export interface SignOutput {
  /** r ‖ s, hex */
  device_signature: string
  challenge_digest: string
  metrics: { sign_ms?: number }
}

export interface ProveOutput {
  system_id: string
  /** base64url(CBOR(ZkpPresentation)) */
  presentation: string
  results: Record<string, string | true>
  witness_ms?: number
  metrics: { witness_ms?: number; prove_ms?: number; total_ms?: number; proof_bytes?: number; presentation_bytes?: number }
}

export type ProveError = 'unsatisfiable' | 'unavailable' | 'error'

/** A refused or failed native step. The message is what the wallet acts on (ProveError); `cause`
 *  is the route's answer, for the guide: "/api/wallet/prove 500 backend_error". */
export class ProverError extends Error {
  constructor(
    message: ProveError,
    public override cause: string,
  ) {
    super(message)
  }
}

/** The route's refusal code (`data.error` in the error body), or the HTTP status class. */
function failure(route: string, e: unknown): ProverError {
  const err = e as { statusCode?: number; data?: { data?: { error?: string } } }
  const code = err.data?.data?.error
  const kind: ProveError = code === 'unsatisfiable' ? code : err.statusCode === 503 ? 'unavailable' : 'error'
  return new ProverError(kind, `${route} ${err.statusCode ?? 'no answer'}${code ? ` ${code}` : ''}`)
}

/** Step 1, once the PIN screen has unlocked the wallet (any PIN does): the device key signs
 *  DeviceAuthentication for this request. No PIN leaves the phone. */
export async function unlockAndSign(o: { request: RequestObject; credential: number; systemId: string }): Promise<SignOutput> {
  try {
    return await $fetch<SignOutput>('/api/wallet/sign', {
      method: 'POST',
      body: { request: o.request, system_id: o.systemId, device_key: mdocMaterial(o.credential).device_key },
    })
  } catch (e) {
    throw failure('/api/wallet/sign', e)
  }
}

/** Steps 2 and 3: the witness from the credential, then the proof. */
export async function prove(o: { request: RequestObject; queryId: string; systemId: string; deviceSignature: string; credential: number }): Promise<ProveOutput> {
  const m = mdocMaterial(o.credential)
  try {
    return await $fetch<ProveOutput>('/api/wallet/prove', {
      method: 'POST',
      body: {
        request: o.request,
        credential_query_id: o.queryId,
        system_id: o.systemId,
        credential: m.credential,
        secret_seed: m.secret_seed,
        device_signature: o.deviceSignature,
      },
    })
  } catch (e) {
    throw failure('/api/wallet/prove', e)
  }
}

export interface BbsProveOutput {
  system_id: string
  /** base64url(CBOR(ZkpPresentation)); its proof is the BBS-CD envelope */
  presentation: string
  results: Record<string, string | true>
  metrics: {
    offline_ms?: number
    bbs_ms?: number
    ecdsa_pop_ms?: number
    device_sign_ms?: number
    pseudonym_ms?: number
    date_range_ms?: number | null
    online_ms?: number
    prove_ms?: number
    total_ms?: number
    presentation_bytes?: number
    parts?: { bbs_proof: number; ecdsa_pop: number; pseudonym: number; date_range: number | null }
  }
}

/** bbs_cd, once the PIN screen has unlocked the wallet: one step. The device key signs inside the
 *  ecdsa-pop plugin; the phone sends the BBS credential and the device key, as for the mdoc. */
export async function proveBbs(o: { request: RequestObject; queryId: string; credential: number }): Promise<BbsProveOutput> {
  const m = holders[o.credential]!
  try {
    return await $fetch<BbsProveOutput>('/api/wallet/prove', {
      method: 'POST',
      body: { request: o.request, credential_query_id: o.queryId, credential: m.credential, device_key: m.device_key },
    })
  } catch (e) {
    throw failure('/api/wallet/prove', e)
  }
}
