import type { RequestObject } from '#shared/types/oid4vp'
import { holders } from './holder'

// The phone's native steps, through the site's /api/wallet/* routes to the prover (the Vega
// addon). Each call carries the holder material that step needs; the prover keeps none of it.

export interface SignOutput {
  /** r ‖ s, hex */
  device_signature: string
  challenge_digest: string
  metrics: { sign_ms?: number }
}

export interface ProveOutput {
  circuit_id: string
  /** base64url(CBOR(CircuitZkPresentation)) */
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
export async function unlockAndSign(o: { request: RequestObject; credential: number }): Promise<SignOutput> {
  try {
    return await $fetch<SignOutput>('/api/wallet/sign', {
      method: 'POST',
      body: { request: o.request, device_key: holders[o.credential]!.device_key },
    })
  } catch (e) {
    throw failure('/api/wallet/sign', e)
  }
}

/** Steps 2 and 3: the witness from the credential, then the proof. */
export async function prove(o: { request: RequestObject; circuitId: string; deviceSignature: string; credential: number }): Promise<ProveOutput> {
  try {
    return await $fetch<ProveOutput>('/api/wallet/prove', {
      method: 'POST',
      body: {
        request: o.request,
        circuit_id: o.circuitId,
        credential: holders[o.credential]!.credential,
        secret_seed: holders[o.credential]!.secret_seed,
        device_signature: o.deviceSignature,
      },
    })
  } catch (e) {
    throw failure('/api/wallet/prove', e)
  }
}
