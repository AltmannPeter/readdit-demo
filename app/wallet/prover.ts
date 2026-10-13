import type { RequestObject } from '#shared/types/oid4vp'
import { holder } from './holder'

// The phone's native steps, through the site's /api/wallet/* routes to the prover (the Vega
// addon). Each call carries the holder material that step needs; the prover keeps none of it.

export interface SignOutput {
  /** r ‖ s, hex */
  device_signature: string
  challenge_digest: string
  metrics: { sign_ms?: number; simulated?: boolean }
}

export interface ProveOutput {
  circuit_id: string
  /** base64url(CBOR(CircuitZkPresentation)) */
  presentation: string
  results: Record<string, string | true>
  witness_ms?: number
  metrics: { witness_ms?: number; prove_ms?: number; total_ms?: number; proof_bytes?: number; presentation_bytes?: number; simulated?: boolean }
}

export type ProveError = 'invalid_pin' | 'unsatisfiable' | 'unavailable' | 'error'

function failure(e: unknown): Error {
  const err = e as { statusCode?: number; data?: { statusMessage?: string } }
  const code = err.data?.statusMessage
  return new Error(code === 'invalid_pin' || code === 'unsatisfiable' ? code : err.statusCode === 503 ? 'unavailable' : 'error')
}

/** Step 1: the PIN unlocks the device key, which signs DeviceAuthentication for this request. */
export async function unlockAndSign(o: { request: RequestObject; pin: string }): Promise<SignOutput> {
  try {
    return await $fetch<SignOutput>('/api/wallet/sign', {
      method: 'POST',
      body: { request: o.request, pin: o.pin, device_key: holder.device_key },
    })
  } catch (e) {
    throw failure(e)
  }
}

/** Steps 2 and 3: the witness from the credential, then the proof. */
export async function prove(o: { request: RequestObject; circuitId: string; deviceSignature: string }): Promise<ProveOutput> {
  try {
    return await $fetch<ProveOutput>('/api/wallet/prove', {
      method: 'POST',
      body: {
        request: o.request,
        circuit_id: o.circuitId,
        credential: holder.credential,
        secret_seed: holder.secret_seed,
        device_signature: o.deviceSignature,
      },
    })
  } catch (e) {
    throw failure(e)
  }
}
