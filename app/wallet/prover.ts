import type { RequestObject } from '#shared/types/oid4vp'

export interface ProveOutput {
  circuit_id: string
  /** base64url(CBOR(CircuitZkPresentation)) */
  presentation: string
}

export type ProveError = 'invalid_pin' | 'unsatisfiable' | 'unavailable' | 'error'

/** Calls the prover service through the site's /api/wallet/prove. */
export async function proveWithService(o: { request: RequestObject; circuitId: string; pin: string }): Promise<ProveOutput> {
  try {
    return await $fetch<ProveOutput>('/api/wallet/prove', {
      method: 'POST',
      body: { request: o.request, circuit_id: o.circuitId, pin: o.pin },
    })
  } catch (e) {
    const err = e as { statusCode?: number; data?: { statusMessage?: string } }
    const code = err.data?.statusMessage
    throw new Error(code === 'invalid_pin' || code === 'unsatisfiable' ? code : err.statusCode === 503 ? 'unavailable' : 'error')
  }
}
