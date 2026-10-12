// The ONLY place that talks to the backend services (or, in offline mode, to the built-in
// simulation in offline-backend.ts).
// Prover: holds the demo holder's credential, device key and seed; checks the PIN; builds the presentation.
// Verifier: verifies a presentation against the site's own request and session values.
// Contract: docs/backend-api.md

import type { RequestObject } from '#shared/types/oid4vp'
import { OfflineError, offlineProver, offlineVerifier } from './offline-backend'

export interface ServiceInfo {
  service: string
  implementation: string
  version: string
  stub?: boolean
  circuits: Array<{ circuit_id: string; proof_system: string }>
}

export interface Handover {
  client_id: string
  nonce: string
  response_uri: string
  jwk_thumbprint: string | null
}

export interface ProveMetrics {
  simulated?: boolean
  load_ms?: number
  witness_ms?: number
  prove_ms?: number
  total_ms?: number
  peak_memory_mb?: number
  proof_bytes?: number
  presentation_bytes?: number
}

export interface ProveResult {
  circuit_id: string
  presentation: string
  results: Record<string, string | true>
  metrics: ProveMetrics
}

export interface VerifyMetrics {
  simulated?: boolean
  decode_ms?: number
  load_ms?: number
  verify_ms?: number
  total_ms?: number
  proof_bytes?: number
}

export type VerifyResult =
  | { ok: true; circuit_id: string; results: Record<string, string | true>; metrics: VerifyMetrics }
  | { ok: false; reason: string; metrics?: VerifyMetrics }

export class ServiceError extends Error {
  constructor(
    public service: 'prover' | 'verifier',
    public status: number,
    public code: string,
  ) {
    super(`${service}: ${code}`)
  }
}

async function call<T>(service: 'prover' | 'verifier', base: string, path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${base}${path}`, {
      method: init?.method ?? 'GET',
      headers: init?.body ? { 'content-type': 'application/json' } : undefined,
      body: init?.body ? JSON.stringify(init.body) : undefined,
      signal: AbortSignal.timeout(60_000),
    })
  } catch {
    throw new ServiceError(service, 503, 'unavailable')
  }
  const text = await res.text()
  let json: Record<string, unknown> = {}
  try {
    json = text ? JSON.parse(text) : {}
  } catch {
    throw new ServiceError(service, 502, 'bad_response')
  }
  if (!res.ok) throw new ServiceError(service, res.status, String(json.error ?? 'error'))
  return json as T
}

const urls = () => {
  const cfg = useRuntimeConfig()
  return { prover: String(cfg.proverUrl).replace(/\/$/, ''), verifier: String(cfg.verifierUrl).replace(/\/$/, '') }
}

const offline = () => backendMode().mode === 'offline'

async function offlineCall<T>(service: 'prover' | 'verifier', fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    if (e instanceof OfflineError) throw new ServiceError(service, e.status, e.code)
    throw e
  }
}

export const prover = {
  info: () => (offline() ? offlineProver.info() : call<ServiceInfo>('prover', urls().prover, '/info')),
  credential: (holder: string) =>
    offline()
      ? offlineProver.credential()
      : call<Record<string, unknown>>('prover', urls().prover, `/holders/${encodeURIComponent(holder)}/credentials/nym_auth`),
  prove: (body: {
    holder: string
    pin: string
    circuit_id: string
    credential_query_id: string
    request: RequestObject
    handover: Handover
  }) =>
    offline()
      ? offlineCall('prover', () => offlineProver.prove(body))
      : call<ProveResult>('prover', urls().prover, '/prove', { method: 'POST', body }),
}

export const verifier = {
  info: () => (offline() ? offlineVerifier.info() : call<ServiceInfo>('verifier', urls().verifier, '/info')),
  verify: (body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; now: string }) =>
    offline()
      ? offlineCall('verifier', () => offlineVerifier.verify(body))
      : call<VerifyResult>('verifier', urls().verifier, '/verify', { method: 'POST', body }),
}

/** Service info for the tech view; never throws. */
export async function servicesStatus() {
  const [p, v] = await Promise.allSettled([prover.info(), verifier.info()])
  return {
    mode: backendMode().mode,
    phoneFactor: backendMode().phoneFactor,
    prover: p.status === 'fulfilled' ? { up: true, ...p.value } : { up: false },
    verifier: v.status === 'fulfilled' ? { up: true, ...v.value } : { up: false },
  }
}
