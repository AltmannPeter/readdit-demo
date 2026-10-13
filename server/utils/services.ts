// The ONLY place that calls the proof backend: the Vega Node addon (native/vega, Rust, built with
// `npm run build:native`). There is no other backend. When the addon cannot load, the server
// refuses to start (server/plugins/vega.ts).
//
// Prover: the phone's native steps. The mocked wallet sends the credential material each step
// needs (credential, device key, secret_seed); the prover keeps none of it. The device key signs
// DeviceAuthentication (the wallet's PIN screen unlocks it on the phone, with any PIN; the prover
// takes none), then the prover builds the witness and proves.
// Verifier: verifies a presentation against the site's own request, handover and clock.
// Both sides build their keys from the circuits once, when the server starts (server/plugins/vega.ts).
// Contract: docs/backend-api.md

import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { RequestObject } from '#shared/types/oid4vp'
import { type FaultStep, takeFault } from './test-faults'

export interface ServiceCircuit {
  circuit_id: string
  proof_system: string
  shapes_sha256?: string | null
  public_inputs?: string[]
}

export interface ServiceInfo {
  service: string
  implementation: string
  version: string
  circuits: ServiceCircuit[]
  load_ms?: number
  threads?: number
  trust_anchors?: Array<{ subject: string; not_after: number }>
  proof_time_tolerance_s?: number
}

export interface Handover {
  client_id: string
  nonce: string
  response_uri: string
  jwk_thumbprint: string | null
}

/** The device key as the wallet holds it (P-256 JWK with its private part). */
export interface DeviceKeyJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  d: string
}

export interface WalletCredential {
  format: 'mso_mdoc'
  doctype: string
  /** base64url IssuerSigned */
  issuer_signed: string
}

export interface SignBody {
  device_key: DeviceKeyJwk
  doc_type: string
  handover: Handover
}

export interface SignResult {
  /** r ‖ s, hex */
  device_signature: string
  session_transcript: string
  challenge_digest: string
  metrics: { sign_ms?: number }
}

export interface ProveBody {
  circuit_id: string
  credential_query_id: string
  request: RequestObject
  handover: Handover
  credential: WalletCredential
  secret_seed: string
  device_signature: string
}

export interface WitnessSummary {
  proof_time: string
  results: Record<string, string | true>
  public_inputs: Array<{ name: string; values: string[] }>
  counts: { shared: number; precommitted: number; rest: number; public: number } | null
  metrics: { witness_ms?: number }
}

export interface ProveMetrics {
  /** One-time key build when the server started. */
  load_ms?: number
  witness_ms?: number
  prove_ms?: number
  /** witness + prove, per presentation */
  total_ms?: number
  peak_memory_mb?: number | null
  proof_bytes?: number
  presentation_bytes?: number
  threads?: number
}

export interface ProveResult {
  circuit_id: string
  presentation: string
  results: Record<string, string | true>
  metrics: ProveMetrics
  witness?: WitnessSummary
}

export interface VerifyMetrics {
  decode_ms?: number
  /** One-time key build when the server started. */
  load_ms?: number
  verify_ms?: number
  total_ms?: number
  proof_bytes?: number
  peak_memory_mb?: number | null
}

export type VerifyResult =
  | { ok: true; circuit_id: string; results: Record<string, string | true>; metrics: VerifyMetrics }
  | { ok: false; reason: string; code?: string; input?: string | null; metrics?: VerifyMetrics }

/** The HTTP status text for a prover refusal code (docs/backend-api.md, "Prover refusals"). The code
 *  itself travels in the error body as `data.error`. */
export function proverMessage(code: string): string {
  if (code === 'unsatisfiable') return 'The credential does not meet the request.'
  if (code.startsWith('unsupported_')) return 'The request cannot be proven with this circuit.'
  if (code === 'bad_credential' || code === 'bad_request') return 'The credential or the call is not valid.'
  if (code === 'unavailable') return 'The prover is not available.'
  if (code === 'backend_error') return 'The prover failed.'
  return 'The prover could not complete the request.'
}

/**
 * A refusal or a failure of the backend. `unavailable` (503): the addon is not loaded.
 * `backend_error` (500): an addon call failed (it threw, or its result was not JSON). Any other
 * code is a prover refusal the addon returned (docs/backend-api.md).
 */
export class ServiceError extends Error {
  constructor(
    public service: 'prover' | 'verifier',
    public status: number,
    public code: string,
    public detail?: string,
  ) {
    super(`${service}: ${code}${detail ? ` (${detail})` : ''}`)
  }
}

// ---- the addon ----

interface NativeWitness {
  readonly summary: string
}
interface NativeProver {
  readonly info: string
  sign(input: string): Promise<string>
  witness(input: string): Promise<NativeWitness | string>
  prove(witness: NativeWitness): Promise<string>
}
interface NativeVerifier {
  readonly info: string
  verify(input: string): Promise<string>
}
interface NativeAddon {
  loadProver(shapes: string): Promise<NativeProver>
  loadVerifier(shapes: string, trustAnchorsPem: string, toleranceS: number): Promise<NativeVerifier>
}
interface Native {
  prover: NativeProver
  verifier: NativeVerifier
}

const g = globalThis as unknown as { __readditVega?: Promise<Native> }

/**
 * Loads the addon and builds both sides' keys, once. A failure is not kept: the next call tries
 * again. The caller reports it (server/plugins/vega.ts at start, `native` below on a request).
 */
export function loadNative(): Promise<Native> {
  if (g.__readditVega) return g.__readditVega
  const loading = (async () => {
    const cfg = useRuntimeConfig()
    const path = (p: unknown) => resolve(process.cwd(), String(p))
    let addon: NativeAddon
    try {
      addon = createRequire(import.meta.url)(path(cfg.vegaAddon)) as NativeAddon
    } catch (e) {
      throw new Error(`The Vega addon ${path(cfg.vegaAddon)} could not be loaded. (${(e as Error).message})`)
    }
    const shapes = path(cfg.vegaShapes)
    const anchors = await readFile(path(cfg.vegaTrustAnchors), 'utf8')
    const [prover, verifier] = await Promise.all([
      addon.loadProver(shapes),
      addon.loadVerifier(shapes, anchors, Number(cfg.proofTimeToleranceS)),
    ])
    return { prover, verifier }
  })()
  g.__readditVega = loading
  loading.catch(() => {
    if (g.__readditVega === loading) g.__readditVega = undefined
  })
  return loading
}

async function native(service: 'prover' | 'verifier'): Promise<Native> {
  try {
    return await loadNative()
  } catch (e) {
    console.error(`[vega] ${service}: the addon is not loaded: ${(e as Error).message} Run npm run build:native.`)
    throw new ServiceError(service, 503, 'unavailable', (e as Error).message)
  }
}

/**
 * One call into the addon, with its result parsed. A call that throws (a panic in the addon, a
 * result that is not JSON) is a failure of the backend: 500 backend_error, logged with the reason.
 * `takeFault` fails the call the same way when a test armed it (test-faults.ts; never without
 * READDIT_TEST_FAULTS=1).
 */
async function call<T>(service: 'prover' | 'verifier', step: FaultStep, fn: () => Promise<T>): Promise<T> {
  try {
    if (takeFault(step)) throw new Error(`test fault: the ${step} call failed (READDIT_TEST_FAULTS)`)
    return await fn()
  } catch (e) {
    console.error(`[vega] ${step} failed: ${(e as Error).message}`)
    throw new ServiceError(service, 500, 'backend_error', (e as Error).message)
  }
}

/** A prover step's JSON: the result, or the refusal as a ServiceError. */
function outcome<T>(json: { ok: boolean; status?: number; error?: string; detail?: string }): T {
  if (!json.ok) throw new ServiceError('prover', json.status ?? 500, json.error ?? 'error', json.detail)
  return json as T
}

export const prover = {
  async info(): Promise<ServiceInfo> {
    const n = await native('prover')
    return call('prover', 'prover.info', async () => JSON.parse(n.prover.info) as ServiceInfo)
  },

  /** Step 1: the device key signs DeviceAuthentication. */
  async sign(body: SignBody): Promise<SignResult> {
    const n = await native('prover')
    return outcome<SignResult>(await call('prover', 'prover.sign', async () => JSON.parse(await n.prover.sign(JSON.stringify(body)))))
  },

  /** Steps 2 and 3 within this one call: the witness, then the proof. No witness outlives the call. */
  async prove(body: ProveBody): Promise<ProveResult> {
    const n = await native('prover')
    const done = await call('prover', 'prover.prove', async () => {
      const w = await n.prover.witness(JSON.stringify(body))
      if (typeof w === 'string') return { refusal: JSON.parse(w) }
      const witness = JSON.parse(w.summary) as WitnessSummary
      return { result: JSON.parse(await n.prover.prove(w)), witness }
    })
    if ('refusal' in done) return outcome<never>(done.refusal)
    return { ...outcome<ProveResult>(done.result), witness: done.witness }
  },
}

export const verifier = {
  async info(): Promise<ServiceInfo> {
    const n = await native('verifier')
    return call('verifier', 'verifier.info', async () => JSON.parse(n.verifier.info) as ServiceInfo)
  },

  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; now: string }): Promise<VerifyResult> {
    const n = await native('verifier')
    return call('verifier', 'verifier.verify', async () => JSON.parse(await n.verifier.verify(JSON.stringify(body))) as VerifyResult)
  },
}

/** Backend info for the tech view; never throws, and never takes a test fault. */
export async function servicesStatus() {
  let n: Native | undefined
  let error = ''
  try {
    n = await loadNative()
  } catch (e) {
    error = (e as Error).message
  }
  const read = (side: NativeProver | NativeVerifier | undefined) => {
    if (!side) return { up: false as const, error }
    try {
      return { up: true as const, ...(JSON.parse(side.info) as ServiceInfo) }
    } catch (e) {
      return { up: false as const, error: (e as Error).message }
    }
  }
  return { prover: read(n?.prover), verifier: read(n?.verifier) }
}
