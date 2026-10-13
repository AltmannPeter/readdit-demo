// The ONLY place that calls the proof backend: the Vega Node addon (native/vega, Rust, built with
// `npm run build:native`), or in offline mode the built-in simulation in offline-backend.ts.
//
// Prover: the phone's native steps. The mocked wallet sends the credential material each step
// needs (credential, device key, secret_seed); the prover keeps none of it. It checks the PIN
// before the device key signs DeviceAuthentication, builds the witness and proves.
// Verifier: verifies a presentation against the site's own request, handover and clock.
// Both sides build their keys from the circuits once, when the server starts (server/plugins/vega.ts).
// Contract: docs/backend-api.md

import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { RequestObject } from '#shared/types/oid4vp'
import { OfflineError, offlineProver, offlineVerifier } from './offline-backend'

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
  stub?: boolean
  offline?: boolean
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
  pin: string
  device_key: DeviceKeyJwk
  doc_type: string
  handover: Handover
}

export interface SignResult {
  /** r ‖ s, hex */
  device_signature: string
  session_transcript: string
  challenge_digest: string
  metrics: { sign_ms?: number; simulated?: boolean }
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
  metrics: { witness_ms?: number; simulated?: boolean }
}

export interface ProveMetrics {
  simulated?: boolean
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
  simulated?: boolean
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
  loadProver(shapes: string, pin: string): Promise<NativeProver>
  loadVerifier(shapes: string, trustAnchorsPem: string, toleranceS: number): Promise<NativeVerifier>
}
interface Native {
  prover: NativeProver
  verifier: NativeVerifier
}

const g = globalThis as unknown as { __readditVega?: Promise<Native> }

/** Loads the addon and builds both sides' keys, once. A failure is logged and retried on the next call. */
export function loadNative(): Promise<Native> {
  if (g.__readditVega) return g.__readditVega
  const loading = (async () => {
    const cfg = useRuntimeConfig()
    const path = (p: unknown) => resolve(process.cwd(), String(p))
    let addon: NativeAddon
    try {
      addon = createRequire(import.meta.url)(path(cfg.vegaAddon)) as NativeAddon
    } catch (e) {
      throw new Error(`The Vega addon ${path(cfg.vegaAddon)} could not be loaded. Run npm run build:native. (${(e as Error).message})`)
    }
    const shapes = path(cfg.vegaShapes)
    const anchors = await readFile(path(cfg.vegaTrustAnchors), 'utf8')
    const [prover, verifier] = await Promise.all([
      addon.loadProver(shapes, String(cfg.walletPin)),
      addon.loadVerifier(shapes, anchors, Number(cfg.proofTimeToleranceS)),
    ])
    return { prover, verifier }
  })()
  g.__readditVega = loading
  loading.catch((e: Error) => {
    console.error(`[vega] ${e.message}`)
    if (g.__readditVega === loading) g.__readditVega = undefined
  })
  return loading
}

async function native(service: 'prover' | 'verifier'): Promise<Native> {
  try {
    return await loadNative()
  } catch (e) {
    throw new ServiceError(service, 503, 'unavailable', (e as Error).message)
  }
}

/** A prover step's JSON: the result, or the refusal as a ServiceError. */
function outcome<T>(text: string): T {
  const json = JSON.parse(text) as { ok: boolean; status?: number; error?: string; detail?: string }
  if (!json.ok) throw new ServiceError('prover', json.status ?? 500, json.error ?? 'error', json.detail)
  return json as T
}

const offline = () => backendMode().mode === 'offline'

async function offlineCall<T>(service: 'prover' | 'verifier', fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    if (e instanceof OfflineError) throw new ServiceError(service, e.status, e.code, e.detail)
    throw e
  }
}

export const prover = {
  async info(): Promise<ServiceInfo> {
    if (offline()) return offlineProver.info()
    return JSON.parse((await native('prover')).prover.info) as ServiceInfo
  },

  /** Step 1: the PIN unlocks the device key, which signs DeviceAuthentication. */
  async sign(body: SignBody): Promise<SignResult> {
    if (offline()) return offlineCall('prover', () => offlineProver.sign(body))
    const n = await native('prover')
    return outcome<SignResult>(await n.prover.sign(JSON.stringify(body)))
  },

  /** Steps 2 and 3 within this one call: the witness, then the proof. No witness outlives the call. */
  async prove(body: ProveBody): Promise<ProveResult> {
    if (offline()) return offlineCall('prover', () => offlineProver.prove(body))
    const n = await native('prover')
    const w = await n.prover.witness(JSON.stringify(body))
    if (typeof w === 'string') return outcome<never>(w)
    const witness = JSON.parse(w.summary) as WitnessSummary
    const out = outcome<ProveResult>(await n.prover.prove(w))
    return { ...out, witness }
  },
}

export const verifier = {
  async info(): Promise<ServiceInfo> {
    if (offline()) return offlineVerifier.info()
    return JSON.parse((await native('verifier')).verifier.info) as ServiceInfo
  },

  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; now: string }): Promise<VerifyResult> {
    if (offline()) return offlineCall('verifier', () => offlineVerifier.verify(body))
    const n = await native('verifier')
    return JSON.parse(await n.verifier.verify(JSON.stringify(body))) as VerifyResult
  },
}

/** Backend info for the tech view; never throws. */
export async function servicesStatus() {
  const [p, v] = await Promise.allSettled([prover.info(), verifier.info()])
  const down = (r: PromiseRejectedResult) => ({
    up: false as const,
    error: r.reason instanceof ServiceError ? (r.reason.detail ?? r.reason.code) : String(r.reason),
  })
  return {
    mode: backendMode().mode,
    phoneFactor: backendMode().phoneFactor,
    prover: p.status === 'fulfilled' ? { up: true as const, ...p.value } : down(p),
    verifier: v.status === 'fulfilled' ? { up: true as const, ...v.value } : down(v),
  }
}
