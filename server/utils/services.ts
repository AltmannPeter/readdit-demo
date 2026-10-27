// The ONLY place that calls the proof backends, three Node addons (Rust, built with
// `npm run build:native`):
//   Vega (native/vega) and Longfellow (native/longfellow): circuits over the nym_auth mdoc (mso_mdoc);
//   BBS (native/bbs): a scheme over the nym_auth BBS credential (bbs_cd, docs/bbs_cd.md).
// All three answer a zkp_req credential query with a ZkpPresentation (rulebook v0.4).
// Each loads on its own. The site starts when at least one loads (server/plugins/backends.ts) and
// offers only the circuits and formats of the backends that loaded (server/utils/vp.ts).
//
// mso_mdoc (Vega, Longfellow):
// Prover: the phone's native steps. The mocked wallet sends the credential material each step
// needs (credential, device key, secret_seed); the prover keeps none of it. The device key signs
// DeviceAuthentication (the wallet's PIN screen unlocks it on the phone, with any PIN; the prover
// takes none), then the prover builds the witness and proves.
// Verifier: verifies a presentation against the site's own request, handover and clock.
// Both sides load their circuits once, when the server starts (server/plugins/backends.ts).
// Contract: docs/backend-api.md

import { createRequire } from 'node:module'
import { Decoder } from 'cbor-x'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import type { RequestObject } from '#shared/types/oid4vp'
import { type FaultStep, takeFault } from './test-faults'

/** One phase of vega-prover's own (its tracing spans), merged by name: runs, total time, and on
 *  one thread the most heap one run held. */
export interface PhaseNode {
  name: string
  n: number
  ms: number
  mb: number | null
  children: PhaseNode[]
}

/** A step's profile (/tech's Profiling switch): folded stacks from the sampler (`entry;…;leaf` →
 *  samples), the samples outside the addon's code (`other`), the step's sampled wall time, and for
 *  Vega the library's phases. */
export interface StepProfile {
  hz?: number
  ms?: number
  samples?: number
  other?: number
  lost?: number
  stacks?: Record<string, number>
  phases?: PhaseNode[] | null
}

/** A part of a proof or a presentation and its bytes; `code` when the name is a field name of
 *  the encoding. */
export interface SizePart {
  name: string
  bytes: number
  code?: boolean
  children: SizePart[]
}

/** Takes `key` out of an addon's metrics, so the profile and the parts travel apart from the
 *  metrics that go into the session's trace. */
function take<T>(metrics: unknown, key: string): T | undefined {
  if (!metrics || typeof metrics !== 'object' || !(key in metrics)) return undefined
  const m = metrics as Record<string, unknown>
  const v = m[key]
  delete m[key]
  return (v ?? undefined) as T | undefined
}

export interface ServiceCircuit {
  system_id: string
  proof_system: string
  /** The SHA-256 of the circuits as data: shapes.zst (Vega), circuits.zst (Longfellow). */
  shapes_sha256?: string | null
  artifact_sha256?: string | null
  public_inputs?: string[]
}

export interface ServiceInfo {
  service: string
  implementation: string
  version: string
  circuits: ServiceCircuit[]
  load_ms?: number
  /** Longfellow: always 1. */
  threads?: number
  /** Vega: the threads the switch gives it when on (the machine's cores). */
  max_threads?: number
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
  system_id: string
  credential_query_id: string
  request: RequestObject
  handover: Handover
  credential: WalletCredential
  secret_seed: string
  device_signature: string
  /** The rulebook version ("0.4" when absent). */
  rulebook?: string
}

export interface WitnessSummary {
  proof_time: string
  results: Record<string, string | true>
  public_inputs: Array<{ name: string; values: string[] }>
  /** Vega: the table's values; Longfellow: each circuit's inputs. */
  counts:
    | { shared: number; precommitted: number; rest: number; public: number }
    | { hash: { inputs: number; public: number }; signature: { inputs: number; public: number } }
    | null
  metrics: { witness_ms?: number; heap_mb?: number | null }
}

export interface ProveMetrics {
  /** One-time key build when the server started. */
  load_ms?: number
  witness_ms?: number
  prove_ms?: number
  /** witness + prove, per presentation */
  total_ms?: number
  /** The most heap the step's own Rust code held at once (for a circuit proof: witness and
   *  prove), above what was held before it. */
  heap_mb?: number | null
  /** The heap the loaded keys or circuits of this side hold (loaded once at start). */
  keys_mb?: number | null
  /** Circuit proofs: the witness held from the witness step into the prove step (part of heap_mb). */
  witness_mb?: number | null
  /** The server process's peak resident set during the step (Linux only): Node and all addons. */
  peak_memory_mb?: number | null
  proof_bytes?: number
  presentation_bytes?: number
  threads?: number
}

export interface ProveResult {
  system_id: string
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
  /** The threads the check ran on (Vega, BBS: the /tech switch; Longfellow: 1). */
  threads?: number
  /** The most heap the step's own Rust code held at once (for a circuit proof: witness and
   *  prove), above what was held before it. */
  heap_mb?: number | null
  /** The heap the loaded keys or circuits of this side hold (loaded once at start). */
  keys_mb?: number | null
  /** Circuit proofs: the witness held from the witness step into the prove step (part of heap_mb). */
  witness_mb?: number | null
  /** The server process's peak resident set during the step (Linux only): Node and all addons. */
  peak_memory_mb?: number | null
}

export type VerifyResult =
  | { ok: true; system_id: string; results: Record<string, string | true>; bounds?: { ge?: string | null; le?: string | null } | null; metrics: VerifyMetrics }
  | { ok: false; reason: string; code?: string; input?: string | null; certificate?: string | null; metrics?: VerifyMetrics }

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

// ---- mso_mdoc: the Vega and Longfellow circuit addons ----
//
// Both addons have the same interface and prove the same statement over the same mdoc; each lists
// its circuit in `info`. A prover step goes to the addon of the circuit the wallet chose; a
// verification goes to the addon of the circuit the presentation names.

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
  /** Vega: the path of shapes.zst; Longfellow: the directory of circuits.zst. */
  loadProver(circuits: string): Promise<NativeProver>
  loadVerifier(circuits: string, trustAnchorsPem: string, toleranceS: number): Promise<NativeVerifier>
}
interface Native {
  prover: NativeProver
  verifier: NativeVerifier
}

/** The circuit backends, in the order of preference. */
export const CIRCUIT_BACKENDS = ['vega', 'longfellow'] as const
export type CircuitBackend = (typeof CIRCUIT_BACKENDS)[number]
const LABELS: Record<CircuitBackend, string> = { vega: 'Vega', longfellow: 'Longfellow' }

const g = globalThis as unknown as { __communityCircuits?: Partial<Record<CircuitBackend, Promise<Native>>> }

function backendPaths(name: CircuitBackend) {
  const cfg = useRuntimeConfig()
  return name === 'vega'
    ? { addon: cfg.vegaAddon, circuits: cfg.vegaShapes, anchors: cfg.vegaTrustAnchors }
    : { addon: cfg.longfellowAddon, circuits: cfg.longfellowCircuits, anchors: cfg.longfellowTrustAnchors }
}

/**
 * Loads one circuit addon and both its sides, once. A failure is not kept: the next call tries
 * again. The caller reports it (server/plugins/backends.ts at start, `nativeFor` below on a request).
 */
export function loadCircuitBackend(name: CircuitBackend): Promise<Native> {
  const cache = (g.__communityCircuits ??= {})
  if (cache[name]) return cache[name]
  const loading = (async () => {
    const cfg = useRuntimeConfig()
    const paths = backendPaths(name)
    const path = (p: unknown) => resolve(process.cwd(), String(p))
    let addon: NativeAddon
    try {
      addon = createRequire(import.meta.url)(path(paths.addon)) as NativeAddon
    } catch (e) {
      throw new Error(`The ${LABELS[name]} addon ${path(paths.addon)} could not be loaded. (${(e as Error).message})`)
    }
    const circuits = path(paths.circuits)
    const anchors = await readFile(path(paths.anchors), 'utf8')
    const [prover, verifier] = await Promise.all([
      addon.loadProver(circuits),
      addon.loadVerifier(circuits, anchors, Number(cfg.proofTimeToleranceS)),
    ])
    return { prover, verifier }
  })()
  cache[name] = loading
  loading.catch(() => {
    if (cache[name] === loading) delete cache[name]
  })
  return loading
}

/** The circuit backends that load, in order; 503 unavailable when none does. */
async function loadedCircuitBackends(service: 'prover' | 'verifier'): Promise<Array<{ name: CircuitBackend; n: Native }>> {
  const settled = await Promise.allSettled(CIRCUIT_BACKENDS.map((name) => loadCircuitBackend(name)))
  const up = CIRCUIT_BACKENDS.flatMap((name, i) => {
    const r = settled[i]!
    return r.status === 'fulfilled' ? [{ name, n: r.value }] : []
  })
  if (!up.length) {
    const why = settled.map((r, i) => (r.status === 'rejected' ? `${LABELS[CIRCUIT_BACKENDS[i]!]}: ${(r.reason as Error).message}` : '')).filter(Boolean).join(' ')
    console.error(`[circuits] ${service}: no addon is loaded: ${why} Run npm run build:native.`)
    throw new ServiceError(service, 503, 'unavailable', why)
  }
  return up
}

/** The circuit ids an addon side lists. */
function circuitsOf(side: { info: string }): string[] {
  try {
    return (JSON.parse(side.info) as ServiceInfo).circuits.map((c) => c.system_id)
  } catch {
    return []
  }
}

/** The loaded backend whose side lists `circuitId`, or the first loaded one (which refuses an
 *  unknown circuit itself). */
async function backendFor(service: 'prover' | 'verifier', circuitId: string | undefined) {
  const up = await loadedCircuitBackends(service)
  return up.find((b) => circuitId && circuitsOf(b.n[service]).includes(circuitId)) ?? up[0]!
}

/**
 * One call into an addon, with its result parsed. A call that throws (a panic in the addon, a
 * result that is not JSON) is a failure of the backend: 500 backend_error, logged with the reason.
 * `takeFault` fails the call the same way when a test armed it (test-faults.ts; never without
 * COMMUNITY_TEST_FAULTS=1).
 */
async function call<T>(service: 'prover' | 'verifier', step: FaultStep, fn: () => Promise<T>, backend: string): Promise<T> {
  try {
    if (takeFault(step)) throw new Error(`test fault: the ${step} call failed (COMMUNITY_TEST_FAULTS)`)
    return await fn()
  } catch (e) {
    console.error(`[${backend}] ${step} failed: ${(e as Error).message}`)
    throw new ServiceError(service, 500, 'backend_error', (e as Error).message)
  }
}

/** A prover step's JSON: the result, or the refusal as a ServiceError. */
function outcome<T>(json: { ok: boolean; status?: number; error?: string; detail?: string }): T {
  if (!json.ok) throw new ServiceError('prover', json.status ?? 500, json.error ?? 'error', json.detail)
  return json as T
}

/** The info of every loaded backend's side, merged: the circuits in the order of preference. */
async function mergedInfo(service: 'prover' | 'verifier'): Promise<ServiceInfo> {
  const up = await loadedCircuitBackends(service)
  return call(service, `${service}.info`, async () => {
    const infos = up.map((b) => JSON.parse(b.n[service].info) as ServiceInfo)
    return { ...infos[0]!, implementation: infos.map((i) => i.implementation).join('; '), circuits: infos.flatMap((i) => i.circuits) }
  }, 'circuits')
}

/** /tech's switches in the call's JSON: `parallel` for the addons that have threads (Vega, BBS;
 *  Longfellow runs on one thread whatever the switch says), and `profile`. */
function threading(backend: CircuitBackend | 'bbs'): { parallel?: boolean; profile?: boolean } {
  const profile = store().profiling ? { profile: true } : {}
  return backend === 'longfellow' ? profile : { parallel: store().multithreading, ...profile }
}

const gp = globalThis as unknown as { __communityProfiled?: Promise<unknown> }

/**
 * With Profiling on, one addon call at a time across the three addons: the sampler is
 * process-wide, so two steps sampled at once would mix. Off, calls run as they come.
 */
async function oneAtATime<T>(fn: () => Promise<T>): Promise<T> {
  if (!store().profiling) return fn()
  const before = gp.__communityProfiled ?? Promise.resolve()
  let release!: () => void
  const mine = new Promise<void>((r) => (release = r))
  gp.__communityProfiled = before.then(() => mine)
  await before.catch(() => {})
  try {
    return await fn()
  } finally {
    release()
  }
}

/** The system a presentation names (CBOR ZkpPresentation, `system_id`), if it decodes. */
function presentedCircuit(presentation: string): string | undefined {
  try {
    const m = new Decoder({ mapsAsObjects: false, useRecords: false }).decode(Buffer.from(presentation, 'base64url')) as unknown
    const id = m instanceof Map ? m.get('system_id') : undefined
    return typeof id === 'string' ? id : undefined
  } catch {
    return undefined
  }
}

export const prover = {
  /** Every loaded circuit prover's circuits. */
  async info(): Promise<ServiceInfo> {
    return mergedInfo('prover')
  },

  /** Step 1: the device key signs DeviceAuthentication. The message is the same for every
   *  circuit; the addon of `circuitId` signs, or the first loaded one. */
  async sign(body: SignBody, circuitId?: string): Promise<SignResult & { profile?: StepProfile }> {
    const b = await backendFor('prover', circuitId)
    const r = outcome<SignResult>(await call('prover', 'prover.sign', () => oneAtATime(async () => JSON.parse(await b.n.prover.sign(JSON.stringify({ ...body, ...threading(b.name) })))), b.name))
    return { ...r, profile: take<StepProfile>(r.metrics, 'profile') }
  },

  /** Steps 2 and 3 within this one call, by the addon of `body.system_id`: the witness, then the
   *  proof. No witness outlives the call. */
  async prove(body: ProveBody): Promise<ProveResult & { backend: CircuitBackend; profiles: { witness?: StepProfile; prove?: StepProfile }; proof_parts?: SizePart[] }> {
    const b = await backendFor('prover', body.system_id)
    const done = await call('prover', 'prover.prove', () => oneAtATime(async () => {
      const w = await b.n.prover.witness(JSON.stringify({ ...body, ...threading(b.name) }))
      if (typeof w === 'string') return { refusal: JSON.parse(w) }
      const witness = JSON.parse(w.summary) as WitnessSummary
      return { result: JSON.parse(await b.n.prover.prove(w)), witness }
    }), b.name)
    if ('refusal' in done) return outcome<never>(done.refusal)
    const r = outcome<ProveResult>(done.result)
    const profiles = { witness: take<StepProfile>(done.witness.metrics, 'profile'), prove: take<StepProfile>(r.metrics, 'profile') }
    return { ...r, witness: done.witness, backend: b.name, profiles, proof_parts: take<SizePart[]>(r.metrics, 'proof_parts') }
  },
}

export const verifier = {
  /** Every loaded circuit verifier's circuits. */
  async info(): Promise<ServiceInfo> {
    return mergedInfo('verifier')
  },

  /** By the addon of the circuit the presentation names. */
  /** `learned_issuers`: Document Signer certificates (base64 DER) trusted besides the configured
   *  trust anchors (server/utils/issuers.ts). An `issuer_key_set` refusal for a certificate that is
   *  not trusted carries it as `certificate` (base64 DER). */
  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; rulebook?: string; now: string; learned_issuers?: string[] }): Promise<VerifyResult & { profile?: StepProfile }> {
    const b = await backendFor('verifier', presentedCircuit(body.presentation))
    const r = await call('verifier', 'verifier.verify', () => oneAtATime(async () => JSON.parse(await b.n.verifier.verify(JSON.stringify({ ...body, ...threading(b.name) }))) as VerifyResult), b.name)
    return { ...r, profile: take<StepProfile>(r.metrics, 'profile') }
  },
}

// ---- the BBS addon (bbs_cd) ----
//
// Prover: one call per presentation. The mocked wallet sends the BBS credential and its device
// key; the device key signs inside the ecdsa-pop plugin (hashed ECDSA over the plugin's device
// message), so there is no separate signing step. Verifier: derives the BBS request from the site's
// own request and handover, against the issuer parameters it trusts (bbsIssuerParams).

export interface BbsScheme {
  system_id: string
  proof_system: string
  schema_id: string
  schema_digest: string
  plugins: string[]
}

export interface BbsInfo {
  service: string
  implementation: string
  version: string
  schemes: BbsScheme[]
  issuers?: Array<{ issuer_pk: string; schema_id: string; schema_digest: string }>
  load_ms?: number
  max_threads?: number
}

export interface BbsCredential {
  format: 'bbs_cd'
  schema_id: string
  issuer_params: string
  signature: string
  messages: string[]
}

export interface BbsProveBody {
  request: RequestObject
  credential_query_id: string
  handover: Handover
  credential: BbsCredential
  device_key: DeviceKeyJwk
  /** The rulebook version ("0.4" when absent): v0.5 writes proof_time and takes ages in years. */
  rulebook?: string
}

export interface BbsProveMetrics {
  load_ms?: number
  /** BBS commitments and the ecdsa-pop preparation (request-independent). */
  offline_ms?: number
  bbs_ms?: number
  ecdsa_pop_ms?: number
  device_sign_ms?: number
  pseudonym_ms?: number
  date_range_ms?: number | null
  online_ms?: number
  /** offline + online */
  prove_ms?: number
  total_ms?: number
  /** The most heap the step's own Rust code held at once (for a circuit proof: witness and
   *  prove), above what was held before it. */
  heap_mb?: number | null
  /** The heap the loaded keys or circuits of this side hold (loaded once at start). */
  keys_mb?: number | null
  /** Circuit proofs: the witness held from the witness step into the prove step (part of heap_mb). */
  witness_mb?: number | null
  /** The server process's peak resident set during the step (Linux only): Node and all addons. */
  peak_memory_mb?: number | null
  proof_bytes?: number
  presentation_bytes?: number
  parts?: { bbs_proof: number; ecdsa_pop: number; pseudonym: number; date_range: number | null }
}

export interface BbsProveResult {
  system_id: string
  presentation: string
  results: Record<string, string | true>
  metrics: BbsProveMetrics
  statement: { audience: string; nonce: string; verifier_input: string; committed: string[]; plugins: string[] }
}

export type BbsVerifyResult =
  | { ok: true; system_id: string; results: Record<string, string | true>; bounds?: { ge?: string | null; le?: string | null } | null; metrics: VerifyMetrics & { parse_ms?: number; bbs_ms?: number; ecdsa_pop_ms?: number; pseudonym_ms?: number; date_range_ms?: number | null } }
  | { ok: false; reason: string; code?: string; issuer_key?: string | null; metrics?: VerifyMetrics }

interface NativeBbsProver {
  readonly info: string
  prove(input: string): Promise<string>
}
interface NativeBbsVerifier {
  readonly info: string
  verify(input: string): Promise<string>
}
interface NativeBbsAddon {
  loadProver(): Promise<NativeBbsProver>
  loadVerifier(issuerParamsPath: string): Promise<NativeBbsVerifier>
}
interface NativeBbs {
  prover: NativeBbsProver
  verifier: NativeBbsVerifier
}

const gb = globalThis as unknown as { __communityBbs?: Promise<NativeBbs> }

/** Loads the BBS addon and the trusted issuer parameters, once; a failure is retried at the next call. */
export function loadBbs(): Promise<NativeBbs> {
  if (gb.__communityBbs) return gb.__communityBbs
  const loading = (async () => {
    const cfg = useRuntimeConfig()
    const path = (p: unknown) => resolve(process.cwd(), String(p))
    let addon: NativeBbsAddon
    try {
      addon = createRequire(import.meta.url)(path(cfg.bbsAddon)) as NativeBbsAddon
    } catch (e) {
      throw new Error(`The BBS addon ${path(cfg.bbsAddon)} could not be loaded. (${(e as Error).message})`)
    }
    const [prover, verifier] = await Promise.all([addon.loadProver(), addon.loadVerifier(path(cfg.bbsIssuerParams))])
    return { prover, verifier }
  })()
  gb.__communityBbs = loading
  loading.catch(() => {
    if (gb.__communityBbs === loading) gb.__communityBbs = undefined
  })
  return loading
}

async function bbsNative(service: 'prover' | 'verifier'): Promise<NativeBbs> {
  try {
    return await loadBbs()
  } catch (e) {
    console.error(`[bbs] ${service}: the addon is not loaded: ${(e as Error).message} Run npm run build:native.`)
    throw new ServiceError(service, 503, 'unavailable', (e as Error).message)
  }
}

export const bbsProver = {
  async info(): Promise<BbsInfo> {
    const n = await bbsNative('prover')
    return call('prover', 'prover.info', async () => JSON.parse(n.prover.info) as BbsInfo, 'bbs')
  },

  /** One presentation: commitments, the device signature inside ecdsa-pop, the plugin proofs. */
  async prove(body: BbsProveBody): Promise<BbsProveResult & { profile?: StepProfile; proof_parts?: SizePart[] }> {
    const n = await bbsNative('prover')
    const r = outcome<BbsProveResult>(await call('prover', 'prover.prove', () => oneAtATime(async () => JSON.parse(await n.prover.prove(JSON.stringify({ ...body, ...threading('bbs') })))), 'bbs'))
    return { ...r, profile: take<StepProfile>(r.metrics, 'profile'), proof_parts: take<SizePart[]>(r.metrics, 'proof_parts') }
  },
}

export const bbsVerifier = {
  async info(): Promise<BbsInfo> {
    const n = await bbsNative('verifier')
    return call('verifier', 'verifier.info', async () => JSON.parse(n.verifier.info) as BbsInfo, 'bbs')
  },

  /** `learned_issuers`: BBS issuer keys (base64) trusted besides the configured issuer
   *  (server/utils/issuers.ts). An `issuer_key_set` refusal for a key that is not trusted carries
   *  it as `issuer_key`. */
  /** `rulebook`: the demo profile's version ("0.4", "0.5"); `now` and `proof_time_tolerance_s`:
   *  the verifier's clock and tolerance for proof_time (v0.5, with an age check). */
  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; rulebook?: string; now?: string; proof_time_tolerance_s?: number; learned_issuers?: string[] }): Promise<BbsVerifyResult & { profile?: StepProfile }> {
    const n = await bbsNative('verifier')
    const r = await call('verifier', 'verifier.verify', () => oneAtATime(async () => JSON.parse(await n.verifier.verify(JSON.stringify({ ...body, ...threading('bbs') }))) as BbsVerifyResult), 'bbs')
    return { ...r, profile: take<StepProfile>(r.metrics, 'profile') }
  },
}

// ---- both ----

/** Each backend that loads, or why not: the site starts with at least one (server/plugins/backends.ts). */
export async function loadBackends(): Promise<{ vega: string | null; longfellow: string | null; bbs: string | null }> {
  const err = (p: Promise<unknown>) => p.then(() => null, (e: Error) => e.message)
  const [vega, longfellow, bbs] = await Promise.all([err(loadCircuitBackend('vega')), err(loadCircuitBackend('longfellow')), err(loadBbs())])
  return { vega, longfellow, bbs }
}

/** Backend info for the tech view; never throws, and never takes a test fault. */
export async function servicesStatus() {
  const read = <T>(side: { info: string } | undefined, error: string) => {
    if (!side) return { up: false as const, error }
    try {
      return { up: true as const, ...(JSON.parse(side.info) as T) }
    } catch (e) {
      return { up: false as const, error: (e as Error).message }
    }
  }
  const settle = async <T>(p: Promise<T>): Promise<[T | undefined, string]> => {
    try {
      return [await p, '']
    } catch (e) {
      return [undefined, (e as Error).message]
    }
  }
  const [[vega, vegaError], [lf, lfError], [b, bbsError]] = await Promise.all([
    settle(loadCircuitBackend('vega')),
    settle(loadCircuitBackend('longfellow')),
    settle(loadBbs()),
  ])
  return {
    prover: read<ServiceInfo>(vega?.prover, vegaError),
    verifier: read<ServiceInfo>(vega?.verifier, vegaError),
    lfProver: read<ServiceInfo>(lf?.prover, lfError),
    lfVerifier: read<ServiceInfo>(lf?.verifier, lfError),
    bbsProver: read<BbsInfo>(b?.prover, bbsError),
    bbsVerifier: read<BbsInfo>(b?.verifier, bbsError),
  }
}
