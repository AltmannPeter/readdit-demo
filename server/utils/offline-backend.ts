// Built-in OFFLINE backend: a simulation of the Vega prover and verifier for when the addon fails
// or cannot be built on stage. Same contract as the addon (docs/backend-api.md).
// It does not create or verify a zero-knowledge proof. It checks the PIN, reads the birth date
// from the credential the wallet sends and checks the age predicate, derives the real pseudonym
// from the wallet's secret_seed, returns a CBOR presentation with a random "proof" of Vega's size,
// and waits as long as the benchmark model says (shared/benchmarks.ts). Every metric it reports
// is marked simulated.

import { randomBytes } from 'node:crypto'
import { decode, encode, Tag } from 'cbor-x'
import type { RequestObject } from '#shared/types/oid4vp'
import { NYM_DOCTYPE } from '#shared/types/oid4vp'
import { derivePseudonym } from '#shared/utils/pseudonym'
import { fromHex, toHex } from '#shared/utils/bytes'
import { readIssuerSigned } from '#shared/utils/mdoc'
import { findCircuit } from '#shared/registry/circuits'
import { simulatedVega } from '#shared/benchmarks'
import type { Handover, ProveBody, ProveResult, ServiceInfo, SignBody, SignResult, VerifyResult } from './services'

const CIRCUIT = findCircuit('urn:circuits:vega:nym_auth:v1')!
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

function info(service: 'prover' | 'verifier'): ServiceInfo {
  return {
    service,
    implementation: `Offline simulation (built in, no zero-knowledge ${service === 'prover' ? 'proof' : 'verification'})`,
    version: '0.2.0',
    stub: true,
    offline: true,
    // The circuit it stands in for, as the registry names it.
    circuits: [
      {
        circuit_id: CIRCUIT.circuit_id,
        proof_system: CIRCUIT.proof_system,
        shapes_sha256: CIRCUIT.artifact?.sha256 ?? null,
        public_inputs: CIRCUIT.public_inputs.map((p) => p.name),
      },
    ],
  }
}

export class OfflineError extends Error {
  constructor(
    public status: number,
    public code: string,
    public detail?: string,
  ) {
    super(code)
  }
}

export const offlineProver = {
  info: async () => info('prover'),

  async sign(body: SignBody): Promise<SignResult> {
    if (body.pin !== String(useRuntimeConfig().walletPin)) throw new OfflineError(401, 'invalid_pin')
    if (body.doc_type !== NYM_DOCTYPE) throw new OfflineError(400, 'unsupported_request')
    const m = simulatedVega(backendMode().phoneFactor).sign
    await sleep(m.sign_ms)
    return { device_signature: toHex(randomBytes(64)), session_transcript: '', challenge_digest: '', metrics: { ...m, simulated: true } }
  },

  async prove(body: ProveBody): Promise<ProveResult> {
    if (body.circuit_id !== CIRCUIT.circuit_id) throw new OfflineError(400, 'unsupported_circuit')
    const q = body.request.dcql_query.credentials.find((c) => c.id === body.credential_query_id)
    if (!q || q.meta.doctype_value !== NYM_DOCTYPE) throw new OfflineError(400, 'unsupported_request')
    let credential
    try {
      credential = readIssuerSigned(body.credential.issuer_signed)
    } catch (e) {
      throw new OfflineError(400, 'bad_credential', (e as Error).message)
    }

    const results: Record<string, Uint8Array | true> = {}
    const decoded: Record<string, string | true> = {}
    for (const r of q.req) {
      if (r.id === 'pseudonym-v1-sha256') {
        if (r.params.config !== 'known-offender-matching-ssc' || r.params.verifier_id_type !== 'x509_san_dns') {
          throw new OfflineError(400, 'unsupported_config')
        }
        const nym = await derivePseudonym({ config: r.params.config, seed: fromHex(body.secret_seed), verifierId: body.handover.client_id })
        results[r.return] = fromHex(nym)
        decoded[r.return] = nym
      } else if (r.id === 'age_check') {
        const { ge, le } = r.params
        const birth = credential.birthDate
        if ((ge && birth < ge) || (le && birth > le)) throw new OfflineError(422, 'unsatisfiable', 'the birth date lies outside the requested range')
        results[r.return] = true
        decoded[r.return] = true
      } else {
        throw new OfflineError(400, 'unsupported_function')
      }
    }

    const m = simulatedVega(backendMode().phoneFactor).prove
    await sleep(m.total_ms)
    const proofTime = iso(new Date())
    const presentation = encode({
      circuit_id: body.circuit_id,
      proof: randomBytes(m.proof_bytes),
      issuer_key_set: [credential.documentSigner],
      proof_time: new Tag(proofTime, 0),
      results,
    })
    return {
      circuit_id: body.circuit_id,
      presentation: Buffer.from(presentation).toString('base64url'),
      results: decoded,
      metrics: { ...m, presentation_bytes: presentation.length, simulated: true },
      witness: { proof_time: proofTime, results: decoded, public_inputs: [], counts: null, metrics: { witness_ms: m.witness_ms, simulated: true } },
    }
  },
}

export const offlineVerifier = {
  info: async () => info('verifier'),

  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; handover: Handover; now: string }): Promise<VerifyResult> {
    let p: { circuit_id: string; proof?: Uint8Array; issuer_key_set?: unknown[]; proof_time?: unknown; results?: Record<string, unknown> }
    try {
      p = decode(Buffer.from(body.presentation, 'base64url'))
    } catch {
      return { ok: false, code: 'presentation', reason: 'not CBOR' }
    }
    const offered = body.request.client_metadata.vp_formats_supported.circuit_zk.circuit_id_values
    if (p.circuit_id !== CIRCUIT.circuit_id) return { ok: false, code: 'circuit', reason: 'unknown circuit' }
    if (offered && !offered.includes(p.circuit_id)) return { ok: false, code: 'circuit', reason: 'circuit not offered' }
    const q = body.request.dcql_query.credentials.find((c) => c.id === body.credential_query_id)
    if (!q) return { ok: false, code: 'request', reason: 'unknown credential query' }
    if (Object.keys(p.results ?? {}).sort().join() !== q.req.map((r) => r.return).sort().join()) {
      return { ok: false, code: 'results', reason: 'results keys do not match req' }
    }
    const results: Record<string, string | true> = {}
    for (const r of q.req) {
      const v = p.results![r.return]
      if (r.id === 'pseudonym-v1-sha256') {
        if (!(v instanceof Uint8Array) || v.length !== 32) return { ok: false, code: 'results', reason: 'bad pseudonym' }
        results[r.return] = Buffer.from(v).toString('hex')
      } else if (r.id === 'age_check') {
        if (v !== true) return { ok: false, code: 'results', reason: 'bad predicate result' }
        results[r.return] = true
      }
    }
    const m = simulatedVega(backendMode().phoneFactor).verify
    await sleep(m.total_ms)
    return { ok: true, circuit_id: p.circuit_id, results, metrics: { ...m, simulated: true } }
  },
}
