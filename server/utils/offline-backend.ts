// Built-in OFFLINE backend: a simulation of the prover and verifier services for when the
// containers or the network fail on stage. Same contract as the services (docs/backend-api.md).
// It does not create or verify a zero-knowledge proof. It derives the real pseudonym, checks the
// PIN and the age predicate, returns a CBOR presentation with a random "proof" of Longfellow's
// size, and waits as long as the benchmark model says (shared/benchmarks.ts). All metrics it
// reports are marked simulated.

import { randomBytes } from 'node:crypto'
import { decode, encode, Tag } from 'cbor-x'
import type { RequestObject } from '#shared/types/oid4vp'
import { derivePseudonym } from '#shared/utils/pseudonym'
import { fromHex, sha256, toHex } from '#shared/utils/bytes'
import { simulatedLongfellow } from '#shared/benchmarks'
import type { Handover, ProveResult, ServiceInfo, VerifyResult } from './services'

const CIRCUITS = [{ circuit_id: 'urn:circuits:longfellow:nym_auth:v1', proof_system: 'longfellow-libzk-v1' }]
const DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'
const SEED_HEX = '9f3c1a6e5b27d8044c0e7a1f62b9d351'
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

const g = globalThis as unknown as { __readditOfflineHolder?: Promise<{ ssc: string; thumbprint: string; issued: Date }> }

function holder() {
  g.__readditOfflineHolder ??= (async () => {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
    const thumb = Buffer.from(await sha256(new TextEncoder().encode(canonical))).toString('base64url')
    return { ssc: toHex(await sha256(fromHex(SEED_HEX))), thumbprint: thumb, issued: new Date(Date.now() - 30 * 86_400_000) }
  })()
  return g.__readditOfflineHolder
}

function info(service: 'prover' | 'verifier'): ServiceInfo & { offline: true } {
  return {
    service,
    implementation: `Offline simulation (built in, no zero-knowledge ${service === 'prover' ? 'proof' : 'verification'})`,
    version: '0.1.0',
    stub: true,
    offline: true,
    circuits: CIRCUITS,
  }
}

export class OfflineError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(code)
  }
}

export const offlineProver = {
  info: async () => info('prover'),

  async credential() {
    const cfg = useRuntimeConfig()
    const h = await holder()
    const until = new Date(h.issued.getTime() + 365 * 86_400_000)
    return {
      docType: DOCTYPE,
      namespace: DOCTYPE,
      title: 'Age and pseudonym',
      encoding: 'ISO/IEC 18013-5 mdoc',
      compactProfile: true,
      issuer: { name: 'Demo Issuer', country: 'SE', documentSigner: 'CN=Demo Document Signer, O=Demo Issuer, C=SE' },
      validity: { signed: iso(h.issued), validFrom: iso(h.issued), validUntil: iso(until) },
      attributes: { birth_date: String(cfg.offlineBirthDate), ssc: h.ssc, psc: null },
      mso: { digestAlgorithm: 'SHA-256', signatureAlgorithm: 'ES256' },
      deviceKey: {
        kty: 'EC',
        crv: 'P-256',
        jwkThumbprint: h.thumbprint,
        protection: 'Offline simulation. A real wallet keeps this key in the phone\'s secure hardware.',
      },
    }
  },

  async prove(body: {
    pin: string
    circuit_id: string
    credential_query_id: string
    request: RequestObject
    handover: Handover
  }): Promise<ProveResult> {
    const cfg = useRuntimeConfig()
    if (body.pin !== String(cfg.offlinePin)) throw new OfflineError(401, 'invalid_pin')
    if (!CIRCUITS.some((c) => c.circuit_id === body.circuit_id)) throw new OfflineError(400, 'unsupported_circuit')
    const q = body.request.dcql_query.credentials.find((c) => c.id === body.credential_query_id)
    if (!q || q.meta.doctype_value !== DOCTYPE) throw new OfflineError(400, 'unsupported_request')

    const birth = String(cfg.offlineBirthDate)
    const results: Record<string, Uint8Array | true> = {}
    const decoded: Record<string, string | true> = {}
    for (const r of q.req) {
      if (r.id === 'pseudonym-v1-sha256') {
        const nym = await derivePseudonym({
          config: r.params.config,
          seed: fromHex(SEED_HEX),
          verifierId: body.handover.client_id,
          verifierContext: r.params.verifier_context,
        })
        results[r.return] = fromHex(nym)
        decoded[r.return] = nym
      } else if (r.id === 'age_check') {
        const { ge, le } = r.params
        if ((ge && birth < ge) || (le && birth > le)) throw new OfflineError(422, 'unsatisfiable')
        results[r.return] = true
        decoded[r.return] = true
      } else {
        throw new OfflineError(400, 'unsupported_function')
      }
    }

    const m = simulatedLongfellow(backendMode().phoneFactor).prove
    await sleep(m.total_ms)
    const presentation = encode({
      circuit_id: body.circuit_id,
      proof: randomBytes(m.proof_bytes),
      issuer_key_set: [randomBytes(16)],
      proof_time: new Tag(iso(new Date()), 0),
      results,
    })
    return {
      circuit_id: body.circuit_id,
      presentation: Buffer.from(presentation).toString('base64url'),
      results: decoded,
      metrics: { ...m, presentation_bytes: presentation.length, simulated: true },
    }
  },
}

export const offlineVerifier = {
  info: async () => info('verifier'),

  async verify(body: { request: RequestObject; credential_query_id: string; presentation: string; now: string }): Promise<VerifyResult> {
    let p: { circuit_id: string; proof?: Uint8Array; issuer_key_set?: unknown[]; proof_time?: unknown; results?: Record<string, unknown> }
    try {
      p = decode(Buffer.from(body.presentation, 'base64url'))
    } catch {
      return { ok: false, reason: 'not CBOR' }
    }
    const offered = body.request.client_metadata.vp_formats_supported.circuit_zk.circuit_id_values
    if (!CIRCUITS.some((c) => c.circuit_id === p.circuit_id)) return { ok: false, reason: 'unknown circuit' }
    if (offered && !offered.includes(p.circuit_id)) return { ok: false, reason: 'circuit not offered' }
    const q = body.request.dcql_query.credentials.find((c) => c.id === body.credential_query_id)
    if (!q) return { ok: false, reason: 'unknown credential query' }
    if (Object.keys(p.results ?? {}).sort().join() !== q.req.map((r) => r.return).sort().join()) {
      return { ok: false, reason: 'results keys do not match req' }
    }
    const results: Record<string, string | true> = {}
    for (const r of q.req) {
      const v = p.results![r.return]
      if (r.id === 'pseudonym-v1-sha256') {
        if (!(v instanceof Uint8Array) || v.length !== 32) return { ok: false, reason: 'bad pseudonym' }
        results[r.return] = Buffer.from(v).toString('hex')
      } else if (r.id === 'age_check') {
        if (v !== true) return { ok: false, reason: 'bad predicate result' }
        results[r.return] = true
      }
    }
    const m = simulatedLongfellow(backendMode().phoneFactor).verify
    await sleep(m.total_ms)
    return { ok: true, circuit_id: p.circuit_id, results, metrics: { ...m, simulated: true } }
  },
}
