// STUB verifier service. Implements the HTTP contract in docs/backend-api.md so the demo
// runs end to end. It does NOT verify a zero-knowledge proof. It decodes the presentation
// and runs the structural checks a real verifier also runs. Replace this container with
// the Longfellow verifier service.

import { createServer } from 'node:http'
import { decode } from 'cbor-x'

const PORT = Number(process.env.PORT ?? 8082)
const CIRCUITS = [{ circuit_id: 'urn:circuits:longfellow:nym_auth:v1', proof_system: 'longfellow-libzk-v1' }]
const PROOF_TIME_TOLERANCE_MS = 5 * 60_000

function verify(body) {
  const t0 = performance.now()
  let p
  try {
    p = decode(Buffer.from(body.presentation, 'base64url'))
  } catch {
    return { ok: false, reason: 'not CBOR' }
  }
  const decodeMs = performance.now() - t0
  const offered = body.request?.client_metadata?.vp_formats_supported?.circuit_zk?.circuit_id_values
  if (!CIRCUITS.some((c) => c.circuit_id === p.circuit_id)) return { ok: false, reason: 'unknown circuit' }
  if (offered && !offered.includes(p.circuit_id)) return { ok: false, reason: 'circuit not offered' }
  if (!Array.isArray(p.issuer_key_set) || !p.issuer_key_set.length) return { ok: false, reason: 'no issuer key set' }
  if (p.proof_time) {
    const t = Date.parse(p.proof_time instanceof Date ? p.proof_time.toISOString() : String(p.proof_time.value ?? p.proof_time))
    if (!Number.isFinite(t) || Math.abs(Date.parse(body.now) - t) > PROOF_TIME_TOLERANCE_MS) return { ok: false, reason: 'proof_time out of tolerance' }
  }

  const q = body.request?.dcql_query?.credentials?.find((c) => c.id === body.credential_query_id)
  if (!q) return { ok: false, reason: 'unknown credential query' }
  const expected = q.req.map((r) => r.return).sort().join()
  if (Object.keys(p.results ?? {}).sort().join() !== expected) return { ok: false, reason: 'results keys do not match req' }

  const results = {}
  for (const r of q.req) {
    const v = p.results[r.return]
    if (r.id === 'pseudonym-v1-sha256') {
      if (!(v instanceof Uint8Array) || v.length !== 32) return { ok: false, reason: 'bad pseudonym' }
      results[r.return] = Buffer.from(v).toString('hex')
    } else if (r.id === 'age_check') {
      if (v !== true) return { ok: false, reason: 'bad predicate result' }
      results[r.return] = true
    }
  }

  // A real verifier recomputes verifier_input, the session transcript and the req
  // parameters, then verifies p.proof against the circuit here. The stub cannot.
  const total = performance.now() - t0
  return {
    ok: true,
    circuit_id: p.circuit_id,
    results,
    metrics: { decode_ms: +decodeMs.toFixed(2), verify_ms: 0, total_ms: +total.toFixed(2), proof_bytes: p.proof?.length ?? 0 },
  }
}

function send(res, status, json) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(json))
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')
  if (req.method === 'GET' && url.pathname === '/info') {
    return send(res, 200, { service: 'verifier', implementation: 'Stub verifier (does not verify proofs)', version: '0.1.0', stub: true, circuits: CIRCUITS })
  }
  if (req.method === 'POST' && url.pathname === '/verify') {
    let raw = ''
    for await (const chunk of req) raw += chunk
    try {
      return send(res, 200, verify(JSON.parse(raw)))
    } catch {
      return send(res, 400, { error: 'bad_request' })
    }
  }
  send(res, 404, { error: 'not_found' })
}).listen(PORT, () => console.log(`stub verifier on :${PORT}`))
