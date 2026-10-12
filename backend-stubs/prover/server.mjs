// STUB prover service. Implements the HTTP contract in docs/backend-api.md so the demo
// runs end to end. It does NOT create a zero-knowledge proof: the `proof` field is a
// marker. Replace this container with the Longfellow prover service.
//
// What it does for real: holds a demo nym_auth holder (birth_date, secret_seed, ssc,
// device key), checks the PIN, evaluates age_check, derives the pseudonym with
// pseudonym-v1-sha256, and returns base64url(CBOR(CircuitZkPresentation)).

import { createServer } from 'node:http'
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto'
import { encode, Tag } from 'cbor-x'

const PORT = Number(process.env.PORT ?? 8081)
const PIN = process.env.DEMO_PIN ?? '123456'
const CIRCUITS = [{ circuit_id: 'urn:circuits:longfellow:nym_auth:v1', proof_system: 'longfellow-libzk-v1' }]
const DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest()

const seed = Buffer.from(process.env.DEMO_SECRET_SEED ?? '9f3c1a6e5b27d8044c0e7a1f62b9d351', 'hex')
const deviceKey = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const deviceJwk = deviceKey.publicKey.export({ format: 'jwk' })
const jwkThumbprint = createHash('sha256')
  .update(JSON.stringify({ crv: deviceJwk.crv, kty: deviceJwk.kty, x: deviceJwk.x, y: deviceJwk.y }))
  .digest('base64url')
const now = new Date()
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

const holder = {
  id: 'demo-persona',
  birth_date: process.env.DEMO_BIRTH_DATE ?? '2011-03-14',
  ssc: sha256(seed).toString('hex'),
  signed: iso(new Date(now.getTime() - 30 * 86_400_000)),
  validFrom: iso(new Date(now.getTime() - 30 * 86_400_000)),
  validUntil: iso(new Date(now.getTime() + 335 * 86_400_000)),
}

function credentialView() {
  return {
    docType: DOCTYPE,
    namespace: DOCTYPE,
    title: 'Age and pseudonym',
    encoding: 'ISO/IEC 18013-5 mdoc',
    compactProfile: true,
    issuer: { name: 'Demo Issuer', country: 'SE', documentSigner: 'CN=Demo Document Signer, O=Demo Issuer, C=SE' },
    validity: { signed: holder.signed, validFrom: holder.validFrom, validUntil: holder.validUntil },
    attributes: {
      birth_date: holder.birth_date,
      ssc: holder.ssc,
      psc: null,
    },
    mso: { digestAlgorithm: 'SHA-256', signatureAlgorithm: 'ES256' },
    deviceKey: { kty: 'EC', crv: 'P-256', jwkThumbprint, protection: 'Software key in the stub. A real wallet uses the phone\'s secure hardware.' },
  }
}

function ageHolds(params) {
  const b = holder.birth_date
  return (!params.ge || b >= params.ge) && (!params.le || b <= params.le)
}

function prove(body) {
  const t0 = performance.now()
  if (body.pin !== PIN) return [401, { error: 'invalid_pin' }]
  if (!CIRCUITS.some((c) => c.circuit_id === body.circuit_id)) return [400, { error: 'unsupported_circuit' }]
  const q = body.request?.dcql_query?.credentials?.find((c) => c.id === body.credential_query_id)
  if (!q || q.meta?.doctype_value !== DOCTYPE) return [400, { error: 'unsupported_request' }]

  const results = {}
  const decoded = {}
  for (const r of q.req) {
    if (r.id === 'pseudonym-v1-sha256') {
      if (r.params.config !== 'known-offender-matching-ssc') return [400, { error: 'unsupported_config' }]
      const nym = sha256(Buffer.from(`nym_auth/v1/${r.params.config}`), seed, Buffer.alloc(32), sha256(Buffer.from(body.handover.client_id)))
      results[r.return] = nym
      decoded[r.return] = nym.toString('hex')
    } else if (r.id === 'age_check') {
      if (!ageHolds(r.params)) return [422, { error: 'unsatisfiable' }]
      results[r.return] = true
      decoded[r.return] = true
    } else {
      return [400, { error: 'unsupported_function' }]
    }
  }

  const proof = Buffer.from('STUB-NO-PROOF')
  const presentation = encode({
    circuit_id: body.circuit_id,
    proof,
    issuer_key_set: [randomBytes(16)],
    proof_time: new Tag(iso(new Date()), 0),
    results,
  })
  const b64 = Buffer.from(presentation).toString('base64url')
  const ms = performance.now() - t0
  return [200, {
    circuit_id: body.circuit_id,
    presentation: b64,
    results: decoded,
    metrics: { prove_ms: +ms.toFixed(2), total_ms: +ms.toFixed(2), proof_bytes: proof.length, presentation_bytes: presentation.length },
  }]
}

function send(res, status, json) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(json))
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')
  if (req.method === 'GET' && url.pathname === '/info') {
    return send(res, 200, { service: 'prover', implementation: 'Stub prover (no zero-knowledge proof)', version: '0.1.0', stub: true, circuits: CIRCUITS })
  }
  if (req.method === 'GET' && url.pathname === `/holders/${holder.id}/credentials/nym_auth`) return send(res, 200, credentialView())
  if (req.method === 'POST' && url.pathname === '/prove') {
    let raw = ''
    for await (const chunk of req) raw += chunk
    try {
      const [status, json] = prove(JSON.parse(raw))
      return send(res, status, json)
    } catch {
      return send(res, 400, { error: 'bad_request' })
    }
  }
  send(res, 404, { error: 'not_found' })
}).listen(PORT, () => console.log(`stub prover on :${PORT}`))
