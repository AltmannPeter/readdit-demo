// Checks the Vega addon directly, without the site: real proofs of the demo credential, the
// pseudonym against an independent computation, and the verifier's refusals, each for its own
// reason. Run after `npm run build:native`:   node scripts/vega-check.mjs
//
// Checks (exit 1 on the first failure):
//   G1  a login presentation proves and verifies;
//   G2  the verified pseudonym equals SHA-256("nym_auth/v1/known-offender-matching-ssc" ‖ seed ‖ 0x00×32 ‖ SHA-256(client_id)),
//       computed here with node:crypto, and is the same at two logins;
//   G3  the verifier refuses, with the expected code and input: a flipped proof byte, a changed results.nym,
//       a handover with another nonce, a proof_time outside the tolerance, a changed proof_time, other age bounds;
//   G4  a wrong PIN gets 401 invalid_pin; an 18+ request for the persona gets 422 unsatisfiable.
import { createRequire } from 'node:module'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const require = createRequire(import.meta.url)
const addon = require(`${root}native/vega/readdit-vega.node`)
const wallet = JSON.parse(readFileSync(`${root}app/wallet/demo-wallet.json`, 'utf8'))
const SHAPES = `${root}native/vega/circuits/mdoc/shapes.zst`
const ANCHORS = readFileSync(`${root}native/vega/demo/document-signer.pem`, 'utf8')
const HOST = 'readdit.example'
const CLIENT_ID = `x509_san_dns:${HOST}`
const CIRCUIT = 'urn:circuits:vega:nym_auth:v1'
const DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'

let failures = 0
const check = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
  if (!ok) failures++
}

// Birth-date bounds of an age gate, as shared/utils/age.ts defines them: minAge N -> le = today − N years;
// maxAge N -> ge = today − (N + 1) years + 1 day.
const pad = (n) => String(n).padStart(2, '0')
const today = new Date().toISOString().slice(0, 10)
const minusYears = (iso, y) => {
  const [Y, M, D] = iso.split('-').map(Number)
  const last = new Date(Date.UTC(Y - y, M, 0)).getUTCDate()
  return `${Y - y}-${pad(M)}-${pad(Math.min(D, last))}`
}
const plusDays = (iso, d) => new Date(Date.parse(`${iso}T00:00:00Z`) + d * 86_400_000).toISOString().slice(0, 10)
const TEEN = { ge: plusDays(minusYears(today, 18), 1), le: minusYears(today, 13) }
const ADULT = { le: minusYears(today, 18) }

function request(age, nonce = randomBytes(16).toString('hex')) {
  const req = [{ id: 'pseudonym-v1-sha256', return: 'nym', params: { config: 'known-offender-matching-ssc', verifier_id_type: 'x509_san_dns' } }]
  if (age) req.push({ id: 'age_check', return: 'age', params: { ...age } })
  const session = randomBytes(16).toString('hex')
  return {
    aud: 'https://self-issued.me/v2',
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: `http://localhost:3000/api/vp/response/${session}`,
    client_id: CLIENT_ID,
    nonce,
    state: randomBytes(16).toString('hex'),
    dcql_query: { credentials: [{ id: 'nym_attestation', format: 'circuit_zk', meta: { doctype_value: DOCTYPE }, req }] },
    client_metadata: { client_name: 'Readdit', vp_formats_supported: { circuit_zk: { circuit_proof_system_values: ['vega-v1'], circuit_id_values: [CIRCUIT] } } },
  }
}
const handoverOf = (r) => ({ client_id: r.client_id, nonce: r.nonce, response_uri: r.response_uri, jwk_thumbprint: null })

let t = performance.now()
const prover = await addon.loadProver(SHAPES, '123456')
const proverLoad = performance.now() - t
t = performance.now()
const verifier = await addon.loadVerifier(SHAPES, ANCHORS, 300)
const verifierLoad = performance.now() - t
console.log(`load: prover ${proverLoad.toFixed(0)} ms, verifier ${verifierLoad.toFixed(0)} ms (wall, includes the addon's own load_ms ${JSON.parse(prover.info).load_ms} / ${JSON.parse(verifier.info).load_ms})`)

async function sign(r, pin = '123456') {
  return JSON.parse(await prover.sign(JSON.stringify({ pin, device_key: wallet.device_key, doc_type: DOCTYPE, handover: handoverOf(r) })))
}

async function present(r) {
  const s = await sign(r)
  if (!s.ok) return s
  const w = await prover.witness(JSON.stringify({
    circuit_id: CIRCUIT, credential_query_id: 'nym_attestation', request: r, handover: handoverOf(r),
    credential: wallet.credential, secret_seed: wallet.secret_seed, device_signature: s.device_signature,
  }))
  if (typeof w === 'string') return JSON.parse(w)
  return JSON.parse(await prover.prove(w))
}

async function verify(r, presentation, { handover = handoverOf(r), now = new Date().toISOString() } = {}) {
  return JSON.parse(await verifier.verify(JSON.stringify({ request: r, credential_query_id: 'nym_attestation', presentation, handover, now })))
}

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest()
const expectedNym = sha256(
  Buffer.from('nym_auth/v1/known-offender-matching-ssc'),
  Buffer.from(wallet.secret_seed, 'hex'),
  Buffer.alloc(32),
  sha256(Buffer.from(CLIENT_ID)),
).toString('hex')

// G1 + G2: two logins.
const nyms = []
for (const i of [1, 2]) {
  const r = request(undefined)
  const p = await present(r)
  check(`G1 login ${i}: proof created`, p.ok === true, p.ok ? `witness ${p.metrics.witness_ms} ms, prove ${p.metrics.prove_ms} ms, proof ${p.metrics.proof_bytes} B, presentation ${p.metrics.presentation_bytes} B, peak ${p.metrics.peak_memory_mb} MB` : JSON.stringify(p))
  if (!p.ok) continue
  const v = await verify(r, p.presentation)
  check(`G1 login ${i}: verified`, v.ok === true, v.ok ? `verify ${v.metrics.verify_ms} ms` : `${v.code} ${v.input ?? ''} ${v.reason}`)
  check(`G1 login ${i}: no age key in results`, v.ok && Object.keys(v.results).join() === 'nym', JSON.stringify(v.results))
  nyms.push(v.results?.nym)
}
check('G2 pseudonym = independent SHA-256 derivation', nyms[0] === expectedNym, `${nyms[0]} vs ${expectedNym}`)
check('G2 same pseudonym at two logins', nyms.length === 2 && nyms[0] === nyms[1])

// G3: tamper with a teenspace presentation.
const r = request(TEEN)
const p = await present(r)
check('G3 teenspace (13–17) proof created', p.ok === true, p.ok ? `age bounds ge ${TEEN.ge}, le ${TEEN.le}` : JSON.stringify(p))
const honest = await verify(r, p.presentation)
check('G3 honest presentation verifies with age true', honest.ok === true && honest.results.age === true, JSON.stringify(honest.results ?? honest))

const bytes = Buffer.from(p.presentation, 'base64url')
const b64 = (b) => Buffer.from(b).toString('base64url')
const flipAt = (buf, i, mask = 0x01) => {
  const out = Buffer.from(buf)
  out[i] ^= mask
  return out
}
const expectRefusal = (name, v, code, input) =>
  check(name, v.ok === false && v.code === code && (input === undefined || v.input === input), v.ok ? 'accepted' : `${v.code} ${v.input ?? ''}: ${v.reason}`)

// a. a flipped byte in the proof: the proof bstr's head is 5a + u32 length.
const proofLen = p.metrics.proof_bytes
const head = Buffer.from([0x5a, (proofLen >>> 24) & 255, (proofLen >>> 16) & 255, (proofLen >>> 8) & 255, proofLen & 255])
const proofAt = bytes.indexOf(head) + head.length
check('G3 proof located in the presentation', proofAt > head.length - 1)
const flips = {}
for (const k of [0.1, 0.3, 0.5, 0.7, 0.9, 0.999]) {
  const v = await verify(r, b64(flipAt(bytes, proofAt + Math.floor(k * proofLen))))
  flips[v.ok ? 'accepted' : v.code] = (flips[v.ok ? 'accepted' : v.code] ?? 0) + 1
}
check('G3a flipped proof byte (6 offsets): all refused as proof_invalid or proof_encoding', !flips.accepted && Object.keys(flips).every((c) => c === 'proof_invalid' || c === 'proof_encoding'), JSON.stringify(flips))
check('G3a at least one flip reaches the SNARK check (proof_invalid)', (flips.proof_invalid ?? 0) > 0, JSON.stringify(flips))

// b. a changed results.nym.
const nymAt = bytes.indexOf(Buffer.from(honest.results.nym, 'hex'))
expectRefusal('G3b changed results.nym', await verify(r, b64(flipAt(bytes, nymAt + 31))), 'public_input', 'results.nym')

// c. a handover with another nonce (the verifier's session holds another nonce).
const other = { ...r, nonce: randomBytes(16).toString('hex') }
expectRefusal('G3c handover with another nonce', await verify(other, p.presentation), 'public_input', 'session_transcript')

// d. proof_time outside the tolerance (300 s), and a proof_time changed within it.
expectRefusal('G3d proof_time outside tolerance (now + 10 min)', await verify(r, p.presentation, { now: new Date(Date.now() + 600_000).toISOString() }), 'proof_time')
const tdate = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/.exec(bytes.toString('latin1'))
const tAt = tdate.index + tdate[0].length - 2 // the last digit of the seconds
const shifted = Buffer.from(bytes)
shifted[tAt] = shifted[tAt] === 0x30 ? 0x31 : shifted[tAt] - 1
expectRefusal('G3d proof_time changed by one second (within tolerance)', await verify(r, b64(shifted)), 'public_input', 'proof_time')

// e. other age bounds than the request's: the same session (nonce, response_uri) asking for another range.
const withAge = (req, age) => {
  const q = req.dcql_query.credentials[0]
  return { ...req, dcql_query: { credentials: [{ ...q, req: [q.req[0], { id: 'age_check', return: 'age', params: age }] }] } }
}
expectRefusal('G3e other age bound ge (one day later)', await verify(withAge(r, { ge: plusDays(TEEN.ge, 1), le: TEEN.le }), p.presentation), 'public_input', 'age_check.ge')
expectRefusal('G3e other age bound le (one day earlier)', await verify(withAge(r, { ge: TEEN.ge, le: plusDays(TEEN.le, -1) }), p.presentation), 'public_input', 'age_check.le')

// G4 at the addon: a wrong PIN, and the 18+ community.
const wrong = await sign(request(undefined), '000000')
check('G4 wrong PIN refused 401 invalid_pin', wrong.ok === false && wrong.status === 401 && wrong.error === 'invalid_pin', JSON.stringify(wrong))
const adult = await present(request(ADULT))
check('G4 18+ request: 422 unsatisfiable', adult.ok === false && adult.status === 422 && adult.error === 'unsatisfiable', JSON.stringify(adult))

console.log(failures ? `${failures} check(s) failed` : 'all checks passed')
process.exit(failures ? 1 : 0)
