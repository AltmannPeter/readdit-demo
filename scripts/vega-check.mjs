// Checks the Vega addon directly, without the site: real proofs of the wallet's two demo
// credentials, the pseudonym against an independent computation, and the verifier's refusals, each
// for its own reason. Run after `npm run build:native`:   node scripts/vega-check.mjs
//
// Checks (exit 1 if any fails):
//   G1  for each credential, a login presentation proves and verifies;
//   G2  for each credential, the verified pseudonym equals SHA-256("nym_auth/v1/known-offender-matching-ssc" ‖ seed ‖ 0x00×32 ‖ SHA-256(client_id)),
//       computed here with node:crypto, and is the same at two logins; the two credentials' pseudonyms differ;
//   G3  the verifier refuses, with the expected code and input: a flipped proof byte, a changed results.nym,
//       a handover with another nonce, a proof_time outside the tolerance, a changed proof_time, other age bounds;
//   G4  the prover takes no PIN: sign inputs with two different PINs both sign, and both proofs
//       verify; the adult credential proves 18+, and the 18+ request refuses the teen with 422 unsatisfiable.
import { createRequire } from 'node:module'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const require = createRequire(import.meta.url)
const addon = require(`${root}native/vega/community-vega.node`)
const [teen, adult] = JSON.parse(readFileSync(`${root}app/wallet/demo-wallet.json`, 'utf8')).holders
const SHAPES = `${root}native/vega/circuits/mdoc/shapes.zst`
const ANCHORS = readFileSync(`${root}native/vega/demo/document-signer.pem`, 'utf8')
const HOST = 'community.example'
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
  const _req = [{ fn_id: 'pseudonym', return: 'nym', params: { config: 'known-offender-matching-ssc', ver: 1, prf: 'sha-256' } }]
  if (age) _req.push({ fn_id: 'age_check', return: 'age', params: { ...age } })
  const session = randomBytes(16).toString('hex')
  return {
    aud: 'https://self-issued.me/v2',
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: `http://localhost:3000/api/vp/response/${session}`,
    client_id: CLIENT_ID,
    nonce,
    state: randomBytes(16).toString('hex'),
    dcql_query: { credentials: [{ id: 'nym_attestation', format: 'zkp_req', meta: { source_format: 'mso_mdoc', doctype_value: DOCTYPE }, _req }] },
    client_metadata: { client_name: 'Community', vp_formats_supported: { zkp_req: { proof_system_values: ['vega-v1'], system_id_values: [CIRCUIT] } } },
  }
}
const handoverOf = (r) => ({ client_id: r.client_id, nonce: r.nonce, response_uri: r.response_uri, jwk_thumbprint: null })

let t = performance.now()
const prover = await addon.loadProver(SHAPES)
const proverLoad = performance.now() - t
t = performance.now()
const verifier = await addon.loadVerifier(SHAPES, ANCHORS, 300)
const verifierLoad = performance.now() - t
console.log(`load: prover ${proverLoad.toFixed(0)} ms, verifier ${verifierLoad.toFixed(0)} ms (wall, includes the addon's own load_ms ${JSON.parse(prover.info).load_ms} / ${JSON.parse(verifier.info).load_ms})`)

/** Step 1 with `wallet`'s device key; `extra` adds fields to the input (a PIN, which the prover does not read). */
async function sign(r, wallet, extra = {}) {
  return JSON.parse(await prover.sign(JSON.stringify({ ...extra, device_key: wallet.device_key, doc_type: DOCTYPE, handover: handoverOf(r) })))
}

async function present(r, wallet = teen, extra = {}) {
  const s = await sign(r, wallet, extra)
  if (!s.ok) return s
  const w = await prover.witness(JSON.stringify({
    system_id: CIRCUIT, credential_query_id: 'nym_attestation', request: r, handover: handoverOf(r),
    credential: wallet.credential, secret_seed: wallet.secret_seed, device_signature: s.device_signature,
  }))
  if (typeof w === 'string') return JSON.parse(w)
  return JSON.parse(await prover.prove(w))
}

async function verify(r, presentation, { handover = handoverOf(r), now = new Date().toISOString() } = {}) {
  return JSON.parse(await verifier.verify(JSON.stringify({ request: r, credential_query_id: 'nym_attestation', presentation, handover, now })))
}

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest()
const nymOf = (wallet) =>
  sha256(Buffer.from('nym_auth/v1/known-offender-matching-ssc'), Buffer.from(wallet.secret_seed, 'hex'), Buffer.alloc(32), sha256(Buffer.from(CLIENT_ID))).toString('hex')
const expectedNym = nymOf(teen)

// G1 + G2: two logins with each credential.
const verified = {}
for (const [name, wallet] of [['teen', teen], ['adult', adult]]) {
  const nyms = []
  for (const i of [1, 2]) {
    const r = request(undefined)
    const p = await present(r, wallet)
    check(`G1 ${name} login ${i}: proof created`, p.ok === true, p.ok ? `witness ${p.metrics.witness_ms} ms, prove ${p.metrics.prove_ms} ms, proof ${p.metrics.proof_bytes} B, presentation ${p.metrics.presentation_bytes} B, peak ${p.metrics.peak_memory_mb} MB` : JSON.stringify(p))
    if (!p.ok) continue
    const v = await verify(r, p.presentation)
    check(`G1 ${name} login ${i}: verified`, v.ok === true, v.ok ? `verify ${v.metrics.verify_ms} ms` : `${v.code} ${v.input ?? ''} ${v.reason}`)
    check(`G1 ${name} login ${i}: no age key in results`, v.ok && Object.keys(v.results).join() === 'nym', JSON.stringify(v.results))
    nyms.push(v.results?.nym)
  }
  check(`G2 ${name} pseudonym = independent SHA-256 derivation`, nyms[0] === nymOf(wallet), `${nyms[0]} vs ${nymOf(wallet)}`)
  check(`G2 ${name} same pseudonym at two logins`, nyms.length === 2 && nyms[0] === nyms[1])
  verified[name] = nyms[0]
}
check('G2 the two credentials give different pseudonyms', verified.teen && verified.adult && verified.teen !== verified.adult, `${verified.teen?.slice(0, 16)}… vs ${verified.adult?.slice(0, 16)}…`)

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
  return { ...req, dcql_query: { credentials: [{ ...q, _req: [q._req[0], { fn_id: 'age_check', return: 'age', params: age }] }] } }
}
expectRefusal('G3e other age bound ge (one day later)', await verify(withAge(r, { ge: plusDays(TEEN.ge, 1), le: TEEN.le }), p.presentation), 'public_input', 'age_check.ge')
expectRefusal('G3e other age bound le (one day earlier)', await verify(withAge(r, { ge: TEEN.ge, le: plusDays(TEEN.le, -1) }), p.presentation), 'public_input', 'age_check.le')

// G4 at the addon: any PIN signs (the prover takes none), and the 18+ community.
for (const pin of ['000000', '987654']) {
  const r4 = request(undefined)
  const p4 = await present(r4, teen, { pin })
  const v4 = p4.ok ? await verify(r4, p4.presentation) : p4
  check(`G4 PIN ${pin}: signs, and the proof verifies`, v4.ok === true && v4.results?.nym === expectedNym, v4.ok ? `nym ${v4.results.nym.slice(0, 16)}…` : JSON.stringify(v4))
}
const rAdult = request(ADULT)
const pAdult = await present(rAdult, adult)
const vAdult = pAdult.ok ? await verify(rAdult, pAdult.presentation) : pAdult
check('G4 18+ request, adult credential: proves, verifies, age true', vAdult.ok === true && vAdult.results.age === true && vAdult.results.nym === nymOf(adult), JSON.stringify(vAdult.results ?? vAdult))
const teen18 = await present(request(ADULT), teen)
check('G4 18+ request, teen credential: 422 unsatisfiable', teen18.ok === false && teen18.status === 422 && teen18.error === 'unsatisfiable', JSON.stringify(teen18))

// G5: rulebook v0.5's request side on the v0.4 circuit and credential (the v0.5 circuits over bsc
// and psc are not here yet): age_check is an assertion with a range in years, and both sides
// compute the bounds from the UTC date of proof_time.
{
  const v05 = (range) => {
    const req = request(TEEN)
    const q = req.dcql_query.credentials[0]
    return { ...req, dcql_query: { credentials: [{ ...q, _req: [q._req[0], { fn_id: 'age_check', params: { range } }] }] } }
  }
  const present05 = async (r5, wallet = teen) => {
    const s5 = await sign(r5, wallet)
    const w = await prover.witness(JSON.stringify({
      system_id: CIRCUIT, credential_query_id: 'nym_attestation', request: r5, handover: handoverOf(r5),
      credential: wallet.credential, secret_seed: wallet.secret_seed, device_signature: s5.device_signature, rulebook: '0.5',
    }))
    if (typeof w === 'string') return JSON.parse(w)
    return JSON.parse(await prover.prove(w))
  }
  const verify05 = async (r5, presentation, rulebook = '0.5') =>
    JSON.parse(await verifier.verify(JSON.stringify({ request: r5, credential_query_id: 'nym_attestation', presentation, handover: handoverOf(r5), now: new Date().toISOString(), rulebook })))
  const r5 = v05('13-17')
  const p5 = await present05(r5)
  const v5 = p5.ok ? await verify05(r5, p5.presentation) : p5
  check('G5 v0.5 13-17: proves and verifies, no age output', v5.ok === true && Object.keys(v5.results).join() === 'nym' && v5.results.nym === expectedNym, JSON.stringify(v5.results ?? v5))
  check('G5 v0.5 bounds from the date of proof_time', v5.bounds?.ge === TEEN.ge && v5.bounds?.le === TEEN.le, JSON.stringify(v5.bounds))
  const t18 = await present05(v05('18+'))
  check('G5 v0.5 18+, teen: 422 unsatisfiable', t18.ok === false && t18.status === 422, JSON.stringify(t18))
  const a18 = await present05(v05('18+'), adult)
  const va = a18.ok ? await verify05(v05('18+'), a18.presentation) : a18
  check('G5 v0.5 18+, adult: proves; another request (nonce) does not verify', a18.ok === true && va.ok === false, JSON.stringify(va.code ?? va))
  expectRefusal('G5 v0.5 presentation read as v0.4', await verify05(r5, p5.presentation, '0.4'), 'request')
}

console.log(failures ? `${failures} check(s) failed` : 'all checks passed')
process.exit(failures ? 1 : 0)
