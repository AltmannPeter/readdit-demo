// Terminal benchmark: N presentations per cell through the mocked phone's own routes (sign, prove,
// the encrypted response), against a running site, then the Benchmark's figures for exactly those
// runs (GET /api/tech/measurements?since=…, grouped and summarised as /tech groups them). The runs
// are recorded like any other, so /tech's Benchmark shows them too. `--help` lists the flags.
//
//   npm run bench -- --runs 10 --profile nym-auth-v0.6 --system longfellow --threads 1,all --age 13-17

import { readFileSync, writeFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { fileURLToPath } from 'node:url'
import { createJiti } from 'jiti'
import { CompactEncrypt, importJWK } from 'jose'

const HELP = `npm run bench -- [flags]          (or: node scripts/bench.mjs [flags])

Runs presentations against a running Community site and prints the Benchmark's figures for
exactly those runs: prove and verify time (median, min-max), the time by step, proof and
presentation size, prover and verifier memory. The runs also appear in /tech's Benchmark.

  --base URL        the site (default http://localhost:3000)
  --runs N          measured runs per cell (default 10)
  --warmup N        unmeasured runs first, per cell (default 1)
  --profile ID      demo profile: nym-auth-v0.4, nym-auth-v0.5, nym-auth-v0.6
                    (default: the one the site runs; switching resets the demo)
  --system LIST     vega, longfellow, bbs, comma-separated (default: every system the profile
                    can use)
  --threads LIST    1, all, or 1,all (default 1,all)
  --age VALUE       none, 13-17 or 18+ (default none: the pseudonym only)
  --phone NAME      teen or adult (default teen; bbs is the teen's BBS credential)
  --profiling       run with /tech's Profiling on (a few percent slower; adds flame graphs)
  --out FILE        also write every measured run: .json (the full records) or .csv
  -h, --help        this text

Each cell is one profile × system × thread count. The script sets /tech's switches for each
cell and puts them back at the end (profile, accepted proof systems, multithreading, Profiling).
`

// ---- flags ----
const argv = process.argv.slice(2)
const flags = {}
for (let i = 0; i < argv.length; i++) {
  const a = argv[i]
  if (a === '-h' || a === '--help') flags.help = true
  else if (a === '--profiling') flags.profiling = true
  else if (a.startsWith('--')) {
    const [k, v] = a.includes('=') ? [a.slice(2, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a.slice(2), argv[++i]]
    if (v === undefined) fail(`--${k} needs a value`)
    flags[k] = v
  } else fail(`unknown argument ${a}`)
}
if (flags.help) {
  process.stdout.write(HELP)
  process.exit(0)
}
function fail(m) {
  console.error(`bench: ${m}\n\n${HELP}`)
  process.exit(2)
}
const known = new Set(['base', 'runs', 'warmup', 'profile', 'system', 'threads', 'age', 'phone', 'out', 'help', 'profiling'])
for (const k of Object.keys(flags)) if (!known.has(k)) fail(`unknown flag --${k}`)
const BASE = (flags.base ?? 'http://localhost:3000').replace(/\/$/, '')
const RUNS = Number(flags.runs ?? 10)
const WARMUP = Number(flags.warmup ?? 1)
if (!Number.isInteger(RUNS) || RUNS < 1) fail('--runs must be a whole number of at least 1')
if (!Number.isInteger(WARMUP) || WARMUP < 0) fail('--warmup must be a whole number')
const SYSTEMS = { vega: 'vega-v1', longfellow: 'longfellow-libzk-v1', bbs: 'bbs-cd-plugins-v0.1' }
const AGES = { none: 'none', '13-17': 'range13to17', '18+': 'over18' }
const age = flags.age ?? 'none'
if (!AGES[age]) fail('--age is none, 13-17 or 18+')
const phone = flags.phone ?? 'teen'
if (phone !== 'teen' && phone !== 'adult') fail('--phone is teen or adult')
const threadsList = (flags.threads ?? '1,all').split(',').map((t) => t.trim())
if (!threadsList.length || threadsList.some((t) => t !== '1' && t !== 'all')) fail('--threads is 1, all, or 1,all')
if (flags.out && !/\.(json|csv)$/i.test(flags.out)) fail('--out must end in .json or .csv')

// ---- the site's own code and the demo wallet ----
const root = fileURLToPath(new URL('../', import.meta.url))
const jiti = createJiti(import.meta.url)
const { findSystem } = await jiti.import(`${root}shared/registry/circuits.ts`)
const { encryptCwt, encodeAuthorizationResponse, CWT_CONTENT_TYPE } = await jiti.import(`${root}shared/utils/cwt.ts`)
const [teen, adult] = JSON.parse(readFileSync(`${root}app/wallet/demo-wallet.json`, 'utf8')).holders
const [teenBbs] = JSON.parse(readFileSync(`${root}app/wallet/demo-wallet-bbs.json`, 'utf8')).holders

// ---- HTTP with one cookie jar (the site ties a session to the browser that started it) ----
let cookie = ''
async function call(method, path, { json, form, body, headers = {} } = {}) {
  const h = { ...headers, ...(cookie && { cookie }) }
  let payload = body
  if (json !== undefined) {
    h['content-type'] = 'application/json'
    payload = JSON.stringify(json)
  } else if (form !== undefined) {
    h['content-type'] = 'application/x-www-form-urlencoded'
    payload = new URLSearchParams(form).toString()
  }
  let res
  try {
    res = await fetch(path.startsWith('http') ? path : BASE + path, { method, headers: h, body: payload })
  } catch (e) {
    console.error(`bench: cannot reach ${BASE} (${e.cause?.code ?? e.message}). Is the site running? --base sets its address.`)
    process.exit(1)
  }
  const set = res.headers.getSetCookie?.() ?? []
  if (set.length) cookie = [...new Map([...cookie.split('; ').filter(Boolean), ...set.map((c) => c.split(';')[0])].map((c) => [c.split('=')[0], c])).values()].join('; ')
  const text = await res.text()
  let data = text
  try {
    data = JSON.parse(text)
  } catch {
    /* a JWS, or text */
  }
  return { status: res.status, data, text, code: data?.data?.error }
}
const must = async (what, p) => {
  const r = await p
  if (r.status >= 300) throw new Error(`${what}: ${r.status}${r.code ? ` ${r.code}` : ''}${r.data?.statusMessage ? ` (${r.data.statusMessage})` : ''}`)
  return r
}

// ---- one presentation, as the demo phone makes it ----
const credentialFor = (version, holder) => (version === '0.5' ? holder.v05 : version === '0.6' ? holder.v06 : { credential: holder.credential })

async function present(cell) {
  const { version, proofSystem, ids } = cell
  const s = (await must('session', call('POST', '/api/vp/session', { json: { purpose: 'dev', age: AGES[age] } }))).data
  const uri = new URLSearchParams(s.authorizationUrl.slice(s.authorizationUrl.indexOf('?') + 1)).get('request_uri')
  const meta = { vp_formats_supported: { zkp_req: { proof_system_values: [proofSystem], system_id_values: ids } } }
  const jws = (await must('request_uri', call('POST', uri, { form: { wallet_nonce: crypto.randomUUID(), wallet_metadata: JSON.stringify(meta) } }))).text.trim()
  const req = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString())
  const offered = req.client_metadata?.vp_formats_supported?.zkp_req?.system_id_values ?? []
  const systemId = offered.find((id) => findSystem(id)?.proof_system === proofSystem)
  if (!systemId) throw new Error(`the site offers no ${proofSystem} system under this profile (${offered.join(', ') || 'none'})`)
  let presentation, queryId
  if (proofSystem === SYSTEMS.bbs) {
    queryId = req.dcql_query.credentials.find((q) => q.meta.source_format === 'bbs_cd').id
    const p = await must('prove', call('POST', '/api/wallet/prove', { json: { request: req, credential_query_id: queryId, credential: teenBbs.credential, device_key: teenBbs.device_key, ...(version !== '0.4' && { rulebook: version }) } }))
    presentation = p.data.presentation
  } else {
    const holder = phone === 'adult' ? adult : teen
    const held = credentialFor(version, holder)
    if (!held?.credential) throw new Error(`the ${phone}'s phone has no v${version} mdoc`)
    queryId = req.dcql_query.credentials.find((q) => q.meta.source_format === 'mso_mdoc').id
    const sg = await must('sign', call('POST', '/api/wallet/sign', { json: { request: req, system_id: systemId, device_key: holder.device_key } }))
    const p = await must('prove', call('POST', '/api/wallet/prove', {
      json: { request: req, credential_query_id: queryId, system_id: systemId, credential: held.credential, secret_seed: holder.secret_seed, ...(held.birth_date && { birth_date: held.birth_date }), device_signature: sg.data.device_signature, ...(version !== '0.4' && { rulebook: version }) },
    }))
    presentation = p.data.presentation
  }
  // The response in the Response Mode the request asks for.
  const body = { state: req.state, vp_token: { [queryId]: [presentation] } }
  const jwk = req.client_metadata.jwks.keys[0]
  if (req.response_mode === 'direct_post.cwt') {
    const { bytes } = await encryptCwt(encodeAuthorizationResponse(body), jwk)
    await must('response_uri', call('POST', req.response_uri, { body: Buffer.from(bytes), headers: { 'content-type': CWT_CONTENT_TYPE } }))
  } else {
    const jwe = await new CompactEncrypt(Buffer.from(JSON.stringify(body))).setProtectedHeader({ alg: jwk.alg, enc: 'A128GCM', kid: jwk.kid }).encrypt(await importJWK(jwk, jwk.alg))
    await must('response_uri', call('POST', req.response_uri, { form: { response: jwe } }))
  }
  const v = (await must('session status', call('GET', `/api/vp/session/${s.id}`))).data
  if (v.status !== 'verified') throw new Error(`the presentation was not verified: ${v.status}${v.failure ? ` (${v.failure}; the server log names the rule)` : ''}`)
}

// ---- printing ----
const ms = (x) => (x == null ? '–' : x >= 1000 ? `${(x / 1000).toFixed(2)} s` : `${x < 10 ? x.toFixed(1) : Math.round(x)} ms`)
const spread = (s, f = ms) => (s ? `${f(s.median)}  (${f(s.min)}–${f(s.max)})` : '–')
const bytes = (b) => (b == null ? '–' : `${Math.round(b).toLocaleString('en-GB')} B`)
const mb = (x) => (x == null ? '–' : `${x.toFixed(1)} MB`)
const steps = (list) => (list?.length ? list.map((s) => `${s.name} ${ms(s.ms)}`).join(' · ') : '')
function printRow(r) {
  console.log(`  prove    ${spread(r.prove).padEnd(26)}${steps(r.steps.prove)}`)
  console.log(`  verify   ${spread(r.verify).padEnd(26)}${steps(r.steps.verify)}`)
  console.log(`  size     proof ${spread(r.proof_bytes, bytes)} · presentation ${bytes(r.presentation_bytes?.median)}`)
  // As /tech's memory bars: prover = keys + witness + work, verifier = keys + work (medians).
  const m = r.memory
  const sum = (...xs) => (xs.every((x) => x == null) ? null : xs.reduce((t, x) => t + (x ?? 0), 0))
  console.log(`  memory   prover ${mb(sum(m.prove.keys_mb, m.prove.witness_mb, m.prove.work_mb))} = keys ${mb(m.prove.keys_mb)} + witness ${mb(m.prove.witness_mb)} + work ${mb(m.prove.work_mb)} · verifier ${mb(sum(m.verify.keys_mb, m.verify.work_mb))} = keys ${mb(m.verify.keys_mb)} + work ${mb(m.verify.work_mb)}`)
}

// ---- the run ----
const overview = async () => (await must('overview', call('GET', '/api/tech/overview'))).data
const before = await overview()
const profileId = flags.profile ?? before.profile
const manifest = before.profiles.find((p) => p.id === profileId)
if (!manifest) fail(`--profile ${profileId}: the site has ${before.profiles.map((p) => p.id).join(', ')}`)
const version = manifest.version
const available = (manifest.systems ?? []).filter((s) => s.status === 'available').map((s) => s.proof_system)
const wanted = flags.system ? flags.system.split(',').map((s) => s.trim()) : Object.keys(SYSTEMS).filter((k) => available.includes(SYSTEMS[k]))
for (const s of wanted) {
  if (!SYSTEMS[s]) fail(`--system ${s}: vega, longfellow or bbs`)
  if (!available.includes(SYSTEMS[s])) fail(`--system ${s}: ${manifest.label} cannot use it (${(manifest.systems ?? []).find((x) => x.proof_system === SYSTEMS[s])?.note ?? 'pending'})`)
}
if (phone === 'adult' && wanted.includes('bbs')) fail('--phone adult: there is no adult BBS credential')
const caps = (await must('capabilities', call('GET', '/api/wallet/capabilities'))).data
const idsOf = (ps) => [...(caps.circuits ?? []), ...(caps.schemes ?? [])].map((c) => c.system_id).filter((id) => findSystem(id)?.proof_system === ps)

const restore = async () => {
  if ((await overview()).profile !== before.profile) await call('POST', '/api/tech/demo-profile', { json: { profile: before.profile } })
  for (const ps of Object.values(SYSTEMS)) await call('POST', '/api/tech/accept', { json: { proof_system: ps, accept: before.acceptedProofSystems.includes(ps) } })
  await call('POST', '/api/tech/threads', { json: { parallel: before.multithreading } })
  await call('POST', '/api/tech/profiling', { json: { on: before.profiling } })
}
let interrupted = false
process.on('SIGINT', async () => {
  if (interrupted) process.exit(130)
  interrupted = true
  console.error('\nbench: interrupted; putting /tech back as it was')
  await restore()
  process.exit(130)
})

const cores = before.measurements?.machine?.cores ?? availableParallelism()
const machine = before.measurements?.machine
console.log(`${manifest.label} · ${machine ? `${machine.cpu}, ${machine.cores} cores, ${machine.platform}` : BASE} · ${RUNS} runs per cell (+${WARMUP} warm-up)`)
console.log(`statement: ${age === 'none' ? 'pseudonym' : `pseudonym and age ${age}`} · phone: ${phone}${flags.profiling ? ' · Profiling on' : ''}`)
if (profileId !== before.profile) console.log(`switching the site to ${profileId} (this resets the demo; it switches back at the end)`)

const results = []
const records = []
let failed = null
try {
  if (profileId !== before.profile) await must('demo profile', call('POST', '/api/tech/demo-profile', { json: { profile: profileId } }))
  await must('profiling', call('POST', '/api/tech/profiling', { json: { on: !!flags.profiling } }))
  for (const sys of wanted) {
    const proofSystem = SYSTEMS[sys]
    for (const ps of Object.values(SYSTEMS)) await must('accept', call('POST', '/api/tech/accept', { json: { proof_system: ps, accept: ps === proofSystem } }))
    for (const t of threadsList) {
      const parallel = t === 'all'
      await must('threads', call('POST', '/api/tech/threads', { json: { parallel } }))
      const cell = { version, proofSystem, ids: idsOf(proofSystem) }
      const label = `${sys} · ${parallel ? `${cores} threads` : '1 thread'}`
      process.stdout.write(`\n${label}: ${WARMUP} warm-up, then runs `)
      for (let k = 0; k < WARMUP; k++) await present(cell)
      const newest = (await must('measurements', call('GET', '/api/tech/measurements'))).data.newest
      const since = newest ? new Date(Date.parse(newest) + 1).toISOString() : new Date(0).toISOString()
      for (let k = 0; k < RUNS; k++) {
        await present(cell)
        process.stdout.write('.')
      }
      process.stdout.write(` ${RUNS}\n`)
      const m = (await must('measurements', call('GET', `/api/tech/measurements?since=${encodeURIComponent(since)}${flags.out ? '&raw=1' : ''}`))).data
      const rows = m.rows.filter((r) => r.proof_system === proofSystem)
      if (!rows.length) throw new Error(`no measurement recorded for ${label}`)
      for (const r of rows) {
        console.log(`${r.label} · ${r.statement} · ${r.threads ?? '?'} thread${r.threads === 1 ? '' : 's'} · ${r.runs} runs`)
        printRow(r)
        results.push({ system: sys, ...r })
      }
      if (flags.out) records.push(...(m.records ?? []).filter((x) => x.proof_system === proofSystem))
    }
  }
} catch (e) {
  failed = e
} finally {
  await restore()
}
if (failed) {
  const hint = /unsatisfiable/.test(failed.message) ? ` The ${phone}'s credential cannot prove that age: try --phone ${phone === 'teen' ? 'adult' : 'teen'} or another --age.` : ''
  console.error(`\nbench: ${failed.message}${hint}`)
  process.exit(1)
}

// ---- summary table and --out ----
if (results.length > 1) {
  console.log('\n| system | threads | runs | prove (median) | verify (median) | proof |')
  console.log('|---|---:|---:|---:|---:|---:|')
  for (const r of results) console.log(`| ${r.system} | ${r.threads} | ${r.runs} | ${ms(r.prove?.median)} | ${ms(r.verify?.median)} | ${bytes(r.proof_bytes?.median)} |`)
}
if (flags.out) {
  if (/\.json$/i.test(flags.out)) writeFileSync(flags.out, `${JSON.stringify({ profile: profileId, machine, rows: results, records }, null, 1)}\n`)
  else {
    const cols = ['at', 'profile', 'proof_system', 'statement', 'prove.threads', 'prove.total_ms', 'prove.sign_ms', 'prove.witness_ms', 'prove.prebuild_ms', 'prove.prove_ms', 'verify.total_ms', 'verify.verify_ms', 'prove.proof_bytes', 'prove.presentation_bytes', 'prove.heap_mb', 'prove.keys_mb', 'prove.witness_mb', 'verify.heap_mb', 'verify.keys_mb', 'profiled']
    const get = (o, path) => path.split('.').reduce((x, k) => x?.[k], o)
    const csv = [cols.join(','), ...records.map((r) => cols.map((c) => JSON.stringify(get(r, c) ?? '')).join(','))].join('\n')
    writeFileSync(flags.out, `${csv}\n`)
  }
  console.log(`\nwrote ${records.length} runs to ${flags.out}`)
}
