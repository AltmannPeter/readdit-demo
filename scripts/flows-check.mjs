// Drives every flow of the inventory against a running production build: in the browser where a
// person can reach the path, and over HTTP where only a client can (replay, tampering, malformed
// bodies, expiry, another browser). For each path it checks the product's state (the phone's
// screen, the site's dialog and page), the guide's step, the servers' answers (status and code),
// and that nothing carries over into the next path. Exits 1 on a failed check, or on a console
// error that is not one of the deliberate ones (ALLOWED, by status and route).
// scripts/demo-flow.mjs stays the presentation order and its screenshots.
//
// Two phones, one person each (app/wallet/holder.ts, PHONES): the teen's phone holds the teen's
// mdoc (born 2011) and the teen's BBS credential (mms_zk, used only when the site accepts BBS:
// group M), the adult's phone the adult's mdoc (born 1990).
//
// The site accepts no proof system after a demo reset (the demo's start). resetDemo() switches
// Vega on again, which every group but L and M assumes; group L runs Longfellow, group M BBS. The dialog shows one at a time;
// Swap phone hands over while the QR code is on screen. Every dialog here picks its phone
// explicitly (open). Any PIN unlocks the wallet.
//
// The server is started for this run with two settings; the run checks them first:
//   NUXT_VP_SESSION_TTL_S=40        requests expire after 40 s, so the expiry paths take a minute
//   READDIT_TEST_FAULTS=1           the test-only hook that fails one addon call (server/utils/test-faults.ts)
// For example:
//   NUXT_VP_SESSION_TTL_S=40 READDIT_TEST_FAULTS=1 PORT=3000 node .output/server/index.mjs > /tmp/server.log 2>&1 &
//   node scripts/flows-check.mjs http://localhost:3000 --server-log /tmp/server.log \
//     [--startup .output/server/index.mjs] [--shots demo-shots]
//
// --server-log  the server's output: each refused presentation must be logged with its rule
// --startup     also starts the built server without the addons and checks that it refuses to run,
//               and that it starts with any one of them
// --shots       saves the screenshots of this run (19-33) there
// --only        runs only the named self-contained groups, for example --only M
// (needs: npm i --no-save playwright && npx playwright install chromium)
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, request as httpRequest } from 'playwright'

const argv = process.argv.slice(2)
const opt = (name) => {
  const i = argv.indexOf(name)
  return i < 0 ? undefined : argv.splice(i, 2)[1]
}
const SERVER_LOG = opt('--server-log')
const STARTUP = opt('--startup')
const SHOTS = opt('--shots')
// --only K,M: run only these groups that need no earlier state (E F H I J K L M G), after the preconditions.
const ONLY = opt('--only')?.split(',')
const BASE = argv[0] ?? 'http://localhost:3000'
// Any 6 digits unlock the wallet: every PIN entry is a different one.
const anyPin = () => String(Math.floor(Math.random() * 1e6)).padStart(6, '0')
const root = fileURLToPath(new URL('../', import.meta.url))
const [teen, adult] = JSON.parse(readFileSync(join(root, 'app/wallet/demo-wallet.json'), 'utf8')).holders
// The teen's BBS credential (mms_zk, docs/mms_zk.md), with the teen's device key.
const [teenBbs] = JSON.parse(readFileSync(join(root, 'app/wallet/demo-wallet-bbs.json'), 'utf8')).holders
const BBS_SCHEME = 'urn:mms:bbs-cd:nym_auth:v1'
const BBS_SYSTEM = 'bbs-cd-plugins-v0.1'
const VEGA = 'urn:circuits:vega:nym_auth:v1'
const LONGFELLOW = 'urn:circuits:longfellow:nym_auth:v1'
const LONGFELLOW_SYSTEM = 'longfellow-libzk-v1'
const WALLET_METADATA = JSON.stringify({ vp_formats_supported: { circuit_zk: { circuit_proof_system_values: ['vega-v1'], circuit_id_values: [VEGA] } } })
if (SHOTS) mkdirSync(SHOTS, { recursive: true })

// ---------------------------------------------------------------------------------------------
// Checks

const results = []
let flow = '-'
const begin = (id, title) => {
  flow = id
  console.log(`\n== ${id}  ${title}`)
}
function check(what, ok, detail) {
  results.push({ flow, what, ok: !!ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}${detail != null && detail !== '' ? `  (${typeof detail === 'string' ? detail : JSON.stringify(detail)})` : ''}`)
  return !!ok
}
const eq = (what, actual, expected) => check(what, JSON.stringify(actual) === JSON.stringify(expected), `got ${JSON.stringify(actual)}`)

// ---------------------------------------------------------------------------------------------
// HTTP: the script's own clients, each with its own cookie jar (a browser of its own)

async function client() {
  return httpRequest.newContext({ baseURL: BASE })
}
/** { status, code, body } of a call; `code` is the error body's data.error. */
async function call(ctx, method, path, o = {}) {
  const res = await ctx.fetch(path, { method, ...o, failOnStatusCode: false })
  const text = await res.text()
  let body = text
  try {
    body = JSON.parse(text)
  } catch {
    /* a JWS or plain text */
  }
  return { status: res.status(), code: body?.data?.error, body, text }
}
const answer = (r) => `${r.status}${r.code ? ` ${r.code}` : ''}`
const expectAnswer = (what, r, status, code) => check(`${what}: ${status}${code ? ` ${code}` : ''}`, r.status === status && (code === undefined || r.code === code), `got ${answer(r)}${r.body?.statusMessage ? `, "${r.body.statusMessage}"` : ''}`)

const payloadOf = (jws) => JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString())
const requestUriOf = (authUrl) => new URLSearchParams(authUrl.slice(authUrl.indexOf('?') + 1)).get('request_uri')

async function newSession(ctx, body) {
  const r = await call(ctx, 'POST', '/api/vp/session', { data: body })
  if (r.status !== 200) throw new Error(`POST /api/vp/session ${answer(r)}`)
  return r.body
}
/** The wallet's request_uri POST; returns the decoded Request Object. */
async function fetchRequest(ctx, session, walletMetadata = WALLET_METADATA) {
  const r = await call(ctx, 'POST', requestUriOf(session.authorizationUrl), { form: { wallet_nonce: randomUUID(), ...(walletMetadata && { wallet_metadata: walletMetadata }) } })
  if (r.status !== 200) throw new Error(`request_uri ${answer(r)}`)
  return payloadOf(r.text.trim())
}
/** The phone's native steps for `wallet`, through the site's /api/wallet routes. */
async function present(ctx, request, wallet, circuit = VEGA) {
  const s = await call(ctx, 'POST', '/api/wallet/sign', { data: { request, circuit_id: circuit, device_key: wallet.device_key } })
  if (s.status !== 200) throw new Error(`sign ${answer(s)}`)
  const p = await call(ctx, 'POST', '/api/wallet/prove', {
    data: { request, circuit_id: circuit, credential: wallet.credential, secret_seed: wallet.secret_seed, device_signature: s.body.device_signature },
  })
  if (p.status !== 200) throw new Error(`prove ${answer(p)}`)
  return p.body
}
/** mms_zk: one prove call with the BBS credential and its device key. */
async function presentBbs(ctx, request, wallet = teenBbs) {
  const q = request.dcql_query.credentials.find((x) => x.format === 'mms_zk')
  const p = await call(ctx, 'POST', '/api/wallet/prove', { data: { request, credential_query_id: q.id, credential: wallet.credential, device_key: wallet.device_key } })
  if (p.status !== 200) throw new Error(`prove ${answer(p)}`)
  return p.body
}
const bbsForm = (request, presentation) => ({ state: request.state, vp_token: JSON.stringify({ [request.dcql_query.credentials.find((q) => q.format === 'mms_zk').id]: [presentation] }) })
/** The site's accepted proof systems (/tech's switches). */
const accept = async (proofSystem, yes) => {
  const ctx = await client()
  const r = await call(ctx, 'POST', '/api/tech/accept', { data: { proof_system: proofSystem, accept: yes } })
  await ctx.dispose()
  return r
}
const respond = (ctx, request, form) => call(ctx, 'POST', request.response_uri, { form })
const vpForm = (request, presentation) => ({ state: request.state, vp_token: JSON.stringify({ [request.dcql_query.credentials[0].id]: [presentation] }) })
const poll = (ctx, id) => call(ctx, 'GET', `/api/vp/session/${id}`)
const complete = (ctx, id) => call(ctx, 'POST', `/api/vp/session/${id}/complete`)
async function sessionView(id) {
  const ctx = await client()
  const o = await call(ctx, 'GET', '/api/tech/overview')
  await ctx.dispose()
  return o.body.sessions.find((s) => s.id === id)
}
const rejectedTrace = (s) => s?.trace.filter((t) => t.step === 'verify' && t.label === 'Proof rejected').at(-1)?.data
const serverLog = () => (SERVER_LOG ? readFileSync(SERVER_LOG, 'utf8') : '')
async function accounts() {
  const ctx = await client()
  const o = await call(ctx, 'GET', '/api/mod/overview')
  await ctx.dispose()
  return o.body.accounts
}
/** Resets the demo, then switches on `accepted` (Vega unless said otherwise). */
async function resetDemo(accepted = ['vega-v1']) {
  const ctx = await client()
  await call(ctx, 'POST', '/api/demo/reset')
  for (const id of accepted) await call(ctx, 'POST', '/api/tech/accept', { data: { proof_system: id, accept: true } })
  await ctx.dispose()
}
const acceptedNow = async () => (await call(page.request, 'GET', '/api/tech/overview')).body.acceptedProofSystems
async function armFault(step) {
  const ctx = await client()
  const r = await call(ctx, 'POST', '/api/test/fault', { data: { step } })
  await ctx.dispose()
  if (r.status !== 200) throw new Error(`arming ${step}: ${answer(r)}`)
}

// A presentation's bytes, changed in one place (the CBOR layout of nym-vega's presentation).
const flipAt = (buf, i) => {
  const out = Buffer.from(buf)
  out[i] ^= 0x01
  return out
}
function replaceOnce(buf, from, to) {
  const at = buf.indexOf(from)
  if (at < 0 || from.length !== to.length) throw new Error(`pattern not found: ${from.toString('latin1')}`)
  const out = Buffer.from(buf)
  to.copy(out, at)
  return out
}
const TAMPER = {
  'a flipped proof byte': (b, p) => {
    const len = p.metrics.proof_bytes
    const head = Buffer.from([0x5a, (len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255])
    return flipAt(b, b.indexOf(head) + head.length + Math.floor(len / 2))
  },
  'a changed results.nym': (b, p) => flipAt(b, b.indexOf(Buffer.from(p.results.nym, 'hex')) + 31),
  'a results key that is not the request handle': (b) => replaceOnce(b, Buffer.from([0x63, 0x6e, 0x79, 0x6d]), Buffer.from([0x63, 0x6e, 0x79, 0x78])),
  'proof_time changed by one second': (b) => {
    const t = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/.exec(b.toString('latin1'))
    const out = Buffer.from(b)
    const at = t.index + t[0].length - 2
    out[at] = out[at] === 0x30 ? 0x31 : out[at] - 1
    return out
  },
  'another circuit_id': (b) => replaceOnce(b, Buffer.from(VEGA), Buffer.from(VEGA.replace(':v1', ':v2'))),
}

// ---------------------------------------------------------------------------------------------
// The browser

const browser = await chromium.launch()
// Deliberate HTTP errors the browser logs: [status, route].
const ALLOWED = [
  [410, /^\/api\/vp\/request\/\w+$/], // a used or expired QR code
  [410, /^\/api\/vp\/response\/\w+$/], // an answer after expiry or after the dialog closed
  [404, /^\/api\/vp\/request\/\w+$/], // a QR code after the demo reset
  [404, /^\/api\/vp\/session\/\w+$/], // the dialog's poll after the demo reset
  [503, /^\/api\/vp\/session$/], // the verifier failing when a request starts (test fault)
  [503, /^\/api\/wallet\/capabilities$/], // the prover failing (test fault)
  [500, /^\/api\/wallet\/sign$/], // the prover failing at the signature (test fault)
  [500, /^\/api\/wallet\/prove$/], // the prover failing at the proof (test fault)
  [503, /^\/api\/vp\/response\/\w+$/], // the verifier failing at verification (test fault)
  [500, /^\/api\/comments$/], // a comment the server does not store (simulated by the run)
]
const consoleErrors = []
const allowedSeen = new Set()
/** Sign calls the server refused with 401 over the whole run: none, since any PIN unlocks. */
let signRefused = 0
let ctxBrowser
let page
let net = []
const sessionIds = []

async function openPage() {
  if (ctxBrowser) await ctxBrowser.close()
  ctxBrowser = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5, baseURL: BASE })
  page = await ctxBrowser.newPage()
  net = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const status = Number(/status of (\d{3})/.exec(m.text())?.[1])
    const path = (() => {
      try {
        return new URL(m.location().url).pathname
      } catch {
        return ''
      }
    })()
    const rule = ALLOWED.find(([s, r]) => s === status && r.test(path))
    if (rule) allowedSeen.add(`${status} ${rule[1]}`)
    else consoleErrors.push(`[${flow}] ${m.text()} at ${path || m.location().url}`)
  })
  page.on('pageerror', (e) => consoleErrors.push(`[${flow}] page error: ${e.message}`))
  page.on('response', async (r) => {
    const u = new URL(r.url())
    if (!u.pathname.startsWith('/api/')) return
    const entry = { flow, method: r.request().method(), path: u.pathname.replace(/[0-9a-f]{32}/g, ':id'), status: r.status() }
    if (entry.path === '/api/wallet/sign' && entry.status === 401) signRefused++
    if (u.pathname.startsWith('/api/vp/response/')) {
      const form = new URLSearchParams(r.request().postData() ?? '')
      entry.sent = form.get('error') ? `error=${form.get('error')}` : 'vp_token'
    }
    net.push(entry)
    if (entry.method === 'POST' && entry.path === '/api/vp/session' && entry.status === 200) {
      try {
        sessionIds.push((await r.json()).id)
      } catch {
        /* closed page */
      }
    }
  })
  await page.goto('/')
  await ready()
}

const mark = () => net.length
const since = (m) => net.slice(m)
const has = (m, method, path, status, sent) => since(m).some((e) => e.method === method && e.path === path && e.status === status && (sent === undefined || e.sent === sent))
const count = (m, method, path) => since(m).filter((e) => e.method === method && e.path === path).length
const lastSession = () => sessionIds.at(-1)

const dialog = () => page.getByRole('dialog')
const site = () => page.locator('[role=dialog] section').nth(0)
const phone = () => page.locator('[role=dialog] section').nth(1)
const guidePanel = () => page.getByRole('complementary', { name: 'Guide' })
async function ready() {
  await page.waitForLoadState('networkidle')
  await page.waitForFunction(() => !!document.querySelector('#__nuxt')?.__vue_app__, null, { timeout: 60_000 })
  await page.waitForTimeout(300)
}
async function guideIs(id, timeout = 10_000) {
  try {
    await page.locator(`aside[data-guide-step="${id}"]`).waitFor({ timeout })
    await page.waitForTimeout(250)
    return check(`guide: ${id}`, true)
  } catch {
    return check(`guide: ${id}`, false, `shows ${await guidePanel().getAttribute('data-guide-step')}`)
  }
}
// textContent, not innerText: the guide's context line is uppercased by CSS.
const guideSays = async (text) => check(`guide says "${text}"`, (await guidePanel().textContent()).includes(text))
/** The guide comes to say `text` (after its step transition). */
const guideComesToSay = async (text) => {
  await page.waitForFunction((t) => document.querySelector('aside[data-guide-step]')?.textContent?.includes(t), text, { timeout: 5_000 }).catch(() => {})
  return guideSays(text)
}
async function visible(what, locator, timeout = 10_000) {
  try {
    await locator.first().waitFor({ timeout })
    return check(what, true)
  } catch {
    return check(what, false, 'not shown')
  }
}
const phoneShows = (text, timeout = 15_000) => visible(`phone: "${text}"`, phone().getByText(text, { exact: true }), timeout)
const dialogShows = (text, timeout = 15_000) => visible(`dialog: "${text}"`, site().getByText(text, { exact: true }), timeout)
const pageShows = (text, timeout = 10_000) => visible(`page: "${text}"`, page.getByText(text, { exact: true }), timeout)
async function shot(name) {
  if (!SHOTS) return
  await page.waitForTimeout(400)
  await page.screenshot({ path: join(SHOTS, `${name}.png`) })
  console.log(`  screenshot ${join(SHOTS, `${name}.png`)}`)
}
async function openDetails() {
  if (await guidePanel().locator('details[open]').count()) return
  await guidePanel().locator('summary', { hasText: 'Details' }).click()
  await guidePanel().locator('details[open] section').first().waitFor()
}
/** The guide's Details show the verifier's measured times for the presentation just verified. */
async function expectVerification() {
  const re = /Verification\s*Decoding\s*[\d.,]+ ms\s*Verification\s*[\d.,]+ ms[\s\S]*Verifier call\s*[\d.,]+ ms/
  let text = ''
  for (let k = 0; k < 20; k++) {
    text = (await guidePanel().textContent()) ?? ''
    if (re.test(text)) break
    await page.waitForTimeout(150)
  }
  const m = /Verification\s*Decoding\s*([\d.,]+ ms)\s*Verification\s*([\d.,]+ ms)/.exec(text)
  return check('guide: the verification time is shown', re.test(text), m ? `decoding ${m[1]}, verification ${m[2]}` : 'none')
}

const TEEN = "Teen's phone"
const ADULT = "Adult's phone"
const phoneLabel = async () => ((await page.locator('[data-phone-label]').innerText()) ?? '').split('\n')[0].trim()
/** Swap to the named phone if another is on screen, while the QR code is shown. */
async function usePhone(name) {
  if ((await phoneLabel()) === name) return
  await page.getByRole('button', { name: 'Swap phone' }).click()
  await page.locator('[data-phone-label]', { hasText: name }).waitFor()
  await phone().getByRole('button', { name: 'Scan QR code' }).waitFor({ timeout: 15_000 })
}
/** Opens a wallet dialog with `button`, on the named phone. */
async function open(button, phoneName = TEEN) {
  await button.click()
  await phone().getByRole('button', { name: 'Scan QR code' }).waitFor({ timeout: 15_000 })
  await usePhone(phoneName)
}
const headerButton = (name) => page.getByRole('banner').getByRole('button', { name, exact: true })
/** The id of the session the dialog created after `before`. */
async function newSessionId(before) {
  for (let i = 0; i < 100 && lastSession() === before; i++) await page.waitForTimeout(100)
  return lastSession() !== before ? lastSession() : null
}
/** A dialog that starts afresh: a new session, the phone on its home screen, the QR step in the guide. */
async function expectFresh(guideId, before) {
  await site().getByText('Open an EUDI Wallet App on your phone').waitFor({ timeout: 15_000 })
  check('a new session', !!(await newSessionId(before)), lastSession())
  check('phone on its home screen', await phone().getByRole('button', { name: 'Scan QR code' }).isVisible())
  check('dialog shows no earlier outcome', !(await site().getByText(/Not completed|No account|Account banned/).count()))
  await guideIs(guideId)
}
async function scan() {
  await phone().getByRole('button', { name: 'Scan QR code' }).click()
  await phone().getByText('Scan the QR Code').waitFor()
}
const readRequest = () => phone().getByText(/Request to Share Data|Requirement Not Met|Unsupported Request|Request Expired|Invalid Request|Connection Error|Verifier is not Trusted/).first().waitFor({ timeout: 30_000 })
async function enterPin(pin) {
  await phone().getByText('Enter the Pin').waitFor()
  for (const d of pin) await phone().getByRole('button', { name: d, exact: true }).click()
  await phone().getByRole('button', { name: 'Submit' }).click()
}
/** The guide has moved on from a step, its transition included. */
async function guideLeaves(id) {
  await page.waitForFunction((x) => document.querySelector('aside[data-guide-step]')?.getAttribute('data-guide-step') !== x, id)
  await page.waitForTimeout(350)
}
async function closeDialog(how = 'escape') {
  if (how === 'escape') await page.keyboard.press('Escape')
  else if (how === 'button') await site().getByRole('button', { name: 'Close', exact: true }).first().click()
  else await page.mouse.click(20, 450) // the backdrop, left of the dialog
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
}
/** Sign up or log in through the dialog, start to end, without screenshots. */
async function signIn(name, expectText, phoneName = TEEN) {
  await open(headerButton(name), phoneName)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText(expectText).waitFor({ timeout: 30_000 })
  await closeFromPhone()
}
/** After a success the dialog stays open until Close on the phone's success screen. */
async function closeFromPhone() {
  await phone().getByText('Success!', { exact: true }).waitFor({ timeout: 30_000 })
  await phone().getByRole('button', { name: 'Close', exact: true }).click()
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
}
async function goto(path) {
  await page.goto(path)
  await ready()
}
const me = async () => (await call(page.request, 'GET', '/api/me')).body

// ---------------------------------------------------------------------------------------------

/** Starts the built server with `env`; resolves with its exit code (or 'running' once `until` shows in its output) and the output. */
function startServer(env, until) {
  const child = spawn(process.execPath, [STARTUP], { env: { ...process.env, PORT: '0', ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      child.kill()
      resolve({ code: 'timeout', out })
    }, 60_000)
    const seen = () => {
      if (until && until.every((x) => out.includes(x))) {
        clearTimeout(t)
        child.kill()
        resolve({ code: 'running', out })
      }
    }
    child.stdout.on('data', (d) => ((out += d), seen()))
    child.stderr.on('data', (d) => ((out += d), seen()))
    child.on('exit', (c) => {
      clearTimeout(t)
      resolve({ code: c, out })
    })
  })
}

async function startupWithoutAddon() {
  begin('S16', 'the server refuses to start without any proof backend')
  const none = { NUXT_VEGA_ADDON: '/nonexistent/readdit-vega.node', NUXT_LONGFELLOW_ADDON: '/nonexistent/readdit-longfellow.node', NUXT_BBS_ADDON: '/nonexistent/readdit-bbs.node' }
  let r = await startServer(none)
  eq('exit code', r.code, 1)
  check('says why and what to run', r.out.includes('Readdit cannot start without a proof backend') && r.out.includes('npm run build:native'), r.out.trim().split('\n').slice(-2).join(' | '))
  begin('S16b', 'the server starts with one backend')
  for (const [name, env] of [['vega', 'NUXT_VEGA_ADDON'], ['longfellow', 'NUXT_LONGFELLOW_ADDON'], ['bbs', 'NUXT_BBS_ADDON']]) {
    const only = { ...none }
    delete only[env]
    r = await startServer(only, [`[${name}] prover and verifier ready`, ...['vega', 'longfellow', 'bbs'].filter((x) => x !== name).map((x) => `[${x}] not loaded`)])
    eq(`with the ${name} addon only: running`, r.code, 'running')
  }
}

async function preconditions() {
  begin('pre', 'the server is started for this run')
  const ctx = await client()
  await resetDemo([])
  const nothing = await call(ctx, 'POST', '/api/vp/session', { data: { purpose: 'signin', intent: 'signup' } })
  expectAnswer('nothing accepted after a reset: no request', nothing, 503, 'none_accepted')
  await resetDemo()
  const s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const fault = await call(ctx, 'POST', '/api/test/fault', { data: { step: 'none' } })
  await ctx.dispose()
  const ok = [
    check('requests expire within a minute (NUXT_VP_SESSION_TTL_S)', s.expiresIn <= 60, `expiresIn ${s.expiresIn}`),
    check('the test fault hook is on (READDIT_TEST_FAULTS=1)', fault.status === 400, answer(fault)),
  ]
  if (ok.includes(false)) throw new Error('start the server as the header of scripts/flows-check.mjs says')
  return s.expiresIn
}

// ---- A. Logged out, sign-up, log-in and the wallet's refusals ----

async function groupA() {
  await resetDemo()
  await openPage()

  begin('H4', 'browsing logged out: the home feed and an open community')
  await guideIs('start')
  check('home feed: no posts when logged out', !(await page.locator('article').count()))
  await pageShows('Log in to see posts')
  let m = mark()
  await goto('/c/photography')
  await pageShows('Log in to view c/photography')
  await guideIs('login-required')
  check('no wallet request', count(m, 'POST', '/api/vp/session') === 0)

  begin('H4b', "the home page's Log in opens the log-in; closing it at the QR code")
  await goto('/')
  m = mark()
  await open(page.getByRole('main').getByRole('button', { name: 'Log in', exact: true }))
  await visible('dialog: "Log in to Readdit"', site().getByRole('heading', { name: 'Log in to Readdit' }))
  await guideIs('signin-qr')
  await guideSays('Log-in')
  const voteSession = await newSessionId(undefined)
  await closeDialog('escape')
  await guideIs('request-closed')
  await page.waitForTimeout(300)
  check('the session is cancelled', has(m, 'POST', '/api/vp/session/:id/cancel', 200))
  eq('server status', (await sessionView(voteSession))?.outcome?.reason, 'cancelled')

  begin('S6', 'an age-restricted community while logged out: its requirement, and one request')
  m = mark()
  await goto('/c/teenspace')
  await pageShows('c/teenspace is for ages 13 to 17')
  await pageShows('The same step logs you in to Readdit with a pseudonym.')
  check('no "Log in to view"', !(await page.getByText(/Log in to view/).count()))
  check('one button: Verify age with wallet', (await page.getByRole('button', { name: 'Verify age with wallet' }).count()) === 1)
  await guideIs('age-signin')
  await guideSays('One presentation carries the pseudonym and the age result')
  check('no wallet request yet', count(m, 'POST', '/api/vp/session') === 0)
  expectAnswer('server: an age check alone without a login', await call(page.request, 'POST', '/api/vp/session', { data: { purpose: 'age', community: 'teenspace' } }), 401, 'login_required')
  expectAnswer('server: the combined request for an open community', await call(page.request, 'POST', '/api/vp/session', { data: { purpose: 'signin', intent: 'signup', community: 'photography' } }), 400, 'bad_request')
  await shot('24-gated-community-logged-out')

  begin('S1', 'log-in with no account')
  m = mark()
  await goto('/')
  await open(headerButton('Log in'))
  await guideIs('signin-qr')
  await scan()
  await readRequest()
  await guideIs('consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('No account', 30_000)
  await dialogShows('There is no Readdit account for this wallet. Sign up to create one.')
  await phoneShows('Success!')
  await guideIs('no-account')
  check('the presentation was verified (vp_token 200)', has(m, 'POST', '/api/vp/response/:id', 200, 'vp_token'))
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'no_account' })
  eq('no account was created', (await accounts()).length, 0)
  check('the browser is not logged in', (await me()).account === null)
  check('the dialog offers Sign up', await site().getByRole('button', { name: 'Sign up' }).isVisible())
  await expectVerification()
  await shot('23-login-no-account')

  begin('W1', 'decline at the consent screen')
  let before = lastSession()
  await site().getByRole('button', { name: 'Sign up' }).click()
  await expectFresh('signin-qr', before)
  await guideSays('Sign-up')
  m = mark()
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Decline' }).click()
  await phoneShows('Sharing Cancelled')
  await phoneShows('You cancelled sharing your credentials.')
  await dialogShows('Not completed')
  await dialogShows('Nothing was shared with Readdit.')
  await guideIs('declined')
  check('the wallet answered access_denied (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=access_denied'))
  check('no native step ran', count(m, 'POST', '/api/wallet/sign') === 0 && count(m, 'POST', '/api/wallet/prove') === 0)
  eq('server: the session', (await poll(page.request, lastSession())).body.failure, 'denied')
  eq('no account', (await accounts()).length, 0)
  await shot('19-decline')
  await phone().getByRole('button', { name: 'Close' }).click()
  await guideIs('not-completed')

  begin('W10', 'scanning a QR code that was already used')
  m = mark()
  await scan()
  await phoneShows('Request Expired')
  await phoneShows('This request has expired. Please start again.')
  await guideIs('wallet-error')
  await guideSays('the QR code was already used')
  check('request_uri answered 410', has(m, 'POST', '/api/vp/request/:id', 410))
  expectAnswer('server: request_uri again', await call(page.request, 'POST', `/api/vp/request/${lastSession()}`, { form: { wallet_nonce: 'x' } }), 410, 'already_used')
  await phone().getByRole('button', { name: 'Close' }).click()

  begin('W2', 'cancel at the PIN screen')
  before = lastSession()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('signin-qr', before)
  m = mark()
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await phone().getByText('Enter the Pin').waitFor()
  await guideIs('pin')
  await phone().getByRole('button', { name: 'Cancel' }).click()
  await phoneShows('Sharing Cancelled')
  await dialogShows('Not completed')
  await dialogShows('Nothing was shared with Readdit.')
  await guideIs('pin-cancelled')
  check('the wallet answered access_denied (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=access_denied'))
  check('the device key did not sign', count(m, 'POST', '/api/wallet/sign') === 0)
  eq('no account', (await accounts()).length, 0)
  await shot('20-pin-cancelled')
  await phone().getByRole('button', { name: 'Close' }).click()

  begin('H1', 'sign-up, with any PIN')
  before = lastSession()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('signin-qr', before)
  m = mark()
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await guideIs('pin')
  await guideSays('Any PIN unlocks it in this demo')
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await guideIs('account-created')
  check('the device key signed at the first PIN (200)', since(m).filter((e) => e.path === '/api/wallet/sign').map((e) => e.status).join() === '200')
  await expectVerification()
  await page.waitForTimeout(2500)
  check('the dialog stays open until Close on the phone', await dialog().isVisible())
  await closeFromPhone()
  const created = (await me()).account
  check('logged in', !!created?.handle, created?.handle)
  eq('one account', (await accounts()).length, 1)
  await page.getByRole('banner').getByText(`u/${created.handle}`).waitFor()

  begin('H2', 'log-out')
  await page.getByRole('banner').getByText(`u/${created.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  check('header shows Sign up and Log in', await headerButton('Sign up').isVisible())
  check('server: no account for this browser', (await me()).account === null)
  await guideIs('start')

  begin('H3', 'log-in with an existing account')
  m = mark()
  await signIn('Log in', `Logged in as u/${created.handle}`)
  await guideIs('logged-in')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: true, kind: 'logged_in', handle: created.handle })
  eq('still one account', (await accounts()).length, 1)

  begin('S2', 'sign-up when the pseudonym already has an account')
  await page.getByRole('banner').getByText(`u/${created.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Sign up').waitFor()
  await open(headerButton('Sign up'))
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account already exists', 30_000)
  await dialogShows('There is already an account associated with this user. Log in instead.')
  await guideIs('account-exists')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'account_exists' })
  eq('still one account', (await accounts()).length, 1)
  check('the browser is not logged in', (await me()).account === null)
  // the dialog's Log in sends a new request and logs in
  await dialog().getByRole('button', { name: 'Log in' }).click()
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows(`Logged in as u/${created.handle}`, 30_000)
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: true, kind: 'logged_in', handle: created.handle })
  await closeFromPhone()
  return created
}
// ---- B. Communities, age gates, closing the dialog, comments ----

async function groupB(created) {
  begin('H5', 'an open community, logged in')
  let m = mark()
  await goto('/c/photography')
  await guideIs('open-community')
  check('posts shown', (await page.locator('a[href^="/c/photography/p"]').count()) > 0)
  check('no wallet request', count(m, 'POST', '/api/vp/session') === 0)
  await page.getByRole('button', { name: 'Join', exact: true }).click()
  await visible('Join becomes Joined', page.getByRole('button', { name: 'Joined', exact: true }))
  const up = page.locator('article').first().getByRole('button', { name: 'Upvote' })
  await up.click()
  check('an upvote is shown as cast', /(^|\s)text-brand(\s|$)/.test((await up.getAttribute('class')) ?? ''))
  check('no wallet request for joining or voting', count(m, 'POST', '/api/vp/session') === 0)

  begin('W5', 'requirement not met: c/afterdark (18+)')
  await goto('/c/afterdark')
  await guideIs('age-ask')
  m = mark()
  let before = lastSession()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await expectFresh('age-qr', before)
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await guideIs('unmet')
  await guideSays('born 14 Mar 2011')
  check('one credential on this phone: no Switch credential', !(await phone().getByRole('button', { name: /Switch credential/ }).count()))
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  await guideIs('not-completed')
  check('the wallet answered access_denied (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=access_denied'))
  check('no proof was made', count(m, 'POST', '/api/wallet/prove') === 0 && count(m, 'POST', '/api/wallet/sign') === 0)
  await closeDialog('escape')
  check('no age stored', (await me()).account.birthDateRange === null)

  begin('W8', 'closing the dialog mid-flow')
  await goto('/c/teenspace')
  const closings = [
    ['at the QR code (Escape)', 'escape', async () => {}],
    ['on the request screen (the Close button)', 'button', async () => {
      await scan()
      await readRequest()
    }],
    ['at the PIN (the backdrop)', 'backdrop', async () => {
      await scan()
      await readRequest()
      await phone().getByRole('button', { name: 'Share' }).click()
      await phone().getByText('Enter the Pin').waitFor()
    }],
    ['while the proof is made', 'escape', async () => {
      // A slow phone: the proof's answer is held until the dialog has closed.
      await page.route('**/api/wallet/prove', async (route) => {
        const res = await route.fetch()
        await dialog().waitFor({ state: 'detached', timeout: 30_000 }).catch(() => {})
        await route.fulfill({ response: res })
      })
      await scan()
      await readRequest()
      await phone().getByRole('button', { name: 'Share' }).click()
      await enterPin(anyPin())
      await phone().getByText('Creating presentation...').waitFor()
    }],
  ]
  for (const [where, how, reach] of closings) {
    before = lastSession()
    m = mark()
    await open(page.getByRole('button', { name: 'Verify age with wallet' }))
    await expectFresh('age-qr', before)
    const id = lastSession()
    await reach()
    await closeDialog(how)
    await guideIs('request-closed')
    await page.waitForTimeout(300)
    check(`${where}: the session is cancelled`, has(m, 'POST', '/api/vp/session/:id/cancel', 200))
    const v = await sessionView(id)
    eq(`${where}: server status`, [v?.status, v?.outcome?.reason], ['failed', 'cancelled'])
    if (where.startsWith('while')) {
      await page.waitForResponse((r) => r.url().includes(`/api/vp/response/${id}`), { timeout: 30_000 }).catch(() => {})
      await page.waitForTimeout(300)
      check('the phone answered late and got 410', has(m, 'POST', '/api/vp/response/:id', 410, 'vp_token'))
      await page.unroute('**/api/wallet/prove')
    }
    check(`${where}: no age stored`, (await me()).account.birthDateRange === null)
  }

  begin('H6', 'an age-restricted community granted (13-17)')
  before = lastSession()
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await expectFresh('age-qr', before)
  await scan()
  await readRequest()
  await phoneShows('Age proof: 13–17')
  await guideIs('age-consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText('Age verified').waitFor({ timeout: 30_000 })
  await guideIs('age-verified')
  await expectVerification()
  await closeFromPhone()
  check('posts shown', (await page.locator('a[href^="/c/teenspace/p"]').count()) > 0)
  check('the proven range is stored', !!(await me()).account.birthDateRange?.ge)

  begin('H7', 'returning to an age-verified community')
  m = mark()
  await goto('/')
  check('home feed now has c/teenspace posts', (await page.locator('a[href^="/c/teenspace/"]').count()) > 0)
  await goto('/c/teenspace')
  await guideIs('age-granted')
  check('no wallet request', count(m, 'POST', '/api/vp/session') === 0)

  begin('S7', 'c/afterdark after a 13-17 check: refused by the site')
  m = mark()
  await goto('/c/afterdark')
  await pageShows("You can't enter c/afterdark")
  await guideIs('age-refused')
  check('no wallet request', count(m, 'POST', '/api/vp/session') === 0)
  expectAnswer('server: an age check for c/afterdark', await call(page.request, 'POST', '/api/vp/session', { data: { purpose: 'age', community: 'afterdark' } }), 403, 'age_refused')
  expectAnswer('server: an age check for c/teenspace again', await call(page.request, 'POST', '/api/vp/session', { data: { purpose: 'age', community: 'teenspace' } }), 409, 'age_verified')

  begin('H8', 'commenting')
  await goto('/c/teenspace/p10')
  await page.getByPlaceholder(/Comment as/).fill('Flows check: a comment')
  await page.getByRole('button', { name: 'Comment', exact: true }).click()
  await pageShows('Flows check: a comment')
  await page.route('**/api/comments', (route) => (route.request().method() === 'POST' ? route.fulfill({ status: 500, json: {} }) : route.fallback()))
  await page.getByPlaceholder(/Comment as/).fill('Flows check: not stored')
  await page.getByRole('button', { name: 'Comment', exact: true }).click()
  await pageShows('Your comment was not posted. Try again.')
  check('the draft is kept', (await page.getByPlaceholder(/Comment as/).inputValue()) === 'Flows check: not stored')
  await page.unroute('**/api/comments')
  await page.getByPlaceholder(/Comment as/).fill('')
  const bad = [
    ['no body', {}],
    ['an empty comment', { postId: 'p10', body: '   ' }],
    ['2,001 characters', { postId: 'p10', body: 'x'.repeat(2001) }],
    ['an unknown post', { postId: 'nope', body: 'hi' }],
  ]
  for (const [what, data] of bad) expectAnswer(`server: a comment with ${what}`, await call(page.request, 'POST', '/api/comments', { data }), 400, 'bad_request')
  const anon = await client()
  expectAnswer('server: a comment while logged out', await call(anon, 'POST', '/api/comments', { data: { postId: 'p1', body: 'hi' } }), 401, 'login_required')
  await anon.dispose()
  return created
}

// ---- C. Moderation and bans ----

async function groupC(created) {
  begin('H9', 'moderation: ban')
  const mod = await ctxBrowser.newPage()
  await mod.goto('/mod')
  await mod.waitForLoadState('networkidle')
  await mod.getByText('Flows check: a comment').waitFor()
  await mod.getByRole('button', { name: 'Ban user' }).first().click()
  await mod.getByText('Banned', { exact: true }).first().waitFor()
  await page.bringToFront()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await guideIs('banned')
  check('the login ended', (await me()).account === null)
  const comments = (await call(page.request, 'GET', '/api/comments?postId=p10')).body
  check("the account's comments are hidden", !comments.some((c) => c.body === 'Flows check: a comment'))
  check('the proven age stays with the account', !!(await accounts())[0].birthDateRange?.ge)

  begin('S3', 'a banned account at log-in')
  await open(headerButton('Log in'))
  await guideIs('signin-qr')
  await guideSays('Log-in after the ban')
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await guideIs('signup-refused')
  await guideSays('refused the log-in')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'banned', handle: created.handle })
  await closeDialog('button')

  begin('S4', 'a banned account at sign-up')
  await open(headerButton('Sign up'))
  await guideIs('signin-qr')
  await guideSays('Sign-up after the ban')
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await guideIs('signup-refused')
  await guideSays('refused the sign-up')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'banned', handle: created.handle })
  check('the browser is not logged in', (await me()).account === null)
  await closeDialog('button')

  begin('H9b', 'moderation: unban, then log in again')
  await mod.bringToFront()
  await mod.getByRole('button', { name: 'Unban' }).click()
  await mod.getByText('Active', { exact: true }).first().waitFor()
  await mod.close()
  await page.bringToFront()
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await signIn('Log in', `Logged in as u/${created.handle}`)
  check('logged in again', (await me()).account?.handle === created.handle)
  const ctx = await client()
  expectAnswer('server: a ban without a pseudonym', await call(ctx, 'POST', '/api/mod/ban', { data: {} }), 400, 'bad_request')
  expectAnswer('server: a ban of an unknown account', await call(ctx, 'POST', '/api/mod/ban', { data: { pseudonym: 'ab'.repeat(32) } }), 404, 'unknown_account')
  expectAnswer('server: an unban without a body', await call(ctx, 'POST', '/api/mod/unban'), 400, 'bad_request')
  expectAnswer('server: an unban of an unknown account', await call(ctx, 'POST', '/api/mod/unban', { data: { pseudonym: 'x' } }), 404, 'unknown_account')
  await ctx.dispose()
}

// ---- D. Requests that end on the site's side: another wallet, a ban, a log-out, expiry, a reset ----

async function groupD(ttl) {
  await resetDemo()
  await openPage()
  await signIn('Sign up', 'Account created: u/')
  const handle = (await me()).account.handle

  begin('S19', "the age proof comes from another person's phone, swapped in at the QR code")
  expectAnswer('server: a comment in c/teenspace before an age check', await call(page.request, 'POST', '/api/comments', { data: { postId: 'p10', body: 'hi' } }), 403, 'age_required')
  await goto('/c/afterdark')
  let m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), TEEN)
  await usePhone(ADULT)
  await guideComesToSay('The phones were swapped')
  for (let k = 0; k < 30 && !has(m, 'POST', '/api/vp/session/:id/phone', 200); k++) await page.waitForTimeout(100)
  check('the swap is recorded for the technical view (200)', has(m, 'POST', '/api/vp/session/:id/phone', 200))
  await shot('30-afterdark-phone-swapped')
  await scan()
  await readRequest()
  await phoneShows('Request to Share Data')
  await phoneShows('Age proof: 18+')
  await guideSays('born 20 May 1990')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('The pseudonym in this proof does not match your account. The age proof was not applied.', 30_000)
  await guideIs('mismatch')
  await expectVerification()
  check('the adult credential proved 18+ (vp_token 200)', has(m, 'POST', '/api/vp/response/:id', 200, 'vp_token'))
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'mismatch' })
  check('no age stored for the account', (await me()).account.birthDateRange === null)
  await closeDialog('button')

  begin('S5', 'banned while an age request is open')
  await goto('/c/teenspace')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  const ctx = await client()
  await call(ctx, 'POST', '/api/mod/ban', { data: { pseudonym: (await accounts())[0].pseudonym } })
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await guideIs('signup-refused')
  await guideSays('does not apply the age proof')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'banned', handle })
  check('no age stored', (await accounts())[0].birthDateRange === null)
  await closeDialog('button')
  await call(ctx, 'POST', '/api/mod/unban', { data: { pseudonym: (await accounts())[0].pseudonym } })
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await signIn('Log in', `Logged in as u/${handle}`)

  begin('S20', 'logged out while an age request is open')
  await goto('/c/teenspace')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await call(page.request, 'POST', '/api/logout') // the same browser, from another tab
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('You are no longer logged in. Log in and try again.', 30_000)
  await guideIs('logged-out')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'logged_out' })
  check('no age stored', (await accounts())[0].birthDateRange === null)
  check('no Try again for this outcome', !(await site().getByRole('button', { name: 'Try again' }).count()))
  await closeDialog('button')
  await signIn('Log in', `Logged in as u/${handle}`)

  begin('W9 S8', `an expired QR code (requests last ${ttl} s)`)
  await goto('/c/teenspace')
  // Over HTTP at the same time: a request never fetched, and one fetched but not answered.
  const http = await client()
  await signInOverHttp(http, teen)
  const never = await newSession(http, { purpose: 'signin', intent: 'login' })
  const fetched = await newSession(http, { purpose: 'signin', intent: 'login' })
  const fetchedRequest = await fetchRequest(http, fetched)
  m = mark()
  const beforeExpiry = lastSession()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  const expiredId = await newSessionId(beforeExpiry)
  await dialogShows('The code has expired. Try again.', (ttl + 15) * 1000)
  await guideIs('expired')
  await scan()
  await phoneShows('Request Expired')
  await guideIs('wallet-error')
  await guideSays('the request expired')
  check('request_uri answered 410', has(m, 'POST', '/api/vp/request/:id', 410))
  await shot('22-expired-qr')
  expectAnswer('server: request_uri of the expired request', await call(page.request, 'POST', `/api/vp/request/${expiredId}`, { form: {} }), 410, 'expired')
  eq('server: its completion', (await complete(page.request, expiredId)).body, { ok: false, kind: 'expired' })
  expectAnswer('HTTP: request_uri of a request never fetched', await call(http, 'POST', requestUriOf(never.authorizationUrl), { form: { wallet_nonce: 'n' } }), 410, 'expired')
  const late = await present(http, fetchedRequest, teen)
  expectAnswer('HTTP: an answer after expiry', await respond(http, fetchedRequest, vpForm(fetchedRequest, late.presentation)), 410, 'expired')
  eq('HTTP: the poll', (await poll(http, fetched.id)).body.failure, 'expired')
  eq('HTTP: the completion', (await complete(http, fetched.id)).body, { ok: false, kind: 'expired' })
  await http.dispose()
  await phone().getByRole('button', { name: 'Close' }).click()

  begin('W11', 'the request expires while the phone is on it')
  let before = lastSession()
  m = mark()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('age-qr', before)
  await scan()
  await readRequest()
  await dialogShows('The code has expired. Try again.', (ttl + 15) * 1000)
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await phoneShows('Request Expired', 30_000)
  check('response_uri answered 410', has(m, 'POST', '/api/vp/response/:id', 410, 'vp_token'))
  await guideIs('wallet-error')
  check('no age stored', (await accounts())[0].birthDateRange === null)
  await phone().getByRole('button', { name: 'Close' }).click()

  begin('S18', 'the demo is reset while a request is open')
  before = lastSession()
  m = mark()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('age-qr', before)
  await resetDemo()
  await dialogShows('This code is no longer valid. Try again.')
  await guideIs('gone')
  await scan()
  await phoneShows('Invalid Request')
  await guideSays('it does not know the request')
  check('request_uri answered 404', has(m, 'POST', '/api/vp/request/:id', 404))
  await closeDialog('escape')
  await ctx.dispose()
}

/** Log in an HTTP client with a wallet, so that it can start age checks. */
async function signInOverHttp(ctx, wallet) {
  const s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const request = await fetchRequest(ctx, s)
  const p = await present(ctx, request, wallet)
  await respond(ctx, request, vpForm(request, p.presentation))
  return (await complete(ctx, s.id)).body
}

// ---- E. Requests the wallet does not support ----

async function groupE() {
  await resetDemo()
  await openPage()
  begin('W6', 'a request the wallet cannot satisfy: no circuit in common')
  // The wallet's capabilities, as a wallet without the Vega circuit would report them.
  await page.route('**/api/wallet/capabilities', (route) =>
    route.fulfill({ json: { circuits: [{ circuit_id: LONGFELLOW, proof_system: 'longfellow-libzk-v1' }], schemes: [] } }),
  )
  let m = mark()
  await open(headerButton('Sign up'))
  await scan()
  await readRequest()
  await phoneShows('Unsupported Request')
  await phoneShows('This type of request is not supported.')
  await guideIs('unsupported')
  await guideSays('no circuit or scheme in common')
  await openDetails()
  await guideSays(`the wallet runs ${LONGFELLOW}`)
  await shot('21-unsupported-request')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  await dialogShows('Nothing was shared with Readdit.')
  await guideIs('not-completed')
  await guideSays('invalid_request')
  check('the wallet answered invalid_request (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=invalid_request'))
  eq('server: the session', (await poll(page.request, lastSession())).body.failure, 'invalid_request')
  await closeDialog('escape')
  await page.unroute('**/api/wallet/capabilities')

  // A verifier at the same host asking for a pseudonym configuration the wallet does not support:
  // the real request, changed and signed again by a certificate for readdit.example.
  const signer = await testSigner('readdit.example')
  const variants = [
    ['verifier_id_type semantic', (r) => ({ ...r, params: { ...r.params, verifier_id_type: 'semantic' } }), 'verifier_id_type semantic'],
    ['account-recovery-ssc without verifier_context', (r) => ({ ...r, params: { config: 'account-recovery-ssc', verifier_id_type: 'x509_san_dns' } }), 'verifier_context is required by account-recovery-ssc'],
  ]
  for (const [what, change, reason] of variants) {
    begin('W7', `an unsupported pseudonym request: ${what}`)
    await page.route('**/api/vp/request/*', async (route) => {
      const res = await route.fetch()
      const request = payloadOf((await res.text()).trim())
      const q = request.dcql_query.credentials[0]
      q.req = q.req.map((r) => (r.id === 'pseudonym-v1-sha256' ? change(r) : r))
      await route.fulfill({ status: 200, contentType: 'application/oauth-authz-req+jwt', body: await signer.sign(request) })
    })
    m = mark()
    const before = lastSession()
    await open(headerButton('Sign up'))
    await expectFresh('signin-qr', before)
    await scan()
    await readRequest()
    await phoneShows('Unsupported Request')
    await guideIs('unsupported')
    await openDetails()
    await guideSays(reason)
    await phone().getByRole('button', { name: 'Close' }).click()
    await dialogShows('Not completed')
    check('the wallet answered invalid_request (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=invalid_request'))
    await closeDialog('escape')
    await page.unroute('**/api/vp/request/*')
  }

  begin('W12', 'a request signed for another host: the verifier is not trusted')
  const stranger = await testSigner('evil.example')
  await page.route('**/api/vp/request/*', async (route) => {
    const res = await route.fetch()
    await route.fulfill({ status: 200, contentType: 'application/oauth-authz-req+jwt', body: await stranger.sign(payloadOf((await res.text()).trim())) })
  })
  m = mark()
  await open(headerButton('Sign up'))
  await scan()
  await phoneShows('Verifier is not Trusted')
  await guideIs('wallet-error')
  await guideSays('did not check out')
  await openDetails()
  await guideSays('certificate does not match client_id')
  await dialogShows('Continue on your phone')
  check('the wallet sent nothing', count(m, 'POST', '/api/vp/response/:id') === 0)
  await closeDialog('button')
  await guideIs('request-closed')
  await page.unroute('**/api/vp/request/*')

  begin('W7b', 'the prover refuses an unsupported pseudonym configuration')
  const ctx = await client()
  const s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const request = await fetchRequest(ctx, s)
  const q = request.dcql_query.credentials[0]
  q.req[0].params = { config: 'account-recovery-ssc', verifier_id_type: 'x509_san_dns', verifier_context: 'readdit' }
  const p = await call(ctx, 'POST', '/api/wallet/prove', {
    data: { request, circuit_id: VEGA, credential: teen.credential, secret_seed: teen.secret_seed, device_signature: '00'.repeat(64) },
  })
  expectAnswer('server: /api/wallet/prove', p, 400, 'unsupported_config')
  await ctx.dispose()
}

async function testSigner(host) {
  // @peculiar/x509 needs the Reflect metadata polyfill loaded first.
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  const { CompactSign } = await import('jose')
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
  x509.cryptoProvider.set(globalThis.crypto)
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${host}`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: alg,
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }])],
  })
  const x5c = [Buffer.from(cert.rawData).toString('base64')]
  return {
    sign: (payload) =>
      new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c }).sign(keys.privateKey),
  }
}

// ---- F. The verifier's refusals, over HTTP ----

async function groupF() {
  await resetDemo()
  const ctx = await client()
  const otherBrowser = await client()

  begin('S9', 'an unknown session or request_uri')
  const unknown = 'deadbeef'.repeat(4)
  expectAnswer('request_uri', await call(ctx, 'POST', `/api/vp/request/${unknown}`, { form: {} }), 404, 'unknown_session')
  expectAnswer('response_uri', await call(ctx, 'POST', `/api/vp/response/${unknown}`, { form: { state: 'x' } }), 404, 'unknown_session')
  expectAnswer('poll', await poll(ctx, unknown), 404, 'unknown_session')
  expectAnswer('complete', await complete(ctx, unknown), 404, 'unknown_session')
  expectAnswer('cancel', await call(ctx, 'POST', `/api/vp/session/${unknown}/cancel`), 404, 'unknown_session')

  begin('S17', "another browser's session")
  const mine = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  expectAnswer('poll', await poll(otherBrowser, mine.id), 403, 'other_browser')
  expectAnswer('complete', await complete(otherBrowser, mine.id), 403, 'other_browser')
  expectAnswer('cancel', await call(otherBrowser, 'POST', `/api/vp/session/${mine.id}/cancel`), 403, 'other_browser')

  begin('S14', 'malformed bodies at each route')
  const session = (body, contentType) => call(ctx, 'POST', '/api/vp/session', contentType ? { data: body, headers: { 'content-type': contentType } } : { data: body })
  expectAnswer('session: no body', await call(ctx, 'POST', '/api/vp/session'), 400, 'bad_request')
  expectAnswer('session: not JSON', await session('{oops', 'application/json'), 400, 'bad_request')
  expectAnswer('session: an array', await session([1, 2]), 400, 'bad_request')
  expectAnswer('session: an unknown purpose', await session({ purpose: 'x' }), 400, 'bad_request')
  expectAnswer('session: an unknown intent', await session({ purpose: 'signin', intent: 'admin' }), 400, 'bad_request')
  expectAnswer('session: age without a community', await session({ purpose: 'age' }), 400, 'bad_request')
  expectAnswer('session: age for an open community', await session({ purpose: 'age', community: 'photography' }), 400, 'bad_request')
  expectAnswer('session: age for an unknown community', await session({ purpose: 'age', community: { slug: 'teenspace' } }), 400, 'bad_request')
  const s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const uri = requestUriOf(s.authorizationUrl)
  expectAnswer('request_uri: PUT', await call(ctx, 'PUT', uri), 405, 'method_not_allowed')
  expectAnswer('request_uri: wallet_metadata not JSON', await call(ctx, 'POST', uri, { form: { wallet_metadata: '{oops' } }), 400, 'invalid_wallet_metadata')
  expectAnswer('request_uri: circuit_id_values not a list', await call(ctx, 'POST', uri, { form: { wallet_metadata: JSON.stringify({ vp_formats_supported: { circuit_zk: { circuit_id_values: 5 } } }) } }), 400, 'invalid_wallet_metadata')
  expectAnswer('request_uri: vp_formats_supported null', await call(ctx, 'POST', uri, { form: { wallet_metadata: '{"vp_formats_supported":null}' } }), 400, 'invalid_wallet_metadata')
  eq('request_uri: the session is still unused after the refusals', (await poll(ctx, s.id)).body.status, 'waiting')
  const request = await fetchRequest(ctx, s)
  expectAnswer('response_uri: no body', await call(ctx, 'POST', request.response_uri), 400, 'state_mismatch')
  expectAnswer('response_uri: JSON instead of a form', await call(ctx, 'POST', request.response_uri, { data: { state: request.state } }), 400, 'state_mismatch')
  expectAnswer('complete before an answer', await complete(ctx, s.id), 409, 'not_verified')
  expectAnswer('response_uri: vp_token null', await respond(ctx, request, { state: request.state, vp_token: 'null' }), 200)
  const nullView = await sessionView(s.id)
  eq('response_uri: vp_token null is refused, not a crash', [nullView.status, rejectedTrace(nullView)?.code], ['failed', 'vp_token'])
  for (const [what, vp] of [['not JSON', '{oops'], ['two presentations', JSON.stringify({ nym_attestation: ['a', 'b'] })], ['another query id', JSON.stringify({ other: ['a'] })]]) {
    const t = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r = await fetchRequest(ctx, t)
    expectAnswer(`response_uri: vp_token ${what}`, await respond(ctx, r, { state: r.state, vp_token: vp }), 200)
    eq(`response_uri: vp_token ${what} is refused`, rejectedTrace(await sessionView(t.id))?.code, 'vp_token')
  }
  const wallet = [
    ['sign: no body', '/api/wallet/sign', undefined],
    ['sign: no device key', '/api/wallet/sign', { request }],
    ['prove: no body', '/api/wallet/prove', undefined],
    ['prove: no request', '/api/wallet/prove', { circuit_id: VEGA, credential: teen.credential, secret_seed: teen.secret_seed, device_signature: '00' }],
    ['prove: a request without a credential query', '/api/wallet/prove', { request: { ...request, dcql_query: {} }, circuit_id: VEGA, credential: teen.credential, secret_seed: teen.secret_seed, device_signature: '00' }],
  ]
  for (const [what, path, data] of wallet) expectAnswer(what, await call(ctx, 'POST', path, data === undefined ? {} : { data }), 400, 'bad_request')
  expectAnswer('sign: any PIN signs', await call(ctx, 'POST', '/api/wallet/sign', { data: { request, pin: '000000', device_key: teen.device_key } }), 200)
  expectAnswer('sign: no PIN signs', await call(ctx, 'POST', '/api/wallet/sign', { data: { request, device_key: teen.device_key } }), 200)
  expectAnswer('the removed backend switch', await call(ctx, 'POST', '/api/demo/backend', { data: { mode: 'offline' } }), 404)

  begin('S10 S11', 'a replayed vp_token; another state; another nonce')
  const a = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const ra = await fetchRequest(ctx, a)
  const pa = await present(ctx, ra, teen)
  expectAnswer('another state', await respond(ctx, ra, { ...vpForm(ra, pa.presentation), state: 'f'.repeat(32) }), 400, 'state_mismatch')
  eq('the session still waits for its answer', (await poll(ctx, a.id)).body.status, 'scanned')
  expectAnswer('the honest answer', await respond(ctx, ra, vpForm(ra, pa.presentation)), 200)
  const first = (await complete(ctx, a.id)).body
  eq('applied once', first.kind, 'created')
  expectAnswer('the same answer again (replay)', await respond(ctx, ra, vpForm(ra, pa.presentation)), 400, 'already_answered')
  eq('the completion is unchanged', (await complete(ctx, a.id)).body, first)
  check('the server log names the replay', !SERVER_LOG || serverLog().includes(`[vp] ${a.id}: refused a second response (already_answered)`))
  const b = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  const rb = await fetchRequest(ctx, b)
  expectAnswer("another session's presentation (another nonce)", await respond(ctx, rb, vpForm(rb, pa.presentation)), 200)
  const bv = await sessionView(b.id)
  eq('refused: public_input session_transcript', [bv.status, rejectedTrace(bv)?.code, rejectedTrace(bv)?.input], ['failed', 'public_input', 'session_transcript'])
  eq('the completion', (await complete(ctx, b.id)).body, { ok: false, kind: 'invalid' })
  check('the server log names it', !SERVER_LOG || serverLog().includes(`[vp] ${b.id}: presentation refused: public_input (session_transcript)`))

  begin('S12', 'tampered presentations (native: the proof is checked)')
  const expected = {
    'a flipped proof byte': ['proof_invalid', 'proof_encoding'],
    'a changed results.nym': ['public_input:results.nym'],
    'a results key that is not the request handle': ['results'],
    'proof_time changed by one second': ['public_input:proof_time'],
    'another circuit_id': ['circuit'],
  }
  for (const [what, tamper] of Object.entries(TAMPER)) {
    const t = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r = await fetchRequest(ctx, t)
    const p = await present(ctx, r, teen)
    const changed = tamper(Buffer.from(p.presentation, 'base64url'), p).toString('base64url')
    expectAnswer(`${what}: processed`, await respond(ctx, r, vpForm(r, changed)), 200)
    const v = await sessionView(t.id)
    const got = rejectedTrace(v)
    const label = got ? (got.input ? `${got.code}:${got.input}` : got.code) : 'accepted'
    check(`${what}: refused as ${expected[what].join(' or ')}`, v.status === 'failed' && expected[what].includes(label), `${v.status}, ${label}`)
    eq(`${what}: nothing applied`, (await complete(ctx, t.id)).body, { ok: false, kind: 'invalid' })
    check(`${what}: the server log names the rule`, !SERVER_LOG || serverLog().includes(`[vp] ${t.id}: presentation refused: ${got?.code}`))
  }

  begin('S13', 'error responses from a wallet')
  for (const [error, failure] of [['access_denied', 'denied'], ['invalid_request', 'invalid_request'], ['server_error', 'invalid_request']]) {
    const t = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r = await fetchRequest(ctx, t)
    expectAnswer(`error=${error}`, await respond(ctx, r, { state: r.state, error }), 200)
    eq(`error=${error}: the session`, (await poll(ctx, t.id)).body.failure, failure)
    const v = await sessionView(t.id)
    check(`error=${error}: the trace keeps the code`, v.trace.some((e) => e.step === 'response' && e.data?.error === error))
  }
  check('one account from all of this (the honest answer)', (await accounts()).length === 1)
  await ctx.dispose()
  await otherBrowser.dispose()
}

// ---- H. The backend failing (test-only hook) ----

async function groupH() {
  await resetDemo()
  await openPage()

  begin('S15a', 'the verifier fails when a request starts')
  await armFault('verifier.info')
  let m = mark()
  await headerButton('Sign up').click()
  await dialogShows('Verification is not available right now. Try again later.')
  await dialogShows('Not completed')
  await guideIs('unavailable')
  await guideSays('could not start the request')
  check('session: 503', has(m, 'POST', '/api/vp/session', 503))
  check('the server log names the failure', !SERVER_LOG || serverLog().includes('[circuit_zk] verifier.info failed: test fault'))
  await shot('25-backend-unavailable')
  await scan()
  await phoneShows('Unsupported QR code')
  await guideIs('wallet-error')
  await phone().getByRole('button', { name: 'Close' }).click()
  let before = lastSession()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('signin-qr', before)
  await closeDialog('escape')

  begin('S15b', 'the prover fails when the phone loads (capabilities)')
  // Four times: the route asks both provers (Vega and BBS) and answers 503 only when neither
  // answers, and $fetch retries a GET that answers 503 once.
  for (let k = 0; k < 4; k++) await armFault('prover.info')
  m = mark()
  await headerButton('Sign up').click()
  await phoneShows('Connection Error')
  await guideIs('wallet-error')
  await guideSays('could not reach the provers')
  check('capabilities: 503', has(m, 'GET', '/api/wallet/capabilities', 503))
  await phone().getByRole('button', { name: 'Close' }).click()
  await scan()
  await readRequest()
  await phoneShows('Request to Share Data')
  check('the next scan tried again and worked', has(m, 'GET', '/api/wallet/capabilities', 200))
  await closeDialog('escape')

  for (const [id, step, route] of [['S15c', 'prover.sign', '/api/wallet/sign'], ['S15d', 'prover.prove', '/api/wallet/prove']]) {
    begin(id, `the prover fails at ${step}`)
    await armFault(step)
    m = mark()
    await open(headerButton('Sign up'))
    await scan()
    await readRequest()
    await phone().getByRole('button', { name: 'Share' }).click()
    await enterPin(anyPin())
    await phoneShows('Signing Failed', 30_000)
    await guideIs('wallet-error')
    await guideSays(`did not ${step === 'prover.sign' ? 'sign' : 'create the proof'}`)
    await openDetails()
    await guideSays(`${route} 500 backend_error`)
    check(`${route}: 500`, has(m, 'POST', route, 500))
    check('the wallet sent nothing', count(m, 'POST', '/api/vp/response/:id') === 0)
    await dialogShows('Continue on your phone')
    await closeDialog('button')
    await guideIs('request-closed')
    eq('no account', (await accounts()).length, 0)
  }

  begin('S15e', 'the verifier fails at verification')
  await armFault('verifier.verify')
  m = mark()
  await open(headerButton('Sign up'))
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await phoneShows('Response Error', 30_000)
  await dialogShows('Verification is not available right now. Try again later.')
  check('response_uri: 503', has(m, 'POST', '/api/vp/response/:id', 503, 'vp_token'))
  eq('server: the session', (await poll(page.request, lastSession())).body.failure, 'unavailable')
  await guideIs('wallet-error')
  await guideSays('its verifier failed')
  eq('no account', (await accounts()).length, 0)
  await phone().getByRole('button', { name: 'Close' }).click()
  await guideIs('unavailable')
  await guideSays('could not verify the response')
  before = lastSession()
  await site().getByRole('button', { name: 'Try again' }).click()
  await expectFresh('signin-qr', before)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('after the failure, the next request works', site().getByText(/^Account created: u\//), 30_000)
  await closeFromPhone()
}

// ---- I. Logged out at an age-restricted community: one request logs in and checks the age ----

async function groupI() {
  await resetDemo()
  await openPage()

  begin('G2', 'c/afterdark logged out: Requirement Not Met, still logged out')
  await goto('/c/afterdark')
  await guideIs('age-signin')
  let m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await visible('dialog: "Verify your age"', site().getByRole('heading', { name: 'Verify your age' }))
  await dialogShows('c/afterdark is for ages 18 and older. The same step logs you in with a pseudonym.')
  await guideIs('signin-age-qr')
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await guideIs('unmet')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  await dialogShows('Nothing was shared with Readdit.')
  await guideIs('not-completed')
  await guideSays('No account was created or logged in, and c/afterdark stays closed')
  check('access_denied, once', since(m).filter((e) => e.path === '/api/vp/response/:id' && e.sent === 'error=access_denied').length === 1)
  check('no proof was made', count(m, 'POST', '/api/wallet/prove') === 0)
  check('still logged out', (await me()).account === null)
  eq('no account', (await accounts()).length, 0)
  await closeDialog('escape')
  await pageShows('c/afterdark is for ages 18 and older')

  begin('G1', 'c/teenspace logged out: the account is created and the age verified, in one request')
  await goto('/c/teenspace')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phoneShows('Pseudonym')
  await phoneShows('Age proof: 13–17')
  await guideIs('signin-age-consent')
  await guideSays('in one presentation')
  await shot('26-signin-age-consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//))
  await guideIs('signin-age-verified')
  await expectVerification()
  const done = (await complete(page.request, lastSession())).body
  check('server: created, with the age recorded', done.ok === true && done.kind === 'created' && done.age === true, JSON.stringify(done))
  check('one wallet request for both', count(m, 'POST', '/api/vp/session') === 1 && count(m, 'POST', '/api/wallet/prove') === 1)
  await closeFromPhone()
  check('posts shown', (await page.locator('a[href^="/c/teenspace/p"]').count()) > 0)
  const account = (await me()).account
  check('logged in, with the proven range stored', account?.handle === done.handle && !!account?.birthDateRange?.ge, JSON.stringify(account?.birthDateRange))
  await guideIs('age-verified')

  begin('G3', 'an existing account logs in with the age verified')
  await page.getByRole('banner').getByText(`u/${account.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await goto('/c/teenspace')
  await guideIs('age-signin')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  await dialogShows(`Logged in as u/${account.handle}`)
  await guideIs('signin-age-verified')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: true, kind: 'logged_in', handle: account.handle, age: true })
  eq('still one account', (await accounts()).length, 1)
  await closeFromPhone()

  begin('G4', 'a banned account is refused')
  const ctx = await client()
  await call(ctx, 'POST', '/api/mod/ban', { data: { pseudonym: account.pseudonym } })
  await ctx.dispose()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await goto('/c/teenspace')
  await guideIs('age-signin')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await guideIs('signup-refused')
  await guideSays('refused the log-in and the age check')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: false, kind: 'banned', handle: account.handle })
  check('still logged out', (await me()).account === null)
  await closeDialog('button')
}

// ---- J. The wallet's two credentials ----

async function groupJ() {
  await resetDemo()
  await openPage()

  begin('C0', 'two phones, one credential each')
  await open(headerButton('Sign up'), TEEN)
  check('the dialog names the phone', (await phoneLabel()) === TEEN, await phoneLabel())
  await phone().getByRole('button', { name: 'Change view' }).click()
  let cards = phone().getByRole('button', { name: /^Open Age and pseudonym details, birth date/ })
  await cards.first().waitFor()
  let labels = await cards.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')))
  eq("the teen's phone holds the teen's mdoc", labels.join(' | '), 'Open Age and pseudonym details, birth date 14/03/2011')
  eq("and the teen's BBS credential", await phone().getByRole('button', { name: /^Open Age and pseudonym \(BBS\) details/ }).getAttribute('aria-label'), 'Open Age and pseudonym (BBS) details, birth date 14/03/2011')
  check('no card shows an expiry date (the credentials do not expire)', !(await phone().getByText(/Expiry Date/).count()))
  await cards.first().click()
  await phoneShows('14/03/2011')
  await guideIs('credential')
  await guideSays('an mdoc and a BBS credential')
  await phone().getByRole('button', { name: 'Back' }).click()
  await phone().getByRole('button', { name: 'Change view' }).click()
  await usePhone(ADULT)
  await phone().getByRole('button', { name: 'Change view' }).click()
  cards = phone().getByRole('button', { name: /^Open Age and pseudonym details, birth date/ })
  await cards.first().waitFor()
  labels = await cards.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')))
  eq("the adult's phone holds the adult's credential only", labels.join(' | '), 'Open Age and pseudonym details, birth date 20/05/1990')
  await shot('27-adult-phone')
  await phone().getByRole('button', { name: 'Change view' }).click()
  await closeDialog('escape')
  await signIn('Sign up', 'Account created: u/', TEEN)
  const teenAccount = (await me()).account
  await page.getByRole('banner').getByText(`u/${teenAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Sign up').waitFor()

  begin('C1', "sign-up on the adult's phone")
  let m = mark()
  await open(headerButton('Sign up'), ADULT)
  await scan()
  await readRequest()
  await guideSays('born 20 May 1990')
  await guideSays(ADULT)
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await expectVerification()
  await closeFromPhone()
  const adultAccount = (await me()).account
  check('a new account with another pseudonym', adultAccount.pseudonym !== teenAccount.pseudonym && adultAccount.handle !== teenAccount.handle, `u/${adultAccount.handle} vs u/${teenAccount.handle}`)
  eq('two accounts', (await accounts()).length, 2)

  begin('C2', "c/afterdark on the adult's phone, logged in")
  await goto('/c/afterdark')
  await guideIs('age-ask')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), ADULT)
  await scan()
  await readRequest()
  await phoneShows('Age proof: 18+')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText('Age verified').waitFor({ timeout: 30_000 })
  await expectVerification()
  await closeFromPhone()
  check('c/afterdark posts shown', (await page.locator('a[href^="/c/afterdark/p"]').count()) > 0)
  await guideIs('age-verified')
  await shot('29-afterdark-granted-adult')
  check('the adult account has an 18+ range', !!(await me()).account.birthDateRange?.le)

  begin('C3', "c/teenspace on the adult's phone: Requirement Not Met")
  await goto('/c/teenspace')
  await guideIs('age-refused')
  check('the site refuses without a request, from the 18+ range', (await page.getByText("You can't enter c/teenspace").count()) === 1)
  // Logged out, the combined request lets the adult's phone try c/teenspace.
  await page.getByRole('banner').getByText(`u/${adultAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await goto('/c/teenspace')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), ADULT)
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await guideIs('unmet')
  await guideSays('born 20 May 1990')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  check('access_denied (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=access_denied'))
  check('no proof was made', count(m, 'POST', '/api/wallet/prove') === 0)
  check('still logged out', (await me()).account === null)
  await closeDialog('escape')

  begin('C2b', "c/afterdark on the adult's phone, logged out (one request)")
  await goto('/c/afterdark')
  await guideIs('age-signin')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), ADULT)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  await dialogShows(`Logged in as u/${adultAccount.handle}`)
  await expectVerification()
  await closeFromPhone()
  check('c/afterdark posts shown', (await page.locator('a[href^="/c/afterdark/p"]').count()) > 0)

  begin('C5', 'banning one account leaves the other')
  const ctx = await client()
  await call(ctx, 'POST', '/api/mod/ban', { data: { pseudonym: adultAccount.pseudonym } })
  await ctx.dispose()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await goto('/')
  await signIn('Log in', `Logged in as u/${teenAccount.handle}`, TEEN)
  check('the teen account logs in', (await me()).account?.handle === teenAccount.handle)
  await page.getByRole('banner').getByText(`u/${teenAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await open(headerButton('Log in'), ADULT)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  eq('the adult account is refused', (await complete(page.request, lastSession())).body, { ok: false, kind: 'banned', handle: adultAccount.handle })
  await closeDialog('button')
  const list = await accounts()
  check('only the adult account is banned', list.find((a) => a.pseudonym === adultAccount.pseudonym)?.banned && !list.find((a) => a.pseudonym === teenAccount.pseudonym)?.banned)
}

// ---- G. The technical view ----

async function groupG() {
  begin('T', 'the technical view shows the sessions')
  const tech = await ctxBrowser.newPage()
  await tech.goto('/tech')
  await tech.waitForLoadState('networkidle')
  await tech.getByText('Vega, Longfellow and BBS addons, in process').waitFor()
  check('six service cards: a prover and a verifier per addon', (await tech.getByText(/^(Vega|Longfellow|BBS) (prover|verifier)$/).count()) === 6)
  await tech.getByText('Capability negotiation').waitFor()
  check('the technical view loads', true)
  await tech.close()
}


// ---- K. A community with its own pseudonym: c/france ----

/** One c/france request over HTTP with `wallet`, completed by `ctx`'s browser session. */
async function joinOverHttp(ctx, wallet, link = true) {
  const s = await newSession(ctx, { purpose: 'community', community: 'france', link })
  const request = await fetchRequest(ctx, s)
  const p = await present(ctx, request, wallet)
  await respond(ctx, request, vpForm(request, p.presentation))
  return { request, completion: (await complete(ctx, s.id)).body }
}

async function groupK() {
  await resetDemo()
  await openPage()

  begin('K1', 'c/france logged out: join with its own pseudonym, without a Readdit account')
  await goto('/c/france')
  await pageShows('c/france asks for proof of human')
  await guideIs('community-join')
  await guideSays('No Readdit account is needed')
  check('no c/france posts before joining', !(await page.locator('a[href^="/c/france/p"]').count()))
  let m = mark()
  await open(page.getByRole('button', { name: 'Join with wallet' }), TEEN)
  await guideIs('community-qr')
  await guideSays('x509_san_dns:france.readdit.example')
  await scan()
  await readRequest()
  await phoneShows('france.readdit.example')
  await phoneShows('Specific to france.readdit.example')
  await guideIs('community-consent')
  await shot('31-france-consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Joined c/france as u/…"', site().getByText(/^Joined c\/france as u\//), 30_000)
  await guideIs('community-created')
  await expectVerification()
  let done = (await complete(page.request, lastSession())).body
  check('server: created, not linked', done.ok === true && done.kind === 'created' && done.community === 'france' && !done.linked, JSON.stringify(done))
  check('the presentation was verified (vp_token 200)', has(m, 'POST', '/api/vp/response/:id', 200, 'vp_token'))
  await closeFromPhone()
  check('c/france posts shown', (await page.locator('a[href^="/c/france/p"]').count()) > 0)
  await guideIs('community-member')
  check('no Readdit account', (await me()).account === null)
  const frTeen = (await me()).communities.france
  eq('the c/france account', frTeen?.handle, done.handle)
  await visible('header: the c/france account', page.getByRole('banner').getByText(`u/${frTeen.handle}`))
  await visible('header: marked c/france', page.getByRole('banner').getByText('c/france', { exact: true }))
  check('header: no Sign up', !(await headerButton('Sign up').count()))

  begin('K2', 'a comment in c/france is the c/france account’s')
  await goto('/c/france/p22')
  eq('comment box', await page.locator('textarea').getAttribute('placeholder'), `Comment as u/${frTeen.handle}`)
  await page.locator('textarea').fill('Same in our town.')
  await page.getByRole('button', { name: 'Comment', exact: true }).click()
  await pageShows('Same in our town.')
  let list = await accounts()
  const frRecord = list.find((a) => a.handle === frTeen.handle)
  check('stored as a c/france account, not linked', frRecord?.community === 'france' && frRecord.linkedTo === null, JSON.stringify(frRecord))
  expectAnswer('server: a comment in c/france without a c/france account', await call(await client(), 'POST', '/api/comments', { data: { postId: 'p22', body: 'hi' } }), 403, 'registration_required')

  begin('K3', 'logged in to Readdit, joining c/france is a choice: link, or log out first')
  await goto('/')
  // The home page's Sign up: the header shows the c/france account instead of the buttons.
  await open(page.getByRole('main').getByRole('button', { name: 'Sign up', exact: true }), TEEN)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await closeFromPhone()
  const teenMain = (await me()).account
  check('logged in: no c/france membership until linked', !(await me()).communities.france)
  check('the Readdit pseudonym differs from the c/france one', teenMain.pseudonym !== frRecord.pseudonym)
  await goto('/c/france')
  await guideIs('community-join')
  await guideSays('join and link the two, or log out and join separately')
  await visible('page: logged in as …', page.getByText(`You are logged in as u/${teenMain.handle}.`))
  check('no plain Join with wallet while logged in', !(await page.getByRole('button', { name: 'Join with wallet' }).count()))
  await visible('Log out and join separately', page.getByRole('button', { name: 'Log out and join separately' }))
  await shot('32-france-link-choice')
  m = mark()
  await open(page.getByRole('button', { name: `Join and link to u/${teenMain.handle}` }), TEEN)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows(`In c/france as u/${frTeen.handle}`, 30_000)
  await dialogShows('Linked to your Readdit account.')
  await guideIs('community-linked')
  done = (await complete(page.request, lastSession())).body
  check('server: logged in and linked', done.ok === true && done.kind === 'logged_in' && done.linked === true, JSON.stringify(done))
  await closeFromPhone()
  check('linked', (await me()).communities.france?.linked === true)
  await guideIs('community-member')

  begin('K4', 'one c/france account per Readdit account, one Readdit account per c/france account')
  const ctx = await client()
  {
    // Log in with the teen's Readdit account, linked in K3.
    const s = await newSession(ctx, { purpose: 'signin', intent: 'login' })
    const request = await fetchRequest(ctx, s)
    const p = await present(ctx, request, teen)
    await respond(ctx, request, vpForm(request, p.presentation))
    eq("the teen's Readdit account logs in", (await complete(ctx, s.id)).body.kind, 'logged_in')
  }
  expectAnswer('server: logged in, a join must choose to link', await call(ctx, 'POST', '/api/vp/session', { data: { purpose: 'community', community: 'france' } }), 400, 'link_required')
  let r = await joinOverHttp(ctx, adult)
  eq("the request's client_id", r.request.client_id, 'x509_san_dns:france.readdit.example')
  eq("the adult's wallet for the teen's account", r.completion, { ok: false, kind: 'other_pseudonym', handle: frTeen.handle, community: 'france' })
  const ctx2 = await client()
  await signInOverHttp(ctx2, adult)
  r = await joinOverHttp(ctx2, teen)
  check("the teen's c/france account for the adult's Readdit account: refused", r.completion.ok === false && r.completion.kind === 'linked_elsewhere', JSON.stringify(r.completion))
  r = await joinOverHttp(ctx2, adult)
  check("the adult's own c/france account: created and linked", r.completion.ok === true && r.completion.kind === 'created' && r.completion.linked === true, JSON.stringify(r.completion))
  expectAnswer('server: a community without its own pseudonym', await call(ctx2, 'POST', '/api/vp/session', { data: { purpose: 'community', community: 'photography' } }), 400, 'bad_request')
  await ctx.dispose()
  await ctx2.dispose()
  list = await accounts()
  eq('four accounts: two Readdit, two c/france', list.map((a) => (a.community ? 'c' : 'r')).sort().join(''), 'ccrr')
  {
    // /mod groups each c/france account under the Readdit account it is linked to.
    const mod = await ctxBrowser.newPage()
    await mod.goto('/mod')
    const groups = mod.locator('section').filter({ has: mod.getByRole('heading', { name: 'Accounts' }) }).locator(':scope > ul > li')
    await groups.filter({ hasText: `u/${frTeen.handle}` }).waitFor()
    eq('/mod: two groups', await groups.count(), 2)
    const teenGroup = groups.filter({ hasText: `u/${teenMain.handle}` })
    check("/mod: the teen's c/france account under the teen's Readdit account", (await teenGroup.count()) === 1 && (await teenGroup.getByText(`u/${frTeen.handle}`).count()) === 1)
    await mod.close()
  }

  begin('K5', 'a ban in c/france leaves the Readdit account')
  const mod = await client()
  await call(mod, 'POST', '/api/mod/ban', { data: { pseudonym: frRecord.pseudonym } })
  await mod.dispose()
  await goto('/c/france')
  await pageShows('Your c/france account is banned')
  await guideIs('community-banned')
  eq('the Readdit account is still logged in', (await me()).account?.handle, teenMain.handle)
  await goto('/c/france/p22')
  check('the banned account’s comment is hidden', !(await page.getByText('Same in our town.').count()))
  await page.getByRole('banner').getByText(`u/${teenMain.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await goto('/c/france')
  await open(page.getByRole('button', { name: 'Join with wallet' }), TEEN)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await guideIs('community-ban-refused')
  await closeDialog('button')
  const mod2 = await client()
  await call(mod2, 'POST', '/api/mod/unban', { data: { pseudonym: frRecord.pseudonym } })

  begin('K6', 'a ban of the Readdit account bans its linked c/france account; unbanning lifts both')
  list = await accounts()
  const adultMain = list.find((a) => !a.community && a.handle !== teenMain.handle)
  const adultFr = list.find((a) => a.community === 'france' && a.linkedTo === adultMain?.handle)
  check('the c/france ban is lifted', !list.find((a) => a.pseudonym === frRecord.pseudonym).banned)
  await call(mod2, 'POST', '/api/mod/ban', { data: { pseudonym: teenMain.pseudonym } })
  list = await accounts()
  const frBanned = list.find((a) => a.pseudonym === frRecord.pseudonym).banned
  check('the linked c/france account is banned with it', frBanned?.cascade === true && frBanned.reason === `Readdit account u/${teenMain.handle} banned`, JSON.stringify(frBanned))
  check("the adult's accounts are untouched", !list.find((a) => a.handle === adultMain.handle).banned && !list.find((a) => a.handle === adultFr.handle).banned)
  await call(mod2, 'POST', '/api/mod/ban', { data: { pseudonym: adultFr.pseudonym } })
  check("a c/france ban leaves the adult's Readdit account", !(await accounts()).find((a) => a.handle === adultMain.handle).banned)
  await call(mod2, 'POST', '/api/mod/unban', { data: { pseudonym: teenMain.pseudonym } })
  list = await accounts()
  check('unbanning the Readdit account lifts the cascaded ban', !list.find((a) => a.handle === teenMain.handle).banned && !list.find((a) => a.pseudonym === frRecord.pseudonym).banned)
  check("but not a c/france account's own ban", !!list.find((a) => a.handle === adultFr.handle).banned)
  // A banned c/france account stays banned when its Readdit account is banned and unbanned.
  await call(mod2, 'POST', '/api/mod/ban', { data: { pseudonym: adultMain.pseudonym } })
  await call(mod2, 'POST', '/api/mod/unban', { data: { pseudonym: adultMain.pseudonym } })
  check("the c/france account's own ban survives", (await accounts()).find((a) => a.handle === adultFr.handle).banned?.reason === 'Community rules')
  await mod2.dispose()

  begin('K7', 'logged in, "Log out and join separately" joins without linking')
  await resetDemo()
  await openPage()
  await goto('/')
  await signIn('Sign up', /^Account created: u\//)
  const teenMain2 = (await me()).account
  await goto('/c/france')
  await guideIs('community-join')
  await open(page.getByRole('button', { name: 'Log out and join separately' }), TEEN)
  check('logged out of Readdit', (await me()).account === null)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Joined c/france as u/…"', site().getByText(/^Joined c\/france as u\//), 30_000)
  await guideIs('community-created')
  done = (await complete(page.request, lastSession())).body
  check('server: created, not linked', done.ok === true && done.kind === 'created' && !done.linked, JSON.stringify(done))
  await closeFromPhone()
  const sep = await me()
  check('a c/france member, not linked, not logged in to Readdit', sep.account === null && sep.communities.france?.linked === false, JSON.stringify(sep))
  check('stored unlinked', (await accounts()).find((a) => a.handle === done.handle)?.linkedTo === null)
  check('the Readdit account still exists', !!(await accounts()).find((a) => a.handle === teenMain2.handle))
}

// ---- M. BBS: the mms_zk format next to circuit_zk (docs/mms_zk.md) ----

async function groupM() {
  await resetDemo()
  await openPage()

  begin('M1', "the site's accepted proof systems, switched in /tech")
  let o = (await call(page.request, 'GET', '/api/tech/overview')).body
  eq('accepted: Vega (switched on by this run)', o.acceptedProofSystems, ['vega-v1'])
  check('all three backends loaded', o.services.bbsProver.up && o.services.bbsVerifier.up && o.services.prover.up && o.services.verifier.up && o.services.lfProver.up && o.services.lfVerifier.up)
  eq('server: turning off the last proof system is allowed', (await accept('vega-v1', false)).body.acceptedProofSystems, [])
  await accept('vega-v1', true)
  expectAnswer('server: an unknown proof system', await accept('vega-v2', true), 400, 'bad_request')
  {
    const ctx = await client()
    const s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const req = await fetchRequest(ctx, s)
    eq('Vega only: one credential query, circuit_zk', req.dcql_query.credentials.map((q) => q.format), ['circuit_zk'])
    check('no mms_zk metadata', !req.client_metadata.vp_formats_supported.mms_zk && !req.dcql_query.credential_sets)
    await ctx.dispose()
  }
  const tech = await ctxBrowser.newPage()
  await tech.goto('/tech')
  await tech.locator(`[data-accept="${BBS_SYSTEM}"]`).check()
  for (let k = 0; k < 30 && !(await call(page.request, 'GET', '/api/tech/overview')).body.acceptedProofSystems.includes(BBS_SYSTEM); k++) await page.waitForTimeout(100)
  o = (await call(page.request, 'GET', '/api/tech/overview')).body
  eq('/tech: BBS switched on', o.acceptedProofSystems, ['vega-v1', BBS_SYSTEM])
  await tech.close()

  begin('M2', 'both accepted: the request offers both formats as alternatives; the teen signs up with the BBS credential')
  let m = mark()
  await open(headerButton('Sign up'), TEEN)
  await scan()
  await readRequest()
  let req = (await sessionView(lastSession())).request
  eq('two credential queries', req.dcql_query.credentials.map((q) => `${q.id}:${q.format}`), ['nym_attestation:circuit_zk', 'nym_attestation_bbs:mms_zk'])
  eq('credential_sets: one of them', req.dcql_query.credential_sets, [{ options: [['nym_attestation'], ['nym_attestation_bbs']] }])
  eq('mms_zk metadata', req.client_metadata.vp_formats_supported.mms_zk, { proof_system_values: [BBS_SYSTEM], scheme_id_values: [BBS_SCHEME] })
  eq('the BBS req', req.dcql_query.credentials[1].req, [{ id: 'pseudonym-bbs-v1', return: 'nym', params: { config: 'known-offender-matching-ssc', verifier_id_type: 'x509_san_dns' } }])
  const view = await sessionView(lastSession())
  eq("the teen's phone tells both formats in wallet_metadata", Object.keys(view.walletMetadata.vp_formats_supported).sort(), ['circuit_zk', 'mms_zk'])
  await visible('Switch credential: the BBS credential is the other match', phone().getByRole('button', { name: /Switch credential/ }))
  await phone().getByRole('button', { name: /Switch credential/ }).click()
  await guideIs('switch-credential')
  await phone().getByRole('button', { name: /^Select credential Age and pseudonym \(BBS\)/ }).click()
  await phoneShows('Request to Share Data')
  await phoneShows('Specific to readdit.example')
  await guideIs('consent')
  await openDetails()
  await guideSays('pseudonym-bbs-v1')
  await guideSays('BBS nym_auth v1 (bbs-cd-plugins-v0.1)')
  await shot('33-bbs-consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await guideIs('pin')
  await guideSays('ecdsa-pop plugin proves')
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await expectVerification()
  await guideSays('the BBS addon')
  check('one prove call, no sign call', has(m, 'POST', '/api/wallet/prove', 200) && !has(m, 'POST', '/api/wallet/sign', 200))
  let sv = await sessionView(lastSession())
  eq('the answered query', sv.answered, 'nym_attestation_bbs')
  eq('the scheme used', sv.scheme?.scheme_id, BBS_SCHEME)
  const proveTrace = sv.trace.find((t) => t.step === 'prove')?.data
  check('the prove trace has each part', proveTrace?.format === 'mms_zk' && proveTrace.metrics.ecdsa_pop_ms > 0 && proveTrace.metrics.parts?.bbs_proof > 0, JSON.stringify(proveTrace?.metrics?.parts))
  eq('plugins in the BBS request', proveTrace?.statement?.plugins, ['ecdsa-pop/0.1', 'pseudonym/0.1'])
  await closeFromPhone()
  const bbsAccount = (await me()).account
  let list = await accounts()
  eq('stored as a BBS account', list.find((a) => a.handle === bbsAccount.handle)?.format, 'mms_zk')

  begin('M3', 'the next request starts with the BBS credential: c/teenspace proves 13–17 with date-range')
  // A link, not a reload: the phone keeps its chosen card until the page reloads.
  await page.click('a[href="/c/teenspace"]')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), TEEN)
  await scan()
  await readRequest()
  await phoneShows('Age proof: 13–17')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  sv = await sessionView(lastSession())
  eq('answered with the BBS credential', sv.answered, 'nym_attestation_bbs')
  eq('plugins, with date-range', sv.trace.find((t) => t.step === 'prove')?.data?.statement?.plugins, ['ecdsa-pop/0.1', 'pseudonym/0.1', 'date-range/0.1'])
  await closeFromPhone()
  check('the age range is recorded on the BBS account', !!(await me()).account?.birthDateRange, JSON.stringify((await me()).account?.birthDateRange))
  await goto('/c/afterdark')
  await pageShows("You can't enter c/afterdark")

  begin('M4', 'the mdoc gives another account: its pseudonym is another function')
  await page.getByRole('banner').getByText(`u/${bbsAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  // The page was reloaded (goto), so the phone starts again with its first card, the mdoc.
  await open(headerButton('Log in'), TEEN)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: /Switch credential/ }).click()
  await visible('Switch credential offers the BBS credential', phone().getByRole('button', { name: /^Select credential Age and pseudonym \(BBS\)/ }))
  await phone().getByRole('button', { name: 'Close' }).click()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('No account', 30_000)
  eq('answered with the mdoc', (await sessionView(lastSession())).answered, 'nym_attestation')
  await closeDialog('escape')

  begin('M5', 'BBS only: the adult has no BBS credential; the teen logs in to the same BBS account')
  eq('server: Vega off', (await accept('vega-v1', false)).body.acceptedProofSystems, [BBS_SYSTEM])
  m = mark()
  await open(headerButton('Log in'), ADULT)
  await scan()
  await readRequest()
  await phoneShows('Unsupported Request')
  await guideIs('unsupported')
  await openDetails()
  await guideSays('the request asks for mms_zk')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed', 15_000)
  await closeDialog('escape')
  await open(headerButton('Log in'), TEEN)
  await scan()
  await readRequest()
  check('one matching credential: no Switch credential', !(await phone().getByRole('button', { name: /Switch credential/ }).count()))
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows(`Logged in as u/${bbsAccount.handle}`, 30_000)
  await closeFromPhone()

  begin('M6', 'c/france with BBS: its own pseudonym, linked when chosen')
  await goto('/c/france')
  await open(page.getByRole('button', { name: `Join and link to u/${bbsAccount.handle}` }), TEEN)
  await scan()
  await readRequest()
  await phoneShows('Specific to france.readdit.example')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Joined c/france as u/…"', site().getByText(/^Joined c\/france as u\//), 30_000)
  await closeFromPhone()
  const fr = (await me()).communities.france
  check('linked, another pseudonym', fr?.linked === true && fr.handle !== bbsAccount.handle, JSON.stringify(fr))

  begin('M7', 'a ban sticks to the BBS pseudonym (known-offender matching)')
  const mod = await client()
  await call(mod, 'POST', '/api/mod/ban', { data: { pseudonym: bbsAccount.pseudonym } })
  await mod.dispose()
  await goto('/')
  await headerButton('Sign up').waitFor()
  await open(headerButton('Sign up'), TEEN)
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Account banned', 30_000)
  await closeDialog('button')

  begin('M8', 'over HTTP: the BBS verifier refuses replays and tampering')
  const ctx = await client()
  let s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  req = await fetchRequest(ctx, s)
  eq('BBS only: one mms_zk query', req.dcql_query.credentials.map((q) => q.format), ['mms_zk'])
  let p = await presentBbs(ctx, req)
  check('prove: a 32-byte pseudonym', /^[0-9a-f]{64}$/.test(p.results.nym), p.results.nym)
  expectAnswer('prove: without a device key', await call(ctx, 'POST', '/api/wallet/prove', { data: { request: req, credential_query_id: 'nym_attestation_bbs', credential: teenBbs.credential } }), 400, 'bad_request')
  {
    const other = await call(ctx, 'POST', '/api/wallet/prove', { data: { request: req, credential_query_id: 'nym_attestation_bbs', credential: teenBbs.credential, device_key: adult.device_key } })
    expectAnswer("prove: another phone's device key", other, 400, 'bad_credential')
  }
  const bytes = Buffer.from(p.presentation, 'base64url')
  for (const [what, at] of [['a flipped byte in the BBS proof', 40], ['a flipped byte in the ecdsa-pop proof', Math.floor(bytes.length / 2)], ['a flipped byte in the pseudonym proof', bytes.length - 60]]) {
    const s2 = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r2 = await fetchRequest(ctx, s2)
    const p2 = await presentBbs(ctx, r2)
    const b2 = Buffer.from(p2.presentation, 'base64url')
    b2[Math.min(at, b2.length - 1)] ^= 1
    await respond(ctx, r2, bbsForm(r2, b2.toString('base64url')))
    const v = await sessionView(s2.id)
    const refused = v.trace.find((t) => t.step === 'verify' && t.label === 'Proof rejected')?.data
    check(`refused: ${what}`, v.status === 'failed' && (refused?.code === 'proof_invalid' || refused?.code === 'presentation'), refused ? `${refused.code}: ${refused.reason}` : v.status)
  }
  // The genuine presentation, for another request: refused (nonce and handover differ).
  {
    const s3 = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r3 = await fetchRequest(ctx, s3)
    await respond(ctx, r3, bbsForm(r3, p.presentation))
    const refused = (await sessionView(s3.id)).trace.find((t) => t.label === 'Proof rejected')?.data
    eq('refused: a presentation made for another request', refused?.code, 'proof_invalid')
  }
  let r = await respond(ctx, req, bbsForm(req, p.presentation))
  check('the genuine one: processed (200)', r.status === 200, answer(r))
  check('verified', (await sessionView(s.id)).status === 'verified')
  expectAnswer('a replay', await respond(ctx, req, bbsForm(req, p.presentation)), 400, 'already_answered')
  // A vp_token that answers both queries, or the circuit_zk one with a BBS presentation.
  await accept('vega-v1', true)
  s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  req = await fetchRequest(ctx, s)
  p = await presentBbs(ctx, req)
  await respond(ctx, req, { state: req.state, vp_token: JSON.stringify({ nym_attestation: [p.presentation], nym_attestation_bbs: [p.presentation] }) })
  eq('refused: two answers', (await sessionView(s.id)).trace.find((t) => t.label === 'Proof rejected')?.data?.code, 'vp_token')
  s = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
  req = await fetchRequest(ctx, s)
  p = await presentBbs(ctx, req)
  await respond(ctx, req, { state: req.state, vp_token: JSON.stringify({ nym_attestation: [p.presentation] }) })
  const wrong = (await sessionView(s.id)).trace.find((t) => t.label === 'Proof rejected')?.data
  check('refused: a BBS presentation as the mdoc answer', !!wrong, wrong ? `${wrong.code}: ${wrong.reason}` : 'accepted')
  await ctx.dispose()

  begin('M10', "a switch in /tech applies to a QR code already on screen")
  await accept(BBS_SYSTEM, false)
  await goto('/')
  await open(headerButton('Log in'), ADULT)
  check('Vega only when the QR code appears', (await sessionView(lastSession())).offer.mms_zk === undefined)
  await accept(BBS_SYSTEM, true)
  await accept('vega-v1', false)
  await scan()
  await readRequest()
  await phoneShows('Unsupported Request')
  let sv10 = await sessionView(lastSession())
  check('the request the wallet fetched offers BBS only', sv10.request.dcql_query.credentials.map((q) => q.format).join() === 'mms_zk', JSON.stringify(sv10.request.dcql_query.credentials.map((q) => q.format)))
  check('the trace says why', sv10.trace.some((t) => t.label === 'Offer updated: the accepted proof systems changed'))
  await phone().getByRole('button', { name: 'Close' }).click()
  await closeDialog('escape')

  begin('M11', 'a format switched off after the scan: its presentation is refused')
  await accept('vega-v1', true)
  {
    const c = await client()
    const s11 = await newSession(c, { purpose: 'signin', intent: 'signup' })
    const r11 = await fetchRequest(c, s11)
    const p11 = await present(c, r11, adult)
    await accept('vega-v1', false)
    await respond(c, r11, vpForm(r11, p11.presentation))
    const v = await sessionView(s11.id)
    const refused = v.trace.find((t) => t.label === 'Proof rejected')?.data
    check('refused: circuit_zk is no longer accepted', v.status === 'failed' && refused?.code === 'format', refused ? `${refused.code}: ${refused.reason}` : v.status)
    await c.dispose()
  }

  begin('M9', 'a demo reset switches every proof system off')
  await resetDemo([])
  eq('accepted', await acceptedNow(), [])
}

// ---- L. Longfellow: the second circuit_zk backend, over the same mdoc (SPEC.md L) ----

async function groupL() {
  await resetDemo([])
  await openPage()

  begin('L1', 'nothing accepted (the demo\'s start): the dialog stops before the QR code')
  let m = mark()
  await headerButton('Sign up').click()
  await dialogShows('No proof accepted')
  await dialogShows('Readdit does not accept any proof yet. Switch one on in the technical view, then try again.')
  await guideIs('none-accepted')
  check('session: 503', has(m, 'POST', '/api/vp/session', 503))
  await closeDialog('escape')
  const tech = await ctxBrowser.newPage()
  await tech.goto('/tech')
  await visible('/tech says nothing is accepted', tech.locator('[data-none-accepted]'))
  check('/tech: three proof systems to tick', (await tech.locator('[data-accept]').count()) === 3)
  await tech.locator(`[data-accept="${LONGFELLOW_SYSTEM}"]`).check()
  for (let k = 0; k < 30 && !(await acceptedNow()).includes(LONGFELLOW_SYSTEM); k++) await page.waitForTimeout(100)
  eq('/tech: Longfellow switched on', await acceptedNow(), [LONGFELLOW_SYSTEM])
  await tech.close()

  begin('L2', 'Longfellow only: the teen signs up; the request offers the Longfellow circuit')
  m = mark()
  await open(headerButton('Sign up'), TEEN)
  await scan()
  await readRequest()
  let sv = await sessionView(lastSession())
  eq('circuit_zk with the Longfellow circuit only', sv.request.client_metadata.vp_formats_supported.circuit_zk, { circuit_proof_system_values: [LONGFELLOW_SYSTEM], circuit_id_values: [LONGFELLOW] })
  eq('one credential query, circuit_zk', sv.request.dcql_query.credentials.map((q) => q.format), ['circuit_zk'])
  await phoneShows('Request to Share Data')
  await guideIs('consent')
  await openDetails()
  await guideSays('Longfellow nym_auth v1 (longfellow-libzk-v1)')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await expectVerification()
  await guideSays('the Longfellow addon')
  sv = await sessionView(lastSession())
  eq('the circuit used', sv.circuit?.circuit_id, LONGFELLOW)
  const proveTrace = sv.trace.find((t) => t.step === 'prove')?.data
  check('proved by the Longfellow addon, about 344 kB', proveTrace?.backend === 'longfellow' && proveTrace.metrics.proof_bytes > 300_000, `${proveTrace?.backend}, ${proveTrace?.metrics?.proof_bytes} bytes`)
  const witnessTrace = sv.trace.find((t) => t.step === 'witness')?.data
  eq('the witness: both circuits', witnessTrace?.counts, { hash: { inputs: 97032, public: 586 }, signature: { inputs: 4765, public: 1155 } })
  check('sign and prove went to /api/wallet', has(m, 'POST', '/api/wallet/sign', 200) && has(m, 'POST', '/api/wallet/prove', 200))
  await closeFromPhone()
  const lf = (await me()).account

  begin('L3', 'the teen tries c/afterdark first, then proves 13–17 for c/teenspace with Longfellow')
  await goto('/c/afterdark')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), TEEN)
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  check('no proof was made', count(m, 'POST', '/api/wallet/prove') === 0)
  await closeDialog('escape')
  await goto('/c/teenspace')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), TEEN)
  await scan()
  await readRequest()
  await phoneShows('Age proof: 13–17')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  eq('with Longfellow', (await sessionView(lastSession())).circuit?.circuit_id, LONGFELLOW)
  await closeFromPhone()
  check('the age range is recorded', !!(await me()).account?.birthDateRange)
  await goto('/c/afterdark')
  await pageShows("You can't enter c/afterdark")

  begin('L4', 'Vega only: the same pseudonym, so the teen logs in to the same account')
  await accept('vega-v1', true)
  await accept(LONGFELLOW_SYSTEM, false)
  await goto('/')
  await page.getByRole('banner').getByText(`u/${lf.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await signIn('Log in', `Logged in as u/${lf.handle}`)
  eq('with Vega', (await sessionView(lastSession())).circuit?.circuit_id, VEGA)

  begin('L5', 'both accepted: Vega first; a wallet that runs only Longfellow is sent Longfellow')
  await accept(LONGFELLOW_SYSTEM, true)
  eq('accepted, in order', await acceptedNow(), ['vega-v1', LONGFELLOW_SYSTEM])
  const ctx = await client()
  let s = await newSession(ctx, { purpose: 'signin', intent: 'login' })
  let req = await fetchRequest(ctx, s, null)
  eq('without wallet_metadata: both circuits, Vega first', req.client_metadata.vp_formats_supported.circuit_zk.circuit_id_values, [VEGA, LONGFELLOW])
  s = await newSession(ctx, { purpose: 'signin', intent: 'login' })
  const lfOnly = JSON.stringify({ vp_formats_supported: { circuit_zk: { circuit_proof_system_values: [LONGFELLOW_SYSTEM], circuit_id_values: [LONGFELLOW] } } })
  req = await fetchRequest(ctx, s, lfOnly)
  eq('tailored to the wallet', req.client_metadata.vp_formats_supported.circuit_zk, { circuit_proof_system_values: [LONGFELLOW_SYSTEM], circuit_id_values: [LONGFELLOW] })
  let p = await present(ctx, req, teen, LONGFELLOW)
  eq('prove: the Longfellow circuit', p.circuit_id, LONGFELLOW)
  eq('the same pseudonym as the account', p.results.nym, lf.pseudonym)
  expectAnswer('the response', await respond(ctx, req, vpForm(req, p.presentation)), 200)
  let done = (await complete(ctx, s.id)).body
  check('logged in to the same account', done.ok === true && done.kind === 'logged_in' && done.handle === lf.handle, JSON.stringify(done))
  {
    const r = await call(ctx, 'POST', '/api/wallet/prove', { data: { request: req, circuit_id: LONGFELLOW, credential: adult.credential, secret_seed: teen.secret_seed, device_signature: '00'.repeat(64) } })
    expectAnswer("prove: another holder's seed", r, 400, 'bad_credential')
  }

  begin('L6', 'the adult signs up with Longfellow and proves 18+ for c/afterdark')
  await accept('vega-v1', false)
  await goto('/')
  await page.getByRole('banner').getByText(`u/${lf.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Sign up').waitFor()
  await signIn('Sign up', 'Account created: u/', ADULT)
  await goto('/c/afterdark')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }), ADULT)
  await scan()
  await readRequest()
  await phoneShows('Age proof: 18+')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  eq('with Longfellow', (await sessionView(lastSession())).circuit?.circuit_id, LONGFELLOW)
  await closeFromPhone()

  begin('L7', 'over HTTP: the Longfellow verifier refuses tampering and a presentation for another request')
  const tampers = {
    ...TAMPER,
    'another circuit_id': (b) => replaceOnce(b, Buffer.from(LONGFELLOW), Buffer.from(LONGFELLOW.replace(':v1', ':v2'))),
  }
  const expected = {
    'a flipped proof byte': ['proof_invalid:hash', 'proof_invalid:signature', 'proof_encoding'],
    'a changed results.nym': ['proof_invalid:hash'],
    'a results key that is not the request handle': ['results'],
    'proof_time changed by one second': ['proof_invalid:hash'],
    'another circuit_id': ['circuit'],
  }
  for (const [what, tamper] of Object.entries(tampers)) {
    const t = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const r = await fetchRequest(ctx, t, lfOnly)
    const pt = await present(ctx, r, teen, LONGFELLOW)
    const changed = tamper(Buffer.from(pt.presentation, 'base64url'), pt).toString('base64url')
    await respond(ctx, r, vpForm(r, changed))
    const v = await sessionView(t.id)
    const got = rejectedTrace(v)
    const label = got ? (got.input ? `${got.code}:${got.input}` : got.code) : 'accepted'
    check(`${what}: refused as ${expected[what].join(' or ')}`, v.status === 'failed' && expected[what].includes(label), `${v.status}, ${label}`)
  }
  {
    const a = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const ra = await fetchRequest(ctx, a, lfOnly)
    const pa = await present(ctx, ra, teen, LONGFELLOW)
    const b = await newSession(ctx, { purpose: 'signin', intent: 'signup' })
    const rb = await fetchRequest(ctx, b, lfOnly)
    await respond(ctx, rb, vpForm(rb, pa.presentation))
    const got = rejectedTrace(await sessionView(b.id))
    check("another session's presentation: refused, proof_invalid", got?.code === 'proof_invalid', got ? `${got.code}:${got.input}` : 'accepted')
  }

  begin('L8', 'Longfellow switched off after the scan: its presentation is refused')
  await accept('vega-v1', true)
  s = await newSession(ctx, { purpose: 'signin', intent: 'login' })
  req = await fetchRequest(ctx, s, lfOnly)
  p = await present(ctx, req, teen, LONGFELLOW)
  await accept(LONGFELLOW_SYSTEM, false)
  await respond(ctx, req, vpForm(req, p.presentation))
  const v8 = await sessionView(s.id)
  const r8 = rejectedTrace(v8)
  check('refused: format, Longfellow no longer accepted', v8.status === 'failed' && r8?.code === 'format', r8 ? `${r8.code}: ${r8.reason}` : v8.status)
  await ctx.dispose()

  begin('L9', 'a demo reset switches every proof system off')
  await resetDemo([])
  eq('accepted', await acceptedNow(), [])
}

// ---------------------------------------------------------------------------------------------

let crashed = null
try {
  if (STARTUP) await startupWithoutAddon()
  const ttl = await preconditions()
  if (ONLY) {
    const groups = { E: groupE, F: groupF, H: groupH, I: groupI, J: groupJ, K: groupK, L: groupL, M: groupM, G: groupG }
    for (const g of ONLY) await groups[g]()
    throw Object.assign(new Error('only'), { only: true })
  }
  const created = await groupA()
  await groupB(created)
  await groupC(created)
  await groupD(ttl)
  await groupE()
  await groupF()
  await groupH()
  await groupI()
  await groupJ()
  await groupM()
  await groupL()
  await groupK()
  await groupG()
} catch (e) {
  if (!e.only) {
    crashed = e
    check(`the run reached the end`, false, e.message.split('\n')[0])
    if (page) await page.screenshot({ path: join(SHOTS ?? '.', 'flows-failure.png') }).catch(() => {})
  }
}
await browser.close()

console.log('\n== console')
for (const a of ALLOWED) console.log(`${allowedSeen.has(`${a[0]} ${a[1]}`) ? 'seen   ' : 'unused '} deliberate ${a[0]} ${a[1]}`)
check('no console error except the deliberate ones', consoleErrors.length === 0, consoleErrors.join('\n'))
check('any PIN signs: no sign call was refused with 401 in the whole run', signRefused === 0, `${signRefused}`)
const failed = results.filter((r) => !r.ok)
const flows = [...new Set(results.map((r) => r.flow))]
console.log(`\n${results.length - failed.length}/${results.length} checks passed over ${flows.length} flows${failed.length ? `; failed:\n${failed.map((f) => `  [${f.flow}] ${f.what}  ${f.detail ?? ''}`).join('\n')}` : ''}`)
if (crashed) console.error(crashed.stack)
process.exit(failed.length ? 1 : 0)
