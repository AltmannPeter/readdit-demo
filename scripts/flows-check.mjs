// Drives every flow of the inventory against a running production build: in the browser where a
// person can reach the path, and over HTTP where only a client can (replay, tampering, malformed
// bodies, expiry, another browser). For each path it checks the product's state (the phone's
// screen, the site's dialog and page), the guide's step, the servers' answers (status and code),
// and that nothing carries over into the next path. Exits 1 on a failed check, or on a console
// error that is not one of the deliberate ones (ALLOWED, by status and route).
// scripts/demo-flow.mjs stays the presentation order and its screenshots.
//
// The wallet holds two credentials (app/wallet/demo-wallet.json): the teen's (born 2011, the
// default for every request) and an adult's (born 1990). Any PIN unlocks the wallet.
//
// The server is started for this run with two settings; the run checks them first:
//   NUXT_VP_SESSION_TTL_S=40        requests expire after 40 s, so the expiry paths take a minute
//   READDIT_TEST_FAULTS=1           the test-only hook that fails one addon call (server/utils/test-faults.ts)
// For example:
//   NUXT_VP_SESSION_TTL_S=40 READDIT_TEST_FAULTS=1 PORT=3000 node .output/server/index.mjs > /tmp/server.log 2>&1 &
//   node scripts/flows-check.mjs http://localhost:3000 --server-log /tmp/server.log \
//     [--startup .output/server/index.mjs] [--shots docs/screenshots/vega-siros-wallet]
//
// --server-log  the server's output: each refused presentation must be logged with its rule
// --startup     also starts the built server without the addon and checks that it refuses to run
// --shots       saves the screenshots of this run (19-29) there
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
const BASE = argv[0] ?? 'http://localhost:3000'
// Any 6 digits unlock the wallet: every PIN entry is a different one.
const anyPin = () => String(Math.floor(Math.random() * 1e6)).padStart(6, '0')
const root = fileURLToPath(new URL('../', import.meta.url))
const [teen, adult] = JSON.parse(readFileSync(join(root, 'app/wallet/demo-wallet.json'), 'utf8')).holders
const VEGA = 'urn:circuits:vega:nym_auth:v1'
const LONGFELLOW = 'urn:circuits:longfellow:nym_auth:v1'
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
async function fetchRequest(ctx, session) {
  const r = await call(ctx, 'POST', requestUriOf(session.authorizationUrl), { form: { wallet_nonce: randomUUID(), wallet_metadata: WALLET_METADATA } })
  if (r.status !== 200) throw new Error(`request_uri ${answer(r)}`)
  return payloadOf(r.text.trim())
}
/** The phone's native steps for `wallet`, through the site's /api/wallet routes. */
async function present(ctx, request, wallet) {
  const s = await call(ctx, 'POST', '/api/wallet/sign', { data: { request, device_key: wallet.device_key } })
  if (s.status !== 200) throw new Error(`sign ${answer(s)}`)
  const p = await call(ctx, 'POST', '/api/wallet/prove', {
    data: { request, circuit_id: VEGA, credential: wallet.credential, secret_seed: wallet.secret_seed, device_signature: s.body.device_signature },
  })
  if (p.status !== 200) throw new Error(`prove ${answer(p)}`)
  return p.body
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
async function resetDemo() {
  const ctx = await client()
  await call(ctx, 'POST', '/api/demo/reset')
  await ctx.dispose()
}
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

async function open(button) {
  await button.click()
  await phone().getByRole('button', { name: 'Scan QR code' }).waitFor({ timeout: 15_000 })
}
const headerButton = (name) => page.getByRole('banner').getByRole('button', { name, exact: true })
/** The id of the session the dialog created after `before`. */
async function newSessionId(before) {
  for (let i = 0; i < 100 && lastSession() === before; i++) await page.waitForTimeout(100)
  return lastSession() !== before ? lastSession() : null
}
/** A dialog that starts afresh: a new session, the phone on its home screen, the QR step in the guide. */
async function expectFresh(guideId, before) {
  await site().getByText('Open SIROS ID on your phone').waitFor({ timeout: 15_000 })
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
/** "Switch credential" on the phone, then the one other credential the popup offers. */
async function switchCredential() {
  await phone().getByRole('button', { name: /^Switch credential/ }).click()
  await phone().getByText('Select the credential to use for this request.').waitFor()
  await phone().getByRole('button', { name: /^Select credential/ }).click()
  await phone().getByText('Select the credential to use for this request.').waitFor({ state: 'detached' })
  await guideLeaves('switch-credential')
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
async function signIn(name, expectText) {
  await open(headerButton(name))
  await scan()
  await readRequest()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText(expectText).waitFor({ timeout: 30_000 })
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
}
async function goto(path) {
  await page.goto(path)
  await ready()
}
const me = async () => (await call(page.request, 'GET', '/api/me')).body

// ---------------------------------------------------------------------------------------------

async function startupWithoutAddon() {
  begin('S16', 'the server refuses to start without the addon')
  const child = spawn(process.execPath, [STARTUP], {
    env: { ...process.env, PORT: '0', NUXT_VEGA_ADDON: '/nonexistent/readdit-vega.node' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let out = ''
  child.stdout.on('data', (d) => (out += d))
  child.stderr.on('data', (d) => (out += d))
  const code = await new Promise((r) => {
    const t = setTimeout(() => {
      child.kill()
      r('timeout')
    }, 30_000)
    child.on('exit', (c) => {
      clearTimeout(t)
      r(c)
    })
  })
  eq('exit code', code, 1)
  check('says why and what to run', out.includes('Readdit cannot start without its proof backend') && out.includes('npm run build:native'), out.trim().split('\n').slice(0, 2).join(' | '))
}

async function preconditions() {
  begin('pre', 'the server is started for this run')
  const ctx = await client()
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
  check('home feed: no post from an age-restricted community', !(await page.locator('a[href^="/c/teenspace/"], a[href^="/c/afterdark/"]').count()))
  check('home feed: posts from open communities', (await page.locator('a[href^="/c/photography/"]').count()) > 0)
  let m = mark()
  await goto('/c/photography')
  await pageShows('Log in to view c/photography')
  await guideIs('login-required')
  check('no wallet request', count(m, 'POST', '/api/vp/session') === 0)

  begin('H4b', 'voting while logged out opens the log-in; closing it at the QR code')
  await goto('/')
  m = mark()
  await page.getByRole('button', { name: 'Upvote' }).first().click()
  await phone().getByRole('button', { name: 'Scan QR code' }).waitFor({ timeout: 15_000 })
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
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
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
  await dialogShows(`Logged in as u/${created.handle}`, 30_000)
  await dialogShows('This wallet already has an account.')
  await guideIs('logged-in')
  await guideSays('creates no second account')
  await expectVerification()
  eq('server: the completion', (await complete(page.request, lastSession())).body, { ok: true, kind: 'logged_in', handle: created.handle })
  eq('still one account', (await accounts()).length, 1)
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
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
  check('the phone offers the other credential (Switch credential)', await phone().getByRole('button', { name: 'Switch credential' }).isVisible())
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
  await phoneShows('Between 13 and 17')
  await guideIs('age-consent')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText('Age verified').waitFor({ timeout: 30_000 })
  await guideIs('age-verified')
  await expectVerification()
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
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

  begin('S19', "the age proof comes from the wallet's other credential")
  expectAnswer('server: a comment in c/teenspace before an age check', await call(page.request, 'POST', '/api/comments', { data: { postId: 'p10', body: 'hi' } }), 403, 'age_required')
  await goto('/c/afterdark')
  let m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await switchCredential()
  await phoneShows('Request to Share Data')
  await guideSays('born 20 May 1990')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('The response belongs to a different account.', 30_000)
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
    route.fulfill({ json: { circuits: [{ circuit_id: LONGFELLOW, proof_system: 'longfellow-libzk-v1' }] } }),
  )
  let m = mark()
  await open(headerButton('Sign up'))
  await scan()
  await readRequest()
  await phoneShows('Unsupported Request')
  await phoneShows('This type of request is not supported.')
  await guideIs('unsupported')
  await guideSays('no circuit in common')
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
  check('the server log names the failure', !SERVER_LOG || serverLog().includes('[vega] verifier.info failed: test fault'))
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
  // Twice: $fetch retries a GET that answers 503 once.
  await armFault('prover.info')
  await armFault('prover.info')
  m = mark()
  await headerButton('Sign up').click()
  await phoneShows('Connection Error')
  await guideIs('wallet-error')
  await guideSays('could not reach the prover')
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
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
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
  await phoneShows('Between 13 and 17')
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
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
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
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })

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

  begin('C0', 'two credentials in the wallet')
  await open(headerButton('Sign up'))
  await phone().getByRole('button', { name: 'Change view' }).click()
  const cards = phone().getByRole('button', { name: /^Open Age and pseudonym details, expiry date/ })
  await cards.first().waitFor()
  const labels = await cards.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')))
  check('two Age and pseudonym cards, told apart by their expiry dates', labels.length === 2 && labels[0] !== labels[1], labels.join(' | '))
  await shot('27-wallet-two-credentials')
  await cards.nth(1).click()
  await phoneShows('20/05/1990')
  await guideIs('credential')
  await guideSays('issued for a birth date of 20 May 1990')
  await phone().getByRole('button', { name: 'Back' }).click()
  await cards.nth(0).click()
  await phoneShows('14/03/2011')
  await guideSays('issued for a birth date of 14 Mar 2011')
  await phone().getByRole('button', { name: 'Back' }).click()
  await phone().getByRole('button', { name: 'Change view' }).click()
  await closeDialog('escape')
  await signIn('Sign up', 'Account created: u/')
  const teenAccount = (await me()).account
  await page.getByRole('banner').getByText(`u/${teenAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Sign up').waitFor()

  begin('C1 C6', 'sign-up with the adult credential, choosing it on the request screen both ways')
  let m = mark()
  await open(headerButton('Sign up'))
  await scan()
  await readRequest()
  await phoneShows('Expiry Date: 13/10/2027')
  await guideSays('born 14 Mar 2011')
  await phone().getByRole('button', { name: /^Switch credential/ }).click()
  await phone().getByText('Select the credential to use for this request.').waitFor()
  await guideIs('switch-credential')
  await shot('28-switch-credential')
  await phone().getByRole('button', { name: /^Select credential/ }).click()
  await phoneShows('Expiry Date: 11/10/2028')
  await guideLeaves('switch-credential')
  await guideIs('consent')
  await guideSays('UsedAge and pseudonym, born 20 May 1990')
  await switchCredential()
  await phoneShows('Expiry Date: 13/10/2027')
  await guideSays('Used' + 'Age and pseudonym, born 14 Mar 2011')
  await switchCredential()
  await phoneShows('Expiry Date: 11/10/2028')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await visible('dialog: "Account created: u/…"', site().getByText(/^Account created: u\//), 30_000)
  await expectVerification()
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
  const adultAccount = (await me()).account
  check('a new account with another pseudonym', adultAccount.pseudonym !== teenAccount.pseudonym && adultAccount.handle !== teenAccount.handle, `u/${adultAccount.handle} vs u/${teenAccount.handle}`)
  eq('two accounts', (await accounts()).length, 2)

  begin('C2', 'c/afterdark with the adult credential, logged in')
  await goto('/c/afterdark')
  await guideIs('age-ask')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await switchCredential()
  await phoneShows('18 or older')
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await site().getByText('Age verified').waitFor({ timeout: 30_000 })
  await expectVerification()
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
  check('c/afterdark posts shown', (await page.locator('a[href^="/c/afterdark/p"]').count()) > 0)
  await guideIs('age-verified')
  await shot('29-afterdark-granted-adult')
  check('the adult account has an 18+ range', !!(await me()).account.birthDateRange?.le)

  begin('C3', 'c/teenspace with the adult credential: Requirement Not Met')
  await goto('/c/teenspace')
  await guideIs('age-refused')
  check('the site refuses without a request, from the 18+ range', (await page.getByText("You can't enter c/teenspace").count()) === 1)
  // Logged out, the combined request lets the adult credential try c/teenspace.
  await page.getByRole('banner').getByText(`u/${adultAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await goto('/c/teenspace')
  m = mark()
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phoneShows('Request to Share Data')
  await switchCredential()
  await phoneShows('Requirement Not Met')
  await guideIs('unmet')
  await guideSays('born 20 May 1990')
  await phone().getByRole('button', { name: 'Close' }).click()
  await dialogShows('Not completed')
  check('access_denied (200)', has(m, 'POST', '/api/vp/response/:id', 200, 'error=access_denied'))
  check('no proof was made', count(m, 'POST', '/api/wallet/prove') === 0)
  check('still logged out', (await me()).account === null)
  await closeDialog('escape')

  begin('C2b', 'c/afterdark with the adult credential, logged out (one request)')
  await goto('/c/afterdark')
  await guideIs('age-signin')
  await open(page.getByRole('button', { name: 'Verify age with wallet' }))
  await scan()
  await readRequest()
  await phoneShows('Requirement Not Met')
  await switchCredential()
  await phone().getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await dialogShows('Age verified', 30_000)
  await dialogShows(`Logged in as u/${adultAccount.handle}`)
  await expectVerification()
  await dialog().waitFor({ state: 'detached', timeout: 10_000 })
  check('c/afterdark posts shown', (await page.locator('a[href^="/c/afterdark/p"]').count()) > 0)

  begin('C5', 'banning one account leaves the other')
  const ctx = await client()
  await call(ctx, 'POST', '/api/mod/ban', { data: { pseudonym: adultAccount.pseudonym } })
  await ctx.dispose()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Dismiss' }).click()
  await goto('/')
  await signIn('Log in', `Logged in as u/${teenAccount.handle}`)
  check('the teen account logs in', (await me()).account?.handle === teenAccount.handle)
  await page.getByRole('banner').getByText(`u/${teenAccount.handle}`).click()
  await page.getByRole('button', { name: 'Log out' }).click()
  await headerButton('Log in').waitFor()
  await open(headerButton('Log in'))
  await scan()
  await readRequest()
  await switchCredential()
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
  await tech.getByText('Vega addon, in process').waitFor()
  await tech.getByText('Capability negotiation').waitFor()
  check('the technical view loads', true)
  await tech.close()
}

// ---------------------------------------------------------------------------------------------

let crashed = null
try {
  if (STARTUP) await startupWithoutAddon()
  const ttl = await preconditions()
  const created = await groupA()
  await groupB(created)
  await groupC(created)
  await groupD(ttl)
  await groupE()
  await groupF()
  await groupH()
  await groupI()
  await groupJ()
  await groupG()
} catch (e) {
  crashed = e
  check(`the run reached the end`, false, e.message.split('\n')[0])
  if (page) await page.screenshot({ path: join(SHOTS ?? '.', 'flows-failure.png') }).catch(() => {})
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
