// Runs the presentation order headlessly against the running site and saves a screenshot of each
// step, in flow order, to ./demo-shots (or the directory given as the second argument).
// Needs the site with its proof backend (npm run build:native, then npm run dev).
// Usage: node scripts/demo-flow.mjs [baseUrl] [outDir]
//        (needs: npm i --no-save playwright && npx playwright install chromium)
//
// Order: sign-up (QR, credential, scan, consent, wrong PIN, proving, success), an open community,
// c/afterdark (requirement not met), c/teenspace (age range granted), c/afterdark refused by the
// site, a comment, the ban from /mod, the second sign-up ending in "Account banned", and /tech.
// Exits 1 on a console error or when a step does not reach its expected state.
import { mkdirSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://localhost:3000'
const OUT = process.argv[3] ?? 'demo-shots'
const PIN = process.env.DEMO_PIN ?? '123456'
mkdirSync(OUT, { recursive: true })
for (const f of readdirSync(OUT)) if (f.endsWith('.png')) rmSync(join(OUT, f))

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5 })
const page = await context.newPage()
const errors = []
const watch = (p) => {
  // The wrong-PIN step returns 401 and the unmet age check 422 on purpose; the browser logs them.
  p.on('console', (m) => m.type() === 'error' && !/\b(401|422)\b/.test(m.text()) && errors.push(`${p.url()}: ${m.text()}`))
  p.on('pageerror', (e) => errors.push(`${p.url()}: ${e}`))
}
watch(page)

// What the phone sends: the prover routes' statuses and what it posts to response_uri.
const net = []
page.on('response', (r) => {
  const u = new URL(r.url())
  const req = r.request()
  if (u.pathname.startsWith('/api/wallet/sign') || u.pathname.startsWith('/api/wallet/prove')) net.push(`${u.pathname} ${r.status()}`)
  if (u.pathname.startsWith('/api/vp/response/')) {
    const form = new URLSearchParams(req.postData() ?? '')
    net.push(`response_uri ${form.get('error') ? `error=${form.get('error')}` : 'vp_token'} ${r.status()}`)
  }
})

const phone = page.locator('[role=dialog] section').nth(1)
let n = 0
const shot = async (name, target = page, { settle = 400 } = {}) => {
  const p = 'screenshot' in target && 'goto' in target ? target : page
  await p.waitForTimeout(settle)
  n += 1
  const file = join(OUT, `${String(n).padStart(2, '0')}-${name}.png`)
  await target.screenshot({ path: file })
  console.log(`  ${file}`)
}
const step = (s) => console.log(s)
// After a navigation: wait until Vue has mounted and the page is quiet, so clicks reach handlers.
const ready = async (p) => {
  await p.waitForLoadState('networkidle')
  await p.waitForFunction(() => !!document.querySelector('#__nuxt')?.__vue_app__, null, { timeout: 60_000 })
  await p.waitForTimeout(300)
}
// The whole content of the phone's scrolling screen in one image: the phone frame is let grow to
// the content's height for the shot, then put back.
const fullPhoneShot = async (name) => {
  await phone.locator('.overflow-y-auto').first().evaluate((el) => {
    const frame = el.closest('.select-none')
    for (let e = el; e && e !== frame.parentElement; e = e.parentElement) {
      e.dataset.saved = e.getAttribute('style') ?? ''
      e.style.height = 'auto'
      e.style.maxHeight = 'none'
      e.style.overflow = 'visible'
      e.style.flex = 'none'
    }
  })
  await shot(name, phone)
  await phone.locator('.overflow-y-auto').first().evaluate((el) => {
    const frame = el.closest('.select-none')
    for (let e = el; e && e !== frame.parentElement; e = e.parentElement) {
      e.setAttribute('style', e.dataset.saved)
      delete e.dataset.saved
    }
  })
}
const scrollPhone = async (to) => {
  await phone.locator('.overflow-y-auto').first().evaluate((el, where) => el.scrollTo({ top: where === 'bottom' ? el.scrollHeight : 0 }), to)
}
const scan = async () => {
  await phone.getByRole('button', { name: 'Scan QR code' }).click()
  await phone.getByText('Scan the QR Code').waitFor()
}
const readRequest = async () => phone.getByText(/Request to Share Data|Requirement not met|Request not supported/).waitFor({ timeout: 20_000 })
const typePin = async (pin) => {
  for (const d of pin) await phone.getByRole('button', { name: d, exact: true }).click()
}

try {
  await page.request.post(`${BASE}/api/demo/reset`)

  // 1. Sign up: QR, the credential, scan, consent, a wrong PIN, proving, success.
  step('1. sign up')
  await page.goto(BASE)
  await ready(page)
  await page.getByRole('banner').getByRole('button', { name: 'Sign up' }).click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await phone.getByText('Age and pseudonym').first().waitFor()
  await shot('signup-qr-and-wallet-home')
  await phone.getByRole('button', { name: 'Open Age and pseudonym details' }).first().click()
  await phone.getByText('Date of birth:').waitFor()
  await shot('wallet-credential-detail', phone)
  const [details] = await Promise.all([context.waitForEvent('page'), phone.getByRole('button', { name: 'Open the credential details in a new window' }).click()])
  watch(details)
  await details.setViewportSize({ width: 560, height: 1250 })
  await ready(details)
  await details.getByText('What this credential contains').waitFor()
  await details.screenshot({ path: join(OUT, `${String(++n).padStart(2, '0')}-credential-window.png`), fullPage: true })
  await details.close()
  await phone.getByRole('button', { name: 'Back' }).click()
  await phone.getByRole('heading', { name: 'Credentials' }).waitFor()
  await page.waitForTimeout(400) // the screen transition
  await scan()
  await phone.locator('svg.text-green-600').waitFor({ timeout: 5_000 })
  await shot('wallet-scan', phone, { settle: 0 })
  await readRequest()
  await shot('signup-consent')
  await fullPhoneShot('signup-consent-full')
  await phone.getByRole('button', { name: 'Share' }).click()
  await typePin('000000')
  await phone.getByText('You have entered an incorrect PIN').waitFor({ timeout: 10_000 })
  await shot('wrong-pin', phone)
  await typePin(PIN)
  await phone.getByText('Presentation sent successfully').waitFor({ timeout: 30_000 })
  await shot('wallet-proof-steps', phone, { settle: 0 })
  await phone.getByText('Success!').waitFor({ timeout: 30_000 })
  await shot('wallet-success', page, { settle: 100 })
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
  await page.getByRole('banner').getByText(/^u\//).first().waitFor()
  await shot('logged-in')

  // 2. An open community needs only the login: no age request.
  step('2. open community')
  await page.click('a[href="/c/photography"]')
  await ready(page)
  await page.getByRole('heading', { name: 'c/photography' }).waitFor()
  await shot('open-community-no-age-check')

  // 3. 18+: the wallet cannot meet the requirement; the site shows "Not completed".
  step('3. c/afterdark')
  await page.click('a[href="/c/afterdark"]')
  await page.getByRole('button', { name: 'Verify age with wallet' }).click()
  await scan()
  await readRequest()
  await phone.getByText('Requirement not met').waitFor()
  await shot('afterdark-requirement-not-met')
  await phone.getByRole('button', { name: 'Close' }).click()
  await page.getByText('Not completed').waitFor()
  await shot('afterdark-not-completed')
  await page.keyboard.press('Escape')
  await page.getByRole('dialog').waitFor({ state: 'detached' })

  // 4. 13–17: the same pseudonym plus the age range; access granted.
  step('4. c/teenspace')
  await page.click('a[href="/c/teenspace"]')
  await page.getByRole('button', { name: 'Verify age with wallet' }).click()
  await scan()
  await readRequest()
  await phone.getByText('You are between 13 and 17').waitFor()
  await shot('teenspace-consent')
  await fullPhoneShot('teenspace-consent-full')
  await phone.getByRole('button', { name: 'Share' }).click()
  await typePin(PIN)
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
  await shot('teenspace-granted')

  // 5. 18+ is now refused by the site itself, without asking the wallet.
  step('5. c/afterdark refused by the site')
  await page.click('a[href="/c/afterdark"]')
  await page.getByText("You can't enter").waitFor()
  await shot('afterdark-refused-by-site')

  // 6. A comment, then the moderator bans the account.
  step('6. comment and ban')
  await page.goto(`${BASE}/c/teenspace/p10`)
  await ready(page)
  await page.getByPlaceholder(/Comment as/).fill('Anyone want to swap phone numbers?')
  await page.getByRole('button', { name: 'Comment', exact: true }).click()
  await page.getByText('Anyone want to swap phone numbers?').waitFor()
  await shot('comment')

  const tech = await context.newPage()
  watch(tech)
  await tech.goto(`${BASE}/tech`)
  await ready(tech)
  await tech.getByText('Capability negotiation').waitFor()

  const mod = await context.newPage()
  watch(mod)
  await mod.goto(`${BASE}/mod`)
  await ready(mod)
  await mod.getByRole('button', { name: 'Ban user' }).first().click()
  await mod.getByText('Banned', { exact: true }).first().waitFor()
  await shot('mod-ban', mod)

  await page.bringToFront()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await shot('user-banned')

  // 7. The same wallet signs up again: the same pseudonym, so "Account banned".
  step('7. second sign-up')
  await page.getByRole('banner').getByRole('button', { name: 'Sign up' }).click()
  await scan()
  await readRequest()
  await phone.getByRole('button', { name: 'Share' }).click()
  await typePin(PIN)
  await page.getByText('Account banned').waitFor({ timeout: 30_000 })
  await shot('signup-again-account-banned')

  // 8. The technical view: the teenspace session, with the real metrics.
  step('8. /tech')
  await tech.bringToFront()
  await tech.setViewportSize({ width: 1440, height: 2100 })
  await tech.getByRole('button', { name: /Age check, c\/teenspace/ }).click()
  await tech.getByText('Proof verified').first().waitFor()
  await shot('tech-teenspace', tech, { settle: 1200 })
} catch (e) {
  // Leave the state the run stopped in.
  await page.screenshot({ path: join(OUT, 'failure.png') })
  console.error(`FAILED: ${e.message}\nscreenshot: ${join(OUT, 'failure.png')}`)
  await browser.close()
  process.exit(1)
}

console.log(`phone traffic:\n  ${net.join('\n  ')}`)
// The use cases, as the phone's traffic shows them.
const count = (line) => net.filter((l) => l === line).length
const expect = [
  ['a wrong PIN is refused with 401', count('/api/wallet/sign 401') === 1],
  ['c/afterdark: the wallet answers access_denied, once', count('response_uri error=access_denied 200') === 1],
  ['three presentations proved: sign-up, c/teenspace, the second sign-up', count('/api/wallet/prove 200') === 3],
  ['three vp_token responses', count('response_uri vp_token 200') === 3],
]
for (const [what, ok] of expect) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`)
  if (!ok) errors.push(`expected: ${what}`)
}
console.log(errors.length ? `errors:\n${errors.join('\n')}` : 'ok, no console errors')
await browser.close()
process.exit(errors.length ? 1 : 0)
