// Runs the presentation order headlessly against the running site and saves a screenshot of each
// step, in flow order, to ./demo-shots (or the directory given as the second argument). Every
// screenshot is the browser viewport as the person sees it: Readdit, the phone in the wallet
// dialog, and the guide panel.
// Needs the site with its proof backend (npm run build:native, then npm run dev).
// Usage: node scripts/demo-flow.mjs [baseUrl] [outDir]
//        (needs: npm i --no-save playwright && npx playwright install chromium)
//
// Order: sign-up on the teen's phone (QR, credential, scan, consent, PIN, proving, success), an
// open community, c/afterdark (requirement not met; then the adult's phone swapped in at the QR
// code, refused with "Pseudonym does not match"), c/teenspace (age range granted), c/afterdark
// refused by the site, c/france joined with its own pseudonym (linked), a comment, the ban from
// /mod, the second sign-up ending in "Account banned", and /tech.
// At each step it checks that the guide panel shows the matching step.
// Exits 1 on a console error or when a step does not reach its expected state.
import { mkdirSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://localhost:3000'
const OUT = process.argv[3] ?? 'demo-shots'
// Any 6 digits unlock the wallet: each PIN entry is a different one.
const anyPin = () => String(Math.floor(Math.random() * 1e6)).padStart(6, '0')
mkdirSync(OUT, { recursive: true })
for (const f of readdirSync(OUT)) if (f.endsWith('.png')) rmSync(join(OUT, f))

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5 })
const page = await context.newPage()
const errors = []
const watch = (p) => {
  // The unmet age check may return 422 on purpose; the browser logs it.
  p.on('console', (m) => m.type() === 'error' && !/\b422\b/.test(m.text()) && errors.push(`${p.url()}: ${m.text()}`))
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
const guidePanel = page.getByRole('complementary', { name: 'Guide' })
let n = 0
/** A viewport capture of the page as it is on screen. */
const shot = async (name, { settle = 400 } = {}) => {
  await page.waitForTimeout(settle)
  n += 1
  const file = join(OUT, `${String(n).padStart(2, '0')}-${name}.png`)
  await page.screenshot({ path: file })
  console.log(`  ${file}`)
}
const step = (s) => console.log(s)
// After a navigation: wait until Vue has mounted and the page is quiet, so clicks reach handlers.
const ready = async (p) => {
  await p.waitForLoadState('networkidle')
  await p.waitForFunction(() => !!document.querySelector('#__nuxt')?.__vue_app__, null, { timeout: 60_000 })
  await p.waitForTimeout(300)
}
/** The guide panel shows this step. */
const guide = async (id, { settle = 250 } = {}) => {
  await page.locator(`aside[data-guide-step="${id}"]`).waitFor({ timeout: 10_000 })
  await page.waitForTimeout(settle) // the guide's transition
}
const openDetails = async () => {
  await guidePanel.locator('summary', { hasText: 'Details' }).click()
  await guidePanel.locator('details[open] section').first().waitFor()
}
const phoneScroller = () => phone.locator('.overflow-y-auto').first()
/** When the phone's screen is taller than the phone, a second capture scrolled to its end. */
const shotScrolledIfLonger = async (name) => {
  const longer = await phoneScroller().evaluate((el) => el.scrollHeight > el.clientHeight + 1)
  if (!longer) return
  await phoneScroller().evaluate((el) => el.scrollTo({ top: el.scrollHeight }))
  await shot(name)
  await phoneScroller().evaluate((el) => el.scrollTo({ top: 0 }))
}
const scan = async () => {
  await phone.getByRole('button', { name: 'Scan QR code' }).click()
  await phone.getByText('Scan the QR Code').waitFor()
}
const readRequest = async () => phone.getByText(/Request to Share Data|Requirement Not Met|Unsupported Request/).waitFor({ timeout: 20_000 })
/** Swap to the named phone while the QR code is on screen ("Teen's phone", "Adult's phone"). */
const usePhone = async (name) => {
  const label = page.locator('[data-phone-label]')
  if ((await label.innerText()).startsWith(name)) return
  await page.getByRole('button', { name: 'Swap phone' }).click()
  await label.filter({ hasText: name }).waitFor()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await page.waitForTimeout(400) // the swap animation
}
const enterPin = async (pin) => {
  for (const d of pin) await phone.getByRole('button', { name: d, exact: true }).click()
  await phone.getByRole('button', { name: 'Submit' }).click()
}

try {
  await page.request.post(`${BASE}/api/demo/reset`)

  // 1. Sign up: QR, the credential, scan, consent, PIN, proving, success.
  step('1. sign up')
  await page.goto(BASE)
  await ready(page)
  await guide('start')
  await page.getByRole('banner').getByRole('button', { name: 'Sign up' }).click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await usePhone("Teen's phone")
  await phone.getByText('Age and pseudonym').first().waitFor()
  await guide('signin-qr')
  await shot('signup-qr')
  await phone.getByRole('button', { name: 'Open Age and pseudonym details' }).first().click()
  await phone.getByText('Birth Date:', { exact: true }).waitFor()
  await guide('credential')
  await openDetails()
  await guidePanel.getByText('Document type').waitFor()
  await shot('wallet-credential')
  await phone.getByRole('button', { name: 'Back' }).click()
  await phone.getByRole('heading', { name: 'Credentials' }).waitFor()
  await page.waitForTimeout(400) // the screen transition
  await scan()
  await guide('scan')
  await phone.locator('svg.text-green-600').waitFor({ timeout: 5_000 })
  await shot('wallet-scan', { settle: 0 })
  await readRequest()
  await guide('consent')
  await openDetails()
  await shot('signup-consent')
  await shotScrolledIfLonger('signup-consent-scrolled')
  await phone.getByRole('button', { name: 'Share' }).click()
  await guide('pin')
  await enterPin(anyPin())
  await phone.getByText('Presentation sent successfully').waitFor({ timeout: 30_000 })
  await guide('proving', { settle: 0 })
  await shot('proof', { settle: 0 })
  // The dialog stays open until Close on the phone's success screen.
  await phone.getByText('Success!').waitFor({ timeout: 30_000 })
  await shot('signup-success', { settle: 180 })
  if (!(await page.getByText(/^Account created: u\//).isVisible())) errors.push('the sign-up success screenshot missed the open dialog')
  await guide('account-created', { settle: 0 })
  await phone.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
  await page.getByRole('banner').getByText(/^u\//).first().waitFor()
  await guide('account-created')
  await openDetails()
  await shot('account-created')

  // 2. An open community needs only the login: no age request.
  step('2. open community')
  await page.click('a[href="/c/photography"]')
  await ready(page)
  await page.getByRole('heading', { name: 'c/photography' }).waitFor()
  await guide('open-community')
  await shot('open-community')

  // 3. 18+: the wallet cannot meet the requirement; the site shows "Not completed".
  step('3. c/afterdark')
  await page.click('a[href="/c/afterdark"]')
  await page.getByRole('button', { name: 'Verify age with wallet' }).waitFor()
  await guide('age-ask')
  await openDetails()
  await shot('afterdark-age-required')
  await page.getByRole('button', { name: 'Verify age with wallet' }).click()
  await guide('age-qr')
  await scan()
  await readRequest()
  await phone.getByText('Requirement Not Met').waitFor()
  await guide('unmet')
  await shot('afterdark-requirement-not-met')
  await phone.getByRole('button', { name: 'Close' }).click()
  await page.getByText('Not completed').waitFor()
  await guide('not-completed')
  await shot('afterdark-not-completed')

  // 3b. Borrowing the adult's phone: swapped in at the QR code, it proves 18+, but its pseudonym
  // is not the logged-in account's, so Readdit rejects the presentation.
  step('3b. c/afterdark with the adult\'s phone')
  await page.getByRole('button', { name: 'Try again' }).click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await guide('age-qr')
  await usePhone("Adult's phone")
  await guidePanel.getByText('The phones were swapped').waitFor()
  await shot('afterdark-phone-swapped')
  await scan()
  await readRequest()
  await phone.getByText('Age proof: 18+').waitFor()
  await guide('age-consent')
  await phone.getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await page.getByText('Pseudonym does not match').waitFor({ timeout: 30_000 })
  await guide('mismatch')
  await shot('afterdark-pseudonym-does-not-match')
  await page.keyboard.press('Escape')
  await page.getByRole('dialog').waitFor({ state: 'detached' })

  // 4. 13–17: the same pseudonym plus the age range; access granted.
  step('4. c/teenspace')
  await page.click('a[href="/c/teenspace"]')
  await page.getByRole('button', { name: 'Verify age with wallet' }).click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await usePhone("Teen's phone")
  await scan()
  await readRequest()
  await phone.getByText('Age proof: 13–17').waitFor()
  await guide('age-consent')
  await openDetails()
  await shot('teenspace-consent')
  await shotScrolledIfLonger('teenspace-consent-scrolled')
  await phone.getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await phone.getByText('Success!').waitFor({ timeout: 30_000 })
  await phone.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
  await guide('age-verified')
  await openDetails()
  await shot('teenspace-age-verified')

  // 5. 18+ is now refused by the site itself, without asking the wallet.
  step('5. c/afterdark refused by the site')
  await page.click('a[href="/c/afterdark"]')
  await page.getByText("You can't enter").waitFor()
  await guide('age-refused')
  await openDetails()
  await shot('afterdark-refused-by-readdit')

  // 5b. c/france: its own pseudonym, one account per person, linked to the logged-in account.
  step('5b. c/france')
  await page.click('a[href="/c/france"]')
  const joinAndLink = page.getByRole('button', { name: /^Join and link to u\// })
  await joinAndLink.waitFor()
  await guide('community-join')
  await openDetails()
  await shot('france-join')
  await joinAndLink.click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await usePhone("Teen's phone")
  await guide('community-qr')
  await scan()
  await readRequest()
  await guide('community-consent')
  await shot('france-consent')
  await phone.getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await phone.getByText('Success!').waitFor({ timeout: 30_000 })
  await page.getByText(/^Joined c\/france as u\//).waitFor({ timeout: 30_000 })
  await guide('community-linked')
  await shot('france-joined')
  await phone.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
  await guide('community-member')
  await shot('france-member')

  // 6. A comment, then the moderator bans the account.
  step('6. comment and ban')
  await page.goto(`${BASE}/c/teenspace/p10`)
  await ready(page)
  await guide('age-granted')
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

  await page.bringToFront()
  await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
  await guide('banned')
  await openDetails()
  await shot('user-banned')

  // 7. The same wallet signs up again: the same pseudonym, so "Account banned".
  step('7. second sign-up')
  await page.getByRole('banner').getByRole('button', { name: 'Sign up' }).click()
  await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
  await usePhone("Teen's phone")
  await guide('signin-qr')
  await guidePanel.getByText('Sign-up after the ban').waitFor()
  await scan()
  await readRequest()
  await guide('consent')
  await phone.getByRole('button', { name: 'Share' }).click()
  await enterPin(anyPin())
  await page.getByText('Account banned').waitFor({ timeout: 30_000 })
  await guide('signup-refused')
  await openDetails()
  await shot('signup-again-account-banned')

  // 8. The technical view: the teenspace session, with the real metrics.
  step('8. /tech')
  await tech.bringToFront()
  await tech.getByRole('button', { name: /Age check, c\/teenspace/ }).click()
  await tech.getByText('Proof verified').first().waitFor()
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
  ['any PIN signs: no sign call is refused (no 401)', net.filter((l) => l.startsWith('/api/wallet/sign ') && l !== '/api/wallet/sign 200').length === 0 && count('/api/wallet/sign 200') === 5],
  ["c/afterdark on the teen's phone: the wallet answers access_denied, once", count('response_uri error=access_denied 200') === 1],
  ["five presentations proved: sign-up, c/afterdark on the adult's phone, c/teenspace, c/france, the second sign-up", count('/api/wallet/prove 200') === 5],
  ['five vp_token responses', count('response_uri vp_token 200') === 5],
]
for (const [what, ok] of expect) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`)
  if (!ok) errors.push(`expected: ${what}`)
}
console.log(errors.length ? `errors:\n${errors.join('\n')}` : 'ok, no console errors')
await browser.close()
process.exit(errors.length ? 1 : 0)
