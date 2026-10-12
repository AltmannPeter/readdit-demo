// Runs the presentation order headlessly and saves screenshots to ./demo-shots.
// Needs the site and both backend services running.
// Usage: node scripts/demo-flow.mjs [baseUrl]   (needs: npm i -D playwright && npx playwright install chromium)
import { mkdirSync } from 'node:fs'
import { chromium } from 'playwright'

const BASE = process.argv[2] ?? 'http://localhost:3000'
const PIN = process.env.DEMO_PIN ?? '123456'
const OUT = 'demo-shots'
mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page = await context.newPage()
const errors = []
const watch = (p) => {
  // The wrong-PIN step returns 401 on purpose; the browser logs it.
  p.on('console', (m) => m.type() === 'error' && !m.text().includes('401') && errors.push(`${p.url()}: ${m.text()}`))
  p.on('pageerror', (e) => errors.push(`${p.url()}: ${e}`))
}
watch(page)

const phone = page.locator('[role=dialog] section').nth(1)
const shot = async (name, p = page) => {
  await p.waitForTimeout(400)
  await p.screenshot({ path: `${OUT}/${name}.png` })
}
const scan = async () => {
  await phone.getByRole('button', { name: 'Scan QR code' }).click()
  await phone.getByText(/asks for:|Requirement not met|Request not supported/).waitFor({ timeout: 15_000 })
}
const typePin = async (pin) => {
  for (const d of pin) await phone.getByRole('button', { name: d, exact: true }).click()
}
const approve = async () => {
  await phone.getByRole('button', { name: 'Continue' }).click()
  await typePin(PIN)
  await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
}

await page.request.post(`${BASE}/api/demo/reset`)

// 1. Sign up, with one wrong PIN first
await page.goto(BASE)
await page.getByRole('banner').getByRole('button', { name: 'Log in' }).click()
await phone.getByRole('button', { name: 'Scan QR code' }).waitFor()
await shot('01-login-qr')
const [details] = await Promise.all([context.waitForEvent('page'), phone.getByLabel('Open Age and pseudonym details').click()])
await details.setViewportSize({ width: 560, height: 1100 })
await details.getByText('What this credential contains').waitFor()
await shot('02-credential-details', details)
await details.close()
await scan()
await shot('03-login-request')
await phone.getByRole('button', { name: 'Continue' }).click()
await typePin('000000')
await phone.getByText('Wrong PIN').waitFor({ timeout: 10_000 })
await shot('04-wrong-pin')
await typePin(PIN)
await page.getByRole('dialog').waitFor({ state: 'detached', timeout: 30_000 })
await shot('05-logged-in')

// 2. 18+ community: requirement not met
await page.click('a[href="/c/afterdark"]')
await page.getByRole('button', { name: 'Verify age with wallet' }).click()
await scan()
await shot('06-adult-unmet')
await phone.getByRole('button', { name: 'Close' }).click()
await page.getByText('Not completed').waitFor()
await shot('07-adult-not-completed')
await page.keyboard.press('Escape')
await page.getByRole('dialog').waitFor({ state: 'detached' })

// 3. 13–17 community: granted
await page.click('a[href="/c/teenspace"]')
await page.getByRole('button', { name: 'Verify age with wallet' }).click()
await scan()
await shot('08-teen-request')
await approve()
await shot('09-teen-in')

// 4. 18+ is now refused by the site without asking the wallet
await page.click('a[href="/c/afterdark"]')
await page.getByText("You can't enter").waitFor()
await shot('10-adult-refused')

// 5. Comment, then a moderator bans the account
await page.goto(`${BASE}/c/teenspace/p10`)
await page.getByPlaceholder(/Comment as/).fill('Anyone want to swap phone numbers?')
await page.getByRole('button', { name: 'Comment', exact: true }).click()
await page.getByText('Anyone want to swap phone numbers?').waitFor()
await shot('11-comment')

const tech = await context.newPage()
watch(tech)
await tech.goto(`${BASE}/tech`)
await tech.getByText('Capability negotiation').waitFor()
await tech.setViewportSize({ width: 1440, height: 1300 })
await shot('12-tech', tech)

const mod = await context.newPage()
watch(mod)
await mod.goto(`${BASE}/mod`)
await mod.getByRole('button', { name: 'Ban user' }).first().click()
await mod.getByText('Banned', { exact: true }).first().waitFor()
await shot('13-mod-banned', mod)

await page.bringToFront()
await page.getByText('has been banned from Readdit').waitFor({ timeout: 10_000 })
await shot('14-user-banned')

// 6. The same wallet tries to sign up again
await page.getByRole('banner').getByRole('button', { name: 'Sign up' }).click()
await scan()
await approve().catch(() => {})
await page.getByText('Account banned').waitFor({ timeout: 15_000 })
await shot('15-signup-again-banned')

console.log(errors.length ? `console errors:\n${errors.join('\n')}` : 'ok, no console errors')
await browser.close()
process.exit(errors.length ? 1 : 0)
