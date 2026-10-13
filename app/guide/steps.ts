// The guide panel's current step: a title, a short neutral summary and optional details, derived
// from the state of the site, the dialog and the wallet. Every fact comes from that state: the
// request as the wallet analysed it, the circuit's registry entry, the rulebook's properties of the
// pseudonym configuration (app/wallet/rulebook.ts via consentFor), the measured metrics, the
// credential, and the account as the server reports it.

import type { Account, AgeGate, BirthDateRange, Community } from '#shared/types'
import type { CircuitEntry } from '#shared/registry/circuits'
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import { gateRange } from '#shared/utils/age'
import type { DialogFlow, LastOutcome, WalletFlow } from '~/composables/useFlow'
import type { WalletPurpose } from '~/composables/useWallet'
import type { ConsentView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import { ageText, birthRangeText, fmtDate, parseAuthorizationUrl } from '~/wallet/engine'

export interface GuideRow {
  label: string
  value: string
  /** The value is an identifier or a code. */
  mono?: boolean
  /** The label is an identifier (a protocol field or a public input). */
  code?: boolean
}

export interface GuideSection {
  heading: string
  rows?: GuideRow[]
  items?: string[]
  /** Rows with long values: the label above the value. */
  stacked?: boolean
}

/** The stages of one wallet request, for the panel's progress line. */
export const STAGES = ['QR', 'Scan', 'Consent', 'PIN', 'Proof', 'Result'] as const

export interface GuideStep {
  /** Stable id of the step (data-guide-step). */
  id: string
  /** What the step belongs to: "Sign-up", "Age check · c/teenspace", "Readdit"… */
  context: string
  title: string
  summary: string
  details: GuideSection[]
  /** Index into STAGES while a wallet request is open. */
  stage?: number
}

export interface GuideInput {
  siteName: string
  siteHost: string
  today: string
  dialog: DialogFlow & { open: boolean; purpose: WalletPurpose | null }
  wallet: WalletFlow
  last: LastOutcome | null
  page: { kind: 'home' } | { kind: 'community'; community: Community } | { kind: 'other' }
  /** Access to the community on screen (useCommunityAccess). */
  access: 'login' | 'allow' | 'ask' | 'deny' | null
  account: Account | null
  bannedHandle: string | null
  credential: CredentialView | null
}

const ms = (n: number) => `${n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString('en-GB')} ms`
const kB = (n: number) => `${(n / 1000).toFixed(1)} kB`
const shortHex = (hex: string) => `${hex.slice(0, 8)}…${hex.slice(-8)}`
const communityName = (c: Community | string) => `${COMMUNITY_PREFIX}${typeof c === 'string' ? c : c.slug}`

/** "ages 13 to 17", "ages 18 and older". */
function gateText(gate: AgeGate): string {
  if (gate.minAge != null && gate.maxAge != null) return `ages ${gate.minAge} to ${gate.maxAge}`
  if (gate.minAge != null) return `ages ${gate.minAge} and older`
  return `ages under ${gate.maxAge! + 1}`
}

const rangeText = (r: BirthDateRange | null | undefined) => (r && (r.ge || r.le) ? birthRangeText(r) : 'None')

// ---------------------------------------------------------------------------------------------
// Detail sections

function pseudonymSection(c: ConsentView): GuideSection | null {
  if (!c.pseudonym) return null
  return {
    heading: `Pseudonym · ${c.pseudonym.config}`,
    rows: [
      { label: 'Value', value: shortHex(c.pseudonym.value), mono: true },
      { label: 'verifier_id', value: c.pseudonym.verifierId, mono: true, code: true },
    ],
    items: c.pseudonym.properties,
  }
}

function ageSection(c: ConsentView, site: string): GuideSection | null {
  if (!c.age) return null
  return {
    heading: 'Age check',
    rows: [
      { label: 'Requested', value: c.age.text },
      { label: 'Bounds', value: c.age.range },
      { label: `${site} receives`, value: 'true, if the birth date lies within the bounds' },
    ],
  }
}

function consentSections(c: ConsentView, site: string): GuideSection[] {
  return [
    pseudonymSection(c),
    ageSection(c, site),
    { heading: 'Not shared', items: c.notShared.map((n) => (n.value ? `${n.label} (${n.value})` : n.label)) },
    { heading: `Also sent to ${site}`, rows: c.alsoSent, stacked: true },
    {
      heading: 'Request',
      rows: [
        { label: 'client_id', value: c.verifier.clientId, mono: true, code: true },
        ...(c.verifier.certificate ? [{ label: 'Signed by', value: c.verifier.certificate }] : []),
      ],
      stacked: true,
    },
  ].filter((s): s is GuideSection => !!s)
}

function proofSection(w: WalletFlow, site: string): GuideSection | null {
  const m = w.metrics
  const circuit = w.view?.circuit
  if (!m && !circuit) return null
  const sim = m?.simulated ? ' (simulated)' : ''
  const rows: GuideRow[] = []
  if (circuit) rows.push({ label: 'Circuit', value: `${circuit.label} (${circuit.proof_system})` })
  if (m?.sign_ms != null) rows.push({ label: 'Device key signature', value: ms(m.sign_ms) + sim })
  if (m?.witness_ms != null) rows.push({ label: 'Witness', value: ms(m.witness_ms) + sim })
  if (m?.prove_ms != null) rows.push({ label: 'Proving', value: ms(m.prove_ms) + sim })
  if (m?.proof_bytes != null) rows.push({ label: 'Proof size', value: kB(m.proof_bytes) + sim })
  if (m?.presentation_bytes != null) rows.push({ label: 'Presentation size', value: kB(m.presentation_bytes) + sim })
  rows.push({
    label: 'Runs on',
    value: m?.simulated
      ? 'The offline simulation: no proof is created, and the times follow the benchmark model'
      : `${site}'s server (the Vega addon), in place of the phone`,
  })
  return { heading: 'Proof', rows }
}

function checksSection(circuit: CircuitEntry | undefined, site: string, simulated = false): GuideSection | null {
  if (!circuit) return null
  // server/utils/offline-backend.ts: no proof, so none of the circuit's public inputs is checked.
  if (simulated) {
    return {
      heading: `What ${site} checks`,
      items: ['Offline simulation: the circuit id, that the request offered it, and the results against the request. There is no proof to verify.'],
    }
  }
  const rows: GuideRow[] = circuit.public_inputs.map((p) => ({
    label: p.name,
    code: true,
    value: `${p.source === 'presentation' ? 'From the presentation' : `Computed by ${site}`}: ${p.derivation}`,
  }))
  const items = circuit.checks_validity ? ['The circuit also proves that the credential is valid at proof_time.'] : undefined
  return { heading: `What ${site} checks`, rows, items, stacked: true }
}

function storedSection(account: Account | null, site: string): GuideSection | null {
  if (!account) return null
  return {
    heading: `Stored by ${site}`,
    rows: [
      { label: 'Pseudonym', value: shortHex(account.pseudonym), mono: true },
      { label: 'Handle', value: `u/${account.handle}, derived from the pseudonym` },
      { label: 'Joined', value: fmtDate(account.joinedAt) },
      { label: 'Proven birth dates', value: rangeText(account.birthDateRange) },
    ],
  }
}

function credentialSection(c: CredentialView | null): GuideSection | null {
  if (!c) return null
  return {
    heading: 'Credential',
    rows: [
      { label: 'Document type', value: c.docType, mono: true },
      { label: 'Encoding', value: `${c.encoding}${c.compactProfile ? ', compact profile' : ''}` },
      { label: 'Data elements', value: c.elements.map((e) => e.id).join(', '), mono: true },
      { label: 'Issuer', value: c.issuer.country ? `${c.issuer.name} (${c.issuer.country})` : c.issuer.name },
      { label: 'Issuer signature', value: `${c.mso.signatureAlgorithm}, ${c.issuer.documentSigner}` },
      { label: 'Attribute digests', value: c.mso.digestAlgorithm },
      { label: 'Valid', value: `${fmtDate(c.validity.validFrom)} to ${fmtDate(c.validity.validUntil)}` },
      { label: 'Device key', value: `${c.deviceKey.kty} ${c.deviceKey.crv}` },
      { label: 'Size', value: `${c.sizes.issuerSigned.toLocaleString('en-GB')} bytes` },
    ],
    items: ['Demo setup: the device key and the secret seed are stored in this page. A production wallet keeps the device key in secure hardware.'],
  }
}

// ---------------------------------------------------------------------------------------------
// Steps while the dialog is open

function requestContext(i: GuideInput): string {
  const p = i.dialog.purpose
  if (p?.kind === 'age') return `Age check · ${communityName(p.community)}`
  if (i.bannedHandle || (i.last && !i.last.ok && i.last.kind === 'banned')) return 'Sign-up after the ban'
  return p?.intent === 'login' ? 'Log-in' : 'Sign-up'
}

function dialogStep(i: GuideInput): GuideStep {
  const w = i.wallet
  const context = requestContext(i)
  switch (w.screen) {
    case 'detail':
    case 'presentations':
      return credentialStep(i, context)
    case 'scan':
      return scanStep(i, context)
    case 'request':
      return consentStep(i, context)
    case 'pin':
      return w.pinRejected ? wrongPinStep(i, context) : pinStep(i, context)
    case 'working':
      return provingStep(i, context)
    case 'unmet':
      return unmetStep(i, context)
    case 'declined':
      return {
        id: 'declined',
        context,
        stage: 2,
        title: 'Declined',
        summary: 'The person declined the request. The wallet answers access_denied and shares nothing.',
        details: [],
      }
    case 'error':
      return {
        id: 'wallet-error',
        context,
        title: w.error?.title ?? 'Error',
        summary: `The wallet stopped with an error: ${w.error?.description ?? ''}`,
        details: [],
      }
  }
  // The wallet is on its home screen or shows "Success!": the dialog's state decides.
  const failure = i.dialog.phase === 'failed' ? i.dialog.failure : w.sentError === 'access_denied' ? 'denied' : w.sentError
  if (failure) return failedStep(i, context, failure)
  if (i.dialog.phase === 'success') return successStep(i, context)
  if (w.screen === 'done' || i.dialog.phase === 'verifying') {
    return {
      id: 'verifying',
      context,
      stage: 5,
      title: 'Verifying',
      summary: w.metrics?.simulated
        ? `${i.siteName} received the presentation and checks it against the request it signed. The offline simulation sends no proof.`
        : `${i.siteName} received the presentation and verifies the proof against the request it signed.`,
      details: [checksSection(w.view?.circuit, i.siteName, !!w.metrics?.simulated)].filter((s): s is GuideSection => !!s),
    }
  }
  return qrStep(i, context)
}

function qrStep(i: GuideInput, context: string): GuideStep {
  const p = i.dialog.purpose
  const auth = i.dialog.authUrl ? parseAuthorizationUrl(i.dialog.authUrl) : null
  const details: GuideSection[] = auth
    ? [
        {
          heading: 'Authorization request in the QR code',
          rows: [
            { label: 'client_id', value: auth.clientId, mono: true, code: true },
            { label: 'request_uri', value: auth.requestUri, mono: true, code: true },
            { label: 'request_uri_method', value: auth.method, mono: true, code: true },
          ],
          stacked: true,
        },
      ]
    : []
  let summary: string
  if (p?.kind === 'age') {
    const c = i.page.kind === 'community' ? i.page.community : null
    const gate = c?.gate ? ` is for ${gateText(c.gate)}` : ''
    summary = `${communityName(p.community)}${gate}. ${
      i.account?.birthDateRange ? 'The age proven so far does not settle this' : `${i.siteName} has no proven age for this account`
    }, so it shows a QR code for a new wallet request.`
  } else if (i.bannedHandle) {
    summary = `u/${i.bannedHandle} is banned. The person signs up again with the same wallet, from a new QR code.`
  } else {
    summary = `${i.siteName} shows a QR code that points to a signed OpenID4VP request. The person scans it with the SIROS ID wallet on their phone.`
  }
  return { id: p?.kind === 'age' ? 'age-qr' : 'signin-qr', context, stage: 0, title: 'QR code', summary, details }
}

function credentialStep(i: GuideInput, context: string): GuideStep {
  const c = i.credential
  return {
    id: 'credential',
    context,
    title: 'The credential',
    summary: `The wallet holds one Age and pseudonym credential${c ? ` from ${c.issuer.name}` : ''}. It contains a birth date and a commitment to a secret seed. Neither value is sent to sites.`,
    details: [credentialSection(c)].filter((s): s is GuideSection => !!s),
  }
}

function scanStep(i: GuideInput, context: string): GuideStep {
  return {
    id: 'scan',
    context,
    stage: 1,
    title: 'Scan',
    summary: `The wallet reads the QR code and fetches the signed request from ${i.siteName}. It checks the signature and that the signing certificate is issued for ${i.siteHost}.`,
    details: [
      {
        heading: 'Fetching the request',
        rows: [
          { label: 'Method', value: 'POST to request_uri, with wallet_metadata and wallet_nonce' },
          { label: 'Circuits the wallet supports', value: i.wallet.walletCircuits.join(', ') || 'None', mono: true },
          { label: 'Certificate chain', value: 'Not checked against a trust anchor by this demo wallet' },
        ],
        stacked: true,
      },
    ],
  }
}

function consentStep(i: GuideInput, context: string): GuideStep {
  const c = i.wallet.consent
  const host = c?.verifier.host ?? i.siteHost
  let summary: string
  if (c?.age) {
    summary = `${i.siteName} asks for the account's pseudonym and proof that the holder is ${c.age.text}. The wallet proves both from the credential; the birth date stays on the phone.`
  } else if (i.bannedHandle) {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives the same one as at the first sign-up, because it depends only on the wallet's secret seed and ${i.siteName}'s verifier_id.`
  } else {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives one that is specific to ${host} and proves that it comes from a valid credential, without revealing the credential.`
  }
  return { id: c?.age ? 'age-consent' : 'consent', context, stage: 2, title: 'Consent', summary, details: c ? consentSections(c, i.siteName) : [] }
}

function pinStep(i: GuideInput, context: string): GuideStep {
  const key = i.credential ? `${i.credential.deviceKey.kty} ${i.credential.deviceKey.crv}, bound to the credential` : 'Bound to the credential'
  return {
    id: 'pin',
    context,
    stage: 3,
    title: 'PIN',
    summary: "The PIN unlocks the wallet's device key, which signs this request. The circuit verifies that signature, so the proof is valid only for this request.",
    details: [
      {
        heading: 'Device key',
        rows: [
          { label: 'Key', value: key },
          { label: 'Signs', value: 'DeviceAuthentication over the OpenID4VP session transcript: client_id, nonce and response_uri' },
          { label: 'Wrong PIN', value: 'Refused before the device key signs' },
        ],
        stacked: true,
      },
    ],
  }
}

function wrongPinStep(i: GuideInput, context: string): GuideStep {
  return {
    id: 'wrong-pin',
    context,
    stage: 3,
    title: 'Wrong PIN',
    summary: `The PIN was wrong, so the device key did not sign and nothing was sent to ${i.siteName}. The wallet asks again.`,
    details: [{ heading: 'Prover response', rows: [{ label: 'Status', value: '401 invalid_pin', mono: true }] }],
  }
}

function provingStep(i: GuideInput, context: string): GuideStep {
  const circuit = i.wallet.view?.circuit
  return {
    id: 'proving',
    context,
    stage: 4,
    title: 'Proof',
    summary: i.wallet.metrics?.simulated
      ? `The offline simulation stands in for the prover: it checks the request against the credential and sends a presentation with a random proof of Vega's size. ${i.siteName} checks the presentation, not a proof.`
      : `The wallet proves the request's statement over its credential${circuit ? ` with ${circuit.label}` : ''} and sends the presentation to ${i.siteName}. ${i.siteName} verifies it against the request it signed.`,
    details: [proofSection(i.wallet, i.siteName)].filter((s): s is GuideSection => !!s),
  }
}

function unmetStep(i: GuideInput, context: string): GuideStep {
  const v = i.wallet.view
  const age = v?.items.find((x) => x.kind === 'age')
  if (v?.problem === 'age' && age && age.kind === 'age') {
    return {
      id: 'unmet',
      context,
      stage: 2,
      title: 'Requirement not met',
      summary: `The request asks for proof of age ${ageText(age)}. The credential's birth date is outside that range, so the wallet cannot make the proof. It answers access_denied, as it does for a declined request.`,
      details: [
        {
          heading: 'Age check',
          rows: [
            { label: 'Requested', value: ageText(age) },
            { label: 'Bounds', value: birthRangeText(age) },
            { label: 'Response', value: 'access_denied, without a description' },
            { label: 'Proof created', value: 'No' },
          ],
        },
      ],
    }
  }
  return {
    id: 'unsupported',
    context,
    stage: 2,
    title: 'Request not supported',
    summary: `The wallet cannot answer this request: ${
      v?.problem === 'no_circuit' ? 'it has no circuit in common with the request' : 'the request is outside what the wallet supports'
    }. It answers invalid_request, which does not depend on the holder's data.`,
    details: [],
  }
}

function successStep(i: GuideInput, context: string): GuideStep {
  const kind = i.dialog.completion?.kind
  const handle = i.dialog.completion?.handle ?? i.account?.handle
  const checks = checksSection(i.wallet.view?.circuit, i.siteName, !!i.wallet.metrics?.simulated)
  const verified = i.wallet.metrics?.simulated ? 'checked the presentation (offline simulation)' : 'verified the proof'
  const proof = proofSection(i.wallet, i.siteName)
  if (kind === 'age') {
    const age = i.wallet.consent?.age
    return {
      id: 'age-verified',
      context,
      stage: 5,
      title: 'Age verified',
      summary: `${i.siteName} ${i.wallet.metrics?.simulated ? 'accepted, from the offline simulation without a proof,' : 'verified'} that the holder is ${age?.text ?? 'in the requested range'} and that the pseudonym is the logged-in account's. It stores the proven birth-date range, not a birth date.`,
      details: [storedSection(i.account, i.siteName), proof, checks].filter((s): s is GuideSection => !!s),
    }
  }
  return {
    id: kind === 'created' ? 'account-created' : 'logged-in',
    context,
    stage: 5,
    title: kind === 'created' ? 'Account created' : 'Logged in',
    summary:
      kind === 'created'
        ? `${i.siteName} ${verified} and created u/${handle}. The pseudonym is the account identifier; ${i.siteName} has no name, email address or birth date for it.`
        : `${i.siteName} ${verified}. The pseudonym belongs to an existing account, so the person is logged in as u/${handle}.`,
    details: [storedSection(i.account, i.siteName), proof, checks].filter((s): s is GuideSection => !!s),
  }
}

function failedStep(i: GuideInput, context: string, failure: string): GuideStep {
  const p = i.dialog.purpose
  const base = { context, stage: 5 }
  switch (failure) {
    case 'banned':
      return bannedSignupStep(i, context, p?.kind === 'age')
    case 'denied':
    case 'invalid_request':
      return {
        ...base,
        id: 'not-completed',
        title: 'Not completed',
        summary:
          p?.kind === 'age'
            ? `${i.siteName} received ${failure === 'denied' ? 'access_denied' : 'invalid_request'} and no data. ${communityName(p.community)} stays closed and the account is unchanged.`
            : `${i.siteName} received ${failure === 'denied' ? 'access_denied' : 'invalid_request'} and no data. No account was created or logged in.`,
        details: [],
      }
    case 'invalid':
      return { ...base, id: 'invalid', title: 'Not verified', summary: `${i.siteName} could not verify the presentation and discarded it. The technical view shows the rule that failed.`, details: [] }
    case 'unavailable':
      return { ...base, id: 'unavailable', title: 'Verifier not available', summary: 'The verifier is not available. The moderation view can switch the proof backend to the offline simulation.', details: [] }
    case 'expired':
      return { ...base, id: 'expired', title: 'Request expired', summary: 'The request expired before the wallet answered. Try again shows a new QR code.', details: [] }
    case 'mismatch':
      return {
        ...base,
        id: 'mismatch',
        title: 'Different account',
        summary: `The pseudonym in the age proof is not the logged-in account's, so ${i.siteName} does not apply it.`,
        details: [],
      }
    default:
      return { ...base, id: 'failed', title: 'Not completed', summary: `The request ended without a result (${failure}).`, details: [] }
  }
}

function bannedSignupStep(i: GuideInput, context: string, ageCheck = false): GuideStep {
  const handle = i.last?.handle ?? i.bannedHandle
  const pseudonym = i.wallet.consent ? pseudonymSection(i.wallet.consent) : null
  return {
    id: 'signup-refused',
    context,
    stage: 5,
    title: 'Account banned',
    summary: ageCheck
      ? `The account${handle ? ` u/${handle}` : ''} is banned, so ${i.siteName} does not apply the age proof.`
      : `The wallet derived the same pseudonym for ${i.siteHost} as at the first sign-up. ${i.siteName} matched it to the banned account${handle ? ` u/${handle}` : ''} and refused the sign-up.`,
    details: pseudonym ? [pseudonym] : [],
  }
}

// ---------------------------------------------------------------------------------------------
// Steps while the site is shown

function siteStep(i: GuideInput): GuideStep {
  const last = i.last
  if (last && !last.ok && last.kind === 'banned' && last.purpose.kind === 'signin') {
    return { ...bannedSignupStep(i, 'Sign-up after the ban'), stage: undefined }
  }
  if (i.bannedHandle) {
    return {
      id: 'banned',
      context: 'Moderation',
      title: 'Account banned',
      summary: `A moderator banned u/${i.bannedHandle} in the moderation view. The ban is stored against the pseudonym; it ended the login and hid the account's comments.`,
      details: [
        {
          heading: 'Ban',
          rows: [
            { label: 'Account', value: `u/${i.bannedHandle}` },
            { label: 'Stored against', value: 'The pseudonym' },
            { label: 'Refused from now on', value: 'Log-in, sign-up and age checks with this pseudonym' },
          ],
          stacked: true,
        },
      ],
    }
  }
  if (i.page.kind === 'community') return communityStep(i, i.page.community)
  if (!i.account) {
    const c = i.credential
    return {
      id: 'start',
      context: i.siteName,
      title: i.siteName,
      summary: `${i.siteName} is a community site with pseudonymous accounts. Sign-up and age checks use the SIROS ID wallet on the person's phone, over OpenID4VP with a QR code.`,
      details: [
        {
          heading: 'Demo setup',
          rows: [
            ...(c ? [{ label: 'Wallet credential', value: `${c.title} (${c.docType}), issued by ${c.issuer.name}` }] : []),
            ...(c ? [{ label: 'Birth date in the credential', value: fmtDate(c.attributes.birth_date) }] : []),
            { label: 'Mocked', value: 'The site and the phone screens' },
            { label: 'Real', value: 'The OpenID4VP requests and responses, the proofs and their verification' },
            { label: 'Posts and other accounts', value: 'Sample data' },
          ],
          stacked: true,
        },
      ],
    }
  }
  if (last?.ok && last.purpose.kind === 'signin') {
    return {
      id: last.kind === 'created' ? 'account-created' : 'logged-in',
      context: i.siteName,
      title: last.kind === 'created' ? 'Account created' : 'Logged in',
      summary: `u/${i.account.handle} is logged in. The home feed shows posts from the communities this account can open.`,
      // The request that just ended: the wallet's state outlives the dialog until the next request.
      details: [
        storedSection(i.account, i.siteName),
        proofSection(i.wallet, i.siteName),
        checksSection(i.wallet.view?.circuit, i.siteName, !!i.wallet.metrics?.simulated),
      ].filter((s): s is GuideSection => !!s),
    }
  }
  return {
    id: 'home',
    context: i.siteName,
    title: 'Home feed',
    summary: 'The home feed shows posts from the communities this account can open. Age-restricted communities appear after a matching age check.',
    details: [storedSection(i.account, i.siteName)].filter((s): s is GuideSection => !!s),
  }
}

function communityStep(i: GuideInput, c: Community): GuideStep {
  const name = communityName(c)
  const context = name
  if (i.access === 'login' || !i.account) {
    return {
      id: 'login-required',
      context,
      title: 'Log-in required',
      summary: `${i.siteName} shows communities only to logged-in accounts. Logging in uses the same wallet request as signing up.`,
      details: [],
    }
  }
  if (!c.gate) {
    return {
      id: 'open-community',
      context,
      title: 'Open community',
      summary: `${name} has no age requirement. The account can read, vote and comment without another wallet request.`,
      details: [],
    }
  }
  const required = gateRange(c.gate, i.today)
  const gateRows: GuideRow[] = [
    { label: 'Requirement', value: gateText(c.gate) },
    { label: 'Birth dates that qualify today', value: birthRangeText(required) },
    { label: 'Proven for this account', value: rangeText(i.account.birthDateRange) },
  ]
  const lastHere = i.last?.purpose.kind === 'age' && i.last.purpose.community === c.slug ? i.last : null
  if (i.access === 'ask') {
    return {
      id: 'age-ask',
      context,
      title: 'Age-restricted community',
      summary: `${name} is for ${gateText(c.gate)}. ${
        i.account.birthDateRange ? 'The age proven so far does not settle this' : `${i.siteName} has no proven age for this account`
      }, so it asks the wallet.${lastHere && !lastHere.ok ? ` The last request ended with ${lastHere.kind === 'denied' ? 'access_denied' : lastHere.kind}.` : ''}`,
      details: [{ heading: 'Age requirement', rows: gateRows, stacked: true }],
    }
  }
  if (i.access === 'deny') {
    return {
      id: 'age-refused',
      context,
      title: `Refused by ${i.siteName}`,
      summary: `${name} is for ${gateText(c.gate)}. The account's proven birth-date range does not overlap that requirement, so ${i.siteName} refuses without asking the wallet.`,
      details: [{ heading: 'Age requirement', rows: [...gateRows, { label: 'Wallet request', value: 'None' }], stacked: true }],
    }
  }
  return {
    id: lastHere?.ok ? 'age-verified' : 'age-granted',
    context,
    title: lastHere?.ok ? 'Age verified' : 'Access granted',
    summary: `The account's proven birth-date range lies within ${name}'s requirement (${gateText(c.gate)}), so ${i.siteName} opens the community. Later visits need no new request.`,
    details: [
      {
        heading: 'Age requirement',
        rows: [...gateRows, { label: 'Age checks passed', value: i.account.ageProofs.map((p) => p.label).join(', ') || 'None' }],
        stacked: true,
      },
      ...(lastHere?.ok ? [proofSection(i.wallet, i.siteName), checksSection(i.wallet.view?.circuit, i.siteName, !!i.wallet.metrics?.simulated)] : []),
    ].filter((s): s is GuideSection => !!s),
  }
}

export function guideStep(i: GuideInput): GuideStep {
  return i.dialog.open ? dialogStep(i) : siteStep(i)
}
