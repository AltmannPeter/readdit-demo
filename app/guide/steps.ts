// The guide panel's current step: a title, a short neutral summary and optional details, derived
// from the state of the site, the dialog and the wallet. Every fact comes from that state: the
// request as the wallet analysed it, the circuit's registry entry, the rulebook's properties of the
// pseudonym configuration (app/wallet/rulebook.ts via consentFor), the measured metrics, the
// credential, and the account as the server reports it.

import type { Account, AgeGate, BirthDateRange, Community } from '#shared/types'
import type { CircuitEntry } from '#shared/registry/circuits'
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import { gateRange } from '#shared/utils/age'
import type { DialogFlow, LastOutcome, VerificationMetrics, WalletFlow } from '~/composables/useFlow'
import type { WalletPurpose } from '~/composables/useWallet'
import type { CommunityAccess } from '~/composables/useCommunityAccess'
import type { ConsentView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import { credentialLabel } from '~/wallet/holder'
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
  access: CommunityAccess | null
  account: Account | null
  bannedHandle: string | null
  /** The wallet's credentials (the one in focus is wallet.credential). */
  credentials: CredentialView[]
}

/** The credential in focus: open on the phone, or used by the request; else the wallet's first. */
const focusOf = (i: GuideInput): CredentialView | null => i.wallet.credential ?? i.credentials[0] ?? null

/** Which credential the request uses, and what choosing another one changes. */
function usedCredentialSection(i: GuideInput, site: string): GuideSection | null {
  const c = i.wallet.credential
  if (!c) return null
  return {
    heading: 'Credential',
    rows: [
      { label: 'Used', value: credentialLabel(c) },
      { label: 'Other matching credentials', value: String(Math.max(0, i.wallet.matching - 1)) },
    ],
    items:
      i.wallet.matching > 1
        ? [
            `Each credential has its own secret seed. Under known-offender-matching-ssc the pseudonym is derived from the seed, so another credential gives another pseudonym for ${i.siteHost}, and so another ${site} account.`,
          ]
        : undefined,
    stacked: true,
  }
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

function consentSections(c: ConsentView, site: string, i: GuideInput): GuideSection[] {
  return [
    usedCredentialSection(i, site),
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
  const rows: GuideRow[] = []
  if (w.credential) rows.push({ label: 'Credential', value: credentialLabel(w.credential) })
  if (circuit) rows.push({ label: 'Circuit', value: `${circuit.label} (${circuit.proof_system})` })
  if (m?.sign_ms != null) rows.push({ label: 'Device key signature', value: ms(m.sign_ms) })
  if (m?.witness_ms != null) rows.push({ label: 'Witness', value: ms(m.witness_ms) })
  if (m?.prove_ms != null) rows.push({ label: 'Proving', value: ms(m.prove_ms) })
  if (m?.proof_bytes != null) rows.push({ label: 'Proof size', value: kB(m.proof_bytes) })
  if (m?.presentation_bytes != null) rows.push({ label: 'Presentation size', value: kB(m.presentation_bytes) })
  rows.push({ label: 'Runs on', value: `${site}'s server (the Vega addon), in place of the phone` })
  return { heading: 'Proof', rows }
}

/** The verifier's timings, apart from the prover's: as measured on this machine, in the server. */
function verificationSection(v: VerificationMetrics | null | undefined, site: string): GuideSection | null {
  if (!v) return null
  const rows: GuideRow[] = []
  if (v.decode_ms != null) rows.push({ label: 'Decoding', value: ms(v.decode_ms) })
  if (v.verify_ms != null) rows.push({ label: 'Verification', value: ms(v.verify_ms) })
  if (v.total_ms != null) rows.push({ label: 'Verifier total', value: ms(v.total_ms) })
  rows.push({ label: 'Verifier call', value: `${ms(v.round_trip_ms)}, timed by ${site}'s response route around the call` })
  rows.push({ label: 'Runs on', value: `${site}'s server (the Vega addon); measured on this machine` })
  return { heading: 'Verification', rows }
}

function checksSection(circuit: CircuitEntry | undefined, site: string): GuideSection | null {
  if (!circuit) return null
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
  if (p?.community) return `Log-in and age check · ${communityName(p.community)}`
  const name = p?.intent === 'login' ? 'Log-in' : 'Sign-up'
  if (i.bannedHandle || (i.last && !i.last.ok && i.last.kind === 'banned')) return `${name} after the ban`
  return name
}

/** What a refusal code from request_uri or response_uri means (server/api/vp/*). */
const REFUSALS: Record<string, string> = {
  already_used: 'the QR code was already used, and each request_uri answers once',
  expired: 'the request expired',
  cancelled: 'the request was cancelled when the dialog was closed',
  unknown_session: 'it does not know the request',
  state_mismatch: 'the state does not match the request',
  already_answered: 'the request already has an answer',
  unavailable: 'its verifier failed',
}

/** The wallet stopped on its own error: what happened and what the site sees, from the error's cause. */
function walletErrorStep(i: GuideInput, context: string): GuideStep {
  const e = i.wallet.error
  const cause = e?.cause ?? ''
  const [endpoint, status, code] = cause.split(' ')
  const ended = i.dialog.phase === 'failed'
  const waits = ended
    ? `${i.siteName}'s request has already ended.`
    : `The wallet sends no response, so ${i.siteName} waits until the request expires or the dialog is closed.`
  let summary: string
  if (endpoint === 'request_uri' && status) {
    summary = `${i.siteName} refused to hand out the request (${status}): ${REFUSALS[code ?? ''] ?? 'see the technical view'}. ${waits}`
  } else if (endpoint === 'response_uri' && status) {
    summary = `${i.siteName} refused the wallet's response (${status}): ${REFUSALS[code ?? ''] ?? 'see the technical view'}. Nothing was applied.`
  } else if (endpoint === '/api/wallet/capabilities') {
    summary = `The wallet could not reach the prover in ${i.siteName}'s server (the Vega addon), so it cannot answer requests. ${waits}`
  } else if (endpoint?.startsWith('/api/wallet/')) {
    summary = `The prover in ${i.siteName}'s server (the Vega addon) did not ${endpoint.endsWith('sign') ? 'sign' : 'create the proof'}. ${waits}`
  } else if (e?.title === 'Verifier is not Trusted') {
    summary = `The signed request did not check out, so the wallet stops and sends nothing to a verifier it cannot trust. ${waits}`
  } else {
    summary = `The wallet stopped with an error: ${e?.description ?? ''} ${waits}`
  }
  return {
    id: 'wallet-error',
    context,
    title: e?.title ?? 'Error',
    summary,
    details: cause ? [{ heading: 'Error', rows: [{ label: 'Cause', value: cause, mono: true }, { label: 'Response sent', value: 'None' }], stacked: true }] : [],
  }
}

function dialogStep(i: GuideInput): GuideStep {
  const w = i.wallet
  const context = requestContext(i)
  if (w.switching) return switchStep(i, context)
  switch (w.screen) {
    case 'detail':
    case 'presentations':
      return credentialStep(i, context)
    case 'scan':
      return scanStep(i, context)
    case 'request':
      return consentStep(i, context)
    case 'pin':
      return pinStep(i, context)
    case 'working':
      return provingStep(i, context)
    case 'unmet':
      return unmetStep(i, context)
    case 'declined':
      return w.declinedAt === 'pin'
        ? {
            id: 'pin-cancelled',
            context,
            stage: 3,
            title: 'Cancelled at the PIN',
            summary: 'The person cancelled at the PIN screen. The device key did not sign, no proof was made, and the wallet answers access_denied, as for a declined request.',
            details: [{ heading: 'Response', rows: [{ label: 'Sent to response_uri', value: 'error=access_denied', mono: true }] }],
          }
        : {
            id: 'declined',
            context,
            stage: 2,
            title: 'Declined',
            summary: 'The person declined the request. The wallet answers access_denied and shares nothing.',
            details: [{ heading: 'Response', rows: [{ label: 'Sent to response_uri', value: 'error=access_denied', mono: true }] }],
          }
    case 'error':
      return walletErrorStep(i, context)
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
      summary: `${i.siteName} received the presentation and verifies the proof against the request it signed.`,
      details: [checksSection(w.view?.circuit, i.siteName)].filter((s): s is GuideSection => !!s),
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
  if (p?.kind === 'signin' && p.community) {
    const c = i.page.kind === 'community' ? i.page.community : null
    summary = `${communityName(p.community)}${c?.gate ? ` is for ${gateText(c.gate)}` : ' has an age requirement'}. The visitor is not logged in, so ${i.siteName} shows one QR code that asks for the pseudonym and the age range together.`
  } else if (p?.kind === 'age') {
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
  const id = p?.kind === 'age' ? 'age-qr' : p?.community ? 'signin-age-qr' : 'signin-qr'
  return { id, context, stage: 0, title: 'QR code', summary, details }
}

function credentialStep(i: GuideInput, context: string): GuideStep {
  const c = focusOf(i)
  const n = i.credentials.length
  return {
    id: 'credential',
    context,
    title: 'The credential',
    summary: `The wallet holds ${n === 1 ? 'one Age and pseudonym credential' : `${n} Age and pseudonym credentials`}${c ? ` from ${c.issuer.name}` : ''}${
      n > 1 && c ? `; this one was issued for a birth date of ${fmtDate(c.attributes.birth_date)}` : ''
    }. Each contains a birth date and a commitment to its own secret seed. Neither value is sent to sites.`,
    details: [credentialSection(c)].filter((s): s is GuideSection => !!s),
  }
}

function switchStep(i: GuideInput, context: string): GuideStep {
  const c = i.wallet.credential
  return {
    id: 'switch-credential',
    context,
    stage: 2,
    title: 'Switch credential',
    summary: `${i.wallet.matching} credentials in the wallet match the request. Each has its own secret seed, so each gives a different pseudonym for ${i.siteHost}, and so a different ${i.siteName} account.`,
    details: [
      {
        heading: 'Credentials',
        rows: i.credentials.map((k) => ({ label: k.index === c?.index ? 'Current' : 'Other', value: credentialLabel(k) })),
        stacked: true,
      },
    ],
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
  const signinAge = !!c?.age && i.dialog.purpose?.kind === 'signin'
  let summary: string
  if (signinAge) {
    summary = `${i.siteName} asks for a pseudonym and proof that the holder is ${c!.age!.text}, in one presentation. The pseudonym logs in to the account, or creates it; the birth date stays on the phone.`
  } else if (c?.age) {
    summary = `${i.siteName} asks for the account's pseudonym and proof that the holder is ${c.age.text}. The wallet proves both from the credential; the birth date stays on the phone.`
  } else if (i.bannedHandle) {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives the same one as at the first sign-up, because it depends only on the wallet's secret seed and ${i.siteName}'s verifier_id.`
  } else {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives one that is specific to ${host} and proves that it comes from a valid credential, without revealing the credential.`
  }
  return { id: signinAge ? 'signin-age-consent' : c?.age ? 'age-consent' : 'consent', context, stage: 2, title: 'Consent', summary, details: c ? consentSections(c, i.siteName, i) : [] }
}

function pinStep(i: GuideInput, context: string): GuideStep {
  const f = focusOf(i)
  const key = f ? `${f.deviceKey.kty} ${f.deviceKey.crv}, bound to the credential` : 'Bound to the credential'
  return {
    id: 'pin',
    context,
    stage: 3,
    title: 'PIN',
    summary: "The PIN unlocks the wallet's device key, which signs this request. Any PIN unlocks it in this demo. The circuit verifies the signature, so the proof is valid only for this request.",
    details: [
      {
        heading: 'Device key',
        rows: [
          { label: 'Key', value: key },
          { label: 'Signs', value: 'DeviceAuthentication over the OpenID4VP session transcript: client_id, nonce and response_uri' },
          { label: 'PIN', value: 'Any 6 digits unlock the key in this demo; the PIN never leaves the phone. The SIROS ID app unlocks with a passkey.' },
        ],
        stacked: true,
      },
    ],
  }
}

function provingStep(i: GuideInput, context: string): GuideStep {
  const circuit = i.wallet.view?.circuit
  return {
    id: 'proving',
    context,
    stage: 4,
    title: 'Proof',
    summary: `The wallet proves the request's statement over its credential${circuit ? ` with ${circuit.label}` : ''} and sends the presentation to ${i.siteName}. ${i.siteName} verifies it against the request it signed.`,
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
      summary: `The request asks for proof of age ${ageText(age)}. The credential's birth date is outside that range, so the wallet cannot make the proof with it. ${
        i.wallet.matching > 1 ? 'Another matching credential can be chosen; closing answers' : 'It answers'
      } access_denied, as it does for a declined request.`,
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
        usedCredentialSection(i, i.siteName),
      ].filter((s): s is GuideSection => !!s),
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
    details: [
      {
        heading: 'Request',
        rows: [
          ...(v?.reason ? [{ label: 'Reason', value: v.reason }] : []),
          { label: 'Response', value: 'invalid_request' },
          { label: 'Proof created', value: 'No' },
        ],
        stacked: true,
      },
    ],
  }
}

function successStep(i: GuideInput, context: string): GuideStep {
  const kind = i.dialog.completion?.kind
  const handle = i.dialog.completion?.handle ?? i.account?.handle
  const checks = checksSection(i.wallet.view?.circuit, i.siteName)
  const proof = proofSection(i.wallet, i.siteName)
  const verification = verificationSection(i.dialog.verification, i.siteName)
  if (i.dialog.completion?.age && (kind === 'created' || kind === 'logged_in')) {
    const age = i.wallet.consent?.age
    return {
      id: 'signin-age-verified',
      context,
      stage: 5,
      title: kind === 'created' ? 'Account created, age verified' : 'Logged in, age verified',
      summary: `${i.siteName} verified one proof for both: the pseudonym, which ${kind === 'created' ? `created u/${handle}` : `belongs to u/${handle}, so the person is logged in`}, and that the holder is ${age?.text ?? 'in the requested range'}. It stores the proven birth-date range, not a birth date.`,
      details: [storedSection(i.account, i.siteName), proof, verification, checks].filter((s): s is GuideSection => !!s),
    }
  }
  if (kind === 'age') {
    const age = i.wallet.consent?.age
    return {
      id: 'age-verified',
      context,
      stage: 5,
      title: 'Age verified',
      summary: `${i.siteName} verified that the holder is ${age?.text ?? 'in the requested range'} and that the pseudonym is the logged-in account's. It stores the proven birth-date range, not a birth date.`,
      details: [storedSection(i.account, i.siteName), proof, verification, checks].filter((s): s is GuideSection => !!s),
    }
  }
  return {
    id: kind === 'created' ? 'account-created' : 'logged-in',
    context,
    stage: 5,
    title: kind === 'created' ? 'Account created' : 'Logged in',
    summary:
      kind === 'created'
        ? `${i.siteName} verified the proof and created u/${handle}. The pseudonym is the account identifier; ${i.siteName} has no name, email address or birth date for it.`
        : i.dialog.purpose?.kind === 'signin' && i.dialog.purpose.intent === 'signup'
          ? `${i.siteName} verified the proof. The pseudonym already has an account, so the sign-up logs in to u/${handle} and creates no second account.`
          : `${i.siteName} verified the proof. The pseudonym belongs to an existing account, so the person is logged in as u/${handle}.`,
    details: [storedSection(i.account, i.siteName), proof, verification, checks].filter((s): s is GuideSection => !!s),
  }
}

/** A request that ended without being applied; when a presentation was verified or refused, its
 *  verifier timings join the details. */
function failedStep(i: GuideInput, context: string, failure: string): GuideStep {
  const step = failedStepFor(i, context, failure)
  const v = verificationSection(i.dialog.verification, i.siteName)
  return v ? { ...step, details: [...step.details, v] } : step
}

function failedStepFor(i: GuideInput, context: string, failure: string): GuideStep {
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
            : p?.community
              ? `${i.siteName} received ${failure === 'denied' ? 'access_denied' : 'invalid_request'} and no data. No account was created or logged in, and ${communityName(p.community)} stays closed.`
              : `${i.siteName} received ${failure === 'denied' ? 'access_denied' : 'invalid_request'} and no data. No account was created or logged in.`,
        details: [],
      }
    case 'invalid':
      return { ...base, id: 'invalid', title: 'Not verified', summary: `${i.siteName} could not verify the presentation and discarded it. The technical view shows the rule that failed.`, details: [] }
    case 'unavailable':
      return {
        ...base,
        id: 'unavailable',
        title: 'Verifier not available',
        summary: `${i.siteName}'s proof backend, the Vega addon in its server, failed, so ${i.siteName} could not ${i.dialog.authUrl ? 'verify the response' : 'start the request'}. Nothing was applied. The technical view and the server log show the error.`,
        details: [],
      }
    case 'expired':
      return { ...base, id: 'expired', title: 'Request expired', summary: 'The request expired before the wallet answered. Its request_uri and response_uri now refuse with 410. Try again shows a new QR code.', details: [] }
    case 'gone':
      return { ...base, id: 'gone', title: 'Request no longer known', summary: `${i.siteName} no longer has this request, for example after a demo reset. Try again shows a new QR code.`, details: [] }
    case 'no_account':
      return {
        ...base,
        id: 'no-account',
        title: 'No account',
        summary: `The wallet proved its pseudonym for ${i.siteHost}, and ${i.siteName} has no account for it. A log-in only finds an existing account; it creates none. Sign up sends the same wallet request and creates the account.`,
        details: [i.wallet.consent ? pseudonymSection(i.wallet.consent) : null].filter((s): s is GuideSection => !!s),
      }
    case 'logged_out':
      return {
        ...base,
        id: 'logged-out',
        title: 'Logged out',
        summary: `The browser was logged out while the wallet answered, so ${i.siteName} has no account to apply the age proof to. Nothing was stored.`,
        details: [],
      }
    case 'login_required':
    case 'age_refused':
    case 'age_verified':
      return {
        ...base,
        id: 'not-started',
        title: 'No request',
        summary:
          failure === 'login_required'
            ? `${i.siteName} asks for an age check only for a logged-in account, so it created no request.`
            : `The age already proven for this account settles this community's requirement, so ${i.siteName} created no request.`,
        details: [],
      }
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

/** The intent of the sign-in request on screen, or of the one that just ended. */
function signinIntent(i: GuideInput): 'signup' | 'login' | null {
  const p = i.dialog.open ? i.dialog.purpose : i.last?.purpose
  return p?.kind === 'signin' ? p.intent : null
}

/** The community of a sign-in that also checks the age, on screen or just ended. */
function signinCommunity(i: GuideInput): string | undefined {
  const p = i.dialog.open ? i.dialog.purpose : i.last?.purpose
  return p?.kind === 'signin' ? p.community : undefined
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
      : `The wallet derived the same pseudonym for ${i.siteHost} as at the first sign-up. ${i.siteName} matched it to the banned account${handle ? ` u/${handle}` : ''} and refused the ${signinCommunity(i) ? 'log-in and the age check' : signinIntent(i) === 'login' ? 'log-in' : 'sign-up'}.`,
    details: pseudonym ? [pseudonym] : [],
  }
}

// ---------------------------------------------------------------------------------------------
// Steps while the site is shown

function siteStep(i: GuideInput): GuideStep {
  const last = i.last
  if (last && !last.ok && last.kind === 'banned' && last.purpose.kind === 'signin') {
    return {
      ...bannedSignupStep(i, last.purpose.community ? `Log-in and age check · ${communityName(last.purpose.community)}` : last.purpose.intent === 'login' ? 'Log-in after the ban' : 'Sign-up after the ban'),
      stage: undefined,
    }
  }
  if (last && !last.ok && last.kind === 'closed') {
    return {
      id: 'request-closed',
      context:
        last.purpose.kind === 'age'
          ? `Age check · ${communityName(last.purpose.community)}`
          : last.purpose.community
            ? `Log-in and age check · ${communityName(last.purpose.community)}`
            : last.purpose.intent === 'login'
              ? 'Log-in'
              : 'Sign-up',
      title: 'Request closed',
      summary: `The dialog was closed before the request ended. ${i.siteName} cancelled the request on its server, so an answer the wallet sends later is refused and nothing is applied.`,
      details: [{ heading: 'Request', rows: [{ label: 'Status', value: 'failed, cancelled', mono: true }, { label: 'Later answers', value: '410 cancelled', mono: true }] }],
    }
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
    return {
      id: 'start',
      context: i.siteName,
      title: i.siteName,
      summary: `${i.siteName} is a community site with pseudonymous accounts. Sign-up and age checks use the SIROS ID wallet on the person's phone, over OpenID4VP with a QR code.`,
      details: [
        {
          heading: 'Demo setup',
          rows: [
            ...i.credentials.map((c, k) => ({ label: `Wallet credential ${k + 1}`, value: `${c.title} (${c.docType}), issued by ${c.issuer.name}, birth date ${fmtDate(c.attributes.birth_date)}` })),
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
        verificationSection(i.dialog.verification, i.siteName),
        checksSection(i.wallet.view?.circuit, i.siteName),
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
  if (i.access === 'ask-signin' && c.gate) {
    const lastHere = i.last?.purpose.community === c.slug ? i.last : null
    return {
      id: 'age-signin',
      context,
      title: 'Age-restricted community',
      summary: `${name} is for ${gateText(c.gate)}. The visitor is not logged in, so ${i.siteName} asks the wallet once for both: the pseudonym, which logs in to the account or creates it, and proof of the age range.${
        lastHere && !lastHere.ok ? ` The last request ended with ${lastHere.kind === 'denied' ? 'access_denied' : lastHere.kind}.` : ''
      }`,
      details: [
        {
          heading: 'One request',
          rows: [
            { label: 'Requirement', value: gateText(c.gate) },
            { label: 'Birth dates that qualify today', value: birthRangeText(gateRange(c.gate, i.today)) },
            { label: 'req', value: 'pseudonym-v1-sha256 and age_check, in one credential query', mono: true },
          ],
          items: [
            'One presentation carries the pseudonym and the age result: both are outputs of the same proof over the same credential, so the age is bound to the pseudonym.',
            `A new pseudonym creates the account; an existing one logs in. ${i.siteName} records the proven age range either way.`,
          ],
          stacked: true,
        },
      ],
    }
  }
  if (i.access === 'login' || !i.account) {
    return {
      id: 'login-required',
      context,
      title: 'Log-in required',
      summary: `${i.siteName} shows communities only to logged-in accounts. Logging in uses the same wallet request as signing up: a log-in finds the existing account, a sign-up creates it.`,
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
  // The last request for this community: an age check, or a sign-in that checked the age.
  const lastHere = i.last?.purpose.community === c.slug ? i.last : null
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
      ...(lastHere?.ok
        ? [proofSection(i.wallet, i.siteName), verificationSection(i.dialog.verification, i.siteName), checksSection(i.wallet.view?.circuit, i.siteName)]
        : []),
    ].filter((s): s is GuideSection => !!s),
  }
}

export function guideStep(i: GuideInput): GuideStep {
  return i.dialog.open ? dialogStep(i) : siteStep(i)
}
