// The guide panel's current step: a title, a short neutral summary and optional details, derived
// from the state of the site, the dialog and the wallet. Every fact comes from that state: the
// request as the wallet analysed it, the circuit's registry entry, the rulebook's properties of the
// pseudonym configuration (app/wallet/rulebook.ts via consentFor), the measured metrics, the
// credential, and the account as the server reports it.

import type { Account, AgeGate, BirthDateRange, Community } from '#shared/types'
import type { CircuitEntry, SchemeEntry } from '#shared/registry/circuits'
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import { gateRange } from '#shared/utils/age'
import type { DialogFlow, LastOutcome, VerificationMetrics, WalletFlow } from '~/composables/useFlow'
import type { WalletPurpose } from '~/composables/useWallet'
import type { CommunityAccess } from '~/composables/useCommunityAccess'
import type { ConsentView, RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import { PHONES, credentialLabel, neverExpires } from '~/wallet/holder'
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
  /** What the step belongs to: "Sign-up", "Age check · c/teenspace", "Community"… */
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
  /** The community account this browser has in the community on screen, if it has its own pseudonym. */
  membership: { handle: string; linked: boolean; banned: boolean; bannedWith: string | null } | null
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
            `Under known-offender-matching-ssc the pseudonym is derived from the credential's seed, so another credential gives another pseudonym for ${i.siteHost}, and so another ${site} account: another person's has its own seed, and a BBS credential uses another PRF (hashdh-bls12381g1), even over the same seed.`,
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
      { label: 'prf', value: c.pseudonym.prf, mono: true, code: true },
      ...(c.pseudonym.prf === 'hashdh-bls12381g1'
        ? [{ label: 'Value', value: 'secret_seed·OP, OP = hash_to_curve_G1(config ‖ verifier_id): a 48-byte BLS12-381 G1 point, computed in the proof' }]
        : [{ label: 'Value', value: shortHex(c.pseudonym.value ?? ''), mono: true }]),
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

/** The addon that runs a request's proofs: Vega or Longfellow for mso_mdoc (by the circuit), BBS
 *  for bbs_cd. */
const addonOf = (v: RequestView | null | undefined) =>
  v?.scheme ? 'the BBS addon' : v?.circuit?.proof_system === 'longfellow-libzk-v1' ? 'the Longfellow addon' : v?.circuit ? 'the Vega addon' : 'its proof addons'

function proofSection(w: WalletFlow, site: string): GuideSection | null {
  const m = w.metrics
  const circuit = w.view?.circuit
  const scheme = w.view?.scheme
  if (!m && !circuit && !scheme) return null
  const rows: GuideRow[] = []
  if (w.credential) rows.push({ label: 'Credential', value: credentialLabel(w.credential) })
  if (circuit) rows.push({ label: 'Circuit', value: `${circuit.label} (${circuit.proof_system})` })
  if (scheme) rows.push({ label: 'Scheme', value: `${scheme.label} (${scheme.proof_system})` })
  const b = m?.bbs
  if (b) {
    if (b.offline_ms != null) rows.push({ label: 'Commitments and preparation', value: `${ms(b.offline_ms)}, before the request in a real wallet` })
    if (b.bbs_ms != null) rows.push({ label: 'BBS proof', value: `${ms(b.bbs_ms)}${b.parts ? `, ${kB(b.parts.bbs_proof)}` : ''}` })
    if (b.ecdsa_pop_ms != null) rows.push({ label: 'Device binding (ecdsa-pop)', value: `${ms(b.ecdsa_pop_ms)}${b.device_sign_ms != null ? `, of which the device signature ${ms(b.device_sign_ms)}` : ''}${b.parts ? `, ${kB(b.parts.ecdsa_pop)}` : ''}` })
    if (b.pseudonym_ms != null) rows.push({ label: 'Pseudonym', value: `${ms(b.pseudonym_ms)}${b.parts ? `, ${b.parts.pseudonym} bytes` : ''}` })
    if (b.date_range_ms != null) rows.push({ label: 'Age range (date-range)', value: `${ms(b.date_range_ms)}${b.parts?.date_range ? `, ${kB(b.parts.date_range)}` : ''}` })
  } else {
    if (m?.sign_ms != null) rows.push({ label: 'Device key signature', value: ms(m.sign_ms) })
    if (m?.witness_ms != null) rows.push({ label: 'Witness', value: ms(m.witness_ms) })
  }
  if (m?.prove_ms != null) rows.push({ label: b ? 'Proving, all parts' : 'Proving', value: ms(m.prove_ms) })
  if (m?.proof_bytes != null && !b) rows.push({ label: 'Proof size', value: kB(m.proof_bytes) })
  if (m?.presentation_bytes != null) rows.push({ label: 'Presentation size', value: kB(m.presentation_bytes) })
  rows.push({ label: 'Runs on', value: `${site}'s server (${addonOf(w.view)}), in place of the phone` })
  return { heading: 'Proof', rows }
}

/** The verifier's timings, apart from the prover's: as measured on this machine, in the server. */
function verificationSection(v: VerificationMetrics | null | undefined, site: string, view?: RequestView | null): GuideSection | null {
  if (!v) return null
  const rows: GuideRow[] = []
  if (v.decode_ms != null) rows.push({ label: 'Decoding', value: ms(v.decode_ms) })
  if (v.verify_ms != null) rows.push({ label: 'Verification', value: ms(v.verify_ms) })
  if (v.total_ms != null) rows.push({ label: 'Verifier total', value: ms(v.total_ms) })
  rows.push({ label: 'Verifier call', value: `${ms(v.round_trip_ms)}, timed by ${site}'s response route around the call` })
  rows.push({ label: 'Runs on', value: `${site}'s server (${addonOf(view)}); measured on this machine` })
  return { heading: 'Verification', rows }
}

const ENCRYPTED_NOTE = 'The response came encrypted (direct_post.jwt) to the key this session put in the request. The key\'s thumbprint is in the handover, so the proof only verifies for that key.'

function checksSection(view: RequestView | null | undefined, site: string): GuideSection | null {
  if (view?.scheme) return schemeChecksSection(view.scheme, site)
  const circuit: CircuitEntry | undefined = view?.circuit
  if (!circuit) return null
  const rows: GuideRow[] = circuit.public_inputs.map((p) => ({
    label: p.name,
    code: true,
    value: `${p.source === 'presentation' ? 'From the presentation' : `Computed by ${site}`}: ${p.derivation}`,
  }))
  const items = [ENCRYPTED_NOTE, ...(circuit.checks_validity ? ['The circuit also proves that the credential is valid at proof_time.'] : [])]
  if (circuit.proof_system === 'longfellow-libzk-v1') {
    items.push(
      'Two circuits: the hash circuit (GF(2^128)) reads the credential, the dates and the pseudonym; the signature circuit (P-256) checks the issuer and device signatures. The MAC tags tie the two to the same message and device key.',
    )
  }
  return { heading: `What ${site} checks`, rows, items, stacked: true }
}

/** bbs_cd: what the BBS verifier derives itself, and what each plugin proves (the registry entry). */
function schemeChecksSection(scheme: SchemeEntry, site: string): GuideSection {
  return {
    heading: `What ${site} checks`,
    rows: [
      ...scheme.statement.map((x) => ({ label: x.name, code: true, value: `Computed by ${site}: ${x.derivation}` })),
      { label: 'BBS proof', code: true, value: 'The signed credential behind the commitments, under the issuer key; nothing disclosed' },
      ...scheme.plugins.map((p) => ({ label: p.id, code: true, value: `On ${p.attribute}: ${p.proves}` })),
    ],
    items: [ENCRYPTED_NOTE, 'Every plugin proof is bound to the request and to the BBS proof\'s commitments, so none can be moved to another presentation. The credential has no expiry for the proof to check.'],
    stacked: true,
  }
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
  if (c.bbs) {
    return {
      heading: 'Credential',
      rows: [
        { label: 'Schema', value: c.bbs.schemaId, mono: true },
        { label: 'Encoding', value: c.encoding },
        { label: 'Attributes', value: c.bbs.attributes.map((a) => `${a.name} (${a.type}${a.messages > 1 ? `, ${a.messages} messages` : ''})`).join(', '), mono: true },
        { label: 'Issuer', value: c.issuer.country ? `${c.issuer.name} (${c.issuer.country})` : c.issuer.name },
        { label: 'Issuer signature', value: `BBS over ${c.bbs.messages} messages, key ${c.bbs.issuerKey.slice(0, 16)}…` },
        { label: 'Valid', value: 'No expiry' },
        { label: 'Device key', value: `${c.deviceKey.kty} ${c.deviceKey.crv}, the same key as the phone's mdoc, attested at issuance` },
        { label: 'Size', value: `${c.sizes.issuerSigned.toLocaleString('en-GB')} bytes` },
      ],
      items: [
        'The pseudonym seed is a signed attribute the issuer chose and keeps (nym-seed.issuer-known), so the issuer can compute any pseudonym of the holder.',
        'Demo setup: the device key and the credential are stored in this page. A production wallet keeps the device key in secure hardware.',
      ],
    }
  }
  return {
    heading: 'Credential',
    rows: [
      { label: 'Document type', value: c.docType, mono: true },
      { label: 'Encoding', value: `${c.encoding}${c.compactProfile ? ', compact profile' : ''}` },
      { label: 'Data elements', value: c.elements.map((e) => e.id).join(', '), mono: true },
      { label: 'Issuer', value: c.issuer.country ? `${c.issuer.name} (${c.issuer.country})` : c.issuer.name },
      { label: 'Issuer signature', value: `${c.mso.signatureAlgorithm}, ${c.issuer.documentSigner}` },
      { label: 'Attribute digests', value: c.mso.digestAlgorithm },
      { label: 'Valid', value: `From ${fmtDate(c.validity.validFrom)}; ${neverExpires(c.validity.validUntil) ? 'no expiry (9999-12-31)' : `until ${fmtDate(c.validity.validUntil)}`}` },
      { label: 'Device key', value: `${c.deviceKey.kty} ${c.deviceKey.crv}` },
      { label: 'Size', value: `${c.sizes.issuerSigned.toLocaleString('en-GB')} bytes` },
    ],
    items: ['Demo setup: the device key and the secret seed are stored in this page. A production wallet keeps the device key in secure hardware.'],
  }
}

// ---------------------------------------------------------------------------------------------
// Steps while the dialog is open

function requestContext(i: GuideInput): string {
  const phone = i.wallet.phone ? ` · ${i.wallet.phone}` : ''
  return purposeContext(i) + phone
}

function purposeContext(i: GuideInput): string {
  const p = i.dialog.purpose
  if (p?.kind === 'community') return `Join · ${communityName(p.community)}`
  if (p?.kind === 'age') return `Age check · ${communityName(p.community)}`
  if (p?.community) return `Log-in and age check · ${communityName(p.community)}`
  const name = p?.intent === 'login' ? 'Log-in' : 'Sign-up'
  if (i.bannedHandle || (i.last && !i.last.ok && i.last.kind === 'banned')) return `${name} after the ban`
  return name
}

/** The context of a request that has ended, for the site's steps. */
function lastContext(p: WalletPurpose): string {
  if (p.kind === 'community') return `Join · ${communityName(p.community)}`
  if (p.kind === 'age') return `Age check · ${communityName(p.community)}`
  if (p.community) return `Log-in and age check · ${communityName(p.community)}`
  return p.intent === 'login' ? 'Log-in' : 'Sign-up'
}

/** The verifier identity of a request: Community's, or a community's own (Community.nymHost). */
function hostOf(i: GuideInput): string {
  return i.wallet.consent?.verifier.host ?? (i.page.kind === 'community' && i.dialog.purpose?.kind === 'community' ? (i.page.community.nymHost ?? i.siteHost) : i.siteHost)
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
  none_accepted: 'it accepts no proof system now (all switched off in the technical view)',
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
    summary = `The wallet could not reach the provers in ${i.siteName}'s server (the Vega, Longfellow and BBS addons), so it cannot answer requests. ${waits}`
  } else if (endpoint?.startsWith('/api/wallet/')) {
    summary = `The prover in ${i.siteName}'s server (${addonOf(i.wallet.view)}) did not ${endpoint.endsWith('sign') ? 'sign' : 'create the proof'}. ${waits}`
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
            details: [{ heading: 'Response', rows: [{ label: 'Sent to response_uri', value: 'error=access_denied, encrypted (JWE)', mono: true }] }],
          }
        : {
            id: 'declined',
            context,
            stage: 2,
            title: 'Declined',
            summary: 'The person declined the request. The wallet answers access_denied and shares nothing.',
            details: [{ heading: 'Response', rows: [{ label: 'Sent to response_uri', value: 'error=access_denied, encrypted (JWE)', mono: true }] }],
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
      details: [checksSection(w.view, i.siteName)].filter((s): s is GuideSection => !!s),
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
  if (auth && i.wallet.phone) details.push({ heading: 'Phone', rows: [{ label: 'In front of the QR code', value: i.wallet.phone }] })
  let summary: string
  if (p?.kind === 'community') {
    summary = `${communityName(p.community)} asks for its own pseudonym. The QR code's client_id is ${auth?.clientId ?? 'the community’s'}, so the wallet derives a pseudonym for that name, unrelated to the one for ${i.siteHost}.`
  } else if (p?.kind === 'signin' && p.community) {
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
  if (i.dialog.swapped) {
    summary = `The phones were swapped: the ${i.wallet.phone.replace(/^\w/, (ch) => ch.toLowerCase()) || 'other phone'} now faces the QR code. The request names no wallet, so any phone can answer it; only what its presentation proves counts. ${summary}`
  }
  const id = p?.kind === 'community' ? 'community-qr' : p?.kind === 'age' ? 'age-qr' : p?.community ? 'signin-age-qr' : 'signin-qr'
  return { id, context, stage: 0, title: 'QR code', summary, details }
}

function credentialStep(i: GuideInput, context: string): GuideStep {
  const c = focusOf(i)
  const phone = PHONES.find((p) => p.label === i.wallet.phone)
  const n = phone ? phone.credentials.length : i.credentials.length
  const bbsToo = i.credentials.some((k) => k.format === 'bbs_cd' && (!phone || phone.credentials.includes(k.index)))
  return {
    id: 'credential',
    context,
    title: 'The credential',
    summary: c?.format === 'bbs_cd'
      ? `This is the BBS form of the Age and pseudonym credential, from ${c.issuer.name}: a birth date, a pseudonym seed and the device key, signed with BBS. A presentation commits to them without revealing them, and plugins prove the age range and the pseudonym.`
      : `The wallet holds ${n === 1 ? 'one Age and pseudonym credential' : bbsToo ? 'an mdoc and a BBS credential, both Age and pseudonym,' : `${n} Age and pseudonym credentials`}${c ? ` from ${c.issuer.name}` : ''}${
          n > 1 && c && !bbsToo ? `; this one was issued for a birth date of ${fmtDate(c.attributes.birth_date)}` : ''
        }. Each contains a birth date and its own pseudonym seed. Neither value is sent to sites.`,
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
    summary: `${i.wallet.matching} credentials in the wallet match the request. Another person's has its own seed, and a BBS credential another PRF, so each gives a different pseudonym for ${i.siteHost}, and so a different ${i.siteName} account.`,
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
          { label: 'Schemes the wallet supports', value: i.wallet.walletSchemes.join(', ') || 'None', mono: true },
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
  if (i.dialog.purpose?.kind === 'community') {
    summary = `${communityName(i.dialog.purpose.community)} asks for a pseudonym for ${host}, its own name. The wallet derives it from the same secret seed as for ${i.siteHost}, but the different verifier_id gives a pseudonym that cannot be linked to the Community one.`
  } else if (signinAge) {
    summary = `${i.siteName} asks for a pseudonym and proof that the holder is ${c!.age!.text}, in one presentation. The pseudonym logs in to the account, or creates it; the birth date stays on the phone.`
  } else if (c?.age) {
    summary = `${i.siteName} asks for the account's pseudonym and proof that the holder is ${c.age.text}. The wallet proves both from the credential; the birth date stays on the phone.`
  } else if (i.bannedHandle) {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives the same one as at the first sign-up, because it depends only on the wallet's secret seed and ${i.siteName}'s verifier_id.`
  } else {
    summary = `${i.siteName} asks for a pseudonym. The wallet derives one that is specific to ${host} and proves that it comes from a valid credential, without revealing the credential.`
  }
  const id = i.dialog.purpose?.kind === 'community' ? 'community-consent' : signinAge ? 'signin-age-consent' : c?.age ? 'age-consent' : 'consent'
  return { id, context, stage: 2, title: 'Consent', summary, details: c ? consentSections(c, i.siteName, i) : [] }
}

function pinStep(i: GuideInput, context: string): GuideStep {
  const f = focusOf(i)
  const key = f ? `${f.deviceKey.kty} ${f.deviceKey.crv}, bound to the credential` : 'Bound to the credential'
  if (i.wallet.view?.scheme) {
    return {
      id: 'pin',
      context,
      stage: 3,
      title: 'PIN',
      summary: "The PIN unlocks the wallet's device key, which signs this request. Any PIN unlocks it in this demo. The ecdsa-pop plugin proves that the key in the credential made the signature, without revealing the key.",
      details: [
        {
          heading: 'Device key',
          rows: [
            { label: 'Key', value: key },
            { label: 'Signs', value: "ECDSA-P256-SHA256 over the plugin's device message, which binds the nonce, the request and the presentation's commitments" },
            { label: 'PIN', value: 'Any 6 digits unlock the key in this demo; the PIN never leaves the phone. The SIROS ID app unlocks with a passkey.' },
          ],
          stacked: true,
        },
      ],
    }
  }
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
  const v = i.wallet.view
  const by = v?.circuit ? ` with ${v.circuit.label}` : v?.scheme ? ` with ${v.scheme.label}: a BBS proof and one plugin proof per requested item` : ''
  return {
    id: 'proving',
    context,
    stage: 4,
    title: 'Proof',
    summary: `The wallet proves the request's statement over its credential${by} and sends the presentation to ${i.siteName}. ${i.siteName} verifies it against the request it signed.`,
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
      v?.problem === 'no_circuit' ? 'it has no circuit or scheme in common with the request' : 'the request is outside what the wallet supports'
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
  const checks = checksSection(i.wallet.view, i.siteName)
  const proof = proofSection(i.wallet, i.siteName)
  const verification = verificationSection(i.dialog.verification, i.siteName, i.wallet.view)
  const done = i.dialog.completion
  if (done?.community) {
    const name = communityName(done.community)
    const host = hostOf(i)
    const linkNote = done.linked && i.account ? ` ${i.siteName} recorded that it belongs to u/${i.account.handle}, because that account was logged in.` : ''
    return {
      id: done.linked ? 'community-linked' : kind === 'created' ? 'community-created' : 'community-joined',
      context,
      stage: 5,
      title: kind === 'created' ? `Joined ${name}` : `Back in ${name}`,
      summary:
        (kind === 'created'
          ? `${i.siteName} verified the proof and created u/${handle} in ${name}. The pseudonym is unique to /${done.community}; nothing in it connects to the person's Community pseudonym.`
          : `The pseudonym for ${host} belongs to an existing ${name} account, u/${handle}.`) + linkNote,
      details: [
        {
          heading: `${name} account`,
          rows: [
            { label: 'Verifier identity', value: `x509_san_dns:${host}`, mono: true },
            { label: 'Handle', value: `u/${handle}` },
            { label: 'Linked to a Community account', value: done.linked || i.membership?.linked ? 'Yes, by the person logging in to both' : 'No' },
          ],
          stacked: true,
        },
        proof,
        verification,
        checks,
      ].filter((s): s is GuideSection => !!s),
    }
  }
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
  const v = verificationSection(i.dialog.verification, i.siteName, i.wallet.view)
  return v ? { ...step, details: [...step.details, v] } : step
}

function failedStepFor(i: GuideInput, context: string, failure: string): GuideStep {
  const p = i.dialog.purpose
  const base = { context, stage: 5 }
  if (p?.kind === 'community') {
    const name = communityName(p.community)
    const host = hostOf(i)
    if (failure === 'community_banned' || failure === 'banned') {
      return {
        ...base,
        id: 'community-ban-refused',
        title: 'Account banned',
        summary: `This wallet's ${name} account is banned. The wallet always derives the same pseudonym for ${host}, so it cannot open a new ${name} account either.`,
        details: [],
      }
    }
    if (failure === 'other_pseudonym') {
      return {
        ...base,
        id: 'community-other-pseudonym',
        title: 'Pseudonym does not match',
        summary: `u/${i.account?.handle ?? ''} is already linked to a ${name} account from another wallet. This wallet's pseudonym for ${host} is a different one, so ${i.siteName} does not link a second account: one ${name} account per person.`,
        details: [],
      }
    }
    if (failure === 'linked_elsewhere') {
      return {
        ...base,
        id: 'community-linked-elsewhere',
        title: 'Linked to another account',
        summary: `This wallet's ${name} account is already linked to another Community account. ${i.siteName} links each ${name} account to one Community account at most.`,
        details: [],
      }
    }
  }
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
        summary: `${i.siteName}'s proof backend, ${addonOf(i.wallet.view)} in its server, failed, so ${i.siteName} could not ${i.dialog.authUrl ? 'verify the response' : 'start the request'}. Nothing was applied. The technical view and the server log show the error.`,
        details: [],
      }
    case 'none_accepted':
      return {
        ...base,
        id: 'none-accepted',
        title: 'No proof system accepted',
        summary: `${i.siteName} accepts none of its proof systems, so it has nothing to ask a wallet for and shows no QR code. The demo starts this way. Tick Vega, Longfellow or BBS under "Community accepts" in the technical view, then try again.`,
        details: [],
      }
    case 'expired':
      return { ...base, id: 'expired', title: 'Request expired', summary: 'The request expired before the wallet answered. Its request_uri and response_uri now refuse with 410. Try again shows a new QR code.', details: [] }
    case 'gone':
      return { ...base, id: 'gone', title: 'Request no longer known', summary: `${i.siteName} no longer has this request, for example after a demo reset. Try again shows a new QR code.`, details: [] }
    case 'account_exists':
      return {
        ...base,
        id: 'account-exists',
        title: 'Account already exists',
        summary: `The wallet proved its pseudonym for ${i.siteHost}, and ${i.siteName} already has an account for it. A sign-up only creates an account; it logs nobody in. Log in sends the same wallet request and logs in to the account.`,
        details: [i.wallet.consent ? pseudonymSection(i.wallet.consent) : null].filter((s): s is GuideSection => !!s),
      }
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
        title: 'Pseudonym does not match',
        summary: `${i.wallet.phone ? `The ${i.wallet.phone.toLowerCase()}` : 'The wallet'} made a valid proof, but from a credential that is not the account's: its pseudonym for ${i.siteHost} is not the logged-in account's. ${i.siteName} binds every age result to the account's pseudonym, so it rejects the presentation and applies nothing.`,
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
      context: lastContext(last.purpose),
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
            ...PHONES.map((p) => ({
              label: p.label,
              value: i.credentials
                .filter((c) => p.credentials.includes(c.index))
                .map((c) => `${c.title} (${c.docType}), issued by ${c.issuer.name}, birth date ${fmtDate(c.attributes.birth_date)}`)
                .join('; '),
            })),
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
        verificationSection(i.dialog.verification, i.siteName, i.wallet.view),
        checksSection(i.wallet.view, i.siteName),
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
  if (c.nymHost) return ownPseudonymStep(i, c)
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
            { label: '_req', value: 'pseudonym and age_check, in one zkp_req credential query', mono: true },
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
        ? [proofSection(i.wallet, i.siteName), verificationSection(i.dialog.verification, i.siteName, i.wallet.view), checksSection(i.wallet.view, i.siteName)]
        : []),
    ].filter((s): s is GuideSection => !!s),
  }
}

/** A community with its own pseudonym (Community.nymHost): one account per person, unlinkable to Community's. */
function ownPseudonymStep(i: GuideInput, c: Community): GuideStep {
  const name = communityName(c)
  const host = c.nymHost!
  const identity: GuideSection = {
    heading: 'Own pseudonym',
    rows: [
      { label: 'Verifier identity', value: `x509_san_dns:${host}`, mono: true },
      { label: "Community's", value: `x509_san_dns:${i.siteHost}`, mono: true },
      { label: 'Pseudonym', value: 'pseudonym, known-offender-matching-ssc', mono: true },
    ],
    items: [
      `Different verifier_id, different pseudonym: ${i.siteName} cannot tell which Community account, if any, a ${name} account belongs to, unless the person chooses to link them.`,
      `Known-offender matching still holds for ${host}: one wallet, one ${name} account, and a ban sticks.`,
      `A ban of the Community account also bans the ${name} account linked to it; a ban in ${name} leaves the Community account alone.`,
      `Linking moves no age: age checks always use the logged-in Community account's own proven range, so a ${name} account from another phone opens nothing else.`,
      'Today the request still uses known-offender-matching-ssc, so the issuer, which knows the secret seed, can link the pseudonym to the person. The psc-based configuration that replaces it (config: X in the side nav) prevents that; it needs a new circuit.',
    ],
    stacked: true,
  }
  const m = i.membership
  if (i.access === 'member-banned' && m) {
    return { id: 'community-banned', context: name, title: 'Account banned', summary: m.bannedWith
        ? `A moderator banned the Community account u/${m.bannedWith}, and with it u/${m.handle}, the ${name} account linked to it. Unbanning u/${m.bannedWith} lifts both.`
        : `A moderator banned u/${m.handle} in ${name}. The ban is stored against the ${name} pseudonym; the person's Community account is not affected.`, details: [identity] }
  }
  if (i.access === 'join' || !m) {
    return {
      id: 'community-join',
      context: name,
      title: 'Fully anonymous',
      summary: `${name} is fully anonymous. The person proves they are real with a pseudonym for ${host}, its own name, so the pseudonym is unique to /${c.slug} and each person gets one ${name} account. Association to the main account is optional.${
        i.account
          ? ` Logged in as u/${i.account.handle}, the person chooses: link the two (Link to u/${i.account.handle}), or join separately, which logs out first.`
          : ' No Community account is needed.'
      }`,
      details: [identity],
    }
  }
  return {
    id: 'community-member',
    context: name,
    title: `Member of ${name}`,
    summary: `This browser acts as u/${m.handle} in ${name}${m.linked && i.account ? `, linked to u/${i.account.handle}` : ''}. Posts and comments here appear under the ${name} pseudonym only.`,
    details: [identity],
  }
}

export function guideStep(i: GuideInput): GuideStep {
  return i.dialog.open ? dialogStep(i) : siteStep(i)
}
