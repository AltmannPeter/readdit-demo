// The developer view (/dev): the session's server trace as the rows of a sequence diagram between
// the site's page, its backend and the wallet, and the verifier's checks. Every row comes from a
// step that happened (server/utils/store.ts, addTrace); the mocked phone reports its own steps
// (app/wallet/report.ts), a real wallet does not.
import { findSystem } from '#shared/registry/circuits'
import type { DcqlQuery, EncryptionJwk, RequestObject, VpFormats } from '#shared/types/oid4vp'

export type Actor = 'browser' | 'backend' | 'wallet'
export type Tag = 'openid' | 'nym_auth' | 'zkp'

export interface FlowEvent {
  id: string
  at: number
  actor: Actor
  /** A message to another party; absent: work on the actor's own lifeline. */
  to?: Actor
  title: string
  tag?: Tag
  plain?: string
  method?: string
  payload?: unknown
  status: 'ok' | 'pending' | 'error' | 'info'
}

export interface Check {
  label: string
  detail: string
  status: 'pending' | 'running' | 'pass' | 'fail'
}

export interface TraceEvent {
  at: number
  step: string
  label: string
  data?: Record<string, any>
}

export type DevAge = 'none' | 'over18' | 'range13to17'

/** GET /api/dev/latest: the session as server/utils/dev-view.ts shows it. */
export interface DevSession {
  id: string
  purpose: { kind: 'dev'; age: DevAge } | { kind: 'signin'; intent: 'signup' | 'login'; community?: string } | { kind: 'age' | 'community'; community: string }
  phone: string | null
  status: 'waiting' | 'scanned' | 'responded' | 'verified' | 'failed' | 'completed'
  createdAt: number
  expiresAt: number
  authorizationUrl: string
  dcql: DcqlQuery
  offer: VpFormats
  responseKey: EncryptionJwk
  walletMetadata: unknown
  tailored: boolean
  request: RequestObject | null
  requestJwsHeader: Record<string, unknown> | null
  requestJwsBytes: number | null
  response: { jwe: { header: Record<string, unknown>; bytes: number }; presentation?: { base64url: string; chars: number; decoded: unknown } } | null
  answered: string | null
  outcome: { ok: true; format: string; proofId: string; pseudonym: string; age?: true } | { ok: false; reason: string; detail?: string } | null
  completion: { ok: boolean; kind: string; handle?: string; age?: true; community?: string } | null
  verification: { decode_ms?: number; verify_ms?: number; total_ms?: number; round_trip_ms: number } | null
  trace: TraceEvent[]
}

export const AGE_OPTIONS: Array<{ id: DevAge; label: string }> = [
  { id: 'none', label: 'None' },
  { id: 'over18', label: '18+' },
  { id: 'range13to17', label: '13–17' },
]

export const ACTOR_LONG: Record<Actor, string> = {
  browser: 'Community website',
  backend: 'Community backend',
  wallet: 'SIROS ID wallet (phone)',
}

export const TAG_LABELS: Record<Tag, string> = {
  openid: 'OID4VP extension (nym_auth v0.4)',
  nym_auth: 'nym_auth attestation',
  zkp: 'Zero-knowledge proof',
}

/** "+0.45s": time since the previous step (the first shows +0.00s). */
export function stepDelta(at: number, prevAt: number | undefined) {
  return `+${((prevAt === undefined ? 0 : at - prevAt) / 1000).toFixed(2)}s`
}

/** The proof systems' names in the developer view (Peter, 2026-10-23: VegaMC, Longfellow, BBS);
 *  the rest of the site says Vega. */
export const DEV_NAMES: Record<string, string> = { 'vega-v1': 'VegaMC', 'longfellow-libzk-v1': 'Longfellow', 'bbs-cd-plugins-v0.1': 'BBS' }

/** The developer view's groups of proof systems, by the encoding they prove from. */
export const DEV_GROUPS = [
  { format: 'mso_mdoc', title: 'Circuits', systems: ['vega-v1', 'longfellow-libzk-v1'] },
  { format: 'bbs_cd', title: 'BBS', systems: ['bbs-cd-plugins-v0.1'] },
] as const

/** "VegaMC", "Longfellow", "BBS": a system's (circuit's or scheme's) short name. */
export function systemShort(id?: string): string {
  const e = id ? findSystem(id) : undefined
  return e ? (DEV_NAMES[e.proof_system] ?? e.label.split(' ')[0]!) : (id ?? '')
}

export function purposeText(p: DevSession['purpose']): string {
  if (p.kind === 'dev') return p.age === 'none' ? 'Pseudonym' : `Pseudonym with age proof ${AGE_OPTIONS.find((o) => o.id === p.age)?.label}`
  if (p.kind === 'signin') return `${p.intent === 'login' ? 'Log in' : 'Sign up'}${p.community ? `, age check for c/${p.community}` : ''}`
  if (p.kind === 'community') return `Join c/${p.community}`
  return `Age check for c/${p.community}`
}

const ACTIVE = new Set(['waiting', 'scanned', 'responded'])
const FAILED_TITLES: Record<string, string> = {
  expired: 'Session expired',
  cancelled: 'Request cancelled',
  denied: 'Not completed: access_denied',
  invalid_request: 'Not completed: invalid_request',
  invalid: 'Not completed: presentation refused',
  unavailable: 'Not completed: verifier unavailable',
}

export function eventsOf(s: DevSession): FlowEvent[] {
  const out: FlowEvent[] = []
  const push = (e: Omit<FlowEvent, 'id' | 'status'> & { status?: FlowEvent['status'] }) => out.push({ status: 'ok', ...e, id: String(out.length) })
  const active = ACTIVE.has(s.status)
  const has = (step: string) => s.trace.some((t) => t.step === step)
  const qr = new URLSearchParams(s.authorizationUrl.slice(s.authorizationUrl.indexOf('?') + 1))

  s.trace.forEach((t, i) => {
    const d = t.data ?? {}
    const next = s.trace[i + 1]
    switch (t.step) {
      case 'created':
        push({ at: t.at, actor: 'browser', to: 'backend', method: 'POST /api/vp/session', title: 'Create presentation request', plain: purposeText(s.purpose), payload: { purpose: d.purpose, ...(d.phone && { phone: d.phone }) } })
        push({ at: t.at, actor: 'backend', title: 'Build DCQL query (zkp_req)', tag: 'openid', plain: 'One zkp_req query per source format the site accepts. The functions in _req are computed inside the proof; nothing is disclosed.', payload: s.dcql })
        push({ at: t.at, actor: 'backend', title: 'Declare vp_formats_supported.zkp_req', tag: 'openid', plain: 'The proof systems and approved system ids the site accepts now (/tech).', payload: { vp_formats_supported: d.offer } })
        push({ at: t.at, actor: 'backend', title: 'Make response encryption key', plain: 'An ephemeral ECDH-ES P-256 key for this session. The wallet encrypts its response to it.', payload: { jwk: d.response_key } })
        push({ at: t.at, actor: 'backend', to: 'browser', method: '200 OK', title: 'Session created', payload: { id: s.id, authorization_url: s.authorizationUrl } })
        push({
          at: t.at,
          actor: 'browser',
          title: 'Show QR code, wait for wallet',
          plain: 'Scan with the SIROS ID wallet',
          status: active && !has('request') ? 'pending' : 'ok',
          payload: { qr: s.authorizationUrl, decoded: { scheme: 'openid4vp://', client_id: qr.get('client_id'), request_uri: qr.get('request_uri'), request_uri_method: qr.get('request_uri_method') } },
        })
        break
      case 'phone':
        push({ at: t.at, actor: 'browser', title: t.label, status: 'info' })
        break
      case 'offer':
        push({ at: t.at, actor: 'backend', title: 'Offer updated', plain: 'The accepted proof systems changed since the QR code was shown.', payload: d })
        break
      case 'request':
        push({ at: t.at, actor: 'wallet', to: 'backend', method: 'POST request_uri', title: 'Fetch request + wallet_metadata', tag: 'openid', plain: 'The wallet scanned the code and says which proof systems it runs.', payload: { wallet_metadata: d.wallet_metadata } })
        push({
          at: t.at,
          actor: 'backend',
          title: 'Sign request object (JAR)',
          plain: d.tailored ? 'Tailored to the systems both sides support, then signed with the access certificate key.' : 'Signed with the access certificate key.',
          payload: { offered: d.offered, sent: d.sent, tailored: d.tailored },
        })
        push({ at: t.at, actor: 'backend', to: 'wallet', method: '200 OK', title: 'Signed request object', payload: { bytes: d.bytes, header: s.requestJwsHeader, payload: s.request } })
        break
      case 'refused':
        push({ at: t.at, actor: 'backend', title: t.label, status: 'error', payload: d })
        break
      case 'wallet.authenticate':
        push({ at: t.at, actor: 'wallet', title: 'Authenticate verifier', plain: 'Checks the request signature and that the certificate names the client_id host. Fixes verifier_id.', payload: d })
        break
      case 'wallet.match': {
        const ok = !d.reason && t.label === 'nym_auth attestation matched'
        push({
          at: t.at,
          actor: 'wallet',
          title: ok ? 'Match nym_auth attestation' : t.label,
          tag: 'nym_auth',
          status: ok ? 'ok' : 'error',
          plain: ok ? `The query matches the attestation on this phone. The wallet picks ${systemShort(d.system_id)}, an approved system the site offered.` : (d.reason ?? 'The holder\'s data does not meet the request.'),
          payload: d,
        })
        if (ok) {
          const answered = s.trace.slice(i + 1).some((x) => x.step === 'wallet.consent' || x.step === 'wallet.decline')
          push({ at: t.at, actor: 'wallet', title: 'Holder reviews request', plain: 'Approve or decline on the phone.', status: answered || !active ? 'ok' : 'pending' })
        }
        break
      }
      case 'wallet.consent':
        push({ at: t.at, actor: 'wallet', title: 'Holder approved', plain: 'Then any 6-digit PIN unlocks the device key.', payload: d })
        break
      case 'wallet.decline':
        push({ at: t.at, actor: 'wallet', title: 'Holder declined', status: 'error', payload: d })
        break
      case 'sign':
        push({
          at: t.at,
          actor: 'wallet',
          title: d.error ? 'Device key did not sign' : 'Device key signs',
          status: d.error ? 'error' : 'ok',
          plain: 'ECDSA over DeviceAuthentication: the session transcript, with the encryption key\'s thumbprint in the handover.',
          payload: d,
        })
        break
      case 'witness':
        push({ at: t.at, actor: 'wallet', title: 'Build witness', tag: 'zkp', plain: 'The private inputs of the circuit, from the credential and the seed.', payload: d })
        break
      case 'prove':
        push({
          at: t.at,
          actor: 'wallet',
          title: d.error ? `${t.label} (${systemShort(d.system_id)})` : `Generate ZK proof (${systemShort(d.system_id)})`,
          tag: 'zkp',
          status: d.error ? 'error' : 'ok',
          plain:
            d.format === 'bbs_cd'
              ? 'A BBS proof over committed attributes, with the pseudonym, date-range and ecdsa-pop plugins.'
              : 'The circuit proves the issuer signature, the pseudonym derivation and the date predicate in zero knowledge.',
          payload: d,
        })
        break
      case 'wallet.encrypt':
        push({ at: t.at, actor: 'wallet', title: 'Encrypt response', plain: `JWE (${d.header?.alg}, ${d.header?.enc}) to the site's session key.`, payload: d })
        break
      case 'decrypt': {
        const error = next?.step === 'response' ? next.data?.error : undefined
        push({
          at: t.at,
          actor: 'wallet',
          to: 'backend',
          method: 'POST response_uri',
          title: error ? 'Send error response' : 'Send response (ZkpPresentation)',
          tag: error ? undefined : 'openid',
          plain: error ? `error=${error}, encrypted (direct_post.jwt).` : 'Each vp_token entry is a CBOR ZkpPresentation, sent encrypted (direct_post.jwt).',
          status: error ? 'error' : 'ok',
          payload: { 'content-type': 'application/x-www-form-urlencoded', response: `JWE, ${d.bytes} characters`, header: d.header },
        })
        push({
          at: t.at,
          actor: 'backend',
          title: 'Decrypt response',
          plain: `With the session's private key, in ${d.decrypt_ms} ms.`,
          payload: error
            ? { error, state: '…' }
            : { vp_token: { [s.answered ?? next?.data?.query ?? 'query']: [s.response?.presentation?.base64url ?? '…'] }, state: '…', ZkpPresentation: s.response?.presentation?.decoded },
        })
        break
      }
      case 'response':
        if (s.trace[i - 1]?.step === 'decrypt') break
        push({ at: t.at, actor: 'wallet', to: 'backend', method: 'POST response_uri', title: d.error ? 'Send error response (unencrypted)' : t.label, status: d.error ? 'error' : 'ok', payload: d })
        break
      case 'verify':
        push({
          at: t.at,
          actor: 'backend',
          title: `Verify ZK proof (${systemShort(d.system_id ?? s.trace.find((x) => x.step === 'prove')?.data?.system_id)})`,
          tag: 'zkp',
          status: d.code ? 'error' : 'ok',
          plain: d.code ? `Refused: ${d.code}${d.input ? ` (${d.input})` : ''}. ${d.reason ?? ''}` : 'The verifier checks the proof against a statement it computes itself.',
          payload: d,
        })
        break
      case 'failed':
        push({ at: t.at, actor: 'backend', title: FAILED_TITLES[d.reason] ?? `Not completed: ${d.reason}`, status: 'error', payload: d })
        break
      case 'completed':
        push({
          at: t.at,
          actor: 'backend',
          to: 'browser',
          method: 'POST complete',
          title: d.ok ? 'Result delivered' : 'Result: not applied',
          status: d.ok ? 'ok' : 'error',
          plain: d.ok ? `${d.kind === 'created' ? 'Account created' : 'Logged in'}: u/${d.handle}${d.age ? ', age range recorded' : ''}` : d.kind,
          payload: d,
        })
        break
      default:
        push({ at: t.at, actor: t.step.startsWith('wallet.') ? 'wallet' : 'backend', title: t.label, payload: d })
    }
  })

  // The step that runs now, until its result is in the trace.
  const last = s.trace.at(-1)?.at ?? s.createdAt
  if (s.status === 'scanned' && has('wallet.consent') && !has('prove')) push({ at: last, actor: 'wallet', title: 'Generate ZK proof', tag: 'zkp', status: 'pending' })
  if (s.status === 'responded' && !has('verify')) push({ at: last, actor: 'backend', title: 'Verify ZK proof', tag: 'zkp', status: 'pending' })
  return out
}

/** The verifier's checks of the response, from the session's trace. A refusal fails the check
 *  its code belongs to; the ones after it did not run. */
export function checksOf(s: DevSession): Check[] {
  const verify = s.trace.find((t) => t.step === 'verify')?.data
  const decrypt = s.trace.find((t) => t.step === 'decrypt')?.data
  if (!decrypt && !verify) return []
  const mdoc = s.outcome?.ok ? s.outcome.format === 'mso_mdoc' : s.answered !== 'nym_attestation_bbs'
  const system = verify?.system_id ?? (s.outcome?.ok ? s.outcome.proofId : undefined)
  const list: Array<Check & { codes: string[] }> = [
    { label: 'Response decrypted', detail: `JWE (${decrypt?.header?.alg ?? 'ECDH-ES'}, ${decrypt?.header?.enc ?? 'A128GCM'}) to the session key`, status: 'pending', codes: [] },
    { label: 'Session matches', detail: 'state is this session\'s', status: 'pending', codes: [] },
    { label: 'Presentation decodes', detail: 'one ZkpPresentation for one of the queries', status: 'pending', codes: ['vp_token', 'presentation', 'proof_encoding'] },
    { label: 'Approved system', detail: `${system ?? 'the system'} is in the registry, was offered, and is still accepted`, status: 'pending', codes: ['scheme', 'circuit', 'format'] },
    {
      label: 'Issuer key set trusted',
      detail: mdoc ? 'Document Signer certificates of trusted issuers (issuer hidden in the set)' : 'the trusted BBS issuer key (issuer visible)',
      status: 'pending',
      codes: ['issuer_key_set', 'public_input:issuer_key_set'],
    },
    ...(mdoc ? [{ label: 'proof_time within tolerance', detail: 'against the verifier clock', status: 'pending' as const, codes: ['proof_time', 'public_input:proof_time'] }] : []),
    { label: 'Statement assembled by verifier', detail: 'verifier_input, the handover with the key thumbprint, and the _req parameters, computed here', status: 'pending', codes: ['request'] },
    { label: `ZK proof verifies${system ? ` (${systemShort(system)})` : ''}`, detail: 'against the verifier\'s statement', status: 'pending', codes: ['proof_invalid', 'public_input'] },
    { label: 'Results match request', detail: 'the results keys are the return handles', status: 'pending', codes: ['results'] },
  ]
  if (verify?.issuer_added) list[4]!.detail = `a new issuer, trusted from now on: ${verify.issuer_added}`
  const code = verify?.code ? (verify.input ? `${verify.code}:${verify.input}` : verify.code) : undefined
  if (decrypt) list[0]!.status = list[1]!.status = 'pass'
  if (!verify) {
    if (s.status === 'responded') list[2]!.status = 'running'
    return list.map(({ codes: _c, ...c }) => c)
  }
  let failedAt = -1
  if (code) {
    failedAt = list.findIndex((c) => c.codes.includes(code))
    if (failedAt < 0) failedAt = list.findIndex((c) => c.codes.includes(String(verify.code)))
    if (failedAt < 0) failedAt = list.findIndex((c) => c.label.startsWith('ZK proof'))
  }
  list.forEach((c, k) => {
    if (k < 2) return
    c.status = failedAt < 0 || k < failedAt ? 'pass' : k === failedAt ? 'fail' : 'pending'
    if (k === failedAt) c.detail = `${verify.code}${verify.input ? ` (${verify.input})` : ''}: ${verify.reason}`
  })
  return list.map(({ codes: _c, ...c }) => c)
}
