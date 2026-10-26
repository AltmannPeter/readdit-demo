<script setup lang="ts">
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import type { WalletTransport } from '~/wallet/transport'
import type { ConsentView, RequestView, WalletCaps } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import type { ProofMetrics, WalletScreen } from '~/composables/useFlow'
import type { ProveOutput } from '~/wallet/prover'
import { analyzeRequest, consentFor, parseAuthorizationUrl, queryFor } from '~/wallet/engine'
import { TransportError, encryptResponse, httpTransport } from '~/wallet/transport'
import { report } from '~/wallet/report'
import { loadCredentials, nymCard, type PhoneDef } from '~/wallet/holder'
import { ProverError, prove, proveBbs, unlockAndSign } from '~/wallet/prover'
import { findSystem } from '#shared/registry/circuits'

/**
 * The SIROS ID wallet on the phone (mocked screens, real protocol). Drives the holder side of
 * OpenID4VP: scan -> POST request_uri with wallet_metadata -> verify the signed request -> check
 * it and pick a system (a circuit or a scheme) -> consent -> PIN -> native steps -> POST
 * response_uri. The native steps: for the mdoc (mso_mdoc) sign, then witness and prove; for the
 * BBS credential (bbs_cd) one prove, in which the device key signs.
 * It publishes its state for the guide panel (useWalletFlow).
 *
 * It answers response_uri when the person declines and when the rulebook asks for an Error
 * Response (requirement not met, unsupported request). When it stops on its own error (an
 * untrusted or expired request, a failed native step) it sends nothing, as the SIROS ID wallet
 * does; the site's request then ends when it expires or when the site closes it.
 */
const props = withDefaults(
  defineProps<{
    /** What the camera sees: the openid4vp:// URL in the QR code on screen. */
    url: string | null
    /** The phone this wallet runs on: its credentials, its history, its selected card. */
    phone: PhoneDef
    transport?: WalletTransport
    /** Start scanning the code on screen at once (the developer view's Simulate scan). */
    autoScan?: boolean
  }>(),
  { transport: () => httpTransport, autoScan: false },
)
/** Close on the success screen: the person is done on the phone and goes back to the site. */
const emit = defineEmits<{ finished: []; scanned: [] }>()

// Titles and descriptions from the SIROS ID wallet's English strings (src/locales/en.json).
const ERRORS = {
  connection: { title: 'Connection Error', description: 'The connection to the wallet service was lost. Please try again.' }, // openIdCallback.errorCodes.WEBSOCKET_ERROR
  qr: { title: 'Unsupported QR code', description: 'This QR code is not supported by the wallet. Please scan a credential offer or presentation request.' }, // qrCodeScanner.unsupported*
  expired: { title: 'Request Expired', description: 'This request has expired. Please start again.' }, // FLOW_EXPIRED
  invalid: { title: 'Invalid Request', description: 'The presentation request is invalid and cannot be processed.' }, // INVALID_REQUEST
  network: { title: 'Network Error', description: 'A network error occurred while sharing your credentials. Please try again.' }, // HTTP_ERROR
  untrusted: { title: 'Verifier is not Trusted', description: 'Verifier did not provide valid data for verification.' }, // UNTRUSTED_VERIFIER
  response: { title: 'Response Error', description: 'An error occurred while sending the presentation response.' }, // RESPONSE_ERROR
  signing: { title: 'Signing Failed', description: 'The wallet could not create a signed presentation. Please try again.' }, // SIGNING_FAILED
} as const
type WalletError = (typeof ERRORS)[keyof typeof ERRORS]

const screen = ref<WalletScreen>('home')
const request = ref<RequestObject | null>(null)
const view = ref<RequestView | null>(null)
const consent = ref<ConsentView | null>(null)
/** This phone's credentials (CredentialView.index points into holders). */
const credentials = ref<CredentialView[] | null>(null)
/** The credential in focus (its index): the one whose details are open, or the one the request uses. */
const focus = ref(props.phone.credentials[0] ?? 0)
/** The credential shown on the home screen or opened last; the next request starts with it. */
const selected = useState(`siros-selected-${props.phone.id}`, () => props.phone.credentials[0] ?? 0)
/** The credentials that match one of the current request's credential queries, and the "Switch credential" popup. */
const matching = ref<CredentialView[]>([])
const switching = ref(false)
const verifierSubject = ref('')
const caps = ref<WalletCaps | null>(null)
const detected = ref(false)
const error = ref<{ title: string; description: string; cause?: string } | null>(null)
const workingTitle = ref('')
const metrics = ref<ProofMetrics | null>(null)
const sentError = ref<'access_denied' | 'invalid_request' | null>(null)
const declinedAt = ref<'request' | 'pin' | null>(null)
const today = useToday()
/** Presentations made from this page, per credential, for Recent History and Presentations. */
const history = useState<Array<{ audience: string; at: number; credential: number }>>(`siros-history-${props.phone.id}`, () => [])
const current = computed(() => credentials.value?.find((c) => c.index === focus.value) ?? null)
/** The home screen's card position of the selected credential, and back. */
const selectedPosition = computed(() => Math.max(0, credentials.value?.findIndex((c) => c.index === selected.value) ?? 0))
const selectPosition = (k: number) => (selected.value = credentials.value?.[k]?.index ?? selected.value)
const alternatives = computed(() => matching.value.filter((c) => c.index !== focus.value))
const timers: Array<ReturnType<typeof setTimeout>> = []
let alive = true

const flow = useWalletFlow()
watchEffect(() => {
  flow.value = {
    phone: props.phone.label,
    screen: screen.value,
    credential: current.value,
    matching: matching.value.length,
    switching: switching.value,
    walletCircuits: phoneSystems().filter((id) => findSystem(id)?.source_format === 'mso_mdoc'),
    walletSchemes: phoneSystems().filter((id) => findSystem(id)?.source_format === 'bbs_cd'),
    view: view.value,
    consent: consent.value,
    metrics: metrics.value,
    sentError: sentError.value,
    declinedAt: declinedAt.value,
    error: error.value,
  }
})

/** The credentials and what this wallet can prove; tried again at the next scan when it failed. */
async function prepare(): Promise<boolean> {
  try {
    credentials.value ??= (await loadCredentials()).filter((c) => props.phone.credentials.includes(c.index))
    if (!caps.value) {
      const c = await $fetch<{ circuits?: Array<{ system_id: string }>; schemes?: Array<{ system_id: string }> }>('/api/wallet/capabilities')
      caps.value = { systemIds: [...(c.circuits ?? []), ...(c.schemes ?? [])].map((x) => x.system_id) }
    }
    return true
  } catch (e) {
    const status = (e as { statusCode?: number }).statusCode
    if (alive) fail(ERRORS.connection, `/api/wallet/capabilities ${status ?? 'no answer'}`)
    return false
  }
}
onMounted(async () => {
  if ((await prepare()) && props.autoScan && props.url && screen.value === 'home') startScan()
})

/** The systems this wallet can run for the source formats of the credentials on this phone. */
function phoneSystems(): string[] {
  const formats = new Set(credentials.value?.map((c) => c.format) ?? [])
  return (caps.value?.systemIds ?? []).filter((id) => {
    const f = findSystem(id)?.source_format
    return !!f && formats.has(f)
  })
}

/** wallet_metadata: those systems and their proof systems, in zkp_req. */
function walletMetadata(): WalletMetadata {
  const ids = phoneSystems()
  const encryption = { authorization_encryption_alg_values_supported: ['ECDH-ES'], authorization_encryption_enc_values_supported: ['A128GCM', 'A256GCM'] }
  if (!ids.length) return { vp_formats_supported: {}, ...encryption }
  return { vp_formats_supported: { zkp_req: { proof_system_values: [...new Set(ids.map((id) => findSystem(id)!.proof_system))], system_id_values: ids } }, ...encryption }
}

function fail(e: WalletError, cause?: string) {
  error.value = { ...e, ...(cause && { cause }) }
  screen.value = 'error'
}

function startScan() {
  screen.value = 'scan'
  detected.value = false
  timers.push(
    setTimeout(() => {
      if (screen.value !== 'scan') return
      detected.value = true
      timers.push(setTimeout(onScanned, 500))
    }, 1500),
  )
}

function cancelScan() {
  timers.forEach(clearTimeout)
  screen.value = 'home'
}

/** The wallet error for a refused request_uri: 410 (used, expired or cancelled), 404, or another status. */
function requestUriError(e: TransportError): WalletError {
  if (e.status === 410) return ERRORS.expired
  if (e.status === 404 || e.status === 400) return ERRORS.invalid
  return ERRORS.network
}

async function onScanned() {
  if (screen.value !== 'scan') return
  if (!(await prepare())) return
  const parsed = props.url ? parseAuthorizationUrl(props.url) : null
  if (!parsed) return fail(ERRORS.qr, props.url ? 'not an openid4vp:// request' : 'no QR code on screen')
  // Before the fetch: the site tells this phone's scan from a real phone's by it.
  emit('scanned')
  try {
    const verified = await props.transport.fetchRequest({
      requestUri: parsed.requestUri,
      method: parsed.method,
      clientId: parsed.clientId,
      walletMetadata: walletMetadata(),
    })
    request.value = verified.request
    verifierSubject.value = verified.signer.subject
    await report(verified.request.state, 'authenticate', 'Verifier authenticated', {
      client_id: verified.request.client_id,
      certificate: verified.signer.subject,
      checks: ['ES256 signature by the x5c leaf', 'dNSName SAN equals the client_id host', 'client_id matches the QR code'],
    })
    // Every credential that fits one of the request's queries (format and document type or
    // schema) matches; the one selected on the home screen is used, else the first in the
    // request's order of preference, and the request screen offers the others ("Switch credential").
    const order = verified.request.dcql_query?.credentials ?? []
    const rank = (c: CredentialView) => order.findIndex((q) => q === queryFor(verified.request, c))
    matching.value = credentials.value!.filter((c) => rank(c) >= 0).sort((a, b) => rank(a) - rank(b))
    focus.value = matching.value.find((c) => c.index === selected.value)?.index ?? matching.value[0]?.index ?? credentials.value![0]?.index ?? 0
    await analyze()
  } catch (e) {
    // An HTTP refusal from request_uri; anything else concerns the request's signature or certificate.
    if (e instanceof TransportError) fail(requestUriError(e), e.message)
    else if (e instanceof TypeError) fail(ERRORS.network, `request_uri: ${e.message}`)
    else fail(ERRORS.untrusted, (e as Error).message)
  }
}

/** The request against the chosen credential: the request screen, or Requirement Not Met. */
async function analyze() {
  const cred = current.value!
  view.value = analyzeRequest(request.value!, cred, today.value, caps.value ?? { systemIds: [] })
  consent.value = view.value.satisfiable ? await consentFor(view.value, cred, verifierSubject.value) : null
  screen.value = view.value.satisfiable ? 'request' : 'unmet'
  const v = view.value
  await report(request.value!.state, 'match', v.satisfiable ? 'nym_auth attestation matched' : v.problem === 'age' ? 'Attestation does not meet the age range' : 'Request not supported', {
    credential: cred.docType,
    format: cred.format,
    ...(v.query && { query: v.query.id }),
    ...(v.system && { system_id: v.system.system_id, proof_system: v.system.proof_system }),
    ...(v.reason && { reason: v.reason }),
    response_mode: request.value!.response_mode,
  })
}

/** "Switch credential": the request is checked again against the chosen credential, which the
 *  next request starts with too. */
async function choose(index: number) {
  switching.value = false
  focus.value = index
  selected.value = index
  await analyze()
}

/** Encrypts the response (direct_post.jwt) and posts it to response_uri; a refusal there ends on
 *  the matching error screen (410: Request Expired). */
async function send(body: AuthorizationResponse): Promise<boolean> {
  try {
    const req = request.value!
    const encrypted = await encryptResponse(req, body)
    if (encrypted) {
      await report(req.state, 'encrypt', 'Response encrypted', { header: encrypted.header, bytes: encrypted.jwe.length, encrypt_ms: encrypted.encrypt_ms, payload: 'error' in body ? ['error', 'state'] : ['vp_token', 'state'], ...('error' in body && { error: body.error }) })
    }
    await props.transport.postResponse(req, body, encrypted)
    return true
  } catch (e) {
    if (e instanceof TransportError) fail(e.status === 410 ? ERRORS.expired : ERRORS.response, e.message)
    else fail(ERRORS.response, `response_uri: ${(e as Error).message}`)
    return false
  }
}

/**
 * Rulebook: data-dependent failure or decline -> access_denied without description;
 * a cause independent of holder data may use invalid_request.
 */
async function refuse(next: WalletScreen, at: 'request' | 'pin' | null = null) {
  const independent = view.value?.problem === 'unsupported' || view.value?.problem === 'no_circuit'
  const code = independent ? 'invalid_request' : 'access_denied'
  if (at) await report(request.value!.state, 'decline', 'Holder declined', { at })
  if (!(await send({ state: request.value!.state, error: code }))) return
  sentError.value = code
  declinedAt.value = at
  screen.value = next
}

function toPin() {
  void report(request.value?.state, 'consent', 'Holder approved', { fields: consent.value?.fields.map((f) => f.name) })
  screen.value = 'pin'
}

/** How long the progress screen stays up at least, and the completion status after the last step. */
const MIN_PROGRESS_MS = 1500
const MIN_COMPLETED_MS = 600
const wait = (ms: number) => new Promise((r) => timers.push(setTimeout(r, ms)))

/** The PIN screen unlocked the wallet; any PIN does in this demo, and none leaves the phone. */
async function onPin() {
  const req = request.value!
  const host = view.value!.verifierHost
  const shownAt = Date.now()
  screen.value = 'working'
  workingTitle.value = 'Creating presentation...'
  metrics.value = null
  const queryId = view.value!.query!.id
  let presentation: string
  try {
    if (view.value!.scheme) {
      const out = await proveBbs({ request: req, queryId, credential: focus.value })
      const { prove_ms, presentation_bytes, ...bbs } = out.metrics
      metrics.value = { sign_ms: bbs.device_sign_ms, prove_ms, presentation_bytes, bbs }
      presentation = out.presentation
    } else {
      const systemId = view.value!.circuit!.system_id
      const signed = await unlockAndSign({ request: req, credential: focus.value, systemId })
      metrics.value = { sign_ms: signed.metrics.sign_ms }
      const out: ProveOutput = await prove({ request: req, queryId, systemId, deviceSignature: signed.device_signature, credential: focus.value })
      metrics.value = {
        ...metrics.value,
        witness_ms: out.witness_ms ?? out.metrics.witness_ms,
        prove_ms: out.metrics.prove_ms,
        proof_bytes: out.metrics.proof_bytes,
        presentation_bytes: out.metrics.presentation_bytes,
      }
      presentation = out.presentation
    }
  } catch (e) {
    const code = (e as Error).message
    const cause = e instanceof ProverError ? e.cause : undefined
    if (code === 'unsatisfiable') {
      view.value = { ...view.value!, satisfiable: false, problem: 'age' }
      screen.value = 'unmet'
    } else {
      fail(code === 'unavailable' ? ERRORS.connection : ERRORS.signing, cause)
    }
    return
  }
  workingTitle.value = 'Sending response...'
  if (!(await send({ state: req.state, vp_token: { [queryId]: [presentation] } }))) return
  workingTitle.value = 'Presentation sent successfully'
  history.value = [{ audience: host, at: Date.now(), credential: focus.value }, ...history.value]
  await wait(Math.max(MIN_COMPLETED_MS, MIN_PROGRESS_MS - (Date.now() - shownAt)))
  screen.value = 'done'
}

function reset() {
  request.value = null
  view.value = null
  consent.value = null
  matching.value = []
  switching.value = false
  screen.value = 'home'
}

function finish() {
  reset()
  emit('finished')
}

function openDetails(index: number) {
  focus.value = index
  selected.value = index
  screen.value = 'detail'
}

onBeforeUnmount(() => {
  alive = false
  timers.forEach(clearTimeout)
})
</script>

<template>
  <PhoneFrame :bezel="props.phone.bezel">
    <div class="sid-font relative h-full">
      <Transition
        mode="out-in"
        enter-active-class="transition duration-200 ease-out"
        enter-from-class="opacity-0 translate-x-3"
        leave-active-class="transition duration-150 ease-in"
        leave-to-class="opacity-0 -translate-x-3"
      >
        <WalletHome
          v-if="screen === 'home'"
          key="home"
          :credentials="credentials"
          :history="history"
          :selected="selectedPosition"
          @select="selectPosition"
          @scan="startScan"
          @open="openDetails"
        />
        <WalletDetail
          v-else-if="screen === 'detail' && current"
          key="detail"
          :credential="current"
          @back="screen = 'home'"
          @scan="startScan"
          @presentations="screen = 'presentations'"
        />
        <WalletPresentations
          v-else-if="screen === 'presentations'"
          key="presentations"
          :history="history.filter((h) => h.credential === focus)"
          @back="screen = 'detail'"
          @scan="startScan"
        />
        <WalletScan v-else-if="screen === 'scan'" key="scan" :url="url" :detected="detected" @cancel="cancelScan" />
        <WalletRequest
          v-else-if="screen === 'request' && consent"
          key="request"
          :consent="consent"
          :credential-title="current?.title ?? ''"
          :valid-until="current ? nymCard(current).validUntil : undefined"
          :alternatives="alternatives.length"
          @accept="toPin"
          @cancel="refuse('declined', 'request')"
          @switch="switching = true"
        />
        <WalletUnmet v-else-if="screen === 'unmet' && view" key="unmet" :view="view" :alternatives="alternatives.length" @close="refuse('home')" @switch="switching = true" />
        <WalletPin v-else-if="screen === 'pin' && view" key="pin" :verifier-name="view.verifierName" @done="onPin" @cancel="refuse('declined', 'pin')" />
        <WalletWorking v-else-if="screen === 'working'" key="working" :title="workingTitle" />
        <WalletOutcome
          v-else-if="screen === 'done'"
          key="done"
          kind="done"
          title="Success!"
          :text="`Your data has been shared with ${view?.verifierName}.`"
          @close="finish"
        />
        <WalletOutcome v-else-if="screen === 'declined'" key="declined" kind="declined" title="Sharing Cancelled" text="You cancelled sharing your credentials." @close="reset" />
        <WalletOutcome v-else key="error" kind="error" :title="error?.title ?? ''" :text="error?.description ?? ''" @close="reset" />
      </Transition>
      <WalletSwitch v-if="switching && current" :current="current" :alternatives="alternatives" @select="choose" @close="switching = false" />
    </div>
  </PhoneFrame>
</template>
