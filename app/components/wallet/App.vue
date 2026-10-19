<script setup lang="ts">
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import type { WalletTransport } from '~/wallet/transport'
import type { ConsentView, RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import type { ProofMetrics, WalletScreen } from '~/composables/useFlow'
import type { ProveOutput } from '~/wallet/prover'
import { analyzeRequest, consentFor, parseAuthorizationUrl } from '~/wallet/engine'
import { TransportError, httpTransport } from '~/wallet/transport'
import { loadCredentials, nymCard } from '~/wallet/holder'
import { ProverError, prove, unlockAndSign } from '~/wallet/prover'
import { findCircuit } from '#shared/registry/circuits'

/**
 * The SIROS ID wallet on the phone (mocked screens, real protocol). Drives the holder side of
 * OpenID4VP: scan -> POST request_uri with wallet_metadata -> verify the signed request -> check
 * it and pick a circuit -> consent -> PIN -> native steps (sign, witness and prove) -> POST response_uri.
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
    transport?: WalletTransport
  }>(),
  { transport: () => httpTransport },
)
/** Close on the success screen: the person is done on the phone and goes back to the site. */
const emit = defineEmits<{ finished: [] }>()

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
const credentials = ref<CredentialView[] | null>(null)
/** The credential in focus: the one whose details are open, or the one the request uses. */
const focus = ref(0)
/** The credential shown on the home screen or opened last; the next request starts with it. */
const selected = useState('siros-selected', () => 0)
/** The credentials that match the current request's document type, and the "Switch credential" popup. */
const matching = ref<CredentialView[]>([])
const switching = ref(false)
const verifierSubject = ref('')
const circuitIds = ref<string[] | null>(null)
const detected = ref(false)
const error = ref<{ title: string; description: string; cause?: string } | null>(null)
const workingTitle = ref('')
const metrics = ref<ProofMetrics | null>(null)
const sentError = ref<'access_denied' | 'invalid_request' | null>(null)
const declinedAt = ref<'request' | 'pin' | null>(null)
const today = useToday()
/** Presentations made from this page, per credential, for Recent History and Presentations. */
const history = useState<Array<{ audience: string; at: number; credential: number }>>('siros-history', () => [])
const current = computed(() => credentials.value?.[focus.value] ?? null)
const alternatives = computed(() => matching.value.filter((c) => c.index !== focus.value))
const timers: Array<ReturnType<typeof setTimeout>> = []
let alive = true

const flow = useWalletFlow()
watchEffect(() => {
  flow.value = {
    screen: screen.value,
    credential: current.value,
    matching: matching.value.length,
    switching: switching.value,
    walletCircuits: circuitIds.value ?? [],
    view: view.value,
    consent: consent.value,
    metrics: metrics.value,
    sentError: sentError.value,
    declinedAt: declinedAt.value,
    error: error.value,
  }
})

/** The credential and the circuits this wallet runs; tried again at the next scan when it failed. */
async function prepare(): Promise<boolean> {
  try {
    credentials.value ??= await loadCredentials()
    circuitIds.value ??= (await $fetch<{ circuits: Array<{ circuit_id: string }> }>('/api/wallet/capabilities')).circuits.map((c) => c.circuit_id)
    return true
  } catch (e) {
    const status = (e as { statusCode?: number }).statusCode
    if (alive) fail(ERRORS.connection, `/api/wallet/capabilities ${status ?? 'no answer'}`)
    return false
  }
}
onMounted(prepare)

function walletMetadata(): WalletMetadata {
  const ids = circuitIds.value ?? []
  const systems = [...new Set(ids.map((id) => findCircuit(id)?.proof_system).filter(Boolean) as string[])]
  return { vp_formats_supported: { circuit_zk: { circuit_proof_system_values: systems, circuit_id_values: ids } } }
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
  try {
    const verified = await props.transport.fetchRequest({
      requestUri: parsed.requestUri,
      method: parsed.method,
      clientId: parsed.clientId,
      walletMetadata: walletMetadata(),
    })
    request.value = verified.request
    verifierSubject.value = verified.signer.subject
    // Every credential of the requested document type matches; the one selected on the home
    // screen is used (else the first), and the request screen offers the others ("Switch credential").
    const doctype = verified.request.dcql_query?.credentials?.[0]?.meta?.doctype_value
    matching.value = credentials.value!.filter((c) => c.docType === doctype)
    focus.value = matching.value.find((c) => c.index === selected.value)?.index ?? matching.value[0]?.index ?? 0
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
  view.value = analyzeRequest(request.value!, cred, today.value, circuitIds.value ?? [])
  consent.value = view.value.satisfiable ? await consentFor(view.value, cred, verifierSubject.value) : null
  screen.value = view.value.satisfiable ? 'request' : 'unmet'
}

/** "Switch credential": the request is checked again against the chosen credential. */
async function choose(index: number) {
  switching.value = false
  focus.value = index
  await analyze()
}

/** Posts to response_uri; a refusal there ends on the matching error screen (410: Request Expired). */
async function send(body: AuthorizationResponse): Promise<boolean> {
  try {
    await props.transport.postResponse(request.value!.response_uri, body)
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
  if (!(await send({ state: request.value!.state, error: code }))) return
  sentError.value = code
  declinedAt.value = at
  screen.value = next
}

function toPin() {
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
  let out: ProveOutput
  try {
    const signed = await unlockAndSign({ request: req, credential: focus.value })
    metrics.value = { sign_ms: signed.metrics.sign_ms }
    out = await prove({ request: req, circuitId: view.value!.circuit!.circuit_id, deviceSignature: signed.device_signature, credential: focus.value })
    metrics.value = {
      ...metrics.value,
      witness_ms: out.witness_ms ?? out.metrics.witness_ms,
      prove_ms: out.metrics.prove_ms,
      proof_bytes: out.metrics.proof_bytes,
      presentation_bytes: out.metrics.presentation_bytes,
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
  if (!(await send({ state: req.state, vp_token: { [req.dcql_query.credentials[0]!.id]: [out.presentation] } }))) return
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
  <PhoneFrame>
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
          :selected="selected"
          @select="selected = $event"
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
