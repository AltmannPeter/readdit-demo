<script setup lang="ts">
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import type { WalletTransport } from '~/wallet/transport'
import type { ConsentView, RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import type { ProofMetrics, WalletScreen } from '~/composables/useFlow'
import type { ProveOutput } from '~/wallet/prover'
import { analyzeRequest, consentFor, parseAuthorizationUrl } from '~/wallet/engine'
import { httpTransport } from '~/wallet/transport'
import { loadCredential } from '~/wallet/holder'
import { prove, unlockAndSign } from '~/wallet/prover'
import { findCircuit } from '#shared/registry/circuits'

/**
 * The SIROS ID wallet on the phone (mocked screens, real protocol). Drives the holder side of
 * OpenID4VP: scan -> POST request_uri with wallet_metadata -> verify the signed request -> check
 * it and pick a circuit -> consent -> PIN -> native steps (sign, witness and prove) -> POST response_uri.
 * It publishes its state for the guide panel (useWalletFlow).
 */
const props = withDefaults(
  defineProps<{
    /** What the camera sees: the openid4vp:// URL in the QR code on screen. */
    url: string | null
    transport?: WalletTransport
  }>(),
  { transport: () => httpTransport },
)

// Titles and descriptions from the SIROS ID wallet's English strings (src/locales/en.json).
const ERRORS = {
  connection: { title: 'Connection Error', description: 'The connection to the wallet service was lost. Please try again.' }, // openIdCallback.errorCodes.WEBSOCKET_ERROR
  qr: { title: 'Unsupported QR code', description: 'This QR code is not supported by the wallet. Please scan a credential offer or presentation request.' }, // qrCodeScanner.unsupported*
  expired: { title: 'Request Expired', description: 'This request has expired. Please start again.' }, // FLOW_EXPIRED
  network: { title: 'Network Error', description: 'A network error occurred while sharing your credentials. Please try again.' }, // HTTP_ERROR
  untrusted: { title: 'Verifier is not Trusted', description: 'Verifier did not provide valid data for verification.' }, // UNTRUSTED_VERIFIER
  response: { title: 'Response Error', description: 'An error occurred while sending the presentation response.' }, // RESPONSE_ERROR
  signing: { title: 'Signing Failed', description: 'The wallet could not create a signed presentation. Please try again.' }, // SIGNING_FAILED
} as const

const screen = ref<WalletScreen>('home')
const request = ref<RequestObject | null>(null)
const view = ref<RequestView | null>(null)
const consent = ref<ConsentView | null>(null)
const credential = ref<CredentialView | null>(null)
const circuitIds = ref<string[]>([])
const detected = ref(false)
const error = ref<{ title: string; description: string } | null>(null)
const pinError = ref('')
const pinKey = ref(0)
const workingTitle = ref('')
const metrics = ref<ProofMetrics | null>(null)
const sentError = ref<'access_denied' | 'invalid_request' | null>(null)
const today = useToday()
/** Presentations made from this page, for the home screen's Recent History. */
const history = useState<Array<{ audience: string; at: number }>>('siros-history', () => [])
const timers: Array<ReturnType<typeof setTimeout>> = []

const flow = useWalletFlow()
watchEffect(() => {
  flow.value = {
    screen: screen.value,
    pinRejected: !!pinError.value,
    walletCircuits: circuitIds.value,
    view: view.value,
    consent: consent.value,
    metrics: metrics.value,
    sentError: sentError.value,
    error: error.value,
  }
})

onMounted(async () => {
  try {
    const [cred, caps] = await Promise.all([loadCredential(), $fetch<{ circuits: Array<{ circuit_id: string }> }>('/api/wallet/capabilities')])
    credential.value = cred
    circuitIds.value = caps.circuits.map((c) => c.circuit_id)
  } catch {
    fail(ERRORS.connection)
  }
})

function walletMetadata(): WalletMetadata {
  const systems = [...new Set(circuitIds.value.map((id) => findCircuit(id)?.proof_system).filter(Boolean) as string[])]
  return { vp_formats_supported: { circuit_zk: { circuit_proof_system_values: systems, circuit_id_values: circuitIds.value } } }
}

function fail(e: { title: string; description: string }) {
  error.value = e
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

async function onScanned() {
  if (screen.value !== 'scan' || !credential.value) return
  const parsed = props.url ? parseAuthorizationUrl(props.url) : null
  if (!parsed) return fail(ERRORS.qr)
  try {
    const verified = await props.transport.fetchRequest({
      requestUri: parsed.requestUri,
      method: parsed.method,
      clientId: parsed.clientId,
      walletMetadata: walletMetadata(),
    })
    request.value = verified.request
    view.value = analyzeRequest(verified.request, credential.value, today.value, circuitIds.value)
    if (view.value.satisfiable) {
      consent.value = await consentFor(view.value, credential.value, verified.signer.subject)
      screen.value = 'request'
    } else {
      screen.value = 'unmet'
    }
  } catch (e) {
    // The transport reports an HTTP failure as "request_uri <status>"; anything else concerns the
    // request's signature or certificate.
    const status = /^request_uri (\d+)$/.exec((e as Error).message)?.[1]
    fail(status === '410' ? ERRORS.expired : status ? ERRORS.network : ERRORS.untrusted)
  }
}

async function send(body: AuthorizationResponse) {
  await props.transport.postResponse(request.value!.response_uri, body)
}

/**
 * Rulebook: data-dependent failure or decline -> access_denied without description;
 * a cause independent of holder data may use invalid_request.
 */
async function refuse(next: WalletScreen) {
  const independent = view.value?.problem === 'unsupported' || view.value?.problem === 'no_circuit'
  const code = independent ? 'invalid_request' : 'access_denied'
  try {
    await send({ state: request.value!.state, error: code })
    sentError.value = code
    screen.value = next
  } catch {
    fail(ERRORS.response)
  }
}

function toPin() {
  pinError.value = ''
  pinKey.value++
  screen.value = 'pin'
}

/** How long the progress screen stays up at least, and the completion status after the last step. */
const MIN_PROGRESS_MS = 1500
const MIN_COMPLETED_MS = 600
const wait = (ms: number) => new Promise((r) => timers.push(setTimeout(r, ms)))

async function onPin(pin: string) {
  const req = request.value!
  const host = view.value!.verifierHost
  const shownAt = Date.now()
  screen.value = 'working'
  workingTitle.value = 'Creating presentation...'
  metrics.value = null
  let out: ProveOutput
  try {
    const signed = await unlockAndSign({ request: req, pin })
    metrics.value = { sign_ms: signed.metrics.sign_ms, simulated: signed.metrics.simulated }
    out = await prove({ request: req, circuitId: view.value!.circuit!.circuit_id, deviceSignature: signed.device_signature })
    metrics.value = {
      ...metrics.value,
      witness_ms: out.witness_ms ?? out.metrics.witness_ms,
      prove_ms: out.metrics.prove_ms,
      proof_bytes: out.metrics.proof_bytes,
      presentation_bytes: out.metrics.presentation_bytes,
      simulated: out.metrics.simulated || signed.metrics.simulated,
    }
  } catch (e) {
    const code = (e as Error).message
    if (code === 'invalid_pin') {
      pinError.value = 'You have entered an incorrect pin'
      pinKey.value++
      screen.value = 'pin'
    } else if (code === 'unsatisfiable') {
      view.value = { ...view.value!, satisfiable: false, problem: 'age' }
      screen.value = 'unmet'
    } else {
      fail(code === 'unavailable' ? ERRORS.connection : ERRORS.signing)
    }
    return
  }
  try {
    workingTitle.value = 'Sending response...'
    await send({ state: req.state, vp_token: { [req.dcql_query.credentials[0]!.id]: [out.presentation] } })
  } catch {
    return fail(ERRORS.response)
  }
  workingTitle.value = 'Presentation sent successfully'
  history.value = [{ audience: host, at: Date.now() }, ...history.value]
  await wait(Math.max(MIN_COMPLETED_MS, MIN_PROGRESS_MS - (Date.now() - shownAt)))
  screen.value = 'done'
}

function reset() {
  request.value = null
  view.value = null
  consent.value = null
  screen.value = 'home'
}

onBeforeUnmount(() => timers.forEach(clearTimeout))
</script>

<template>
  <PhoneFrame>
    <div class="sid-font h-full">
      <Transition
        mode="out-in"
        enter-active-class="transition duration-200 ease-out"
        enter-from-class="opacity-0 translate-x-3"
        leave-active-class="transition duration-150 ease-in"
        leave-to-class="opacity-0 -translate-x-3"
      >
        <WalletHome v-if="screen === 'home'" key="home" :credential="credential" :history="history" @scan="startScan" @open="screen = 'detail'" />
        <WalletDetail
          v-else-if="screen === 'detail' && credential"
          key="detail"
          :credential="credential"
          @back="screen = 'home'"
          @scan="startScan"
          @presentations="screen = 'presentations'"
        />
        <WalletPresentations v-else-if="screen === 'presentations'" key="presentations" :history="history" @back="screen = 'detail'" @scan="startScan" />
        <WalletScan v-else-if="screen === 'scan'" key="scan" :url="url" :detected="detected" @cancel="cancelScan" />
        <WalletRequest
          v-else-if="screen === 'request' && consent"
          key="request"
          :consent="consent"
          :credential-title="credential?.title ?? ''"
          @accept="toPin"
          @cancel="refuse('declined')"
        />
        <WalletUnmet v-else-if="screen === 'unmet' && view" key="unmet" :view="view" @close="refuse('home')" />
        <WalletPin
          v-else-if="screen === 'pin' && view"
          :key="`pin-${pinKey}`"
          :verifier-name="view.verifierName"
          :error="pinError"
          @input="pinError = ''"
          @done="onPin"
          @cancel="refuse('declined')"
        />
        <WalletWorking v-else-if="screen === 'working'" key="working" :title="workingTitle" />
        <WalletOutcome
          v-else-if="screen === 'done'"
          key="done"
          kind="done"
          title="Success!"
          :text="`Your data has been shared with ${view?.verifierName}.`"
          @close="reset"
        />
        <WalletOutcome v-else-if="screen === 'declined'" key="declined" kind="declined" title="Sharing Cancelled" text="You cancelled sharing your credentials." @close="reset" />
        <WalletOutcome v-else key="error" kind="error" :title="error?.title ?? ''" :text="error?.description ?? ''" @close="reset" />
      </Transition>
    </div>
  </PhoneFrame>
</template>
