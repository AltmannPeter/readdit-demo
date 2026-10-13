<script setup lang="ts">
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import type { WalletTransport } from '~/wallet/transport'
import type { ConsentView, RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import type { Step } from './Working.vue'
import { analyzeRequest, consentFor, parseAuthorizationUrl } from '~/wallet/engine'
import { httpTransport } from '~/wallet/transport'
import { loadCredential } from '~/wallet/holder'
import { prove, unlockAndSign } from '~/wallet/prover'
import { findCircuit } from '#shared/registry/circuits'

/**
 * The SIROS ID wallet on the phone (mocked screens, real protocol). Drives the holder side of
 * OpenID4VP: scan -> POST request_uri with wallet_metadata -> verify the signed request -> check
 * it and pick a circuit -> consent -> PIN -> native steps (sign, witness and prove) -> POST response_uri.
 */
const props = withDefaults(
  defineProps<{
    /** What the camera sees: the openid4vp:// URL in the QR code on screen. */
    url: string | null
    transport?: WalletTransport
  }>(),
  { transport: () => httpTransport },
)

type Screen = 'home' | 'detail' | 'scan' | 'request' | 'unmet' | 'pin' | 'working' | 'done' | 'declined' | 'error'

const screen = ref<Screen>('home')
const request = ref<RequestObject | null>(null)
const view = ref<RequestView | null>(null)
const consent = ref<ConsentView | null>(null)
const credential = ref<CredentialView | null>(null)
const circuitIds = ref<string[]>([])
const detected = ref(false)
const errorText = ref('')
const pinError = ref('')
const pinKey = ref(0)
const workingTitle = ref('')
const steps = ref<Step[]>([])
const today = useToday()
/** Presentations made from this page, for the home screen's Recent History. */
const history = useState<Array<{ audience: string; at: number }>>('siros-history', () => [])
const timers: Array<ReturnType<typeof setTimeout>> = []

onMounted(async () => {
  try {
    const [cred, caps] = await Promise.all([loadCredential(), $fetch<{ circuits: Array<{ circuit_id: string }> }>('/api/wallet/capabilities')])
    credential.value = cred
    circuitIds.value = caps.circuits.map((c) => c.circuit_id)
  } catch {
    fail('The wallet service is not available.')
  }
})

function walletMetadata(): WalletMetadata {
  const systems = [...new Set(circuitIds.value.map((id) => findCircuit(id)?.proof_system).filter(Boolean) as string[])]
  return { vp_formats_supported: { circuit_zk: { circuit_proof_system_values: systems, circuit_id_values: circuitIds.value } } }
}

function fail(text: string) {
  errorText.value = text
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
  if (!parsed) return fail('No valid QR code found.')
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
  } catch {
    fail('Could not load the request.')
  }
}

async function send(body: AuthorizationResponse) {
  await props.transport.postResponse(request.value!.response_uri, body)
}

/**
 * Rulebook: data-dependent failure or decline -> access_denied without description;
 * a cause independent of holder data may use invalid_request.
 */
async function refuse(next: Screen) {
  const independent = view.value?.problem === 'unsupported' || view.value?.problem === 'no_circuit'
  try {
    await send({ state: request.value!.state, error: independent ? 'invalid_request' : 'access_denied' })
    screen.value = next
  } catch {
    fail('Could not reach the website.')
  }
}

function toPin() {
  pinError.value = ''
  pinKey.value++
  screen.value = 'pin'
}

const ms = (n?: number, simulated?: boolean) => (n == null ? undefined : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms${simulated ? ' (simulated)' : ''}`)

/** How long the progress screen stays up at least, and the completed list after the last step, so the
 *  steps can be read; the times it shows are measured. */
const MIN_PROGRESS_MS = 1500
const MIN_COMPLETED_MS = 600
const wait = (ms: number) => new Promise((r) => timers.push(setTimeout(r, ms)))

async function onPin(pin: string) {
  const req = request.value!
  const host = view.value!.verifierHost
  const shownAt = Date.now()
  screen.value = 'working'
  workingTitle.value = 'Creating presentation...'
  steps.value = [
    { label: 'PIN checked, device key signs the request', state: 'running' },
    { label: 'Witness from your credential', state: 'waiting' },
    { label: 'Zero-knowledge proof', state: 'waiting' },
    { label: `Sending the response to ${host}`, state: 'waiting' },
  ]
  const set = (i: number, patch: Partial<Step>) => (steps.value[i] = { ...steps.value[i]!, ...patch })
  try {
    const signed = await unlockAndSign({ request: req, pin })
    set(0, { state: 'done', detail: ms(signed.metrics.sign_ms, signed.metrics.simulated) })
    set(1, { state: 'running' })
    set(2, { state: 'running' })
    const out = await prove({ request: req, circuitId: view.value!.circuit!.circuit_id, deviceSignature: signed.device_signature })
    const sim = out.metrics.simulated
    set(1, { state: 'done', detail: ms(out.witness_ms ?? out.metrics.witness_ms, sim) })
    set(2, { state: 'done', detail: `${ms(out.metrics.prove_ms, sim)} · proof ${((out.metrics.proof_bytes ?? 0) / 1000).toFixed(1)} kB` })
    set(3, { state: 'running' })
    workingTitle.value = 'Sending response...'
    await send({ state: req.state, vp_token: { [req.dcql_query.credentials[0]!.id]: [out.presentation] } })
    set(3, { state: 'done' })
    workingTitle.value = 'Presentation sent successfully'
    history.value = [{ audience: host, at: Date.now() }, ...history.value]
    await wait(Math.max(MIN_COMPLETED_MS, MIN_PROGRESS_MS - (Date.now() - shownAt)))
    screen.value = 'done'
  } catch (e) {
    const code = (e as Error).message
    if (code === 'invalid_pin') {
      pinError.value = 'You have entered an incorrect PIN.'
      pinKey.value++
      screen.value = 'pin'
    } else if (code === 'unsatisfiable') {
      view.value = { ...view.value!, satisfiable: false, problem: 'age' }
      screen.value = 'unmet'
    } else {
      fail(code === 'unavailable' ? 'The wallet service is not available.' : 'The proof could not be created.')
    }
  }
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
        <WalletDetail v-else-if="screen === 'detail' && credential" key="detail" :credential="credential" @back="screen = 'home'" @scan="startScan" />
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
          @done="onPin"
          @cancel="refuse('declined')"
        />
        <WalletWorking v-else-if="screen === 'working'" key="working" :title="workingTitle" :steps="steps" />
        <WalletOutcome v-else-if="screen === 'done'" key="done" kind="done" :verifier-name="view?.verifierName" @close="reset" />
        <WalletOutcome v-else-if="screen === 'declined'" key="declined" kind="declined" @close="reset" />
        <WalletOutcome v-else key="error" kind="error" :text="errorText" @close="reset" />
      </Transition>
    </div>
  </PhoneFrame>
</template>
