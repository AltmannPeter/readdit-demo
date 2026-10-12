<script setup lang="ts">
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import type { WalletTransport } from '~/wallet/transport'
import type { RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
import { analyzeRequest, parseAuthorizationUrl } from '~/wallet/engine'
import { httpTransport } from '~/wallet/transport'
import { proveWithService } from '~/wallet/prover'
import { findCircuit } from '#shared/registry/circuits'

/**
 * EUDI Wallet App (mock screens). Drives the holder side of OpenID4VP:
 * scan -> POST request_uri with wallet_metadata -> verify signed request -> check request and
 * pick a circuit -> consent -> PIN -> prover service -> POST response_uri.
 */
const props = withDefaults(
  defineProps<{
    /** What the camera sees: the openid4vp:// URL in the QR code on screen. */
    url: string | null
    transport?: WalletTransport
  }>(),
  { transport: () => httpTransport },
)

type Screen = 'home' | 'scan' | 'request' | 'unmet' | 'pin' | 'working' | 'done' | 'declined' | 'error'

const screen = ref<Screen>('home')
const request = ref<RequestObject | null>(null)
const view = ref<RequestView | null>(null)
const credential = ref<CredentialView | null>(null)
const circuitIds = ref<string[]>([])
const errorText = ref('')
const pinError = ref('')
const pinKey = ref(0)
const today = useToday()
let scanTimer: ReturnType<typeof setTimeout> | undefined

onMounted(async () => {
  try {
    const [cred, caps] = await Promise.all([
      $fetch<CredentialView>('/api/wallet/credential'),
      $fetch<{ circuits: Array<{ circuit_id: string }> }>('/api/wallet/capabilities'),
    ])
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
  scanTimer = setTimeout(onScanned, 1500)
}

function cancelScan() {
  clearTimeout(scanTimer)
  screen.value = 'home'
}

async function onScanned() {
  if (screen.value !== 'scan' || !credential.value) return
  const parsed = props.url ? parseAuthorizationUrl(props.url) : null
  if (!parsed) return fail('No valid QR code found.')
  try {
    const req = await props.transport.fetchRequest({
      requestUri: parsed.requestUri,
      method: parsed.method,
      clientId: parsed.clientId,
      walletMetadata: walletMetadata(),
    })
    request.value = req
    view.value = analyzeRequest(req, credential.value, today.value, circuitIds.value)
    screen.value = view.value.satisfiable ? 'request' : 'unmet'
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

async function onPin(pin: string) {
  screen.value = 'working'
  const req = request.value!
  try {
    const out = await proveWithService({ request: req, circuitId: view.value!.circuit!.circuit_id, pin })
    await send({ state: req.state, vp_token: { [req.dcql_query.credentials[0]!.id]: [out.presentation] } })
    screen.value = 'done'
  } catch (e) {
    const code = (e as Error).message
    if (code === 'invalid_pin') {
      pinError.value = 'Wrong PIN. Try again.'
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
  screen.value = 'home'
}

onBeforeUnmount(() => clearTimeout(scanTimer))
</script>

<template>
  <PhoneFrame :dark="screen === 'scan'">
    <Transition
      mode="out-in"
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="opacity-0 translate-x-3"
      leave-active-class="transition duration-150 ease-in"
      leave-to-class="opacity-0 -translate-x-3"
    >
      <WalletHome v-if="screen === 'home'" key="home" :credential="credential" @scan="startScan" />
      <WalletScan v-else-if="screen === 'scan'" key="scan" :url="url" @cancel="cancelScan" />
      <WalletRequest
        v-else-if="screen === 'request' && view"
        key="request"
        :view="view"
        :credential-title="credential?.title ?? ''"
        :issuer="credential?.issuer.name ?? ''"
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
      <WalletWorking v-else-if="screen === 'working'" key="working" title="Creating proof" text="This can take a few seconds." />
      <WalletOutcome v-else-if="screen === 'done'" key="done" kind="done" :verifier-name="view?.verifierName" @close="reset" />
      <WalletOutcome v-else-if="screen === 'declined'" key="declined" kind="declined" @close="reset" />
      <WalletOutcome v-else key="error" kind="error" :text="errorText" @close="reset" />
    </Transition>
  </PhoneFrame>
</template>
