<script setup lang="ts">
// The developer view: the same flow as the Community site, as the protocol runs. Choose the age
// proof on the left; the sequence diagram fills the page; the QR code and the step details open as
// popups; the inspector is a collapsible panel under the diagram. It follows this browser's newest
// session, whichever view started it. No guide here.
import { AGE_OPTIONS, eventsOf } from '~/dev/flow'

definePageMeta({ layout: false })
useHead({ title: 'Community · Developer' })

const flow = useDevFlow()
const { state } = flow
const { refresh } = useAccount()
const inspectorOpen = ref(false)
const attestationOpen = ref(false)
const qrOpen = ref(false)
const selectedId = ref<string | null>(null)
/** Diagram view: everything greyscale, or one highlight mode. */
const view = ref<'all' | 'extensions' | 'zkp'>('all')
const toggleView = (v: 'extensions' | 'zkp') => (view.value = view.value === v ? 'all' : v)

const events = computed(() => (state.value.session ? eventsOf(state.value.session) : []))
const selectedIndex = computed(() => events.value.findIndex((e) => e.id === selectedId.value))
const selectedEvent = computed(() => events.value[selectedIndex.value] ?? null)
const prevAt = computed(() => (selectedIndex.value > 0 ? events.value[selectedIndex.value - 1]!.at : undefined))
const done = computed(() => !!state.value.session && !flow.active.value)

// Presenter keys: 1/2/3 request with age proof none/18+/13–17, S simulate scan, R clear,
// E and Z the highlight views, I the inspector.
function onKey(e: KeyboardEvent) {
  if (e.metaKey || e.ctrlKey || e.altKey) return
  const t = e.target as HTMLElement | null
  if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return
  // The phone in the popup takes its own keys (the PIN).
  if (state.value.phoneShown && qrOpen.value) return
  const k = e.key.toLowerCase()
  if (/^[1-3]$/.test(k)) flow.start(AGE_OPTIONS[Number(k) - 1]!.id)
  else if (k === 's') simulateScan()
  else if (k === 'r') clear()
  else if (k === 'e') toggleView('extensions')
  else if (k === 'z') toggleView('zkp')
  else if (k === 'i') inspectorOpen.value = !inspectorOpen.value
  else return
  e.preventDefault()
}

function simulateScan() {
  qrOpen.value = true
  flow.simulateScan()
}

function clear() {
  qrOpen.value = false
  selectedId.value = null
  flow.reset()
}

let poll: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  window.addEventListener('keydown', onKey)
  await refresh()
  await flow.load()
  poll = setInterval(flow.load, 400)
})
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  clearInterval(poll)
  // Leaving the view ends its own request; the next view starts a new one.
  flow.cancelOwn()
  state.value.phoneShown = false
})

// The QR popup opens when this view's request is ready. A real phone's scan shows "Scanned" briefly,
// then the popup gets out of the way; with the demo's phone it stays until Close on the phone.
let closeTimer: ReturnType<typeof setTimeout> | undefined
watch(
  () => (flow.own.value ? state.value.session?.status : undefined),
  (status, prev) => {
    clearTimeout(closeTimer)
    if (status === 'waiting' && prev !== 'waiting') qrOpen.value = true
    else if (!state.value.phoneShown && status === 'scanned' && prev === 'waiting' && qrOpen.value) closeTimer = setTimeout(() => (qrOpen.value = false), 1000)
    else if (!state.value.phoneShown && status !== 'waiting' && status !== 'scanned') qrOpen.value = false
  },
)
</script>

<template>
  <div class="vd page">
    <header class="top">
      <DevAppBrand />
      <ViewSwitch />
    </header>

    <aside class="side">
      <section>
        <h2 class="section-label">Accepted proof systems</h2>
        <DevAcceptedInfo />
      </section>
      <section>
        <h2 class="section-label">
          Pseudonym presentation with age proof
          <button type="button" class="att" title="Show the nym_auth attestation" @click="attestationOpen = true">
            <svg width="11" height="11" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 1.5h6l3 3v10h-9z M9.5 1.5v3h3 M5.5 8h5 M5.5 10.5h5" fill="none" stroke="currentColor" stroke-width="1.3" /></svg>
            <span class="mono">nym_auth</span>
          </button>
        </h2>
        <DevPresentationPicker />
        <button v-if="done" type="button" class="link clear" @click="clear">Clear</button>
      </section>
      <section>
        <h2 class="section-label">Community account</h2>
        <DevAccountInfo />
      </section>
      <p class="keys mono">1 2 3 request · S scan · R clear · E Z highlight · I inspector</p>
    </aside>

    <main class="main">
      <DevSequenceDiagram v-model:view="view" class="diagram" :events="events" :selected-id="selectedId" @select="(id) => (selectedId = id)" />
      <DevInspectorPanel v-model:open="inspectorOpen" />
    </main>

    <DevQrPopup v-model:open="qrOpen" />
    <DevAttestationPopup v-model:open="attestationOpen" />
    <DevStepDetail :step="selectedIndex + 1" :event="selectedEvent" :prev-at="prevAt" @close="selectedId = null" />
  </div>
</template>

<style scoped>
.page {
  height: 100vh;
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  grid-template-rows: auto minmax(0, 1fr);
  grid-template-areas: 'top top' 'side main';
}
.top {
  grid-area: top;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 24px;
  border-bottom: 1px solid var(--line);
}
.side {
  grid-area: side;
  padding: 24px 20px;
  display: flex;
  flex-direction: column;
  gap: 28px;
  overflow: auto;
  border-right: 1px solid var(--line);
}
.side h2 { margin: 0 0 10px; }
.att {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 4px;
  vertical-align: 1px;
  padding: 1px 6px;
  text-transform: none;
  letter-spacing: 0;
  font-weight: 500;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--bg);
  color: var(--muted);
  font-size: 11px;
}
.att:hover { color: var(--ink); border-color: var(--faint); }
.keys { margin: auto 0 0; font-size: 10.5px; color: var(--faint); line-height: 1.6; }

.main {
  grid-area: main;
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 22px 24px 24px;
  min-width: 0;
  min-height: 0;
}

.clear { margin-top: 14px; }
.link { background: none; border: 0; padding: 0; font-size: 13px; color: var(--ink); text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--faint); }
.link:hover { text-decoration-color: var(--ink); }

.diagram { flex: 1; min-height: 260px; }

@media (max-width: 900px) {
  .page { height: auto; min-height: 100vh; grid-template-columns: 1fr; grid-template-areas: 'top' 'side' 'main'; }
  .side { border-right: 0; border-bottom: 1px solid var(--line); }
  .diagram { height: 70vh; flex: none; }
}
@media (max-width: 640px) {
  .main { padding: 16px; }
  .top { padding: 12px 16px; }
}
</style>
