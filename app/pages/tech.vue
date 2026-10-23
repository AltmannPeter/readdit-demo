<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import { PROOF_SYSTEMS, type CircuitEntry, type SchemeEntry } from '#shared/registry/circuits'

definePageMeta({ layout: false })
useHead({ title: 'Technical view · Community' })

interface Service {
  up: boolean
  service?: string
  implementation?: string
  version?: string
  circuits?: Array<{ system_id: string; proof_system: string; shapes_sha256?: string | null; artifact_sha256?: string | null }>
  schemes?: Array<{ system_id: string; proof_system: string; schema_id: string; plugins: string[] }>
  issuers?: Array<{ issuer_pk: string; schema_id: string }>
  load_ms?: number
  keys_mb?: number | null
  threads?: number
  max_threads?: number
  trust_anchors?: Array<{ subject: string }>
  proof_time_tolerance_s?: number
  error?: string
}
interface Trace {
  at: number
  step: string
  label: string
  data?: Record<string, any>
}
interface Session {
  id: string
  purpose: { kind: 'signin'; intent?: 'signup' | 'login'; community?: string } | { kind: 'age' | 'community'; community: string } | { kind: 'dev'; age: string }
  phone?: string
  status: string
  createdAt: number
  dcql: { credentials: Array<{ id: string; format: 'zkp_req'; meta: Record<string, string>; _req: Array<{ fn_id: string; return: string; params: Record<string, string | number> }> }>; credential_sets?: Array<{ options: string[][] }> }
  answered: string | null
  offer: Formats
  walletMetadata: { vp_formats_supported: Formats } | null
  tailored: boolean
  request: Record<string, any> | null
  requestJwsBytes: number | null
  circuit: Partial<CircuitEntry> | null
  scheme: Partial<SchemeEntry> | null
  outcome: Record<string, any> | null
  completion: { ok: boolean; kind: string } | null
  trace: Trace[]
}
interface Formats {
  zkp_req?: { system_id_values?: string[]; proof_system_values?: string[] }
}
interface Spread {
  median: number
  min: number
  max: number
}
interface Machine {
  cpu: string
  cores: number
  platform: string
  memory_gb: number
}
interface MeasurementRow {
  proof_system: string
  label: string
  statement: string
  threads: number | null
  machine: Machine
  runs: number
  prove: Spread | null
  verify: Spread | null
  proof_bytes: Spread | null
  presentation_bytes: Spread | null
  prove_heap_mb: Spread | null
  verify_heap_mb: Spread | null
  memory: {
    prove: { keys_mb: number | null; witness_mb: number | null; work_mb: number | null }
    verify: { keys_mb: number | null; work_mb: number | null }
  }
  peak_memory_mb: number | null
  last: string
  key: string
  profiled_runs: number
  steps: { prove: Array<{ name: string; ms: number }>; verify: Array<{ name: string; ms: number }> }
  parts: { proof: SizePart[] | null; presentation: SizePart[] | null }
}
interface SizePart {
  name: string
  bytes: number
  children: SizePart[]
}
interface Overview {
  services: { prover: Service; verifier: Service; lfProver: Service; lfVerifier: Service; bbsProver: Service; bbsVerifier: Service }
  acceptedProofSystems: string[]
  multithreading: boolean
  profiling: boolean
  trustNewIssuers: boolean
  learnedIssuers: Array<{ fingerprint: string; subject: string; issuer: string; not_after: string | null; added_at: string; system_id: string }>
  measurements: { runs: number; file: string; machine: Machine; rows: MeasurementRow[] }
  signer: { subject: string; selfSigned: boolean }
  sessions: Session[]
}

const data = ref<Overview | null>(null)
const selected = ref<string | null>(null)
const showRaw = ref(false)
let timer: ReturnType<typeof setInterval> | undefined
const load = async () => {
  try {
    data.value = await $fetch<Overview>('/api/tech/overview')
  } catch {
    /* retry */
  }
}
onMounted(() => {
  load()
  timer = setInterval(load, 700)
})
onBeforeUnmount(() => clearInterval(timer))

const session = computed(() => {
  const list = data.value?.sessions ?? []
  return list.find((s) => s.id === selected.value) ?? list[0] ?? null
})
const step = (name: string) => session.value?.trace.filter((t) => t.step === name).at(-1)
const prove = computed(() => step('prove')?.data)
const verify = computed(() => step('verify')?.data)

const DEV_AGES: Record<string, string> = { none: 'no age', over18: '18+', range13to17: '13–17' }
const purposeText = (p: Session['purpose']) =>
  p.kind === 'dev'
    ? `Developer view, ${DEV_AGES[p.age] ?? p.age}`
    : p.kind === 'signin'
    ? `${p.intent === 'login' ? 'Log in' : 'Sign up'}${p.community ? ` and age check, ${COMMUNITY_PREFIX}${p.community}` : ''}`
    : p.kind === 'community'
      ? `Join ${COMMUNITY_PREFIX}${p.community}`
      : `Age check, ${COMMUNITY_PREFIX}${p.community}`
const kb = (n?: number | null) => (n == null ? '–' : n >= 1000 ? `${(n / 1000).toFixed(1)} kB` : `${n} B`)
const mb = (n?: number | null) => (n == null ? '' : `${n < 10 ? n.toFixed(1) : Math.round(n)} MB`)
const mbSpread = (s: Spread | null) => (!s ? '–' : s.min === s.max ? mb(s.median) : `${mb(s.median)} (${mb(s.min).replace(' MB', '')}–${mb(s.max)})`)
type Counts = { shared: number; precommitted: number; rest: number; public: number } | { hash: { inputs: number; public: number }; signature: { inputs: number; public: number } }
const n = (x: number) => x.toLocaleString('en-GB')
const values = (c?: Counts | null) =>
  !c
    ? ''
    : 'hash' in c
      ? `hash circuit ${n(c.hash.inputs)} inputs (${c.hash.public} public), signature circuit ${n(c.signature.inputs)} (${n(c.signature.public)} public)`
      : `${n(c.shared + c.precommitted + c.rest)} values (shared ${c.shared}, precommitted ${n(c.precommitted)}, rest ${n(c.rest)}), ${c.public} public`
const ms = (n?: number | null) => (n == null ? '–' : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`)
const time = (t: number) => new Date(t).toLocaleTimeString('en-GB')
const since = (t: number) => (session.value ? `+${t - session.value.createdAt} ms` : '')
const reqText = (r: Session['dcql']['credentials'][number]['_req'][number]) =>
  r.fn_id === 'age_check'
    ? `age_check  ${Object.entries(r.params).map(([k, v]) => `${k} ${v}`).join(', ')}`
    : `${r.fn_id}  ${r.params.config}, ver ${r.params.ver}, prf ${r.params.prf}`
const services = computed((): Record<string, Service> => {
  const s = data.value?.services
  return s
    ? {
        'Vega prover': s.prover,
        'Vega verifier': s.verifier,
        'Longfellow prover': s.lfProver,
        'Longfellow verifier': s.lfVerifier,
        'BBS prover': s.bbsProver,
        'BBS verifier': s.bbsVerifier,
      }
    : {}
})
/** Whether the backend of a proof system is loaded (both its sides). */
const loaded = (id: string) => {
  const s = data.value?.services
  if (!s) return false
  if (id === 'vega-v1') return s.prover.up && s.verifier.up
  if (id === 'longfellow-libzk-v1') return s.lfProver.up && s.lfVerifier.up
  return s.bbsProver.up && s.bbsVerifier.up
}
/** Each proof system's prover and verifier, as small icons that open their details. */
const SIDES: Record<string, Array<{ name: string; key: keyof Overview['services']; icon: string }>> = {
  'vega-v1': [
    { name: 'Vega prover', key: 'prover', icon: 'phone' },
    { name: 'Vega verifier', key: 'verifier', icon: 'shield' },
  ],
  'longfellow-libzk-v1': [
    { name: 'Longfellow prover', key: 'lfProver', icon: 'phone' },
    { name: 'Longfellow verifier', key: 'lfVerifier', icon: 'shield' },
  ],
  'bbs-cd-plugins-v0.1': [
    { name: 'BBS prover', key: 'bbsProver', icon: 'phone' },
    { name: 'BBS verifier', key: 'bbsVerifier', icon: 'shield' },
  ],
}
const shortName = (label: string) => label.split(' ')[0]
/** The detail open under the proof systems: a service's name, or 'signing'. */
const openDetail = ref<string | null>(null)
const toggleDetail = (name: string) => (openDetail.value = openDetail.value === name ? null : name)
const openService = computed(() => (openDetail.value && openDetail.value !== 'signing' ? services.value[openDetail.value] : undefined))

/** The width of an open breakdown: the visible width of the Benchmark table, so the bars fit the
 *  screen and stay in view when the table itself is wider and scrolls. */
const benchScroll = ref<HTMLElement | null>(null)
const panelWidth = ref<number | null>(null)
let resize: ResizeObserver | undefined
watch(benchScroll, (el) => {
  resize?.disconnect()
  if (!el) return
  const set = () => (panelWidth.value = el.clientWidth - 40)
  set()
  resize = new ResizeObserver(set)
  resize.observe(el)
})
onBeforeUnmount(() => resize?.disconnect())
const panelStyle = computed(() => (panelWidth.value ? { width: `${panelWidth.value}px` } : { width: '0', minWidth: '100%' }))

/** The Benchmark breakdown open: a row's time, bytes or memory. */
type Breakdown = 'time' | 'size' | 'memory'
const openRow = ref<{ key: string; kind: Breakdown } | null>(null)
const isOpen = (r: MeasurementRow, kind: Breakdown) => openRow.value?.key === r.key && openRow.value.kind === kind
const toggleRow = (r: MeasurementRow, kind: Breakdown) => (openRow.value = isOpen(r, kind) ? null : { key: r.key, kind })
const MEM_COLOURS = { keys: '#9ca3af', witness: '#93c5fd', prove: '#2563eb', verify: '#0d7a64' }
/** The parts of the memory a proof needs (medians): the loaded keys or circuits, the witness held
 *  into the prove step, and the step's own work. */
const memoryBars = (r: MeasurementRow) => {
  const m = r.memory
  const prove = [
    { label: r.proof_system === 'bbs-cd-plugins-v0.1' ? 'Tables loaded at start' : 'Circuits and keys loaded at start', mb: m.prove.keys_mb, colour: MEM_COLOURS.keys },
    ...(m.prove.witness_mb != null ? [{ label: 'Witness, held into the proof', mb: m.prove.witness_mb, colour: MEM_COLOURS.witness }] : []),
    { label: 'Proving', mb: m.prove.work_mb, colour: MEM_COLOURS.prove },
  ]
  const verify = [
    { label: r.proof_system === 'bbs-cd-plugins-v0.1' ? 'Issuer key and tables loaded at start' : 'Circuits and keys loaded at start', mb: m.verify.keys_mb, colour: MEM_COLOURS.keys },
    { label: 'Verifying', mb: m.verify.work_mb, colour: MEM_COLOURS.verify },
  ]
  const total = (parts: Array<{ mb: number | null }>) => parts.reduce((t, p) => t + (p.mb ?? 0), 0)
  const scale = Math.max(total(prove), total(verify), 0.1)
  return [
    { side: 'Prover', parts: prove, total: total(prove), scale },
    { side: 'Verifier', parts: verify, total: total(verify), scale },
  ]
}
/** A side's total memory (median): the loaded keys or circuits plus the step's heap. */
const memTotal = (r: MeasurementRow, side: 'prove' | 'verify') => {
  const m = r.memory?.[side]
  const work = side === 'prove' ? r.prove_heap_mb?.median : r.verify_heap_mb?.median
  if (work == null) return '–'
  return mb((m?.keys_mb ?? 0) + work)
}
const acceptError = ref('')
async function setAccepted(id: string, accept: boolean) {
  acceptError.value = ''
  try {
    await $fetch('/api/tech/accept', { method: 'POST', body: { proof_system: id, accept } })
  } catch (e) {
    acceptError.value = (e as { data?: { statusMessage?: string } }).data?.statusMessage ?? 'Not changed.'
  }
  await load()
}
/** The system ids each side lists in zkp_req (circuits and schemes). */
const ids = (f: Formats | undefined) => f?.zkp_req?.system_id_values?.join(', ') || '–'
const formats = computed(() => (session.value?.offer.zkp_req ? (['zkp_req'] as const) : []))

const threadError = ref('')
async function setThreads(parallel: boolean) {
  threadError.value = ''
  try {
    await $fetch('/api/tech/threads', { method: 'POST', body: { parallel } })
  } catch {
    threadError.value = 'Not changed.'
  }
  await load()
}
const profilingError = ref('')
async function setProfiling(on: boolean) {
  profilingError.value = ''
  try {
    await $fetch('/api/tech/profiling', { method: 'POST', body: { on } })
  } catch {
    profilingError.value = 'Not changed.'
  }
  await load()
}
const issuerError = ref('')
async function issuers(body: { trust_new: boolean } | { forget: string }) {
  issuerError.value = ''
  try {
    await $fetch('/api/tech/issuers', { method: 'POST', body })
  } catch {
    issuerError.value = 'Not changed.'
  }
  await load()
}
const day = (iso: string) => iso.slice(0, 10)
/** The threads a backend runs on now: Vega and BBS follow the switch, Longfellow has one. */
const threadsNow = computed(() => (data.value?.multithreading ? data.value.measurements.machine.cores : 1))
const threadText = (svc: Service) => {
  const n = svc.max_threads != null ? (data.value?.multithreading ? svc.max_threads : 1) : (svc.threads ?? 1)
  return `${n} thread${n === 1 ? '' : 's'}`
}

/** A measured spread: the median, and the range when the runs differ. */
const msSpread = (s: Spread | null) => (!s ? '–' : s.min === s.max ? ms(s.median) : `${ms(s.median)} (${ms(s.min)}–${ms(s.max)})`)
const kbSpread = (s: Spread | null) => (!s ? '–' : kb(s.median))
const machineText = (m: Machine) => `${m.cpu}, ${m.cores} core${m.cores === 1 ? '' : 's'}, ${m.memory_gb} GB, ${m.platform}`
const machines = computed(() => [...new Set((data.value?.measurements.rows ?? []).map((r) => machineText(r.machine)))])
const clearing = ref(false)
async function clearMeasurements() {
  if (!clearing.value) {
    clearing.value = true
    setTimeout(() => (clearing.value = false), 4000)
    return
  }
  clearing.value = false
  await $fetch('/api/tech/measurements/clear', { method: 'POST' }).catch(() => {})
  await load()
}

const statusTone = (s: string) =>
  s === 'completed' || s === 'verified' ? 'bg-emerald-100 text-emerald-800' : s === 'failed' ? 'bg-adult/10 text-adult' : 'bg-canvas text-muted'
</script>

<template>
  <div class="min-h-screen bg-canvas text-ink">
    <header class="border-b border-line bg-surface">
      <div class="mx-auto flex h-14 max-w-6xl items-center gap-3 px-6">
        <AppLogo class="size-7" />
        <span class="font-bold">community</span>
        <span class="text-muted">·</span>
        <span class="font-semibold">Technical view</span>
        <QuickNav class="ml-2" />
      </div>
    </header>

    <main v-if="data" class="mx-auto max-w-6xl space-y-6 px-6 py-6">
      <!-- proof systems: the switches, and each one's prover and verifier as icons -->
      <section class="card p-4">
        <div class="flex flex-wrap items-center gap-x-6 gap-y-2">
          <h2 class="text-sm font-semibold">Proof systems</h2>
          <div v-for="p in PROOF_SYSTEMS" :key="p.id" class="flex items-center gap-2 text-sm" :class="!loaded(p.id) && 'opacity-50'">
            <label class="flex items-center gap-2">
              <input
                type="checkbox"
                :data-accept="p.id"
                :checked="data.acceptedProofSystems.includes(p.id)"
                :disabled="!loaded(p.id)"
                @change="setAccepted(p.id, ($event.target as HTMLInputElement).checked)"
              />
              {{ shortName(p.label) }}
            </label>
            <button
              v-for="side in SIDES[p.id]"
              :key="side.name"
              type="button"
              class="relative flex size-6 items-center justify-center rounded-md border hover:bg-canvas"
              :class="openDetail === side.name ? 'border-ink' : 'border-line'"
              :title="side.name"
              :aria-label="side.name"
              :aria-pressed="openDetail === side.name"
              :data-service="side.name"
              @click="toggleDetail(side.name)"
            >
              <AppIcon :name="side.icon" class="size-3.5" />
              <span class="absolute -top-0.5 -right-0.5 size-1.5 rounded-full" :class="data.services[side.key].up ? 'bg-emerald-500' : 'bg-adult'" />
            </button>
          </div>
          <button
            type="button"
            class="flex size-6 items-center justify-center rounded-md border hover:bg-canvas"
            :class="openDetail === 'signing' ? 'border-ink' : 'border-line'"
            title="Request signing"
            aria-label="Request signing"
            :aria-pressed="openDetail === 'signing'"
            @click="toggleDetail('signing')"
          >
            <AppIcon name="lock" class="size-3.5" />
          </button>
        </div>
        <p v-if="!data.acceptedProofSystems.length" class="mt-2 text-xs font-semibold text-adult" data-none-accepted>None accepted.</p>
        <p v-if="acceptError" class="mt-1 text-xs text-adult">{{ acceptError }}</p>

        <!-- the detail of the icon clicked -->
        <div v-if="openDetail" class="mt-3 border-t border-line pt-3" data-service-detail>
          <template v-if="openDetail === 'signing'">
            <h3 class="text-sm font-semibold">Request signing</h3>
            <p class="mt-1 text-sm break-all">{{ data.signer.subject }}</p>
            <p class="text-xs text-muted">ES256 · x5c · {{ data.signer.selfSigned ? 'self-signed demo certificate' : 'configured certificate' }}</p>
          </template>
          <template v-else-if="openService">
            <div class="flex items-center gap-2">
              <span class="size-2 rounded-full" :class="openService.up ? 'bg-emerald-500' : 'bg-adult'" />
              <h3 class="text-sm font-semibold">{{ openDetail }}</h3>
            </div>
            <template v-if="openService.up">
              <p class="mt-1 text-sm">{{ openService.implementation }}</p>
              <p class="text-xs text-muted">Version {{ openService.version }}</p>
              <p v-if="openService.load_ms != null" class="text-xs text-muted">
                {{ openService.schemes ? 'Tables built once at start' : openService.implementation?.startsWith('Longfellow') ? 'Circuits read once at start' : 'Keys built once at start' }}: {{ ms(openService.load_ms) }}<template v-if="openService.keys_mb != null">, {{ mb(openService.keys_mb) }}</template> · {{ threadText(openService) }}
              </p>
              <p v-if="openService.trust_anchors?.length" class="text-xs text-muted">
                Trust anchor {{ openService.trust_anchors.map((a) => a.subject).join('; ') }} · proof_time tolerance {{ openService.proof_time_tolerance_s }} s
              </p>
              <ul class="mt-2 space-y-0.5 font-mono text-[11px] text-muted">
                <li v-for="c in openService.circuits" :key="c.system_id">{{ c.system_id }} · {{ c.proof_system }}</li>
                <li v-for="c in openService.schemes" :key="c.system_id">{{ c.system_id }} · {{ c.proof_system }} · {{ c.plugins.join(', ') }}</li>
                <li v-for="c in openService.issuers" :key="c.issuer_pk">trusted issuer {{ c.issuer_pk.slice(0, 16) }}… · {{ c.schema_id }}</li>
              </ul>
            </template>
            <template v-else>
              <p class="mt-1 text-sm text-adult">Not available</p>
              <p v-if="openService.error" class="mt-1 text-xs break-words text-muted">{{ openService.error }}</p>
            </template>
          </template>
        </div>

        <div class="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line pt-3">
          <label class="flex items-center gap-2 text-sm">
            <input type="checkbox" data-threads :checked="data.multithreading" @change="setThreads(($event.target as HTMLInputElement).checked)" />
            Multithreading (Vega and BBS)
          </label>
          <span class="text-xs text-muted tabular-nums" data-threads-text>{{ threadsNow }} thread{{ threadsNow === 1 ? '' : 's' }}</span>
          <label class="flex items-center gap-2 text-sm">
            <input type="checkbox" data-profiling :checked="data.profiling" @change="setProfiling(($event.target as HTMLInputElement).checked)" />
            Profiling
          </label>
          <label class="flex items-center gap-2 text-sm">
            <input type="checkbox" data-trust-new :checked="data.trustNewIssuers" @change="issuers({ trust_new: ($event.target as HTMLInputElement).checked })" />
            Trust new issuers
          </label>
        </div>
        <p v-if="threadError || profilingError || issuerError" class="mt-1 text-xs text-adult">{{ threadError || profilingError || issuerError }}</p>
        <ul v-if="data.learnedIssuers.length" class="mt-2 space-y-1 text-xs" data-learned-issuers>
          <li v-for="i in data.learnedIssuers" :key="i.fingerprint" class="flex flex-wrap items-center gap-x-2">
            <span class="break-all">{{ i.subject || 'Unnamed issuer' }}</span>
            <span class="font-mono text-muted" :title="i.fingerprint">{{ i.fingerprint.slice(0, 16) }}</span>
            <span class="text-muted">added {{ day(i.added_at) }}</span>
            <button type="button" class="text-muted underline decoration-dotted underline-offset-2 hover:text-adult" :data-forget-issuer="i.fingerprint" @click="issuers({ forget: i.fingerprint })">Remove</button>
          </li>
        </ul>
      </section>

      <p v-if="!session" class="card p-8 text-center text-sm text-muted">No sessions yet. Start a log-in or age check on Community.</p>

      <template v-else>
        <!-- session picker -->
        <div class="flex flex-wrap gap-2">
          <button
            v-for="s in data.sessions"
            :key="s.id"
            class="rounded-full border px-3 py-1 text-xs"
            :class="s.id === session.id ? 'border-brand bg-brand-soft font-semibold text-brand' : 'border-line bg-surface text-muted'"
            @click="selected = s.id"
          >
            {{ time(s.createdAt) }} · {{ purposeText(s.purpose) }}<template v-if="s.phone"> · {{ s.phone }}</template>
          </button>
        </div>

        <!-- key numbers -->
        <section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div class="card p-4">
            <p class="text-xs text-muted">Status</p>
            <p class="mt-1">
              <span class="rounded px-2 py-0.5 text-sm font-semibold" :class="statusTone(session.status)">{{ session.status }}</span>
            </p>
          </div>
          <div class="card p-4">
            <p class="text-xs text-muted">Prove</p>
            <p class="mt-1 text-2xl font-semibold tabular-nums">{{ ms(prove?.metrics?.total_ms ?? prove?.metrics?.prove_ms) }}</p>
            <p class="text-xs text-muted">round trip {{ ms(prove?.round_trip_ms) }}</p>
          </div>
          <div class="card p-4">
            <p class="text-xs text-muted">Verify</p>
            <p class="mt-1 text-2xl font-semibold tabular-nums">{{ ms(verify?.metrics?.total_ms ?? verify?.metrics?.verify_ms) }}</p>
            <p class="text-xs text-muted">round trip {{ ms(verify?.round_trip_ms) }}</p>
          </div>
          <div class="card p-4">
            <p class="text-xs text-muted">Proof</p>
            <p class="mt-1 text-2xl font-semibold tabular-nums">{{ kb(prove?.metrics?.proof_bytes) }}</p>
            <p class="text-xs text-muted">
              presentation {{ kb(prove?.metrics?.presentation_bytes) }}
            </p>
          </div>
          <div class="card p-4">
            <p class="text-xs text-muted">Request Object</p>
            <p class="mt-1 text-2xl font-semibold tabular-nums">{{ kb(session.requestJwsBytes) }}</p>
            <p class="text-xs text-muted">signed JWT</p>
          </div>
        </section>

        <div class="grid gap-6 lg:grid-cols-2">
          <!-- timeline -->
          <section class="card self-start">
            <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Flow</h2>
            <ol class="divide-y divide-line">
              <li v-for="(t, i) in session.trace" :key="i" class="flex gap-4 px-5 py-3 text-sm">
                <span class="w-20 shrink-0 font-mono text-xs text-muted tabular-nums">{{ since(t.at) }}</span>
                <div class="min-w-0 flex-1">
                  <p class="font-medium">{{ t.label }}</p>
                  <p v-if="t.step === 'request'" class="text-xs text-muted">
                    {{ kb(t.data?.bytes) }} · wallet_metadata {{ t.data?.wallet_metadata ? 'received' : 'none' }} · offer
                    {{ t.data?.tailored ? 'tailored' : 'unchanged' }}
                  </p>
                  <p v-else-if="t.step === 'sign' && t.data?.metrics" class="text-xs text-muted">
                    sign {{ ms(t.data.metrics.sign_ms) }}<template v-if="t.data.challenge_digest"> · e2 {{ t.data.challenge_digest.slice(0, 16) }}…</template>
                  </p>
                  <p v-else-if="t.step === 'witness' && t.data?.metrics" class="text-xs text-muted">
                    {{ ms(t.data.metrics.witness_ms) }}<template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.counts"> · {{ values(t.data.counts) }}</template> · proof_time {{ t.data.proof_time }}
                  </p>
                  <p v-else-if="t.step === 'prove' && t.data?.format === 'bbs_cd' && t.data?.metrics" class="text-xs text-muted">
                    commitments {{ ms(t.data.metrics.offline_ms) }} · BBS proof {{ ms(t.data.metrics.bbs_ms) }} · ecdsa-pop {{ ms(t.data.metrics.ecdsa_pop_ms) }} (device signature {{ ms(t.data.metrics.device_sign_ms) }}) · pseudonym {{ ms(t.data.metrics.pseudonym_ms) }}<template v-if="t.data.metrics.date_range_ms != null"> · date-range {{ ms(t.data.metrics.date_range_ms) }}</template> · presentation {{ kb(t.data.metrics.presentation_bytes) }}<template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.metrics.parts"> (BBS {{ kb(t.data.metrics.parts.bbs_proof) }}, ecdsa-pop {{ kb(t.data.metrics.parts.ecdsa_pop) }}, pseudonym {{ kb(t.data.metrics.parts.pseudonym) }}<template v-if="t.data.metrics.parts.date_range">, date-range {{ kb(t.data.metrics.parts.date_range) }}</template>)</template>
                  </p>
                  <p v-else-if="t.step === 'prove' && t.data?.metrics" class="text-xs text-muted">
                    witness {{ ms(t.data.metrics.witness_ms) }} · prove {{ ms(t.data.metrics.prove_ms) }} · proof {{ kb(t.data.metrics.proof_bytes) }}<template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.metrics.load_ms != null"> · loaded at start {{ ms(t.data.metrics.load_ms) }}</template><template v-if="t.data.metrics.threads"> · {{ t.data.metrics.threads }} thread{{ t.data.metrics.threads === 1 ? '' : 's' }}</template><template v-if="t.data.backend"> · {{ t.data.backend }} addon</template>
                  </p>
                  <p v-else-if="t.step === 'response'" class="text-xs text-muted">
                    {{ kb(t.data?.bytes) }}<template v-if="t.data?.query"> · {{ t.data.query }} ({{ t.data.format }})</template><template v-if="t.data?.error"> · error={{ t.data.error }}</template>
                  </p>
                  <p v-else-if="t.step === 'decrypt' || t.step === 'wallet.encrypt'" class="text-xs text-muted">
                    {{ t.data?.header?.alg }} · {{ t.data?.header?.enc }} · {{ kb(t.data?.bytes) }} · {{ ms(t.data?.decrypt_ms ?? t.data?.encrypt_ms) }}<template v-if="t.data?.error"> · error={{ t.data.error }}</template>
                  </p>
                  <p v-else-if="t.step === 'wallet.match' && t.data?.reason" class="text-xs text-muted">{{ t.data.reason }}</p>
                  <p v-else-if="(t.step === 'verify' || t.step === 'refused') && t.data?.code" class="text-xs text-adult">
                    {{ t.data.code }}<template v-if="t.data.input"> · {{ t.data.input }}</template> · {{ t.data.reason }}
                  </p>
                  <p v-else-if="t.step === 'verify' && t.data?.metrics" class="text-xs text-muted">
                    decode {{ ms(t.data.metrics.decode_ms) }} · verify {{ ms(t.data.metrics.verify_ms) }}<template v-if="t.data.metrics.threads"> on {{ t.data.metrics.threads }} thread{{ t.data.metrics.threads === 1 ? '' : 's' }}</template><template v-if="t.data.metrics.bbs_ms != null"> (BBS proof {{ ms(t.data.metrics.bbs_ms) }}, ecdsa-pop {{ ms(t.data.metrics.ecdsa_pop_ms) }}, pseudonym {{ ms(t.data.metrics.pseudonym_ms) }}<template v-if="t.data.metrics.date_range_ms != null">, date-range {{ ms(t.data.metrics.date_range_ms) }}</template>)</template><template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.metrics.load_ms != null"> · loaded at start {{ ms(t.data.metrics.load_ms) }}</template><template v-if="t.data.issuer_added"> · new issuer trusted: {{ t.data.issuer_added }}</template>
                  </p>
                  <p v-else-if="t.step === 'failed' || t.step === 'completed'" class="text-xs text-muted">
                    {{ t.data?.reason ?? t.data?.kind }}<template v-if="t.data?.detail"> · {{ t.data.detail }}</template>
                  </p>
                  <p v-else-if="t.data?.error" class="text-xs text-adult">{{ t.data.error }}</p>
                </div>
              </li>
            </ol>
          </section>

          <div class="space-y-6">
            <!-- request -->
            <section class="card">
              <div class="flex items-center border-b border-line px-5 py-3">
                <h2 class="text-sm font-semibold">Request (DCQL, zkp_req over {{ session.dcql.credentials.map((q) => q.meta.source_format).join(' or ') }})</h2>
                <button class="ml-auto text-xs font-semibold text-brand" @click="showRaw = !showRaw">{{ showRaw ? 'Summary' : 'Raw JSON' }}</button>
              </div>
              <pre v-if="showRaw" class="max-h-96 overflow-auto px-5 py-3 text-[11px] leading-relaxed">{{ JSON.stringify(session.request ?? session.dcql, null, 2) }}</pre>
              <div v-else class="divide-y divide-line">
                <ul v-for="q in session.dcql.credentials" :key="q.id" class="space-y-1 px-5 py-3 font-mono text-xs">
                  <li class="text-muted">
                    {{ q.id }} · {{ q.format }} · {{ q.meta.source_format }} · {{ q.meta.source_format === 'mso_mdoc' ? `doctype ${q.meta.doctype_value}` : `schema ${q.meta.schema_id_value}` }}<template v-if="session.answered === q.id"> · answered</template>
                  </li>
                  <li v-for="r in q._req" :key="r.return">
                    <span class="text-muted">{{ r.return }} ←</span> {{ reqText(r) }}
                  </li>
                </ul>
                <p v-if="session.dcql.credential_sets" class="px-5 py-2 font-mono text-[11px] text-muted">
                  credential_sets: one of {{ session.dcql.credential_sets[0]!.options.map((o) => o.join('+')).join(' | ') }}
                </p>
              </div>
            </section>

            <!-- negotiation -->
            <section class="card">
              <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Capability negotiation</h2>
              <dl v-for="f in formats" :key="f" class="divide-y divide-line border-b border-line text-xs last:border-b-0">
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Community accepts</dt>
                  <dd class="font-mono">{{ f }}: {{ ids(session.offer) }}</dd>
                </div>
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Wallet supports</dt>
                  <dd class="font-mono">{{ ids(session.walletMetadata?.vp_formats_supported) }}</dd>
                </div>
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Sent in request</dt>
                  <dd class="font-mono">{{ ids(session.request?.client_metadata?.vp_formats_supported) }}</dd>
                </div>
              </dl>
              <div class="grid grid-cols-[9rem_1fr] gap-2 border-t border-line px-5 py-2.5 text-xs">
                <dt class="text-muted">Used</dt>
                <dd class="font-mono">{{ session.circuit?.system_id ?? session.scheme?.system_id ?? prove?.system_id ?? '–' }}</dd>
              </div>
            </section>

            <!-- circuit -->
            <section v-if="session.circuit?.public_inputs" class="card">
              <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">
                {{ session.circuit.label }} · {{ session.circuit.proof_system }}
              </h2>
              <ol class="divide-y divide-line text-xs">
                <li v-for="(p, i) in session.circuit.public_inputs" :key="p.name" class="grid grid-cols-[1.5rem_12.5rem_1fr] gap-2 px-5 py-2">
                  <span class="text-muted tabular-nums">{{ i + 1 }}</span>
                  <span class="font-mono">{{ p.name }}</span>
                  <span class="text-muted">{{ p.source === 'presentation' ? 'from presentation' : 'recomputed by Community' }}: {{ p.derivation }}</span>
                </li>
              </ol>
            </section>

            <!-- scheme -->
            <section v-if="session.scheme?.plugins" class="card">
              <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">{{ session.scheme.label }} · {{ session.scheme.proof_system }}</h2>
              <ol class="divide-y divide-line text-xs">
                <li v-for="x in session.scheme.statement" :key="x.name" class="grid grid-cols-[12.5rem_1fr] gap-2 px-5 py-2">
                  <span class="font-mono">{{ x.name }}</span>
                  <span class="text-muted">recomputed by Community: {{ x.derivation }}</span>
                </li>
                <li v-for="p in session.scheme.plugins" :key="p.id" class="grid grid-cols-[12.5rem_1fr] gap-2 px-5 py-2">
                  <span class="font-mono">{{ p.id }} on {{ p.attribute }}</span>
                  <span class="text-muted">{{ p.proves }}</span>
                </li>
              </ol>
            </section>

            <!-- results -->
            <section v-if="verify?.results" class="card">
              <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Public outputs</h2>
              <dl class="divide-y divide-line text-xs">
                <div v-for="(v, k) in verify.results" :key="k" class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">{{ k }}</dt>
                  <dd class="font-mono break-all">{{ v }}</dd>
                </div>
              </dl>
            </section>
          </div>
        </div>
      </template>
      <!-- measured -->
      <section class="card" data-measured>
        <div class="flex flex-wrap items-start gap-3 border-b border-line px-5 py-3">
          <div class="min-w-0 flex-1">
            <h2 class="text-sm font-semibold">Benchmark</h2>
            <p class="mt-0.5 text-xs text-muted" data-machine>{{ machineText(data.measurements.machine) }}</p>
          </div>
          <button v-if="data.measurements.runs" class="btn-ghost text-xs" data-clear-measurements @click="clearMeasurements">{{ clearing ? 'Click again to clear' : 'Clear' }}</button>
        </div>
        <p v-if="!data.measurements.rows.length" class="px-5 py-6 text-center text-sm text-muted">No measurements yet. Each verified presentation adds one.</p>
        <div v-else ref="benchScroll" class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead>
              <tr class="border-b border-line text-muted">
                <th class="px-5 py-2 font-medium">Proof system</th>
                <th class="px-3 py-2 font-medium">Proves</th>
                <th class="px-3 py-2 font-medium">Threads</th>
                <th class="px-3 py-2 font-medium">Runs</th>
                <th class="px-3 py-2 font-medium">Prove</th>
                <th class="px-3 py-2 font-medium">Verify</th>
                <th class="px-3 py-2 font-medium">Proof</th>
                <th class="px-3 py-2 font-medium">Presentation</th>
                <th class="px-3 py-2 font-medium">Prover memory</th>
                <th class="px-3 py-2 font-medium">Verifier memory</th>
                <th v-if="machines.length > 1" class="px-3 py-2 font-medium">Machine</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              <template v-for="r in data.measurements.rows" :key="r.key">
              <tr class="align-top" :data-measured-row="r.proof_system">
                <td class="px-5 py-2.5 font-medium">{{ r.label }}</td>
                <td class="px-3 py-2.5">{{ r.statement }}</td>
                <td class="px-3 py-2.5 tabular-nums" data-measured-threads>{{ r.threads ?? '–' }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ r.runs }}</td>
                <td v-for="side in (['prove', 'verify'] as const)" :key="side" class="px-3 py-1.5 tabular-nums">
                  <button type="button" class="cell" :aria-expanded="isOpen(r, 'time')" :data-measured-time="side" @click="toggleRow(r, 'time')">
                    {{ msSpread(r[side]) }}
                  </button>
                </td>
                <td v-for="what in (['proof_bytes', 'presentation_bytes'] as const)" :key="what" class="px-3 py-1.5 tabular-nums">
                  <button type="button" class="cell" :aria-expanded="isOpen(r, 'size')" :data-measured-size="what" @click="toggleRow(r, 'size')">
                    {{ kbSpread(r[what]) }}
                  </button>
                </td>
                <td v-for="side in (['prove', 'verify'] as const)" :key="side" class="px-3 py-1.5 tabular-nums">
                  <button type="button" class="cell" :aria-expanded="isOpen(r, 'memory')" :data-measured-memory="side" @click="toggleRow(r, 'memory')">
                    {{ memTotal(r, side) }}
                  </button>
                </td>
                <td v-if="machines.length > 1" class="px-3 py-2.5">{{ machineText(r.machine) }}</td>
              </tr>
              <!-- the time by step and where it goes (profiles), the bytes by part -->
              <tr v-if="isOpen(r, 'time') || isOpen(r, 'size')">
                <td :colspan="machines.length > 1 ? 11 : 10" class="bg-canvas px-5 py-3">
                  <div class="sticky left-5 overflow-x-auto" :style="panelStyle">
                    <TechTimeBreakdown v-if="isOpen(r, 'time')" :row="r" />
                    <TechSizeBreakdown v-else :parts="r.parts" />
                  </div>
                </td>
              </tr>
              <!-- the memory a proof needs, prover and verifier, as stacked bars (medians) -->
              <tr v-if="isOpen(r, 'memory')" data-memory-breakdown>
                <td :colspan="machines.length > 1 ? 11 : 10" class="bg-canvas px-5 py-3">
                  <div class="sticky left-5 overflow-x-auto" :style="panelStyle">
                    <div v-for="bar in memoryBars(r)" :key="bar.side" class="mb-2 last:mb-0">
                      <div class="flex items-baseline justify-between text-[11px]">
                        <span class="font-semibold">{{ bar.side }}</span>
                        <span class="tabular-nums">{{ mb(bar.total) }}</span>
                      </div>
                      <div class="mt-1 flex h-3 overflow-hidden rounded bg-surface">
                        <span
                          v-for="part in bar.parts.filter((x) => x.mb)"
                          :key="part.label"
                          :style="{ width: `${(100 * (part.mb ?? 0)) / bar.scale}%`, backgroundColor: part.colour }"
                          :title="`${part.label}: ${mb(part.mb)}`"
                        />
                      </div>
                      <div class="mt-1 flex flex-wrap gap-x-4 text-[11px] text-muted">
                        <span v-for="part in bar.parts" :key="part.label" class="flex items-center gap-1.5">
                          <span class="size-2 rounded-sm" :style="{ backgroundColor: part.colour }" />{{ part.label }} {{ part.mb == null ? '–' : mb(part.mb) }}
                        </span>
                      </div>
                    </div>
                  </div>
                </td>
              </tr>
              </template>
            </tbody>
          </table>
        </div>
      </section>
    </main>
  </div>
</template>

<style scoped>
.cell {
  border-radius: 0.25rem;
  padding: 0.25rem 0.375rem;
  text-decoration: underline dotted;
  text-decoration-color: var(--color-line);
  text-underline-offset: 4px;
}
.cell:hover {
  background: var(--color-canvas);
}
</style>
