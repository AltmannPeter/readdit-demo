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
  peak_memory_mb: number | null
  last: string
}
interface Overview {
  services: { prover: Service; verifier: Service; lfProver: Service; lfVerifier: Service; bbsProver: Service; bbsVerifier: Service }
  acceptedProofSystems: string[]
  multithreading: boolean
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
const backendsText = computed(() => {
  const up = PROOF_SYSTEMS.filter((p) => loaded(p.id)).map((p) => p.label.split(' ')[0])
  const list = up.length > 1 ? `${up.slice(0, -1).join(', ')} and ${up.at(-1)}` : up[0]
  return up.length ? `${list} addon${up.length > 1 ? 's' : ''}, in process` : 'No backend loaded'
})
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
/** The threads a backend runs on now: Vega and BBS follow the switch, Longfellow has one. */
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
        <span
          v-if="data"
          class="ml-auto rounded-full px-2.5 py-1 text-xs font-semibold"
          :class="PROOF_SYSTEMS.some((p) => loaded(p.id)) ? 'bg-emerald-100 text-emerald-800' : 'bg-adult/10 text-adult'"
        >
          {{ backendsText }}
        </span>
      </div>
    </header>

    <main v-if="data" class="mx-auto max-w-6xl space-y-6 px-6 py-6">
      <!-- accepted proof systems -->
      <section class="card p-4">
        <div class="flex flex-wrap items-center gap-x-6 gap-y-2">
          <h2 class="text-sm font-semibold">Community accepts</h2>
          <label v-for="p in PROOF_SYSTEMS" :key="p.id" class="flex items-center gap-2 text-sm" :class="!loaded(p.id) && 'opacity-50'">
            <input
              type="checkbox"
              :data-accept="p.id"
              :checked="data.acceptedProofSystems.includes(p.id)"
              :disabled="!loaded(p.id)"
              @change="setAccepted(p.id, ($event.target as HTMLInputElement).checked)"
            />
            {{ p.label }} <span class="font-mono text-[11px] text-muted">{{ p.source_format }} · {{ p.id }}</span>
          </label>
        </div>
        <p class="mt-1 text-xs text-muted">
          Only the ticked ones: a wallet request offers their systems in zkp_req when the phone fetches it, so a QR code already on screen follows too, and a presentation in a proof system unticked meanwhile is refused. Vega and Longfellow are circuits over the mdoc (mso_mdoc): the request lists both, Vega first. With BBS (bbs_cd) as well, the DCQL query carries one zkp_req credential query per source format, as alternatives (credential_sets). Nothing is ticked when the demo starts or after a reset.
        </p>
        <p v-if="!data.acceptedProofSystems.length" class="mt-2 text-xs font-semibold text-adult" data-none-accepted>
          Community accepts no proof system: sign-up, log-in and age checks stop before the QR code until one is ticked.
        </p>
        <p v-if="acceptError" class="mt-1 text-xs text-adult">{{ acceptError }}</p>
        <div class="mt-3 flex flex-wrap items-center gap-x-6 gap-y-1 border-t border-line pt-3">
          <label class="flex items-center gap-2 text-sm">
            <input type="checkbox" data-threads :checked="data.multithreading" @change="setThreads(($event.target as HTMLInputElement).checked)" />
            Multithreading (Vega and BBS)
          </label>
          <span class="text-xs text-muted" data-threads-text>
            {{ data.multithreading ? `On: Vega and BBS run on ${data.measurements.machine.cores} threads, one per core of this machine.` : `Off: Vega and BBS run on 1 thread. On, they use all ${data.measurements.machine.cores} cores of this machine.` }}
            Longfellow always runs on 1 thread: Google's runtime has no parallel code.
          </span>
        </div>
        <p v-if="threadError" class="mt-1 text-xs text-adult">{{ threadError }}</p>
      </section>

      <!-- services -->
      <section class="grid gap-4 md:grid-cols-2">
        <div v-for="(svc, name) in services" :key="name" class="card p-4">
          <div class="flex items-center gap-2">
            <span class="size-2 rounded-full" :class="svc.up ? 'bg-emerald-500' : 'bg-adult'" />
            <h2 class="text-sm font-semibold">{{ name }}</h2>
          </div>
          <template v-if="svc.up">
            <p class="mt-2 text-sm">{{ svc.implementation }}</p>
            <p class="text-xs text-muted">Version {{ svc.version }}</p>
            <p v-if="svc.load_ms != null" class="text-xs text-muted">
              {{ svc.schemes ? 'Tables built once at start' : svc.implementation?.startsWith('Longfellow') ? 'Circuits read once at start' : 'Keys built once at start' }}: {{ ms(svc.load_ms) }} · {{ threadText(svc) }}
            </p>
            <p v-if="svc.trust_anchors?.length" class="text-xs text-muted">
              Trust anchor {{ svc.trust_anchors.map((a) => a.subject).join('; ') }} · proof_time tolerance {{ svc.proof_time_tolerance_s }} s
            </p>
            <ul class="mt-2 space-y-0.5 font-mono text-[11px] text-muted">
              <li v-for="c in svc.circuits" :key="c.system_id">{{ c.system_id }} · {{ c.proof_system }}</li>
              <li v-for="c in svc.schemes" :key="c.system_id">{{ c.system_id }} · {{ c.proof_system }} · {{ c.plugins.join(', ') }}</li>
              <li v-for="c in svc.issuers" :key="c.issuer_pk">trusted issuer {{ c.issuer_pk.slice(0, 16) }}… · {{ c.schema_id }}</li>
            </ul>
          </template>
          <template v-else>
            <p class="mt-2 text-sm text-adult">Not available</p>
            <p v-if="svc.error" class="mt-1 text-xs break-words text-muted">{{ svc.error }}</p>
          </template>
        </div>
        <div class="card p-4">
          <h2 class="text-sm font-semibold">Request signing</h2>
          <p class="mt-2 text-sm break-all">{{ data.signer.subject }}</p>
          <p class="text-xs text-muted">ES256 · x5c · {{ data.signer.selfSigned ? 'self-signed demo certificate' : 'configured certificate' }}</p>
        </div>
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
                    witness {{ ms(t.data.metrics.witness_ms) }} · prove {{ ms(t.data.metrics.prove_ms) }} · proof {{ kb(t.data.metrics.proof_bytes) }}<template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.metrics.peak_memory_mb"> · peak RSS of the server process {{ mb(t.data.metrics.peak_memory_mb) }}</template><template v-if="t.data.metrics.load_ms != null"> · loaded at start {{ ms(t.data.metrics.load_ms) }}</template><template v-if="t.data.metrics.threads"> · {{ t.data.metrics.threads }} thread{{ t.data.metrics.threads === 1 ? '' : 's' }}</template><template v-if="t.data.backend"> · {{ t.data.backend }} addon</template>
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
                    decode {{ ms(t.data.metrics.decode_ms) }} · verify {{ ms(t.data.metrics.verify_ms) }}<template v-if="t.data.metrics.threads"> on {{ t.data.metrics.threads }} thread{{ t.data.metrics.threads === 1 ? '' : 's' }}</template><template v-if="t.data.metrics.bbs_ms != null"> (BBS proof {{ ms(t.data.metrics.bbs_ms) }}, ecdsa-pop {{ ms(t.data.metrics.ecdsa_pop_ms) }}, pseudonym {{ ms(t.data.metrics.pseudonym_ms) }}<template v-if="t.data.metrics.date_range_ms != null">, date-range {{ ms(t.data.metrics.date_range_ms) }}</template>)</template><template v-if="t.data.metrics.heap_mb != null"> · memory {{ mb(t.data.metrics.heap_mb) }}</template><template v-if="t.data.metrics.load_ms != null"> · loaded at start {{ ms(t.data.metrics.load_ms) }}</template>
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
            <h2 class="text-sm font-semibold">Measured on this server</h2>
            <p class="mt-0.5 text-xs text-muted">
              Every presentation proved through the phone and verified, {{ data.measurements.runs }} so far, kept in
              <span class="font-mono">{{ data.measurements.file }}</span> across restarts and demo resets. Prove: the phone's work (device signature, witness and proof; BBS: the whole presentation), run here on the server's CPU. Times: median, then the range.
            </p>
            <p class="mt-0.5 text-xs text-muted">This server: {{ machineText(data.measurements.machine) }}.</p>
          </div>
          <button v-if="data.measurements.runs" class="btn-ghost text-xs" data-clear-measurements @click="clearMeasurements">{{ clearing ? 'Click again to clear' : 'Clear' }}</button>
        </div>
        <p v-if="!data.measurements.rows.length" class="px-5 py-6 text-center text-sm text-muted">No measurements yet. Each verified presentation adds one.</p>
        <div v-else class="overflow-x-auto">
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
                <th class="px-3 py-2 font-medium">Process peak</th>
                <th v-if="machines.length > 1" class="px-3 py-2 font-medium">Machine</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              <tr v-for="r in data.measurements.rows" :key="`${r.proof_system}|${r.statement}|${r.threads}|${machineText(r.machine)}`" class="align-top" :data-measured-row="r.proof_system">
                <td class="px-5 py-2.5 font-medium">{{ r.label }}</td>
                <td class="px-3 py-2.5">{{ r.statement }}</td>
                <td class="px-3 py-2.5 tabular-nums" data-measured-threads>{{ r.threads ?? '–' }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ r.runs }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ msSpread(r.prove) }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ msSpread(r.verify) }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ kbSpread(r.proof_bytes) }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ kbSpread(r.presentation_bytes) }}</td>
                <td class="px-3 py-2.5 tabular-nums" data-measured-heap>{{ mbSpread(r.prove_heap_mb) }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ mbSpread(r.verify_heap_mb) }}</td>
                <td class="px-3 py-2.5 tabular-nums">{{ r.peak_memory_mb ? mb(r.peak_memory_mb) : '–' }}</td>
                <td v-if="machines.length > 1" class="px-3 py-2.5">{{ machineText(r.machine) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="border-t border-line px-5 py-2 text-[11px] leading-snug text-muted">
          Prover and verifier memory: the most heap the addon's own code held during the step, above what it held before (for a circuit, witness and proof together); the keys and circuits loaded at start are not in it. Process peak: the server process's peak resident set during a step (Linux only), so it includes Node and all three addons.
        </p>
      </section>
    </main>
  </div>
</template>
