<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import type { CircuitEntry } from '#shared/registry/circuits'
import { DESKTOP_MACHINES, PHONE_FACTOR, SYSTEMS, UPLINK_MBPS, phaseRange, presentationRange } from '#shared/benchmarks'

definePageMeta({ layout: false })
useHead({ title: 'Technical view · Readdit' })

interface Service {
  up: boolean
  service?: string
  implementation?: string
  version?: string
  stub?: boolean
  circuits?: Array<{ circuit_id: string; proof_system: string; shapes_sha256?: string | null }>
  load_ms?: number
  threads?: number
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
  purpose: { kind: 'signin'; intent?: 'signup' | 'login'; community?: string } | { kind: 'age'; community: string }
  status: string
  createdAt: number
  query: { req: Array<{ id: string; return: string; params: Record<string, string> }> }
  offer: { circuit_id_values?: string[]; circuit_proof_system_values?: string[] }
  walletMetadata: { vp_formats_supported: { circuit_zk?: { circuit_id_values?: string[]; circuit_proof_system_values?: string[] } } } | null
  tailored: boolean
  request: Record<string, any> | null
  requestJwsBytes: number | null
  circuit: Partial<CircuitEntry> | null
  outcome: Record<string, any> | null
  completion: { ok: boolean; kind: string } | null
  trace: Trace[]
}
interface Overview {
  services: { prover: Service; verifier: Service }
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

const purposeText = (p: Session['purpose']) =>
  p.kind === 'signin'
    ? `${p.intent === 'login' ? 'Log in' : 'Sign up'}${p.community ? ` and age check, ${COMMUNITY_PREFIX}${p.community}` : ''}`
    : `Age check, ${COMMUNITY_PREFIX}${p.community}`
const kb = (n?: number | null) => (n == null ? '–' : n >= 1000 ? `${(n / 1000).toFixed(1)} kB` : `${n} B`)
const mb = (n?: number | null) => (n == null ? '' : `${Math.round(n)} MB`)
const values = (c?: { shared: number; precommitted: number; rest: number; public: number } | null) =>
  c ? `${(c.shared + c.precommitted + c.rest).toLocaleString('en-GB')} values (shared ${c.shared}, precommitted ${c.precommitted.toLocaleString('en-GB')}, rest ${c.rest.toLocaleString('en-GB')}), ${c.public} public` : ''
const ms = (n?: number | null) => (n == null ? '–' : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`)
const time = (t: number) => new Date(t).toLocaleTimeString('en-GB')
const since = (t: number) => (session.value ? `+${t - session.value.createdAt} ms` : '')
const reqText = (r: Session['query']['req'][number]) =>
  r.id === 'age_check'
    ? `age_check  ${Object.entries(r.params).map(([k, v]) => `${k} ${v}`).join(', ')}`
    : `${r.id}  ${r.params.config}${r.params.verifier_id_type ? `, ${r.params.verifier_id_type}` : ''}`
const services = computed((): Record<string, Service> => {
  const s = data.value?.services
  return s ? { prover: s.prover, verifier: s.verifier } : {}
})

/** "217–588 ms", "0.22–2.9 s" */
function span(r: readonly [number, number] | null): string {
  if (!r) return '–'
  const [a, b] = r
  if (b < 1000) return `${Math.round(a)}–${Math.round(b)} ms`
  const sec = (n: number) => (n >= 10_000 ? (n / 1000).toFixed(0) : (n / 1000).toFixed(n < 1000 ? 2 : 1))
  return `${sec(a)}–${sec(b)} s`
}
const whereText = (w: string) => (w === 'circuit provider' ? 'Circuit provider' : w === 'phone' ? 'Phone' : w === 'network' ? 'Network' : 'Readdit')

const statusTone = (s: string) =>
  s === 'completed' || s === 'verified' ? 'bg-emerald-100 text-emerald-800' : s === 'failed' ? 'bg-adult/10 text-adult' : 'bg-canvas text-muted'
</script>

<template>
  <div class="min-h-screen bg-canvas text-ink">
    <header class="border-b border-line bg-surface">
      <div class="mx-auto flex h-14 max-w-6xl items-center gap-3 px-6">
        <AppLogo class="size-7" />
        <span class="font-bold">readdit</span>
        <span class="text-muted">·</span>
        <span class="font-semibold">Technical view</span>
        <span
          v-if="data"
          class="ml-auto rounded-full px-2.5 py-1 text-xs font-semibold"
          :class="data.services.prover.up && data.services.verifier.up ? 'bg-emerald-100 text-emerald-800' : 'bg-adult/10 text-adult'"
        >
          {{ data.services.prover.up && data.services.verifier.up ? 'Vega addon, in process' : 'Vega addon not loaded' }}
        </span>
      </div>
    </header>

    <main v-if="data" class="mx-auto max-w-6xl space-y-6 px-6 py-6">
      <!-- services -->
      <section class="grid gap-4 md:grid-cols-3">
        <div v-for="(svc, name) in services" :key="name" class="card p-4">
          <div class="flex items-center gap-2">
            <span class="size-2 rounded-full" :class="svc.up ? 'bg-emerald-500' : 'bg-adult'" />
            <h2 class="text-sm font-semibold capitalize">{{ name }}</h2>
            <span v-if="svc.stub" class="ml-auto rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-semibold text-amber-800">STUB</span>
          </div>
          <template v-if="svc.up">
            <p class="mt-2 text-sm">{{ svc.implementation }}</p>
            <p class="text-xs text-muted">Version {{ svc.version }}</p>
            <p v-if="svc.load_ms != null" class="text-xs text-muted">Keys built once at start: {{ ms(svc.load_ms) }} · {{ svc.threads }} threads</p>
            <p v-if="svc.trust_anchors?.length" class="text-xs text-muted">
              Trust anchor {{ svc.trust_anchors.map((a) => a.subject).join('; ') }} · proof_time tolerance {{ svc.proof_time_tolerance_s }} s
            </p>
            <ul class="mt-2 space-y-0.5 font-mono text-[11px] text-muted">
              <li v-for="c in svc.circuits" :key="c.circuit_id">{{ c.circuit_id }} · {{ c.proof_system }}</li>
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

      <p v-if="!session" class="card p-8 text-center text-sm text-muted">No sessions yet. Start a log-in or age check on Readdit.</p>

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
            {{ time(s.createdAt) }} · {{ purposeText(s.purpose) }}
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
                    {{ ms(t.data.metrics.witness_ms) }}<template v-if="t.data.counts"> · {{ values(t.data.counts) }}</template> · proof_time {{ t.data.proof_time }}
                  </p>
                  <p v-else-if="t.step === 'prove' && t.data?.metrics" class="text-xs text-muted">
                    witness {{ ms(t.data.metrics.witness_ms) }} · prove {{ ms(t.data.metrics.prove_ms) }} · proof {{ kb(t.data.metrics.proof_bytes) }}<template v-if="t.data.metrics.peak_memory_mb"> · peak RSS of the server process {{ mb(t.data.metrics.peak_memory_mb) }}</template><template v-if="t.data.metrics.load_ms != null"> · keys built at start {{ ms(t.data.metrics.load_ms) }}</template><template v-if="t.data.metrics.threads"> · {{ t.data.metrics.threads }} threads</template>
                  </p>
                  <p v-else-if="t.step === 'response'" class="text-xs text-muted">
                    {{ kb(t.data?.bytes) }}<template v-if="t.data?.error"> · error={{ t.data.error }}</template>
                  </p>
                  <p v-else-if="(t.step === 'verify' || t.step === 'refused') && t.data?.code" class="text-xs text-adult">
                    {{ t.data.code }}<template v-if="t.data.input"> · {{ t.data.input }}</template> · {{ t.data.reason }}
                  </p>
                  <p v-else-if="t.step === 'verify' && t.data?.metrics" class="text-xs text-muted">
                    decode {{ ms(t.data.metrics.decode_ms) }} · verify {{ ms(t.data.metrics.verify_ms) }}<template v-if="t.data.metrics.load_ms != null"> · keys built at start {{ ms(t.data.metrics.load_ms) }}</template>
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
                <h2 class="text-sm font-semibold">Request (DCQL, circuit_zk)</h2>
                <button class="ml-auto text-xs font-semibold text-brand" @click="showRaw = !showRaw">{{ showRaw ? 'Summary' : 'Raw JSON' }}</button>
              </div>
              <pre v-if="showRaw" class="max-h-96 overflow-auto px-5 py-3 text-[11px] leading-relaxed">{{ JSON.stringify(session.request ?? session.query, null, 2) }}</pre>
              <ul v-else class="space-y-1 px-5 py-3 font-mono text-xs">
                <li class="text-muted">doctype eu.europa.ec.eudi.nym_auth.1</li>
                <li v-for="r in session.query.req" :key="r.return">
                  <span class="text-muted">{{ r.return }} ←</span> {{ reqText(r) }}
                </li>
              </ul>
            </section>

            <!-- negotiation -->
            <section class="card">
              <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Capability negotiation</h2>
              <dl class="divide-y divide-line text-xs">
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Readdit accepts</dt>
                  <dd class="font-mono">{{ session.offer.circuit_id_values?.join(', ') || '–' }}</dd>
                </div>
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Wallet supports</dt>
                  <dd class="font-mono">{{ session.walletMetadata?.vp_formats_supported.circuit_zk?.circuit_id_values?.join(', ') || '–' }}</dd>
                </div>
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Sent in request</dt>
                  <dd class="font-mono">
                    {{ session.request?.client_metadata?.vp_formats_supported?.circuit_zk?.circuit_id_values?.join(', ') || '–' }}
                  </dd>
                </div>
                <div class="grid grid-cols-[9rem_1fr] gap-2 px-5 py-2.5">
                  <dt class="text-muted">Circuit used</dt>
                  <dd class="font-mono">{{ session.circuit?.circuit_id ?? prove?.circuit_id ?? '–' }}</dd>
                </div>
              </dl>
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
                  <span class="text-muted">{{ p.source === 'presentation' ? 'from presentation' : 'recomputed by Readdit' }}: {{ p.derivation }}</span>
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

      <!-- estimates -->
      <section class="card">
        <div class="border-b border-line px-5 py-3">
          <h2 class="text-sm font-semibold">Estimates per step</h2>
          <p class="mt-0.5 text-xs text-muted">
            Desktop: measured on {{ DESKTOP_MACHINES }}. Phone: desktop ×{{ PHONE_FACTOR.min }}–{{ PHONE_FACTOR.max }}, not measured yet.
            Sending the proof assumes a {{ UPLINK_MBPS.min }}–{{ UPLINK_MBPS.max }} Mbit/s mobile uplink.
          </p>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead>
              <tr class="border-b border-line text-muted">
                <th class="px-5 py-2 font-medium">Step</th>
                <th class="px-3 py-2 font-medium">Runs on</th>
                <th class="px-3 py-2 font-medium">How often</th>
                <th
                  v-for="sys in SYSTEMS"
                  :key="sys.key"
                  colspan="2"
                  class="px-3 py-2 font-semibold text-ink"
                >
                  {{ sys.label }}
                </th>
              </tr>
              <tr class="border-b border-line text-muted">
                <th colspan="3" />
                <template v-for="sys in SYSTEMS" :key="sys.key">
                  <th class="px-3 py-1 font-medium">Desktop</th>
                  <th class="px-3 py-1 font-medium">Phone (est.)</th>
                </template>
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              <tr v-for="(phase, i) in SYSTEMS[0]!.phases" :key="phase.id" class="align-top">
                <td class="px-5 py-2.5 font-medium">{{ phase.label }}</td>
                <td class="px-3 py-2.5">{{ whereText(phase.where) }}</td>
                <td class="px-3 py-2.5 text-muted">{{ phase.id === 'precompute' ? 'Once per attestation' : phase.frequency }}</td>
                <template v-for="sys in SYSTEMS" :key="sys.key">
                  <td class="px-3 py-2.5 tabular-nums">
                    <template v-if="sys.phases[i]!.id === 'transfer'">–</template>
                    <template v-else>{{ sys.phases[i]!.desktopMs ? span(sys.phases[i]!.desktopMs) : 'none' }}</template>
                    <p v-if="sys.phases[i]!.detail" class="mt-0.5 max-w-48 text-[11px] leading-snug text-muted">{{ sys.phases[i]!.detail }}</p>
                  </td>
                  <td class="px-3 py-2.5 font-semibold tabular-nums">
                    {{ phase.where === 'circuit provider' ? 'not on phone' : sys.phases[i]!.desktopMs || sys.phases[i]!.id === 'transfer' ? span(phaseRange(sys, sys.phases[i]!)) : 'none' }}
                  </td>
                </template>
              </tr>
              <tr class="bg-canvas/60 align-top">
                <td class="px-5 py-2.5 font-semibold" colspan="3">Per presentation (prove, send, verify)</td>
                <template v-for="sys in SYSTEMS" :key="sys.key">
                  <td class="px-3 py-2.5" />
                  <td class="px-3 py-2.5 text-sm font-bold tabular-nums">
                    {{ span(presentationRange(sys)) }}
                  </td>
                </template>
              </tr>
            </tbody>
          </table>
        </div>
        <ul class="space-y-1 border-t border-line px-5 py-3 text-[11px] leading-snug text-muted">
          <li v-for="sys in SYSTEMS" :key="sys.key">
            <span class="font-semibold text-ink">{{ sys.label }}:</span> {{ sys.notes.join(' ') }}
          </li>
          <li>
            Sources: NYM-AUTH.md (full nym_auth statement on mdoc, Google Rust and Vega provers) and vega-caching-analysis.md
            (per-phase figures, 1920-byte MSO). Setup keys are published, so a phone only downloads them.
          </li>
        </ul>
      </section>
    </main>
  </div>
</template>
