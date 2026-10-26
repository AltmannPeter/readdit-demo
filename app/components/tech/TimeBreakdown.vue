<script setup lang="ts">
// A Benchmark row's time: the prover's and the verifier's steps as stacked bars (medians), then,
// once the row has profiled runs (Profiling on), where the time goes inside, in views to switch
// between: the samples grouped by stage, by stage and field, by operation, by library or by
// function (app/tech/grouping.ts), the call tree as a flame graph, and for Vega its own phases.
import { group, hasStages, type View } from '~/tech/grouping'
interface StepTime {
  name: string
  ms: number
}
interface Phase {
  name: string
  n: number
  ms: number
  mb: number | null
  children: Phase[]
}
interface Side {
  runs: number
  samples: number
  other: number
  lost?: number
  hz: number | null
  stacks: Record<string, number>
  phases: Phase[] | null
}
const props = defineProps<{ row: { key: string; proof_system: string; profiled_runs: number; steps: { prove: StepTime[]; verify: StepTime[] } } }>()

const COLOURS = ['#2563eb', '#93c5fd', '#0d7a64', '#f59e0b', '#a855f7', '#ec4899']
const colour = (name: string, i: number) => (name === 'Other' ? '#d1d5db' : COLOURS[i % COLOURS.length])
const bars = computed(() => {
  const sum = (s: StepTime[]) => s.reduce((t, x) => t + x.ms, 0)
  const scale = Math.max(sum(props.row.steps.prove), sum(props.row.steps.verify), 0.1)
  return [
    { side: 'Prover', steps: props.row.steps.prove, total: sum(props.row.steps.prove), scale },
    { side: 'Verifier', steps: props.row.steps.verify, total: sum(props.row.steps.verify), scale },
  ]
})
const ms = (n: number) => `${n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString('en-GB')} ms`

interface Profile {
  runs: number
  prove: Side
  verify: Side
}
const profile = ref<Profile | null>(null)
const side = ref<'prove' | 'verify'>('prove')
type Shown = View | 'call' | 'phases'
const view = ref<Shown>(hasStages(props.row.proof_system) ? 'stages' : 'call')
const VIEWS = computed(() =>
  [
    ...(hasStages(props.row.proof_system)
      ? ([
          ['stages', 'Stages'],
          ['field', props.row.proof_system === 'longfellow-libzk-v1' ? 'Stages × circuit' : 'Stages × field'],
        ] as const)
      : []),
    ['operations', 'Operations'],
    ['libraries', 'Libraries'],
    ['functions', 'Functions'],
    ['call', 'Call tree'],
    ...(shown.value?.phases?.length ? ([['phases', 'Phases']] as const) : []),
  ] as Array<readonly [Shown, string]>,
)
async function load() {
  if (!props.row.profiled_runs) return
  try {
    profile.value = await $fetch<Profile>(`/api/tech/profile?row=${encodeURIComponent(props.row.key)}`)
  } catch {
    profile.value = null
  }
}
onMounted(load)
watch(() => props.row.profiled_runs, load)
const shown = computed(() => profile.value?.[side.value] ?? null)
watch(shown, (s) => {
  if (view.value === 'phases' && !s?.phases?.length) view.value = hasStages(props.row.proof_system) ? 'stages' : 'call'
})
/** The side's measured time (the medians of its steps), which the groups' shares divide. */
const sideMs = computed(() => bars.value[side.value === 'prove' ? 0 : 1]!.total)
const groups = computed(() =>
  shown.value && view.value !== 'call' && view.value !== 'phases' ? group(shown.value.stacks, view.value, props.row.proof_system, side.value) : [],
)
</script>

<template>
  <div data-time-breakdown>
    <div v-for="bar in bars" :key="bar.side" class="mb-2">
      <div class="flex items-baseline justify-between text-[11px]">
        <span class="font-semibold">{{ bar.side }}</span>
        <span class="tabular-nums">{{ ms(bar.total) }}</span>
      </div>
      <div class="mt-1 flex h-3 overflow-hidden rounded bg-surface">
        <span
          v-for="(s, i) in bar.steps.filter((x) => x.ms > 0)"
          :key="s.name"
          :style="{ width: `${(100 * s.ms) / bar.scale}%`, backgroundColor: colour(s.name, i) }"
          :title="`${s.name}: ${ms(s.ms)}`"
        />
      </div>
      <div class="mt-1 flex flex-wrap gap-x-4 text-[11px] text-muted">
        <span v-for="(s, i) in bar.steps" :key="s.name" class="flex items-center gap-1.5">
          <span class="size-2 rounded-sm" :style="{ backgroundColor: colour(s.name, i) }" />{{ s.name }} {{ ms(s.ms) }}
        </span>
      </div>
    </div>

    <div class="mt-3 border-t border-line pt-3" data-profile>
      <p v-if="!row.profiled_runs" class="text-[11px] text-muted" data-no-profile>No profile yet: switch on Profiling and run a proof.</p>
      <template v-else-if="profile && shown">
        <div class="mb-2 flex flex-wrap items-center gap-2 text-[11px]">
          <div class="flex overflow-hidden rounded border border-line">
            <button
              v-for="s in (['prove', 'verify'] as const)"
              :key="s"
              type="button"
              class="px-2 py-0.5"
              :class="side === s ? 'bg-ink text-surface' : 'bg-surface'"
              :data-profile-side="s"
              @click="side = s"
            >
              {{ s === 'prove' ? 'Prover' : 'Verifier' }}
            </button>
          </div>
          <div class="flex flex-wrap overflow-hidden rounded border border-line">
            <button
              v-for="[id, label] in VIEWS"
              :key="id"
              type="button"
              class="px-2 py-0.5"
              :class="view === id ? 'bg-ink text-surface' : 'bg-surface'"
              :data-profile-view="id"
              @click="view = id"
            >
              {{ label }}
            </button>
          </div>
          <span class="text-muted tabular-nums" data-profile-count>
            {{ shown.samples.toLocaleString('en-GB') }} samples, {{ profile.runs }} run{{ profile.runs === 1 ? '' : 's' }}<template v-if="shown.lost"> · {{ shown.lost }} not traced</template>
          </span>
        </div>
        <TechPhaseTree v-if="view === 'phases' && shown.phases?.length" :phases="shown.phases" />
        <p v-else-if="!shown.samples" class="text-[11px] text-muted">No samples: the step was shorter than the sampling interval.</p>
        <TechFlameGraph v-else-if="view === 'call'" :stacks="shown.stacks" />
        <TechGroupedBreakdown v-else :key="`${view}|${side}`" :groups="groups" :total="shown.samples" :ms="sideMs" />
      </template>
    </div>
  </div>
</template>
