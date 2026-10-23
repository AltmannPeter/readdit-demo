<script setup lang="ts">
// A Benchmark row's bytes: the presentation by field (its CBOR map), and the proof by part, as
// the addon lays it out. Click a part of the proof to see its own parts. From the latest run:
// Longfellow's Merkle paths, and so its size, vary a little from proof to proof.
interface Part {
  name: string
  bytes: number
  code?: boolean
  children: Part[]
}
const props = defineProps<{ parts: { proof: Part[] | null; presentation: Part[] | null } }>()

const COLOURS = ['#2563eb', '#0d7a64', '#f59e0b', '#a855f7', '#0e7490', '#ec4899', '#a16207', '#4d7c0f', '#93c5fd', '#be185d']
const kb = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(1)} kB` : `${n} B`)
const total = (ps: Part[]) => ps.reduce((t, p) => t + p.bytes, 0)
const open = ref<string | null>(null)
const opened = computed(() => props.parts.proof?.find((p) => p.name === open.value) ?? null)
const bars = computed(() =>
  [
    { id: 'presentation', title: 'Presentation', parts: props.parts.presentation },
    { id: 'proof', title: 'Proof', parts: props.parts.proof },
    ...(opened.value?.children.length ? [{ id: 'part', title: opened.value.name, code: opened.value.code, parts: opened.value.children }] : []),
  ].filter((b): b is { id: string; title: string; code?: boolean; parts: Part[] } => !!b.parts?.length),
)
</script>

<template>
  <div data-size-breakdown>
    <p v-if="!bars.length" class="text-[11px] text-muted">No breakdown for these runs.</p>
    <div v-for="bar in bars" :key="bar.id" class="mb-3 last:mb-0" :data-size-bar="bar.id">
      <div class="flex items-baseline justify-between text-[11px]">
        <span class="font-semibold" :class="bar.code && 'font-mono'">{{ bar.title }}</span>
        <span class="tabular-nums">{{ kb(total(bar.parts)) }}</span>
      </div>
      <div class="mt-1 flex h-3 overflow-hidden rounded bg-surface">
        <span
          v-for="(p, i) in bar.parts.filter((x) => x.bytes)"
          :key="p.name"
          :style="{ width: `${(100 * p.bytes) / total(bar.parts)}%`, backgroundColor: COLOURS[i % COLOURS.length] }"
          :title="`${p.name}: ${kb(p.bytes)}`"
        />
      </div>
      <div class="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-muted">
        <template v-for="(p, i) in bar.parts" :key="p.name">
          <button
            v-if="bar.id === 'proof' && p.children.length"
            type="button"
            class="flex items-center gap-1.5 underline decoration-dotted underline-offset-2 hover:text-ink"
            :class="open === p.name && 'text-ink'"
            :aria-expanded="open === p.name"
            :data-size-part="p.name"
            @click="open = open === p.name ? null : p.name"
          >
            <span class="size-2 rounded-sm" :style="{ backgroundColor: COLOURS[i % COLOURS.length] }" /><span :class="p.code && 'font-mono'">{{ p.name }}</span> {{ kb(p.bytes) }}
          </button>
          <span v-else class="flex items-center gap-1.5">
            <span class="size-2 rounded-sm" :style="{ backgroundColor: COLOURS[i % COLOURS.length] }" /><span :class="p.code && 'font-mono'">{{ p.name }}</span> {{ kb(p.bytes) }}
          </span>
        </template>
      </div>
    </div>
  </div>
</template>
