<script setup lang="ts">
// vega-prover's own phases (its tracing spans) as a table: each phase with how many times it ran,
// its time and share of its parent's, and on one thread the most heap it held. Medians over the
// profiled runs. Three levels open at first; click a phase to open or close its children.
interface Phase {
  name: string
  n: number
  ms: number
  mb: number | null
  children: Phase[]
}
const props = defineProps<{ phases: Phase[] }>()

const open = ref(new Set<string>())
const rows = computed(() => {
  const out: Array<{ p: Phase; depth: number; key: string; share: number | null; hasKids: boolean; isOpen: boolean }> = []
  const walk = (list: Phase[], depth: number, prefix: string, parentMs: number | null) => {
    for (const p of list) {
      const key = `${prefix}/${p.name}`
      const isOpen = depth < 2 ? !open.value.has(`-${key}`) : open.value.has(key)
      out.push({ p, depth, key, share: parentMs ? (100 * p.ms) / parentMs : null, hasKids: p.children.length > 0, isOpen })
      if (isOpen) walk(p.children, depth + 1, key, p.ms)
    }
  }
  walk(props.phases, 0, '', null)
  return out
})
const toggle = (key: string, depth: number) => {
  const k = depth < 2 ? `-${key}` : key
  const s = new Set(open.value)
  if (s.has(k)) s.delete(k)
  else s.add(k)
  open.value = s
}
const ms = (n: number) => (n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString('en-GB'))
</script>

<template>
  <table class="w-full text-[11px]" data-phases>
    <thead>
      <tr class="text-muted">
        <th class="py-0.5 text-left font-medium">Phase</th>
        <th class="py-0.5 text-right font-medium">Runs</th>
        <th class="py-0.5 text-right font-medium">ms</th>
        <th class="py-0.5 text-right font-medium">Share</th>
        <th class="py-0.5 text-right font-medium">Heap</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="r in rows" :key="r.key" class="hover:bg-surface">
        <td class="py-0.5 font-mono" :style="{ paddingLeft: `${r.depth * 14}px` }">
          <button v-if="r.hasKids" type="button" class="w-3 text-muted" :aria-expanded="r.isOpen" @click="toggle(r.key, r.depth)">{{ r.isOpen ? '▾' : '▸' }}</button>
          <span v-else class="inline-block w-3" />
          {{ r.p.name }}
        </td>
        <td class="py-0.5 text-right tabular-nums">{{ r.p.n }}</td>
        <td class="py-0.5 text-right tabular-nums">{{ ms(r.p.ms) }}</td>
        <td class="py-0.5 text-right tabular-nums text-muted">{{ r.share == null ? '' : `${r.share.toFixed(0)}%` }}</td>
        <td class="py-0.5 text-right tabular-nums">{{ r.p.mb == null ? '' : `${r.p.mb < 10 ? r.p.mb.toFixed(1) : Math.round(r.p.mb)} MB` }}</td>
      </tr>
    </tbody>
  </table>
</template>
