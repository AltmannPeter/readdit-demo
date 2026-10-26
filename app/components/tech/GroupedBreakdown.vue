<script setup lang="ts">
// One profile view (app/tech/grouping.ts): the groups as a stacked bar, then as a table with
// each group's share, its time (the share of the side's measured time) and a click to open its
// parts, down to the functions.
import type { Group } from '~/tech/grouping'

const props = defineProps<{ groups: Group[]; total: number; ms: number }>()

const COLOURS = ['#2563eb', '#0d7a64', '#f59e0b', '#a855f7', '#0e7490', '#ec4899', '#a16207', '#4d7c0f', '#93c5fd', '#be185d']
const colour = (g: Group, i: number): string => (g.name === 'Other' ? '#d1d5db' : COLOURS[i % COLOURS.length]!)
// The open groups by path; kept while the page polls (the parent gives each view and side its own
// instance, so switching starts closed).
const open = ref(new Set<string>())
const toggle = (key: string) => {
  const s = new Set(open.value)
  if (s.has(key)) s.delete(key)
  else s.add(key)
  open.value = s
}
const allOpen = computed(() => rows.value.every((r) => !r.kids || r.isOpen))
function expandAll() {
  if (allOpen.value) return (open.value = new Set())
  const s = new Set<string>()
  const walk = (gs: Group[], prefix: string) => gs.forEach((g) => g.children.length && (s.add(`${prefix}/${g.name}`), walk(g.children, `${prefix}/${g.name}`)))
  walk(props.groups, '')
  open.value = s
}
const rows = computed(() => {
  const out: Array<{ g: Group; depth: number; key: string; kids: boolean; isOpen: boolean; colour: string | null }> = []
  const walk = (gs: Group[], depth: number, prefix: string) =>
    gs.forEach((g, i) => {
      const key = `${prefix}/${g.name}`
      const isOpen = open.value.has(key)
      out.push({ g, depth, key, kids: g.children.length > 0, isOpen, colour: depth === 0 ? colour(g, i) : null })
      if (isOpen) walk(g.children, depth + 1, key)
    })
  walk(props.groups, 0, '')
  return out
})
const pct = (n: number) => (100 * n) / (props.total || 1)
const ms = (n: number) => {
  const v = (props.ms * n) / (props.total || 1)
  return v < 10 ? v.toFixed(1) : Math.round(v).toLocaleString('en-GB')
}
/** A function's path shortened to its last two parts; the full path in its title. */
const short = (name: string) => (name.includes('::') ? name.split('::').slice(-2).join('::') : name)
</script>

<template>
  <div data-grouped>
    <div class="flex h-3 overflow-hidden rounded bg-surface">
      <span
        v-for="(g, i) in groups"
        :key="g.name"
        :style="{ width: `${pct(g.samples)}%`, backgroundColor: colour(g, i) }"
        :title="`${g.name}: ${pct(g.samples).toFixed(1)}%, ≈ ${ms(g.samples)} ms`"
      />
    </div>
    <table class="mt-2 w-full table-fixed text-[11px]">
      <thead>
        <tr class="text-muted">
          <th class="py-0.5 text-left font-medium">
            <button type="button" class="font-medium underline decoration-dotted underline-offset-2 hover:text-ink" data-grouped-all @click="expandAll">{{ allOpen ? 'Close all' : 'Open all' }}</button>
          </th>
          <th class="w-20 py-0.5 text-right font-medium">≈ ms</th>
          <th class="w-14 py-0.5 text-right font-medium">Share</th>
          <th class="w-28 py-0.5" />
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.key" class="hover:bg-surface" :data-group="r.depth === 0 ? r.g.name : undefined">
          <td class="truncate py-0.5" :style="{ paddingLeft: `${r.depth * 14}px` }" :title="r.g.name">
            <button v-if="r.kids" type="button" class="w-3 text-muted" :aria-expanded="r.isOpen" @click="toggle(r.key)">{{ r.isOpen ? '▾' : '▸' }}</button>
            <span v-else class="inline-block w-3" />
            <span v-if="r.colour" class="mr-1.5 inline-block size-2 rounded-sm" :style="{ backgroundColor: r.colour }" />
            <span :class="[!r.kids && r.g.name.includes('::') && 'font-mono', r.depth === 0 && 'font-semibold']">{{ r.kids ? r.g.name : short(r.g.name) }}</span>
          </td>
          <td class="py-0.5 text-right tabular-nums">{{ ms(r.g.samples) }}</td>
          <td class="py-0.5 text-right tabular-nums text-muted">{{ pct(r.g.samples).toFixed(1) }}%</td>
          <td class="py-0.5 pl-3">
            <div class="h-1.5 rounded bg-surface"><div class="h-1.5 rounded bg-ink/40" :style="{ width: `${pct(r.g.samples)}%` }" /></div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
