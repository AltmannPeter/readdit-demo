<script setup lang="ts">
// A flame graph (icicle: callers on top) of folded stacks, `a;b;c` → samples. Each box is a
// function, as wide as the share of samples spent in it and the functions it called. Click a box
// to zoom into it, the top bar to zoom out. Rust's core, alloc and std frames are hidden unless
// asked for: they carry iterators and vectors, not the proof's own work.
const props = defineProps<{ stacks: Record<string, number> }>()

interface Node {
  name: string
  value: number
  self: number
  children: Map<string, Node>
}

const showStd = ref(false)
/** Rust's own library: core, alloc, std, methods of primitive types (`u64::wrapping_mul`, `[T]`),
 *  and the allocator shim. */
const STD = /^(core|alloc|std|__rustc)::|^(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool|char|str)::|^\[/

const tree = computed(() => {
  const root: Node = { name: 'all', value: 0, self: 0, children: new Map() }
  for (const [stack, n] of Object.entries(props.stacks)) {
    let frames = stack.split(';')
    if (!showStd.value) frames = frames.filter((f) => !STD.test(f))
    root.value += n
    let at = root
    for (const f of frames) {
      let c = at.children.get(f)
      if (!c) at.children.set(f, (c = { name: f, value: 0, self: 0, children: new Map() }))
      c.value += n
      at = c
    }
    at.self += n
  }
  return root
})

/** The path of names from the root to the box zoomed into. */
const focus = ref<string[]>([])
watch(showStd, () => (focus.value = []))
const focused = computed(() => {
  let at = tree.value
  for (const name of focus.value) {
    const c = at.children.get(name)
    if (!c) return tree.value
    at = c
  }
  return at
})

interface Box {
  name: string
  depth: number
  x: number
  w: number
  value: number
  path: string[]
}
const MAX_DEPTH = 60
const boxes = computed(() => {
  const out: Box[] = []
  const total = focused.value.value || 1
  const walk = (n: Node, depth: number, x: number, path: string[]) => {
    if (depth > MAX_DEPTH) return
    let cx = x
    for (const c of [...n.children.values()].sort((a, b) => b.value - a.value)) {
      const w = c.value / total
      if (w >= 0.002) out.push({ name: c.name, depth, x: cx, w, value: c.value, path: [...path, c.name] })
      if (w >= 0.002) walk(c, depth + 1, cx, [...path, c.name])
      cx += w
    }
  }
  walk(focused.value, 1, 0, focus.value)
  return out
})
const depth = computed(() => boxes.value.reduce((d, b) => Math.max(d, b.depth), 0))

/** The functions the samples were in when taken (self time), largest first. */
const top = computed(() => {
  const self = new Map<string, number>()
  const walk = (n: Node) => {
    if (n.self && n !== tree.value) self.set(n.name, (self.get(n.name) ?? 0) + n.self)
    for (const c of n.children.values()) walk(c)
  }
  walk(focused.value)
  const total = focused.value.value || 1
  return [...self.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, n]) => ({ name, pct: (100 * n) / total }))
})

/** The last two segments of a path: `Type::method`, `module::fn`. */
const short = (name: string) => name.split('::').slice(-2).join('::')
const HUES = ['#2563eb', '#0d7a64', '#7c3aed', '#c2410c', '#0e7490', '#a16207', '#be185d', '#4d7c0f', '#475569', '#9333ea']
const crate = (name: string) => name.split('::')[0] || name
/** Colours by crate, the crates with the most samples first, so the main ones differ. */
const palette = computed(() => {
  const total = new Map<string, number>()
  const walk = (n: Node) => {
    for (const c of n.children.values()) {
      total.set(crate(c.name), (total.get(crate(c.name)) ?? 0) + c.self)
      walk(c)
    }
  }
  walk(tree.value)
  const order = [...total.entries()].filter(([c]) => !STD.test(`${c}::`)).sort((a, b) => b[1] - a[1]).map(([c]) => c)
  return new Map(order.map((c, i) => [c, HUES[i % HUES.length]!]))
})
const colour = (name: string) => palette.value.get(crate(name)) ?? '#9ca3af'
const crates = computed(() => [...palette.value.keys()].filter((c) => boxes.value.some((b) => crate(b.name) === c)).slice(0, 10))
const ROW = 17
</script>

<template>
  <div data-flame>
    <div class="mb-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
      <button type="button" class="font-mono hover:underline" :class="focus.length ? 'text-ink' : 'text-muted'" @click="focus = []">all</button>
      <template v-for="(name, i) in focus" :key="i">
        <span class="text-muted">›</span>
        <button type="button" class="font-mono hover:underline" :title="name" @click="focus = focus.slice(0, i + 1)">{{ short(name) }}</button>
      </template>
      <label class="ml-auto flex items-center gap-1.5 text-muted">
        <input v-model="showStd" type="checkbox" data-flame-std />
        core, alloc, std
      </label>
    </div>
    <div class="max-h-[480px] overflow-y-auto rounded border border-line bg-surface">
    <div class="relative overflow-hidden" :style="{ height: `${(depth + 1) * ROW}px` }">
      <button
        type="button"
        class="absolute inset-x-0 top-0 truncate border-b border-line bg-canvas px-1 text-left font-mono text-[10px] leading-[16px]"
        :style="{ height: `${ROW}px` }"
        :title="`${focused.name}: ${focused.value} samples`"
        @click="focus = focus.slice(0, -1)"
      >
        {{ focus.length ? short(focused.name) : 'all' }} · {{ focused.value }} samples
      </button>
      <button
        v-for="b in boxes"
        :key="b.path.join(';')"
        type="button"
        class="absolute truncate border-r border-b border-white/70 px-1 text-left font-mono text-[10px] leading-[16px] text-white hover:brightness-110"
        :style="{ left: `${b.x * 100}%`, width: `${b.w * 100}%`, top: `${b.depth * ROW}px`, height: `${ROW}px`, backgroundColor: colour(b.name) }"
        :title="`${b.name}\n${b.value} samples, ${((100 * b.value) / (focused.value || 1)).toFixed(1)}%`"
        @click="focus = b.path"
      >
        {{ b.w > 0.04 ? short(b.name) : '' }}
      </button>
    </div>
    </div>
    <div class="mt-1 flex flex-wrap gap-x-3 text-[10px] text-muted">
      <span v-for="c in crates" :key="c" class="flex items-center gap-1"><span class="size-2 rounded-sm" :style="{ backgroundColor: colour(c) }" />{{ c }}</span>
    </div>
    <table class="mt-2 w-full table-fixed text-[11px]" data-flame-top>
      <thead>
        <tr class="text-muted">
          <th class="py-0.5 text-left font-medium">Running when sampled</th>
          <th class="w-16 py-0.5 text-right font-medium">Samples</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="t in top" :key="t.name">
          <td class="truncate py-0.5 pr-3 font-mono" :title="t.name">{{ t.name }}</td>
          <td class="py-0.5 text-right tabular-nums">{{ t.pct.toFixed(1) }}%</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
