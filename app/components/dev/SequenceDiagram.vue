<script setup lang="ts">
// Live sequence diagram. Each event is a numbered row: an arrow between two
// lifelines (a message) or a note on one lifeline (local work). Click a row for details.
//
// Default view is greyscale. Two highlight views:
//   extensions — OID4VP extensions needed for nym_auth v0.4 zkp_req, strongly marked
//   zkp        — ZK proof generation and verification, strongly marked
// In both, the other steps shrink and fade so the whole flow fits on one screen.
import { ACTOR_LONG as actorLong, stepDelta, type Actor, type FlowEvent } from '~/dev/flow'

type View = 'all' | 'extensions' | 'zkp'
const props = defineProps<{ events: FlowEvent[]; selectedId: string | null }>()
const emit = defineEmits<{ select: [id: string] }>()
const view = defineModel<View>('view', { default: 'all' })

const lanes: Actor[] = ['browser', 'backend', 'wallet']
const center: Record<Actor, number> = { browser: 100 / 6, backend: 50, wallet: 500 / 6 }

/** Rows keep their original step number and delta even when others are hidden. */
const rows = computed(() => {
  return props.events.map((e, i) => ({ e, n: i + 1, prevAt: props.events[i - 1]?.at }))
})
function hl(e: FlowEvent) {
  if (view.value === 'extensions' && e.tag === 'openid') return 'hl-ext'
  if (view.value === 'zkp' && e.tag === 'zkp') return 'hl-zkp'
  return view.value === 'all' ? '' : 'dim'
}

function arrowStyle(e: FlowEvent) {
  const a = center[e.actor]
  const b = center[e.to!]
  return { left: `${Math.min(a, b)}%`, width: `${Math.abs(a - b)}%` }
}

const scroller = ref<HTMLElement | null>(null)
watch(view, async () => {
  await nextTick()
  scroller.value?.scrollTo({ top: 0, behavior: 'smooth' })
})
watch(
  () => props.events.length,
  async () => {
    if (view.value !== 'all') return
    await nextTick()
    scroller.value?.scrollTo({ top: scroller.value.scrollHeight, behavior: 'smooth' })
  },
)
</script>

<template>
  <div :class="['seq', `view-${view}`]">
    <div class="toolbar">
      <span class="section-label">Highlight</span>
      <button type="button" :class="['tg', 'tg-ext', { on: view === 'extensions' }]" :aria-pressed="view === 'extensions'" @click="view = view === 'extensions' ? 'all' : 'extensions'">
        OID4VP extensions
      </button>
      <button type="button" :class="['tg', 'tg-zkp', { on: view === 'zkp' }]" :aria-pressed="view === 'zkp'" @click="view = view === 'zkp' ? 'all' : 'zkp'">
        ZKP
      </button>
    </div>

    <div class="heads">
      <div v-for="l in lanes" :key="l" class="head">
        <span>{{ actorLong[l] }}</span>
      </div>
    </div>

    <div ref="scroller" class="body">
      <div class="canvas">
        <div class="lifelines track" aria-hidden="true">
          <span v-for="l in lanes" :key="l" :style="{ left: `${center[l]}%` }" />
        </div>

        <p v-if="!events.length" class="empty">Choose an age proof and press Request. The messages between the three parties appear here.</p>

        <ol class="rows">
          <li
            v-for="{ e, n, prevAt } in rows"
            :key="e.id"
            :class="['row', e.status, hl(e), { sel: e.id === selectedId, msg: !!e.to }]"
          >
            <button type="button" class="hit" :aria-label="`Step ${n}: ${e.title}`" @click="emit('select', e.id)" />
            <span class="num mono">{{ n }}</span>
            <span class="t mono">{{ stepDelta(e.at, prevAt) }}</span>

            <div class="track">
              <div v-if="e.to" :class="['arrow', center[e.to] > center[e.actor] ? 'right' : 'left']" :style="arrowStyle(e)">
                <span class="lbl">
                  <span class="lt">{{ e.title }}</span>
                  <span v-if="e.method" class="lm mono">{{ e.method }}</span>
                </span>
                <span class="line" />
                <span class="tip" />
              </div>
              <div v-else class="note" :style="{ left: `${center[e.actor]}%` }">
                {{ e.title }}
              </div>
            </div>
          </li>
        </ol>
      </div>
    </div>
  </div>
</template>

<style scoped>
.seq {
  --gutter: 84px;
  --dull: #6f6f78;
  --dull-line: #c4c4cc;
  display: flex;
  flex-direction: column;
  min-height: 0;
  height: 100%;
  background: var(--bg);
  border: 1px solid var(--line);
  overflow: hidden;
}

/* toolbar */
.toolbar { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-bottom: 1px solid var(--line); min-height: 44px; }
.toolbar .section-label { margin-right: 4px; }
.tg { font-size: 12.5px; font-weight: 500; padding: 5px 12px; border: 1px solid var(--line); background: var(--bg); color: var(--muted); }
.tg:hover { color: var(--ink-2); border-color: var(--faint); }
.tg-ext.on { background: var(--hl-ext); border-color: var(--hl-ext); color: #fff; }
.tg-zkp.on { background: var(--hl-zkp); border-color: var(--hl-zkp); color: #fff; }

/* lanes */
.heads { display: grid; grid-template-columns: repeat(3, 1fr); padding-left: var(--gutter); border-bottom: 1px solid var(--line); }
.head { display: flex; flex-direction: column; align-items: center; gap: 2px; padding: 10px 8px 9px; font-size: 13px; font-weight: 600; color: var(--ink-2); white-space: nowrap; overflow: hidden; }

.body { position: relative; flex: 1; min-height: 0; overflow: auto; }
.canvas { position: relative; min-height: 100%; padding: 10px 0 36px; }
.track { position: absolute; top: 0; bottom: 0; left: var(--gutter); right: 0; }
.lifelines { pointer-events: none; }
.lifelines span { position: absolute; top: 0; bottom: 0; border-left: 1px dashed #dcdce0; }
.empty { position: relative; text-align: center; color: var(--faint); font-size: 13.5px; margin: 80px auto; max-width: 320px; background: var(--bg); padding: 8px; }

/* rows */
.rows { list-style: none; margin: 0; padding: 0; position: relative; }
.row { position: relative; height: 48px; animation: vd-fade-up 0.25s ease-out; transition: opacity 0.2s; }
.row.msg { height: 54px; }
.hit { position: absolute; inset: 0; width: 100%; border: 0; background: transparent; z-index: 2; }
.row .track { pointer-events: none; }
.row:hover { background: #fafafa; }
.row.sel { background: #f1f1f2; }
.num { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 22px; text-align: right; font-size: 11px; color: var(--faint); }
.t { position: absolute; left: 38px; top: 50%; transform: translateY(-50%); font-size: 10.5px; color: var(--faint); }

/* arrows: neutral grey */
.arrow { position: absolute; top: 0; bottom: 0; }
.lbl { position: absolute; left: -40px; right: -40px; top: 7px; display: flex; justify-content: center; gap: 8px; align-items: baseline; white-space: nowrap; overflow: hidden; }
.lbl > span { background: var(--bg); padding: 0 4px; }
.row:hover .lbl > span { background: #fafafa; }
.row.sel .lbl > span { background: #f1f1f2; }
.lt { font-size: 12.5px; color: var(--dull); overflow: hidden; text-overflow: ellipsis; }
.lm { font-size: 10.5px; color: var(--faint); }
.line { position: absolute; left: 0; right: 0; top: 33px; height: 1px; background: var(--dull-line); }
.tip { position: absolute; top: 29px; width: 0; height: 0; border-top: 4.5px solid transparent; border-bottom: 4.5px solid transparent; }
.right .tip { right: 0; border-left: 7px solid var(--dull-line); }
.left .tip { left: 0; border-right: 7px solid var(--dull-line); }

/* notes: square, greyscale */
.note {
  position: absolute;
  top: 50%;
  transform: translate(-50%, -50%);
  max-width: 31%;
  font-size: 12.5px;
  padding: 6px 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  color: var(--dull);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.pending .note { border-style: dashed; border-color: var(--dull); animation: vd-pulse 1.4s ease-in-out infinite; }
.error .note, .error .lt { color: #3f3f46; border-color: #3f3f46; font-weight: 600; }

/* highlight views: very distinct */
.row.hl-ext, .row.hl-zkp { height: 58px; }
.row.hl-ext { --c: var(--hl-ext); background: var(--hl-ext-band); box-shadow: inset 4px 0 0 var(--c); }
.row.hl-zkp { --c: var(--hl-zkp); background: var(--hl-zkp-band); box-shadow: inset 4px 0 0 var(--c); }
.row.hl-ext .note, .row.hl-zkp .note {
  background: var(--c);
  border-color: var(--c);
  color: #fff;
  font-weight: 600;
  font-size: 13.5px;
  padding: 8px 16px;
  max-width: 40%;
  animation: none;
}
/* highlighted messages: filled label; the arrow line itself stays grey */
.row.hl-ext .lbl > span { background: var(--hl-ext-band); }
.row.hl-zkp .lbl > span { background: var(--hl-zkp-band); }
.row.hl-ext .lbl > .lt, .row.hl-zkp .lbl > .lt { background: var(--c); color: #fff; font-weight: 600; font-size: 13.5px; padding: 3px 14px; }
.row.hl-ext .lbl > .lm, .row.hl-zkp .lbl > .lm { color: var(--c); }
.row.hl-ext.msg .lbl, .row.hl-zkp.msg .lbl { top: 5px; }
.row.hl-ext.msg .line, .row.hl-zkp.msg .line { top: 40px; }
.row.hl-ext.msg .tip, .row.hl-zkp.msg .tip { top: 36px; }
.row.hl-ext .num, .row.hl-zkp .num { color: var(--c); font-weight: 700; font-size: 13px; }
.row.hl-ext .t, .row.hl-zkp .t { color: var(--c); }
/* In a highlight view, other steps shrink and fade so the whole flow fits on one screen. */
.row.dim { opacity: 0.35; height: 30px; }
.row.dim:hover { opacity: 0.65; }
.row.dim .lbl { top: 0; }
.row.dim .lt { font-size: 11.5px; }
.row.dim .line { top: 19px; }
.row.dim .tip { top: 15px; }
.row.dim .note { font-size: 11.5px; padding: 2px 10px; }
.row.dim .num, .row.dim .t { font-size: 10px; }


@media (max-width: 720px) {
  .seq { --gutter: 60px; }
  .t { display: none; }
  .head { font-size: 11.5px; white-space: normal; }
  .lm { display: none; }
}
</style>
