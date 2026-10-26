<script setup lang="ts">
// In-page popup with the details of one diagram step.
// Closes on a click outside the window or on Escape. No navigation to other steps.
import { ACTOR_LONG as actorLong, TAG_LABELS as tagLabels, stepDelta, type FlowEvent } from '~/dev/flow'

const props = defineProps<{ event: FlowEvent | null; prevAt?: number; step?: number }>()
const emit = defineEmits<{ close: [] }>()
const closeBtn = ref<HTMLButtonElement | null>(null)

function onKey(e: KeyboardEvent) {
  if (props.event && e.key === 'Escape') emit('close')
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
watch(
  () => props.event?.id,
  async (id) => {
    if (id != null) {
      await nextTick()
      closeBtn.value?.focus()
    }
  },
)
</script>

<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="event" class="vd backdrop" @mousedown.self="emit('close')">
        <div class="win" role="dialog" aria-modal="true" :aria-label="event.title">
          <header>
            <div class="meta mono">
              <template v-if="step">Step {{ step }} · </template>{{ stepDelta(event.at, prevAt) }} since previous step ·
              {{ actorLong[event.actor] }}<template v-if="event.to"> → {{ actorLong[event.to] }}</template>
            </div>
            <button ref="closeBtn" type="button" class="close" @click="emit('close')">Close</button>
          </header>
          <span v-if="event.tag" :class="['tag', `tag-${event.tag}`]">{{ tagLabels[event.tag] }}</span>
          <h3>{{ event.title }}</h3>
          <p v-if="event.method" class="method mono">{{ event.method }}</p>
          <p v-if="event.plain" class="plain">{{ event.plain }}</p>
          <DevJsonView v-if="event.payload !== undefined" :value="event.payload" class="payload" />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.backdrop {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(17, 17, 17, 0.28);
  display: grid;
  place-items: center;
  padding: 24px;
}
.win {
  width: min(720px, 100%);
  max-height: min(80vh, 760px);
  overflow: auto;
  background: var(--bg);
  border-radius: 12px;
  border: 1px solid var(--line);
  box-shadow: 0 30px 80px -20px rgba(0, 0, 0, 0.35);
  padding: 20px 22px 22px;
}
header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.meta { font-size: 11.5px; color: var(--muted); }
.close { font-size: 12.5px; padding: 4px 10px; border-radius: 7px; border: 1px solid var(--line); background: var(--bg); color: var(--ink-2); }
.close:hover { border-color: var(--ink); }
h3 { margin: 10px 0 2px; font-size: 20px; font-weight: 600; letter-spacing: -0.01em; }
.tag { display: inline-block; margin-top: 12px; font-size: 11.5px; font-weight: 600; padding: 2px 8px; border: 1px solid var(--line); color: var(--muted); }
.tag-openid { background: var(--hl-ext); border-color: var(--hl-ext); color: #fff; }
.tag-zkp { background: var(--hl-zkp); border-color: var(--hl-zkp); color: #fff; }
.tag + h3 { margin-top: 6px; }
.method { margin: 0; font-size: 12px; color: var(--muted); }
.plain { margin: 8px 0 0; color: var(--ink-2); font-size: 14px; }
.payload { margin-top: 14px; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.12s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
