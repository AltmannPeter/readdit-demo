<script setup lang="ts">
// The proof systems the site accepts, grouped like the phone list (circuits over mso_mdoc, BBS
// over bbs_cd), each with its switch. The same switches as /tech (POST /api/tech/accept).
import { DEV_GROUPS, DEV_NAMES } from '~/dev/flow'

const flow = useDevFlow()
const { state } = flow
const busy = ref<string | null>(null)
/** A proof system the demo profile cannot use yet (e.g. v0.5 waiting for its circuits). */
const pending = (id: string) => state.value.profile?.pending.find((p) => p.proof_system === id) ?? null

async function toggle(id: string) {
  if (busy.value) return
  busy.value = id
  try {
    await $fetch('/api/tech/accept', { method: 'POST', body: { proof_system: id, accept: !state.value.accepted.includes(id) } })
    await flow.load()
  } finally {
    busy.value = null
  }
}
</script>

<template>
  <div class="info">
    <div v-for="g in DEV_GROUPS" :key="g.format" :class="['group', g.format]">
      <p class="group-head">{{ g.title }}</p>
      <button
        v-for="id in g.systems"
        :key="id"
        type="button"
        role="switch"
        :aria-checked="state.accepted.includes(id)"
        :class="['sys', { on: state.accepted.includes(id) }]"
        :disabled="busy === id || !!pending(id)"
        :title="pending(id)?.note ?? ''"
        :data-accept="id"
        @click="toggle(id)"
      >
        <span class="name">{{ DEV_NAMES[id] }}</span>
        <span class="st mono">{{ pending(id) ? 'pending' : state.accepted.includes(id) ? 'on' : 'off' }}</span>
      </button>
    </div>
  </div>
</template>

<style scoped>
.info { display: flex; flex-direction: column; gap: 10px; }
.group { display: flex; flex-direction: column; gap: 6px; padding: 10px; border: 1.5px solid var(--c); border-radius: 11px; background: var(--band); }
.group.mso_mdoc { --c: #1f55c8; --band: #f3f7fe; }
.group.bbs_cd { --c: #2e5e6e; --band: #f1f7f8; }
.group-head { margin: 0 2px 2px; font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--c); }
.sys { display: flex; align-items: center; justify-content: space-between; gap: 10px; width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); text-align: left; }
.sys:hover:not(:disabled) { border-color: var(--faint); }
.sys:disabled { opacity: 0.6; cursor: progress; }
.name { font-size: 13px; font-weight: 600; }
.st { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: var(--line-2); color: var(--muted); }
.sys.on .st { background: var(--ok-soft); color: var(--ok); font-weight: 700; }
</style>
