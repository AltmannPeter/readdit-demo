<script setup lang="ts">
// What the site accepts now, as /tech switches it. Read only: the switches stay in /tech.
import { PROOF_SYSTEMS, SYSTEM_REGISTRY } from '#shared/registry/circuits'

const { state } = useDevFlow()
const systems = computed(() =>
  PROOF_SYSTEMS.map((p) => ({
    id: p.id,
    label: p.label,
    format: p.source_format,
    on: state.value.accepted.includes(p.id),
    ids: SYSTEM_REGISTRY.filter((e) => e.proof_system === p.id).map((e) => e.system_id),
  })),
)
const none = computed(() => !state.value.accepted.length)
</script>

<template>
  <div class="info">
    <ul>
      <li v-for="s in systems" :key="s.id" :class="{ on: s.on }">
        <span class="st mono">{{ s.on ? 'on' : 'off' }}</span>
        <span class="txt">
          <span class="name">{{ s.label }}</span>
          <span class="detail mono">{{ s.format }} · {{ s.ids.join(', ') }}</span>
        </span>
      </li>
    </ul>
    <p v-if="none" class="warn">Nothing is accepted, so no request starts.</p>
    <p class="note">
      {{ state.multithreading ? 'Vega and BBS on every core.' : 'One thread.' }}
      Switch in <NuxtLink to="/tech">/tech</NuxtLink>.
    </p>
  </div>
</template>

<style scoped>
.info { display: flex; flex-direction: column; gap: 10px; }
ul { list-style: none; margin: 0; padding: 0; border: 1px solid var(--line); border-radius: 9px; }
li { display: flex; gap: 10px; padding: 8px 10px; border-bottom: 1px solid var(--line-2); opacity: 0.5; }
li:last-child { border-bottom: 0; }
li.on { opacity: 1; }
.st { width: 22px; font-size: 11px; color: var(--faint); padding-top: 1px; }
li.on .st { color: var(--ok); font-weight: 600; }
.txt { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.name { font-size: 13px; font-weight: 500; }
.detail { font-size: 10.5px; color: var(--muted); overflow-wrap: anywhere; }
.warn { margin: 0; font-size: 12.5px; color: var(--bad); }
.note { margin: 0; font-size: 12px; color: var(--muted); }
.note a { color: var(--ink); text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--faint); }
</style>
