<script setup lang="ts">
import type { Check } from '~/dev/flow'
defineProps<{ checks: Check[] }>()
const word: Record<Check['status'], string> = { pending: '', running: 'checking', pass: 'pass', fail: 'fail' }
</script>

<template>
  <ul class="checks">
    <li v-for="(c, i) in checks" :key="i" :class="c.status">
      <span class="txt">
        <span class="name">{{ c.label }}</span>
        <span class="detail">{{ c.detail }}</span>
      </span>
      <span class="st mono">{{ word[c.status] }}</span>
    </li>
  </ul>
</template>

<style scoped>
.checks { list-style: none; margin: 0; padding: 0; }
li { display: flex; justify-content: space-between; gap: 16px; padding: 9px 0; border-bottom: 1px solid var(--line-2); }
li:last-child { border-bottom: 0; }
.txt { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.name { font-size: 13.5px; font-weight: 500; }
.detail { font-size: 12px; color: var(--muted); }
.st { font-size: 11.5px; align-self: center; }
.pending { opacity: 0.4; }
.running .st { color: var(--muted); animation: vd-pulse 1s infinite; }
.pass .st { color: var(--ok); }
.fail .st, .fail .name { color: var(--bad); }
</style>
