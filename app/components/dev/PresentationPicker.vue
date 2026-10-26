<script setup lang="ts">
// Every request asks for the pseudonym; the age proof is optional.
import { AGE_OPTIONS } from '~/dev/flow'

const flow = useDevFlow()
const { state } = flow
</script>

<template>
  <div class="pp">
    <div class="seg" role="radiogroup" aria-label="Age proof">
      <button
        v-for="o in AGE_OPTIONS"
        :key="o.id"
        type="button"
        role="radio"
        :aria-checked="state.age === o.id"
        :class="{ on: state.age === o.id }"
        @click="state.age = o.id"
      >
        {{ o.label }}
      </button>
    </div>
    <button type="button" class="go" :disabled="state.starting" @click="flow.start()">Request</button>
    <p v-if="state.error" class="err">{{ state.error }}</p>
  </div>
</template>

<style scoped>
.pp { display: flex; flex-direction: column; gap: 14px; }
.seg { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2px; padding: 3px; background: var(--surface); border: 1px solid var(--line); border-radius: 9px; }
.seg button { border: 0; border-radius: 6px; background: transparent; padding: 7px 4px; font-size: 13.5px; color: var(--muted); transition: background 0.12s, color 0.12s, box-shadow 0.12s; }
.seg button:hover { color: var(--ink); }
.seg button.on { background: var(--bg); color: var(--ink); font-weight: 600; box-shadow: 0 0 0 1px var(--line), 0 1px 2px rgba(0, 0, 0, 0.06); }
.go { font-size: 14px; font-weight: 500; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--sel); background: var(--sel); color: #fff; }
.go:not(:disabled):hover { background: var(--sel-hover); border-color: var(--sel-hover); }
.go:disabled { opacity: 0.35; cursor: default; }
.err { margin: 0; font-size: 12.5px; color: var(--bad); }
</style>
