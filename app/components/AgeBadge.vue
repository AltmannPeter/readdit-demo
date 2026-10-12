<script setup lang="ts">
import type { AgeGate } from '#shared/types'

const props = defineProps<{ gate: AgeGate }>()
const adult = computed(() => isAdultGate(props.gate))
</script>

<template>
  <span
    class="inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] leading-none font-semibold"
    :class="adult ? 'bg-adult/10 text-adult' : 'bg-teen/10 text-teen'"
  >
    {{ gateLabel(props.gate) }}
  </span>
</template>
