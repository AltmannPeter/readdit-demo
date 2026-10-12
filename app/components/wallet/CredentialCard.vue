<script setup lang="ts">
import type { DisplayCredential } from '~/wallet/holder'

const props = defineProps<{ credential: DisplayCredential; tone?: 'dark' | 'light'; compact?: boolean }>()
</script>

<template>
  <div
    class="relative overflow-hidden rounded-2xl text-white shadow-sm"
    :class="[
      props.tone === 'light' ? 'bg-gradient-to-br from-[#6f86a0] to-[#566e88]' : 'bg-gradient-to-br from-w-primary to-w-strong',
      props.compact ? 'px-3.5 py-3' : 'h-36 px-4 py-4',
    ]"
  >
    <span class="pointer-events-none absolute -top-10 -right-8 size-32 rounded-full bg-white/10" />
    <p class="text-[10px] font-medium tracking-wide text-white/70 uppercase">{{ props.credential.issuer }}</p>
    <p class="mt-1 text-[15px] leading-tight font-semibold">{{ props.credential.title }}</p>
    <p v-if="!props.compact" class="mt-0.5 text-xs text-white/75">{{ props.credential.subtitle }}</p>
    <span v-if="!props.compact" class="absolute bottom-4 left-4 h-6 w-8 rounded-md bg-white/25 ring-1 ring-white/30" />
  </div>
</template>
