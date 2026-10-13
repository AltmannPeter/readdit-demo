<script setup lang="ts">
import type { DisplayCredential } from '~/wallet/holder'

// A credential card as the SIROS ID wallet draws one without issuer artwork:
// packages/wallet-common/src/functions/CustomCredentialSvg.ts (829 × 504; background colour,
// name at the top left, description below it, expiry at the bottom right). The reference sizes
// the text for a 350 px card (Arial 35, 20 and 25); this 230 px phone card uses 1.5 times that,
// so the text stays legible on a projector.
const props = defineProps<{ credential: DisplayCredential }>()
const expiry = computed(() =>
  props.credential.validUntil
    ? new Date(props.credential.validUntil).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' })
    : '',
)
</script>

<template>
  <svg viewBox="0 0 829 504" class="block w-full rounded-xl" role="img" :aria-label="`${props.credential.title}, ${props.credential.issuer}`">
    <rect width="100%" height="100%" :fill="props.credential.background" />
    <text x="50" y="96" font-family="Arial, Helvetica, sans-serif" font-size="52" :fill="props.credential.text">{{ props.credential.title }}</text>
    <text x="50" y="150" font-family="Arial, Helvetica, sans-serif" font-size="30" :fill="props.credential.text">{{ props.credential.issuer }}</text>
    <text v-if="expiry" x="790" y="440" text-anchor="end" font-family="Arial, Helvetica, sans-serif" font-size="34" :fill="props.credential.text">
      Expiry Date: {{ expiry }}
    </text>
  </svg>
</template>
