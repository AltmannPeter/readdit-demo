<script setup lang="ts">
import type { DisplayCredential } from '~/wallet/holder'
import { sidDate } from '~/wallet/holder'

// SIROS ID credential type card (src/components/Credentials/CredentialTypeCard.tsx): a square with
// the name's first letter on the card colour, the name in a pill, the issuer below it, and a
// chevron when it can be chosen. The birth date is added, as on the credential card, so that two
// credentials of the same type and issuer can be told apart; an expiry date only if there is one.
const props = defineProps<{ credential: DisplayCredential; clickable?: boolean }>()
defineEmits<{ select: [] }>()
const birth = computed(() => (props.credential.birthDate ? sidDate(props.credential.birthDate) : ''))
const expiry = computed(() => (props.credential.validUntil ? sidDate(props.credential.validUntil) : ''))
</script>

<template>
  <component
    :is="props.clickable ? 'button' : 'div'"
    class="relative flex w-full items-center justify-between gap-4 rounded-lg p-2 text-left"
    :class="props.clickable && 'cursor-pointer border border-sid-gray-700 bg-sid-gray-200 text-sid-gray-900 shadow-xs hover:brightness-[0.85]'"
    :aria-label="props.clickable ? `Select credential ${props.credential.title}${birth ? `, birth date ${birth}` : ''}` : undefined"
    @click="props.clickable && $emit('select')"
  >
    <span class="flex w-full min-w-0 items-start justify-start gap-2">
      <span
        class="flex aspect-square h-16 shrink-0 items-center justify-center rounded-md border border-sid-gray-400 p-1 text-2xl"
        :style="{ backgroundColor: props.credential.background, color: props.credential.text }"
      >
        <span class="font-bold">{{ props.credential.title.charAt(0) }}</span>
      </span>
      <span class="flex w-full min-w-0 flex-col items-start justify-start gap-1 py-1">
        <span
          class="flex w-full items-center justify-between rounded-md px-2 py-1 text-sm font-bold whitespace-nowrap"
          :style="{ backgroundColor: props.credential.background, color: props.credential.text }"
        >
          {{ props.credential.title }}
        </span>
        <span class="max-w-full truncate px-2 text-sm text-sid-gray-700">{{ props.credential.issuer }}</span>
        <span v-if="birth" class="max-w-full px-2 text-sm font-semibold text-sid-gray-900">Birth Date: {{ birth }}</span>
        <span v-if="expiry" class="max-w-full px-2 text-xs text-sid-gray-700">Expiry Date: {{ expiry }}</span>
      </span>
    </span>
    <WalletSirosIcon v-if="props.clickable" name="chevron-right" class="size-6 shrink-0" />
  </component>
</template>
