<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard } from '~/wallet/holder'

// SIROS ID "Switch credential" popup (src/components/Popups/SwitchCredentialPopup.tsx), over the
// request screen: title and close, "Select the credential to use for this request.", the current
// credential, and the other matching credentials to choose from. Strings from switchCredentialPopup.
const props = defineProps<{ current: CredentialView; alternatives: CredentialView[] }>()
defineEmits<{ select: [index: number]; close: [] }>()
</script>

<template>
  <div class="absolute inset-0 z-20 flex items-center justify-center bg-black/50 px-3" role="dialog" aria-modal="true" aria-labelledby="sid-switch-title">
    <div class="max-h-[90%] w-full overflow-y-auto rounded-lg bg-white p-4 text-sid-gray-900 shadow-lg">
      <div class="mb-2 flex items-start justify-between">
        <h2 id="sid-switch-title" class="flex items-center text-lg font-bold">Switch credential</h2>
        <button class="rounded-md p-1.5 text-sid-gray-900 hover:bg-sid-gray-200" aria-label="Close" @click="$emit('close')">
          <WalletSirosIcon name="x" class="size-4" />
        </button>
      </div>
      <p class="mb-6">Select the credential to use for this request.</p>
      <h3 class="mb-2 font-semibold">Current credential</h3>
      <WalletTypeCard :credential="nymCard(props.current)" />
      <hr class="my-2 border-t border-sid-gray-400" />
      <h3 class="mt-4 mb-2 font-semibold">Select another credential</h3>
      <ul class="space-y-2">
        <li v-for="c in props.alternatives" :key="c.index">
          <WalletTypeCard :credential="nymCard(c)" clickable @select="$emit('select', c.index)" />
        </li>
      </ul>
    </div>
  </div>
</template>
