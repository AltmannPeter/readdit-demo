<script setup lang="ts">
import type { RequestView } from '~/wallet/engine'
import { ageText } from '~/wallet/engine'

// The wallet cannot answer: the age predicate does not hold for the credential (the rulebook then
// requires access_denied with no description), or the request is unsupported (invalid_request).
// Laid out as the SIROS ID error screen (PresentationErrorScreen). "Unsupported Request" is the
// wallet's own string (openIdCallback.errorCodes.UNSUPPORTED_FLOW_TYPE); the wallet has no string
// for an unmet age requirement, so that one is written in the same style.
// With other matching credentials, "Switch credential" (presentCredentialsFlow.overview) offers them.
const props = defineProps<{ view: RequestView; alternatives?: number }>()
defineEmits<{ close: []; switch: [] }>()
const age = computed(() => props.view.items.find((i) => i.kind === 'age'))
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 px-6 text-sid-gray-900">
      <WalletSirosIcon name="circle-x" :stroke-width="1" class="mt-10 size-20 text-sid-red" />
      <div class="space-y-4 pt-6" role="alert">
        <template v-if="view.problem === 'age' && age && age.kind === 'age'">
          <h1 class="text-2xl font-bold">Requirement Not Met</h1>
          <p>{{ view.verifierName }} asks you to prove that you are {{ ageText(age) }}. Your credential does not meet this requirement.</p>
        </template>
        <template v-else>
          <h1 class="text-2xl font-bold">Unsupported Request</h1>
          <p>This type of request is not supported.</p>
        </template>
      </div>
    </div>
    <div class="flex shrink-0 flex-col gap-4 bg-white px-6 pt-4 pb-8">
      <WalletButton v-if="props.alternatives" variant="outline" size="lg" @click="$emit('switch')">Switch credential</WalletButton>
      <WalletButton variant="primary" size="lg" @click="$emit('close')">Close</WalletButton>
    </div>
  </div>
</template>
