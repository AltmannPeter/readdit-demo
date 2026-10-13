<script setup lang="ts">
import type { RequestView } from '~/wallet/engine'
import { ageText } from '~/wallet/engine'

// The wallet cannot answer: the age predicate does not hold for the credential (the rulebook then
// requires access_denied with no description), or the request is unsupported. Laid out as the
// SIROS ID error screen.
const props = defineProps<{ view: RequestView }>()
defineEmits<{ close: [] }>()
const age = computed(() => props.view.items.find((i) => i.kind === 'age'))
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 px-6 text-sid-gray-900">
      <WalletSirosIcon name="circle-x" :stroke-width="1" class="mt-10 size-20 text-sid-red" />
      <div class="space-y-4 pt-6" role="alert">
        <template v-if="view.problem === 'age' && age && age.kind === 'age'">
          <h1 class="text-2xl font-bold">Requirement not met</h1>
          <p>{{ view.verifierName }} asks you to prove you are {{ ageText(age) }}. Your credential does not meet this requirement.</p>
        </template>
        <template v-else>
          <h1 class="text-2xl font-bold">Request not supported</h1>
          <p>{{ view.problem === 'no_circuit' ? 'Your wallet does not support the proof method this site asks for.' : 'Your wallet cannot answer this request.' }}</p>
        </template>
        <hr class="border-sid-gray-300" />
        <p class="text-sm font-medium">Nothing is shared with {{ view.verifierName }}.</p>
      </div>
    </div>
    <div class="flex shrink-0 flex-col bg-white px-6 pt-4 pb-8">
      <WalletButton variant="primary" size="lg" @click="$emit('close')">Close</WalletButton>
    </div>
  </div>
</template>
