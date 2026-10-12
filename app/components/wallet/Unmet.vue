<script setup lang="ts">
import type { RequestView } from '~/wallet/engine'
import { ageText } from '~/wallet/engine'

const props = defineProps<{ view: RequestView }>()
defineEmits<{ close: [] }>()
const age = computed(() => props.view.items.find((i) => i.kind === 'age'))
</script>

<template>
  <div class="flex h-full flex-col px-4 pb-8">
    <div class="pt-2">
      <WalletVerifierHeader :name="view.verifierName" :host="view.verifierHost" />
    </div>
    <div class="flex flex-1 flex-col items-center justify-center px-2 text-center">
      <span class="flex size-14 items-center justify-center rounded-full bg-w-soft text-w-primary">
        <AppIcon name="alert" class="size-7" />
      </span>
      <template v-if="view.problem === 'age' && age && age.kind === 'age'">
        <h2 class="mt-4 text-lg font-semibold text-w-ink">Requirement not met</h2>
        <p class="mt-2 text-sm leading-snug text-w-muted">
          {{ view.verifierName }} asks you to prove you are {{ ageText(age) }}. Your credential does not meet this requirement.
        </p>
      </template>
      <template v-else>
        <h2 class="mt-4 text-lg font-semibold text-w-ink">Request not supported</h2>
        <p class="mt-2 text-sm leading-snug text-w-muted">
          {{ view.problem === 'no_circuit' ? 'Your wallet does not support the proof method this site asks for.' : 'Your wallet cannot answer this request.' }}
        </p>
      </template>
      <p class="mt-5 rounded-xl bg-w-surface px-3 py-2 text-xs font-medium text-w-ink">Nothing is shared with {{ view.verifierName }}.</p>
    </div>
    <button class="h-12 w-full rounded-2xl bg-w-primary text-[15px] font-semibold text-white active:bg-w-strong" @click="$emit('close')">
      Close
    </button>
  </div>
</template>
