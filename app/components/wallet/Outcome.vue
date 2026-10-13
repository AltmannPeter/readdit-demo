<script setup lang="ts">
// SIROS ID completion and error screens (PresentationCompleteScreen, PresentationErrorScreen):
// a large thin circle icon, the title, the text, and Close in the bottom bar.
const props = defineProps<{ kind: 'done' | 'declined' | 'error'; title: string; text: string }>()
defineEmits<{ close: [] }>()
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 px-6 text-sid-gray-900">
      <WalletSirosIcon
        :name="props.kind === 'done' ? 'circle-check' : 'circle-x'"
        :stroke-width="1"
        class="mt-10 size-20"
        :class="props.kind === 'done' ? 'text-sid-green' : props.kind === 'declined' ? 'text-sid-gray-700' : 'text-sid-red'"
      />
      <div class="space-y-4 pt-6" :role="props.kind === 'error' ? 'alert' : 'status'">
        <h1 class="text-2xl font-bold">{{ props.title }}</h1>
        <p>{{ props.text }}</p>
        <hr v-if="props.kind === 'done'" class="border-sid-gray-300" />
      </div>
    </div>
    <div class="flex shrink-0 flex-col bg-white px-6 pt-4 pb-8">
      <WalletButton variant="primary" size="lg" @click="$emit('close')">Close</WalletButton>
    </div>
  </div>
</template>
