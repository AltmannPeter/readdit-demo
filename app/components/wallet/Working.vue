<script setup lang="ts">
// SIROS ID progress (PresentationSharingScreen): the spinner and a shimmering status line.
defineProps<{ title: string }>()
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 px-6 pb-16">
      <WalletSpinner />
      <p class="sid-shimmer text-center text-2xl font-bold" role="status" aria-live="polite">{{ title }}</p>
    </div>
  </div>
</template>
