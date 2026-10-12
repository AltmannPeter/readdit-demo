<script setup lang="ts">
defineProps<{ title: string; text?: string }>()
</script>

<template>
  <div class="flex h-full flex-col items-center justify-center px-8 pb-10 text-center">
    <span class="size-14 animate-spin rounded-full border-4 border-w-soft border-t-w-primary" />
    <h2 class="mt-5 text-lg font-semibold text-w-ink">{{ title }}</h2>
    <p v-if="text" class="mt-1 text-sm text-w-muted">{{ text }}</p>
  </div>
</template>
