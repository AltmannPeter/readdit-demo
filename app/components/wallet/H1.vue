<script setup lang="ts">
// SIROS ID page heading (src/components/Shared/Heading.tsx): text-2xl bold, then a divider.
withDefaults(defineProps<{ heading: string; hr?: boolean }>(), { hr: true })
</script>

<template>
  <div>
    <div class="flex items-center justify-between gap-3">
      <h1 class="mb-2 text-2xl leading-tight font-bold text-sid-gray-900">{{ heading }}</h1>
      <slot />
    </div>
    <hr v-if="hr" class="mb-2 border-t border-sid-gray-400" />
  </div>
</template>
