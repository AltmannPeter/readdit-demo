<script setup lang="ts">
defineProps<{ name: string; host: string }>()
</script>

<template>
  <div class="flex items-center gap-3 rounded-2xl bg-w-surface p-3">
    <span class="flex size-10 shrink-0 items-center justify-center rounded-xl bg-w-soft text-base font-bold text-w-strong">
      {{ name.charAt(0).toUpperCase() }}
    </span>
    <div class="min-w-0">
      <p class="truncate text-[15px] font-semibold text-w-ink">{{ name }}</p>
      <p class="flex items-center gap-1 text-xs text-w-muted">
        <AppIcon name="shield" class="size-3.5 text-w-primary" />
        {{ host }}
      </p>
    </div>
  </div>
</template>
