<script setup lang="ts">
const props = withDefaults(defineProps<{ seed: string; size?: 'sm' | 'md' | 'lg' }>(), { size: 'md' })
const sizeClass = { sm: 'size-6 text-[10px]', md: 'size-8 text-xs', lg: 'size-14 text-xl' }
const hue = computed(() => parseInt(props.seed.slice(-4).replace(/[^0-9a-f]/gi, '0') || '0', 16) % 360)
</script>

<template>
  <span
    class="inline-flex shrink-0 items-center justify-center rounded-full font-bold text-white uppercase"
    :class="sizeClass[props.size]"
    :style="{ backgroundColor: `hsl(${hue} 45% 45%)` }"
  >
    {{ props.seed.charAt(0) }}
  </span>
</template>
