<script setup lang="ts">
import type { Community } from '#shared/types'

const props = withDefaults(defineProps<{ community: Community; size?: 'sm' | 'md' | 'lg' }>(), { size: 'md' })
const sizeClass = { sm: 'size-5 text-[10px]', md: 'size-7 text-xs', lg: 'size-16 text-2xl' }
</script>

<template>
  <span
    class="inline-flex shrink-0 items-center justify-center rounded-full font-bold text-white"
    :class="sizeClass[props.size]"
    :style="{ backgroundColor: props.community.color }"
  >
    {{ props.community.slug.charAt(0).toUpperCase() }}
  </span>
</template>
