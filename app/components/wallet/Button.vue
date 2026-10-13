<script setup lang="ts">
// SIROS ID button (src/components/Buttons/Button.tsx): variants and sizes as the reference
// defines them. "default" is the reference's fallback variant (brand-lighter background).
const props = withDefaults(
  defineProps<{ variant?: 'primary' | 'outline' | 'default' | 'delete'; size?: 'sm' | 'md' | 'lg'; disabled?: boolean }>(),
  { variant: 'default', size: 'md', disabled: false },
)
const VARIANTS = {
  primary: 'text-white bg-sid-brand border-sid-brand',
  outline: 'text-sid-gray-900 bg-sid-gray-200 border-sid-gray-700',
  default: 'text-sid-gray-900 bg-sid-brand-lighter border-sid-gray-600',
  delete: 'text-sid-red-light bg-sid-red-dark border-sid-red-dark',
} as const
const SIZES = { sm: 'px-3 py-1', md: 'px-4 py-2', lg: 'px-5 py-3' } as const
</script>

<template>
  <button
    class="flex flex-row flex-nowrap items-center justify-center gap-2 rounded-lg border text-center text-sm font-medium shadow-xs transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2"
    :class="[VARIANTS[props.variant], SIZES[props.size], props.disabled ? 'cursor-not-allowed opacity-75 grayscale' : 'hover:brightness-[0.85]']"
    :disabled="props.disabled"
  >
    <slot />
  </button>
</template>
