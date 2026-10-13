<script setup lang="ts">
// SIROS ID progress (PresentationSharingScreen): the spinner and a shimmering status line, with
// the steps of this presentation and their measured times underneath.
export interface Step {
  label: string
  state: 'done' | 'running' | 'waiting'
  detail?: string
}
defineProps<{ title: string; steps: Step[] }>()
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 px-6 pb-10">
      <WalletSpinner />
      <p class="sid-shimmer text-center text-2xl font-bold" role="status">{{ title }}</p>
      <ul class="mt-2 w-full space-y-2 text-sm">
        <li v-for="s in steps" :key="s.label" class="flex items-start gap-2" :class="s.state === 'waiting' ? 'text-sid-gray-600' : 'text-sid-gray-900'">
          <WalletSirosIcon v-if="s.state === 'done'" name="circle-check" class="mt-px size-4 shrink-0 text-sid-green" />
          <WalletSirosIcon v-else-if="s.state === 'running'" name="loader-circle" class="mt-px size-4 shrink-0 animate-spin text-sid-brand" />
          <span v-else class="mt-px size-4 shrink-0 rounded-full border border-sid-gray-500" />
          <span class="min-w-0 flex-1">{{ s.label }}<span v-if="s.detail" class="block text-xs text-sid-gray-700">{{ s.detail }}</span></span>
        </li>
      </ul>
    </div>
  </div>
</template>
