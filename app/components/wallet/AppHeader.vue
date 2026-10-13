<script setup lang="ts">
// SIROS ID header (src/components/Layout/Header.jsx): connection status on the left, the logo
// and the wallet's name on the right, a bottom border.
</script>

<template>
  <header class="flex shrink-0 items-center justify-between border-b border-sid-gray-400 bg-white p-3 text-sid-gray-900">
    <span class="relative flex items-end" aria-label="Online" role="img">
      <span v-for="h in [3, 6, 9, 12, 16]" :key="h" class="mx-px w-[3px] rounded-t-[1px] bg-current" :style="{ height: `${h}px` }" />
    </span>
    <span class="flex items-center">
      <WalletSirosLogo class="mr-2 w-8" />
      <span class="text-sm font-bold">SIROS ID</span>
    </span>
  </header>
</template>
