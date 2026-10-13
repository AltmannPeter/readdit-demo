<script setup lang="ts">
// SIROS ID spinner (src/components/Shared/Spinner.jsx): a thin LoaderCircle spinning around the logo.
</script>

<template>
  <div class="relative size-28" role="status" aria-label="Loading">
    <WalletSirosIcon name="loader-circle" :stroke-width="1" class="absolute size-28 animate-spin rounded-full text-sid-brand" />
    <div class="absolute inset-0 flex scale-60 items-center justify-center">
      <WalletSirosLogo class="w-28" />
    </div>
  </div>
</template>
