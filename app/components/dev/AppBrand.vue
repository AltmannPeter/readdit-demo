<script setup lang="ts">
const cfg = useRuntimeConfig().public
</script>

<template>
  <NuxtLink to="/dev" class="brand">
    <span class="name">{{ cfg.siteName }}</span>
    <span class="host mono">{{ cfg.siteHost }}</span>
  </NuxtLink>
</template>

<style scoped>
.brand { display: inline-flex; align-items: baseline; gap: 12px; text-decoration: none; color: var(--ink); }
.name { font-weight: 650; font-size: 15px; letter-spacing: -0.01em; }
.host { font-size: 12px; color: var(--muted); }
@media (max-width: 640px) { .host { display: none; } }
</style>
