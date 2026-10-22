<script setup lang="ts">
// Community | Developer: the same flow, as the site's visitor sees it or as the protocol runs.
// The Community side goes back to the page last open there.
const route = useRoute()
const lastSitePath = useState('last-site-path', () => '/')
const dev = computed(() => route.path === '/dev')
</script>

<template>
  <nav class="vs" aria-label="View">
    <NuxtLink :to="lastSitePath" :class="{ on: !dev }" :aria-current="!dev ? 'page' : undefined">Community</NuxtLink>
    <NuxtLink to="/dev" :class="{ on: dev }" :aria-current="dev ? 'page' : undefined">Developer</NuxtLink>
  </nav>
</template>

<style scoped>
.vs { display: inline-flex; gap: 2px; padding: 3px; border: 1px solid #e4e4e7; border-radius: 9px; background: #fafafa; }
.vs a { padding: 4px 12px; border-radius: 6px; font-size: 13px; font-weight: 500; color: #71717a; text-decoration: none; line-height: 1.4; }
.vs a:hover { color: #111111; }
.vs a.on { background: #ffffff; color: #111111; font-weight: 600; box-shadow: 0 0 0 1px #e4e4e7, 0 1px 2px rgba(0, 0, 0, 0.06); }
</style>
