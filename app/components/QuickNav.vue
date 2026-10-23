<script setup lang="ts">
// One-letter links to the demo's views, in every header: c Community, d developer view, t technical
// view, m moderation. The short routes /c, /d, /t and /m redirect to the same pages (nuxt.config).
const route = useRoute()
const LINKS = [
  { key: 'c', to: '/', title: 'Community' },
  { key: 'd', to: '/dev', title: 'Developer view' },
  { key: 't', to: '/tech', title: 'Technical view' },
  { key: 'm', to: '/mod', title: 'Moderation' },
] as const
const current = (to: string) => (to === '/' ? !['/dev', '/tech', '/mod'].includes(route.path) : route.path === to)
</script>

<template>
  <nav class="qn" aria-label="Quick links">
    <NuxtLink v-for="l in LINKS" :key="l.key" :to="l.to" :title="l.title" :aria-label="l.title" :class="{ on: current(l.to) }">{{ l.key }}</NuxtLink>
  </nav>
</template>

<style scoped>
.qn { display: inline-flex; gap: 2px; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; }
.qn a { width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; border-radius: 5px; font-size: 12px; color: #71717a; text-decoration: none; }
.qn a:hover { color: #111111; background: #f4f4f5; }
.qn a.on { color: #111111; font-weight: 700; background: #f4f4f5; }
</style>
