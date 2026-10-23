<script setup lang="ts">
import { communities, COMMUNITY_PREFIX } from '#shared/data/communities'

const route = useRoute()
const isActive = (slug: string) => route.params.slug === slug
</script>

<template>
  <nav class="sticky top-[4.5rem] space-y-6 text-sm">
    <NuxtLink
      to="/"
      class="flex items-center gap-3 rounded-lg px-3 py-2 font-medium hover:bg-surface"
      :class="route.path === '/' && 'bg-surface'"
    >
      <AppIcon name="home" class="size-5" />
      Home
    </NuxtLink>

    <div>
      <h2 class="px-3 pb-2 text-xs font-semibold tracking-wide text-muted uppercase">Communities</h2>
      <ul class="space-y-0.5">
        <li v-for="c in communities" :key="c.slug">
          <NuxtLink
            :to="`/c/${c.slug}`"
            class="flex items-center gap-3 rounded-lg px-3 py-1.5 hover:bg-surface"
            :class="isActive(c.slug) && 'bg-surface font-medium'"
          >
            <CommunityAvatar :community="c" size="sm" />
            <span class="truncate">{{ COMMUNITY_PREFIX }}{{ c.slug }}</span>
            <AgeBadge v-if="c.gate" :gate="c.gate" class="ml-auto" />
            <!-- The pseudonym configuration c/france will ask for; a placeholder until the proofs support it (Peter, 2026-10-23). -->
            <span v-else-if="c.nymHost" class="ml-auto inline-flex items-center rounded-md bg-[#1d4ed8]/10 px-1.5 py-0.5 text-[11px] leading-none font-semibold text-[#1d4ed8]" data-config-badge>config: X</span>
          </NuxtLink>
        </li>
      </ul>
    </div>
  </nav>
</template>
