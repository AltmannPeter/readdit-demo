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
          </NuxtLink>
        </li>
      </ul>
    </div>
  </nav>
</template>
