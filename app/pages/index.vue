<script setup lang="ts">
import { findCommunity } from '#shared/data/communities'
import { posts, rank } from '#shared/data/posts'

const { decide } = useAccount()

// Home shows posts from communities the visitor can already see.
const feed = computed(() => rank(posts.filter((p) => decide(findCommunity(p.community)?.gate ?? null) === 'allow')))
</script>

<template>
  <div class="flex gap-6">
    <div class="min-w-0 flex-1 space-y-3">
      <PostCard v-for="p in feed" :key="p.id" :post="p" show-community />
    </div>
    <aside class="hidden w-80 shrink-0 space-y-4 xl:block">
      <HomeAside />
    </aside>
  </div>
</template>
