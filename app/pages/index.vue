<script setup lang="ts">
import { findCommunity } from '#shared/data/communities'
import { posts, rank } from '#shared/data/posts'

const { account, decide } = useAccount()

// Home shows posts only to logged-in accounts, and only from communities they can already see.
const feed = computed(() => rank(posts.filter((p) => decide(findCommunity(p.community)?.gate ?? null) === 'allow')))
</script>

<template>
  <div class="flex gap-6">
    <div class="min-w-0 flex-1 space-y-3">
      <template v-if="account">
        <PostCard v-for="p in feed" :key="p.id" :post="p" show-community />
      </template>
      <LoginNotice v-else title="Log in to see posts" />
    </div>
    <aside class="hidden w-80 shrink-0 space-y-4 @7xl:block">
      <HomeAside />
    </aside>
  </div>
</template>
