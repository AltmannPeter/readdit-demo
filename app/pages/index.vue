<script setup lang="ts">
import { findCommunity } from '#shared/data/communities'
import { posts, rank } from '#shared/data/posts'

const { account, memberships, decide } = useAccount()

// Home shows posts only to logged-in accounts, and only from communities they can already see:
// a community with its own pseudonym only with an account there.
const visible = (slug: string) => {
  const c = findCommunity(slug)
  if (c?.nymHost) return !!memberships.value[slug] && !memberships.value[slug]!.banned
  return decide(c?.gate ?? null) === 'allow'
}
const feed = computed(() => rank(posts.filter((p) => visible(p.community))))
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
