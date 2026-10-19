<script setup lang="ts">
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'
import { posts, rank } from '#shared/data/posts'

const route = useRoute()
const community = computed(() => findCommunity(String(route.params.slug)))
const { access } = useCommunityAccess(community)
const list = computed(() => rank(posts.filter((p) => p.community === community.value?.slug)))

useHead(() => ({ title: community.value ? `${COMMUNITY_PREFIX}${community.value.slug} · Readdit` : 'Readdit' }))
</script>

<template>
  <div v-if="!community" class="card p-8 text-center text-muted">Community not found.</div>
  <div v-else class="space-y-4">
    <!-- a community with its own pseudonym: joining is the wallet request, not a bookmark -->
    <CommunityHeader :community="community" :can-join="access === 'allow' && !community.nymHost" />
    <div class="flex gap-6">
      <div class="min-w-0 flex-1 space-y-3">
        <template v-if="access === 'allow'">
          <PostCard v-for="p in list" :key="p.id" :post="p" />
        </template>
        <GateNotice v-else :community="community" :state="access" />
      </div>
      <aside class="hidden w-80 shrink-0 @7xl:block">
        <AboutCard :community="community" />
      </aside>
    </div>
  </div>
</template>
