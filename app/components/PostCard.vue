<script setup lang="ts">
import type { Post } from '#shared/types'
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'
import { countComments } from '#shared/data/posts'

const props = defineProps<{ post: Post; showCommunity?: boolean }>()
const community = computed(() => findCommunity(props.post.community)!)
const commentLabel = computed(() => {
  const n = countComments(props.post.comments)
  return `${n} ${n === 1 ? 'comment' : 'comments'}`
})
const url = computed(() => `/c/${props.post.community}/${props.post.id}`)
</script>

<template>
  <article class="card flex overflow-hidden transition-colors hover:border-muted/40">
    <div class="w-12 shrink-0 bg-canvas/50 py-2">
      <VoteControl :id="post.id" :score="post.score" vertical />
    </div>
    <div class="min-w-0 flex-1 px-3 py-2.5">
      <div class="flex flex-wrap items-center gap-1.5 text-xs text-muted">
        <template v-if="props.showCommunity">
          <CommunityAvatar :community="community" size="sm" />
          <NuxtLink :to="`/c/${community.slug}`" class="font-semibold text-ink hover:underline">
            {{ COMMUNITY_PREFIX }}{{ community.slug }}
          </NuxtLink>
          <span aria-hidden="true">·</span>
        </template>
        <span>u/{{ post.author }}</span>
        <span aria-hidden="true">·</span>
        <span>{{ formatAgo(post.hoursAgo) }}</span>
      </div>

      <NuxtLink :to="url" class="block">
        <h2 class="mt-1 text-[17px] leading-snug font-semibold">{{ post.title }}</h2>
        <p class="mt-1 line-clamp-3 text-sm leading-relaxed text-ink/80">{{ post.body }}</p>
      </NuxtLink>

      <div class="mt-2 -ml-3 flex items-center">
        <NuxtLink :to="url" class="btn-ghost">
          <AppIcon name="comment" class="size-4" />
          {{ commentLabel }}
        </NuxtLink>
        <button class="btn-ghost">
          <AppIcon name="share" class="size-4" />
          Share
        </button>
      </div>
    </div>
  </article>
</template>
