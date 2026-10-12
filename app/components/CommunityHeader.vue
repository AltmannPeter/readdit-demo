<script setup lang="ts">
import type { Community } from '#shared/types'
import { COMMUNITY_PREFIX } from '#shared/data/communities'

const props = defineProps<{ community: Community; canJoin: boolean }>()
const { joined, toggle } = useJoined()
</script>

<template>
  <div class="card overflow-hidden">
    <div class="h-20" :style="{ background: `linear-gradient(120deg, ${props.community.color}, ${props.community.color}99)` }" />
    <div class="flex items-end gap-4 px-4 pb-4">
      <CommunityAvatar :community="props.community" size="lg" class="-mt-8 ring-4 ring-surface" />
      <div class="min-w-0 flex-1 pt-2">
        <h1 class="flex items-center gap-2 text-2xl font-bold">
          {{ COMMUNITY_PREFIX }}{{ props.community.slug }}
          <AgeBadge v-if="props.community.gate" :gate="props.community.gate" />
        </h1>
        <p class="text-sm text-muted">{{ props.community.name }}</p>
      </div>
      <button
        v-if="props.canJoin"
        :class="joined[props.community.slug] ? 'btn-outline' : 'btn-primary'"
        @click="toggle(props.community.slug)"
      >
        {{ joined[props.community.slug] ? 'Joined' : 'Join' }}
      </button>
    </div>
  </div>
</template>
