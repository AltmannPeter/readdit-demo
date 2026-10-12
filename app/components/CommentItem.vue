<script setup lang="ts">
import type { Comment } from '#shared/types'

defineProps<{ comment: Comment }>()
</script>

<template>
  <div class="flex gap-3">
    <UserAvatar :seed="comment.author" size="sm" class="mt-0.5" />
    <div class="min-w-0 flex-1">
      <div class="flex items-center gap-1.5 text-xs text-muted">
        <span class="font-semibold text-ink">u/{{ comment.author }}</span>
        <span aria-hidden="true">·</span>
        <span>{{ formatAgo(comment.hoursAgo) }}</span>
      </div>
      <p class="mt-1 text-sm leading-relaxed">{{ comment.body }}</p>
      <div class="mt-1 -ml-1">
        <VoteControl :id="comment.id" :score="comment.score" class="!bg-transparent" />
      </div>
      <div v-if="comment.replies?.length" class="mt-3 space-y-4 border-l-2 border-line pl-4">
        <CommentItem v-for="r in comment.replies" :key="r.id" :comment="r" />
      </div>
    </div>
  </div>
</template>
