<script setup lang="ts">
const props = defineProps<{ id: string; score: number; vertical?: boolean }>()
const { votes, vote } = useVotes()
const dir = computed(() => votes.value[props.id] ?? 0)
const total = computed(() => props.score + dir.value)
</script>

<template>
  <div class="flex items-center gap-1" :class="props.vertical ? 'flex-col' : 'rounded-full bg-canvas px-1'">
    <button
      class="rounded-md p-1 transition-colors hover:bg-brand-soft"
      :class="dir === 1 ? 'text-brand' : 'text-muted hover:text-brand'"
      aria-label="Upvote"
      @click.prevent="vote(props.id, 1)"
    >
      <AppIcon name="up" :filled="dir === 1" class="size-5" />
    </button>
    <span
      class="min-w-8 text-center text-xs font-bold tabular-nums"
      :class="dir === 1 ? 'text-brand' : dir === -1 ? 'text-down' : 'text-ink'"
    >
      {{ formatCount(total) }}
    </span>
    <button
      class="rounded-md p-1 transition-colors hover:bg-down/10"
      :class="dir === -1 ? 'text-down' : 'text-muted hover:text-down'"
      aria-label="Downvote"
      @click.prevent="vote(props.id, -1)"
    >
      <AppIcon name="down" :filled="dir === -1" class="size-5" />
    </button>
  </div>
</template>
