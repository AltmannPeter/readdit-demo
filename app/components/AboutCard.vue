<script setup lang="ts">
import type { Community } from '#shared/types'

defineProps<{ community: Community }>()
</script>

<template>
  <div class="card overflow-hidden">
    <div class="px-4 pt-4 pb-3">
      <h2 class="text-sm font-semibold">About</h2>
      <p class="mt-2 text-sm leading-relaxed">{{ community.description }}</p>
      <dl class="mt-4 grid grid-cols-2 gap-2 text-sm">
        <div>
          <dt class="font-semibold">{{ formatCount(community.members) }}</dt>
          <dd class="text-xs text-muted">Members</dd>
        </div>
        <div>
          <dt class="flex items-center gap-1.5 font-semibold">
            <span class="size-2 rounded-full bg-emerald-500" />{{ formatCount(community.online) }}
          </dt>
          <dd class="text-xs text-muted">Online</dd>
        </div>
      </dl>
      <p class="mt-3 text-xs text-muted">Created {{ community.createdYear }}</p>
    </div>
    <div v-if="community.gate" class="flex items-center gap-2 border-t border-line px-4 py-3 text-sm">
      <AppIcon name="shield" class="size-5 shrink-0 text-brand" />
      <span>Age-checked with the EU Digital Identity Wallet</span>
    </div>
    <div class="border-t border-line px-4 py-3">
      <h2 class="text-sm font-semibold">Rules</h2>
      <ol class="mt-2 space-y-1.5 text-sm">
        <li v-for="(rule, i) in community.rules" :key="i" class="flex gap-2">
          <span class="text-muted tabular-nums">{{ i + 1 }}.</span>
          <span>{{ rule }}</span>
        </li>
      </ol>
    </div>
  </div>
</template>
