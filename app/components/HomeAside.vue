<script setup lang="ts">
// The home page's side card: the logged-in account. Logged out, nothing.
const { account } = useAccount()
</script>

<template>
  <div v-if="account" class="card p-4">
    <div class="flex items-center gap-3">
      <UserAvatar :seed="account.handle" size="lg" />
      <div class="min-w-0">
        <p class="truncate font-semibold">u/{{ account.handle }}</p>
        <p class="text-xs text-muted">Joined {{ account.joinedAt }}</p>
      </div>
    </div>
    <dl class="mt-4 space-y-2 text-sm">
      <div class="flex items-center justify-between">
        <dt class="text-muted">Account</dt>
        <dd class="font-medium">Pseudonymous</dd>
      </div>
      <div class="flex items-center justify-between">
        <dt class="text-muted">Age checks</dt>
        <dd class="font-medium">
          <template v-if="account.ageProofs.length">
            <span v-for="p in account.ageProofs" :key="p.label + p.at" class="ml-1">{{ p.label }}</span>
          </template>
          <template v-else>None</template>
        </dd>
      </div>
    </dl>
  </div>
</template>
