<script setup lang="ts">
// The Community account of this browser: what a request created or logged in to.
const { account } = useAccount()
</script>

<template>
  <div class="acct">
    <template v-if="account">
      <p class="handle">u/{{ account.handle }}</p>
      <p v-if="account.ageProofs.length" class="detail">Age proven: {{ account.ageProofs.map((p) => p.label).join(', ') }}</p>
      <p v-else class="detail">No age proven</p>
    </template>
    <p v-else class="detail">Not logged in</p>
  </div>
</template>

<style scoped>
.acct { display: flex; flex-direction: column; gap: 2px; }
p { margin: 0; }
.handle { font-size: 13.5px; font-weight: 600; }
.detail { font-size: 12.5px; color: var(--muted); }
</style>
