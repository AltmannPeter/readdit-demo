<script setup lang="ts">
const { account, signOut } = useAccount()
const open = ref(false)

async function logOut() {
  open.value = false
  await signOut()
  await navigateTo('/')
}
</script>

<template>
  <div v-if="account" class="relative">
    <button
      class="flex items-center gap-2 rounded-full py-1 pr-2 pl-1 hover:bg-canvas"
      :aria-expanded="open"
      @click="open = !open"
    >
      <UserAvatar :seed="account.handle" size="sm" />
      <span class="hidden text-sm font-medium sm:inline">u/{{ account.handle }}</span>
      <AppIcon name="chevron" class="size-4 text-muted" />
    </button>

    <template v-if="open">
      <div class="fixed inset-0 z-40" @click="open = false" />
      <div class="card absolute right-0 z-50 mt-2 w-64 p-2 shadow-lg">
        <div class="px-3 py-2">
          <p class="text-sm font-semibold">u/{{ account.handle }}</p>
          <p class="mt-0.5 text-xs text-muted">Pseudonymous account</p>
        </div>
        <hr class="my-1 border-line" />
        <button class="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-canvas" @click="logOut">
          <AppIcon name="logout" class="size-4 text-muted" />
          Log out
        </button>
      </div>
    </template>
  </div>
</template>
