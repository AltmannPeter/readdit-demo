<script setup lang="ts">
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'
import { findPost, countComments } from '#shared/data/posts'

const route = useRoute()
const community = computed(() => findCommunity(String(route.params.slug)))
const post = computed(() => {
  const p = findPost(String(route.params.id))
  return p && p.community === community.value?.slug ? p : undefined
})
const { access } = useCommunityAccess(community)
const { account, memberships, refresh } = useAccount()
/** Who comments: the community account in a community with its own pseudonym, else the Community account. */
const author = computed(() => (community.value?.nymHost ? memberships.value[community.value.slug]?.handle : account.value?.handle) ?? null)

interface UserComment {
  id: string
  handle: string
  body: string
  at: number
}
const { data: userComments, refresh: refreshComments } = await useFetch<UserComment[]>('/api/comments', {
  query: { postId: computed(() => String(route.params.id)) },
  default: () => [],
})
const draft = ref('')
const posting = ref(false)
const postError = ref('')
async function submit() {
  const body = draft.value.trim()
  if (!body || posting.value) return
  posting.value = true
  postError.value = ''
  try {
    await $fetch('/api/comments', { method: 'POST', body: { postId: route.params.id, body } })
    draft.value = ''
    await refreshComments()
  } catch (e) {
    const status = (e as { statusCode?: number }).statusCode
    // 401: logged out or banned meanwhile; 403: the age check no longer settles this community.
    if (status === 401 || status === 403) await refresh()
    postError.value = status === 401 ? 'Log in to comment.' : 'Your comment was not posted. Try again.'
  } finally {
    posting.value = false
  }
}
const totalComments = computed(() => (post.value ? countComments(post.value.comments) : 0) + userComments.value.length)

useHead(() => ({ title: post.value ? `${post.value.title} · Community` : 'Community' }))
</script>

<template>
  <div v-if="!community || !post" class="card p-8 text-center text-muted">Post not found.</div>
  <div v-else class="flex gap-6">
    <div class="min-w-0 flex-1 space-y-4">
      <GateNotice v-if="access !== 'allow'" :community="community" :state="access" />
      <template v-else>
        <article class="card px-5 py-4">
          <div class="flex items-center gap-1.5 text-xs text-muted">
            <CommunityAvatar :community="community" size="sm" />
            <NuxtLink :to="`/c/${community.slug}`" class="font-semibold text-ink hover:underline">
              {{ COMMUNITY_PREFIX }}{{ community.slug }}
            </NuxtLink>
            <span aria-hidden="true">·</span>
            <span>u/{{ post.author }}</span>
            <span aria-hidden="true">·</span>
            <span>{{ formatAgo(post.hoursAgo) }}</span>
          </div>
          <h1 class="mt-2 text-2xl leading-snug font-bold">{{ post.title }}</h1>
          <p class="mt-3 leading-relaxed">{{ post.body }}</p>
          <div class="mt-4 flex items-center gap-2">
            <VoteControl :id="post.id" :score="post.score" />
            <span class="btn-ghost">
              <AppIcon name="comment" class="size-4" />
              {{ totalComments }}
            </span>
            <button class="btn-ghost">
              <AppIcon name="share" class="size-4" />
              Share
            </button>
          </div>
        </article>

        <div class="card px-5 py-4">
          <form @submit.prevent="submit">
            <textarea
              v-model="draft"
              rows="3"
              maxlength="2000"
              :placeholder="author ? `Comment as u/${author}` : 'Log in to comment'"
              :disabled="!author"
              class="w-full resize-none rounded-lg border border-line bg-surface px-3 py-2 text-sm outline-none focus:border-brand disabled:bg-canvas"
            />
            <div class="mt-2 flex items-center justify-end gap-3">
              <p v-if="postError" class="text-sm text-adult" role="alert">{{ postError }}</p>
              <button class="btn-primary" type="submit" :disabled="!author || !draft.trim() || posting">Comment</button>
            </div>
          </form>
          <div class="mt-4 space-y-5">
            <CommentItem v-for="c in post.comments" :key="c.id" :comment="c" />
            <CommentItem
              v-for="c in userComments"
              :key="c.id"
              :comment="{ id: c.id, author: c.handle, body: c.body, score: 1, hoursAgo: 0 }"
            />
            <p v-if="!totalComments" class="py-4 text-center text-sm text-muted">No comments yet.</p>
          </div>
        </div>
      </template>
    </div>
    <aside class="hidden w-80 shrink-0 @7xl:block">
      <AboutCard :community="community" />
    </aside>
  </div>
</template>
