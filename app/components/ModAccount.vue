<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'

export interface ModAccountRow {
  pseudonym: string
  handle: string
  joinedAt: string
  ageProofs: Array<{ label: string }>
  /** A community account (a community with its own pseudonym), and the Readdit account it is linked to. */
  community: string | null
  linkedTo: string | null
  /** The format of the presentation that created the account. */
  format: 'mso_mdoc' | 'bbs_cd' | null
  banned: { at: string; reason: string } | null
  comments: number
}

/** One account in /mod. `nested`: a community account shown under the Readdit account it is linked to. */
const props = defineProps<{ account: ModAccountRow; nested?: boolean }>()
const emit = defineEmits<{ ban: [pseudonym: string]; unban: [pseudonym: string] }>()
const a = computed(() => props.account)
</script>

<template>
  <div>
    <div class="flex items-center gap-3">
      <UserAvatar :seed="a.handle" size="sm" />
      <span class="min-w-0 flex-1 truncate text-sm font-semibold">
        u/{{ a.handle }}
        <span v-if="a.community" class="ml-1 rounded bg-canvas px-1.5 py-0.5 text-[11px] font-medium text-muted">{{ COMMUNITY_PREFIX }}{{ a.community }} account</span>
      </span>
      <button v-if="a.banned" class="btn-ghost" @click="emit('unban', a.pseudonym)">Unban</button>
      <button v-else class="btn-ghost !text-adult" @click="emit('ban', a.pseudonym)">Ban</button>
    </div>
    <dl class="mt-2 space-y-1 text-xs">
      <div class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Pseudonym</dt>
        <dd class="font-mono break-all">{{ a.pseudonym }}</dd>
      </div>
      <div class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Joined</dt>
        <dd>{{ a.joinedAt }}</dd>
      </div>
      <div v-if="a.format" class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Credential</dt>
        <dd>{{ a.format === 'bbs_cd' ? 'BBS (bbs_cd)' : 'mdoc (mso_mdoc)' }}</dd>
      </div>
      <div v-if="a.community && !props.nested" class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Linked to</dt>
        <dd>{{ a.linkedTo ? `u/${a.linkedTo}` : 'No Readdit account' }}</dd>
      </div>
      <div v-if="!a.community" class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Age checks</dt>
        <dd>{{ a.ageProofs.map((p) => p.label).join(', ') || 'None' }}</dd>
      </div>
      <div class="flex gap-2">
        <dt class="w-20 shrink-0 text-muted">Status</dt>
        <dd :class="a.banned ? 'font-semibold text-adult' : ''">{{ a.banned ? `Banned (${a.banned.reason})` : 'Active' }}</dd>
      </div>
    </dl>
  </div>
</template>
