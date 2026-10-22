import type { Community } from '../types'

export const COMMUNITY_PREFIX = 'c/'

export const communities: Community[] = [
  {
    slug: 'photography',
    name: 'Photography',
    description: 'Share photos, ask for critique, talk about gear.',
    members: 48_210,
    online: 312,
    color: '#2563eb',
    createdYear: 2019,
    gate: null,
    rules: ['Post your own work.', 'Critique the photo, not the person.', 'Gear questions go in the weekly thread.'],
  },
  {
    slug: 'cooking',
    name: 'Home Cooking',
    description: 'Recipes and questions from home kitchens.',
    members: 61_530,
    online: 402,
    color: '#d97706',
    createdYear: 2018,
    gate: null,
    rules: ['Include the recipe or method.', 'No self-promotion.'],
  },
  {
    slug: 'gaming',
    name: 'Gaming',
    description: 'News, clips and recommendations.',
    members: 120_400,
    online: 1_830,
    color: '#db2777',
    createdYear: 2017,
    gate: null,
    rules: ['Mark spoilers.', 'No piracy links.'],
  },
  {
    slug: 'cycling',
    name: 'Cycling',
    description: 'Commuting, touring and repairs.',
    members: 22_950,
    online: 140,
    color: '#059669',
    createdYear: 2020,
    gate: null,
    rules: ['Be civil about other road users.', 'Repair questions: include the bike model.'],
  },
  {
    slug: 'science',
    name: 'Science',
    description: 'Ask questions, share papers, explain things.',
    members: 87_300,
    online: 650,
    color: '#0891b2',
    createdYear: 2016,
    gate: null,
    rules: ['Cite sources for claims.', 'No medical advice.'],
  },
  {
    slug: 'teenspace',
    name: 'Teen Space',
    description: 'For ages 13 to 17. School, hobbies, advice.',
    members: 15_840,
    online: 221,
    color: '#7c3aed',
    createdYear: 2024,
    gate: { minAge: 13, maxAge: 17 },
    rules: [
      'Members must be 13–17. Age is checked with your wallet.',
      'Do not share phone numbers, addresses or other contact details.',
      'Be kind.',
    ],
  },
  {
    slug: 'afterdark',
    name: 'After Dark',
    description: 'Adult discussion. Members must be 18 or older.',
    members: 33_120,
    online: 190,
    color: '#475569',
    createdYear: 2021,
    gate: { minAge: 18 },
    rules: ['Members must be 18 or older. Age is checked with your wallet.', 'Use content warnings.', 'No personal attacks.'],
  },
  {
    slug: 'france',
    name: 'France',
    description: 'French politics and society. Proof of human: one account per person, no bots.',
    members: 41_270,
    online: 388,
    color: '#1d4ed8',
    createdYear: 2025,
    gate: null,
    nymHost: 'france.community.example',
    rules: [
      'One account per person, proven with your wallet. Your c/france pseudonym is not linked to other sites.',
      'Argue the point, not the person.',
      'Sources for claims about facts.',
    ],
  },
]

/** DNS names Community signs requests for: its own and those of communities with their own pseudonym. */
export function verifierHosts(siteHost: string): string[] {
  return [siteHost, ...communities.flatMap((c) => (c.nymHost ? [c.nymHost] : []))]
}

export function findCommunity(slug: string): Community | undefined {
  return communities.find((c) => c.slug === slug)
}
