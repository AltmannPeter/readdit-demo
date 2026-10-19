import type { Comment, Post } from '../types'

export const posts: Post[] = [
  {
    id: 'p1',
    community: 'photography',
    author: 'amber-heron-7c21',
    title: 'First try at astrophotography from my balcony',
    body: '18 mm, 20 s exposure, ISO 1600. Light pollution is bad here but the Milky Way core still shows. Any tips on stacking?',
    score: 842,
    hoursAgo: 5,
    comments: [
      {
        id: 'c1',
        author: 'polar-comet-19ab',
        body: 'Take 30–40 frames and stack them. Noise drops a lot. Sequator is free.',
        score: 112,
        hoursAgo: 4,
        replies: [{ id: 'c2', author: 'amber-heron-7c21', body: 'Thanks, will try that tonight.', score: 18, hoursAgo: 3 }],
      },
    ],
  },
  {
    id: 'p2',
    community: 'photography',
    author: 'brisk-lynx-a0f3',
    title: 'Is a 50 mm prime worth it as a second lens?',
    body: 'I shoot mostly street and portraits on the kit lens. Budget is tight.',
    score: 215,
    hoursAgo: 9,
    comments: [
      { id: 'c3', author: 'gentle-pine-3e88', body: 'Yes. Cheapest real upgrade you can make.', score: 64, hoursAgo: 8 },
    ],
  },
  {
    id: 'p3',
    community: 'cooking',
    author: 'mellow-maple-51d0',
    title: 'Cardamom buns, third attempt. The dough finally works.',
    body: 'Swapped half the milk for cream and proofed overnight in the fridge. Method in the comments.',
    score: 1320,
    hoursAgo: 7,
    comments: [
      {
        id: 'c4',
        author: 'mellow-maple-51d0',
        body: '500 g flour, 75 g sugar, 2 tsp ground cardamom, 7 g dry yeast, 150 ml milk, 150 ml cream, 100 g butter. Knead 10 min, fridge overnight, shape, bake 220 °C for 8–10 min.',
        score: 301,
        hoursAgo: 7,
      },
      { id: 'c5', author: 'sunny-robin-0d4c', body: 'Overnight proof is the trick. Saving this.', score: 45, hoursAgo: 6 },
    ],
  },
  {
    id: 'p4',
    community: 'cooking',
    author: 'nimble-badger-8812',
    title: 'How do you keep rice from sticking without a rice cooker?',
    body: 'Mine always burns at the bottom.',
    score: 96,
    hoursAgo: 2,
    comments: [
      { id: 'c6', author: 'calm-fjord-6b1e', body: 'Rinse it, 1:1.25 water, lowest heat, lid on, 12 min, then 10 min off the heat without lifting the lid.', score: 38, hoursAgo: 2 },
    ],
  },
  {
    id: 'p5',
    community: 'gaming',
    author: 'rapid-falcon-c4e9',
    title: 'Co-op games that still run on an old laptop?',
    body: 'Integrated graphics, 8 GB RAM. Looking for something to play with my brother.',
    score: 433,
    hoursAgo: 3,
    comments: [
      { id: 'c7', author: 'lucky-otter-2f70', body: 'Anything 2D. Most indie co-op platformers run fine.', score: 51, hoursAgo: 3 },
    ],
  },
  {
    id: 'p6',
    community: 'gaming',
    author: 'golden-cedar-9a35',
    title: 'Finished my first 100% run. 61 hours.',
    body: 'The last collectible took me four hours on its own.',
    score: 1871,
    hoursAgo: 11,
    comments: [{ id: 'c8', author: 'hidden-willow-e612', body: 'Congrats. The last one is always the worst.', score: 88, hoursAgo: 10 }],
  },
  {
    id: 'p7',
    community: 'cycling',
    author: 'silver-spruce-4d02',
    title: 'Winter commute: studded tyres or not?',
    body: '12 km each way, mostly cleared bike paths, but black ice in the mornings.',
    score: 304,
    hoursAgo: 6,
    comments: [
      { id: 'c9', author: 'dusty-marten-71bc', body: 'Studs. One fall costs more than the tyres.', score: 97, hoursAgo: 5 },
    ],
  },
  {
    id: 'p8',
    community: 'science',
    author: 'clever-puffin-0b57',
    title: 'Why does ice float when most solids sink in their own liquid?',
    body: 'Asked my teacher and got a half answer.',
    score: 2290,
    hoursAgo: 14,
    comments: [
      { id: 'c10', author: 'quiet-river-a913', body: 'Hydrogen bonds lock water molecules into an open hexagonal lattice when it freezes. That lattice takes more space than liquid water, so ice is less dense.', score: 640, hoursAgo: 13 },
    ],
  },
  {
    id: 'p9',
    community: 'science',
    author: 'sunny-lynx-5e44',
    title: 'Simple explanation: how can you prove something without showing it?',
    body: 'Heard the term "zero-knowledge proof" in class. How can you prove a fact without revealing it?',
    score: 512,
    hoursAgo: 4,
    comments: [
      {
        id: 'c11',
        author: 'calm-heron-d270',
        body: 'You want to prove you know the code to a locked door. You go in, come out the other side, and repeat as often as asked. After enough rounds the other person is convinced, but never saw the code.',
        score: 205,
        hoursAgo: 4,
      },
    ],
  },
  {
    id: 'p10',
    community: 'teenspace',
    author: 'polar-robin-3c08',
    title: 'Anyone else doing the maths olympiad qualifier?',
    body: 'Three weeks left. Looking for people to practise with.',
    score: 188,
    hoursAgo: 3,
    comments: [{ id: 'c12', author: 'lucky-falcon-60e2', body: 'Me. Combinatorics is killing me.', score: 22, hoursAgo: 2 }],
  },
  {
    id: 'p11',
    community: 'teenspace',
    author: 'gentle-comet-b7d1',
    title: 'Tips for a first summer job interview?',
    body: 'Café job, interview on Friday. What do they usually ask?',
    score: 241,
    hoursAgo: 8,
    comments: [
      { id: 'c13', author: 'brisk-willow-1aa9', body: 'Why you want the job, when you can work, how you handle a rush. Be on time.', score: 40, hoursAgo: 7 },
    ],
  },
  {
    id: 'p12',
    community: 'teenspace',
    author: 'rapid-otter-f4c3',
    title: 'Study playlist. Add yours.',
    body: 'Mostly instrumental, about two hours. Drop suggestions.',
    score: 97,
    hoursAgo: 1,
    comments: [],
  },
  {
    id: 'p13',
    community: 'afterdark',
    author: 'mellow-fjord-2e6a',
    title: 'Bars that still have live jazz on weeknights?',
    body: 'Looking for somewhere quiet enough to talk.',
    score: 77,
    hoursAgo: 5,
    comments: [],
  },
  {
    id: 'p14',
    community: 'afterdark',
    author: 'golden-badger-90d5',
    title: 'Good wine under 15 euros',
    body: 'Post your best value bottles.',
    score: 410,
    hoursAgo: 10,
    comments: [],
  },
  {
    id: 'p20',
    community: 'france',
    author: 'calm-otter-3e81',
    title: 'How do you follow the debates in the Assemblée?',
    body: 'I watch the sessions on LCP but they are long. Any summaries that stay neutral?',
    score: 1_204,
    hoursAgo: 3,
    comments: [
      { id: 'c20', author: 'dry-fern-71c0', body: 'The official compte rendu is dry but complete. I read it on Fridays.', score: 230, hoursAgo: 2 },
    ],
  },
  {
    id: 'p21',
    community: 'france',
    author: 'quiet-plover-0b9d',
    title: 'Why do so few young people vote in municipal elections?',
    body: 'Genuine question. I am 24 and most of my friends skip them. What would make you vote locally?',
    score: 640,
    hoursAgo: 7,
    comments: [],
  },
  {
    id: 'p22',
    community: 'france',
    author: 'amber-ibex-55f2',
    title: 'Rents in medium-sized cities',
    body: 'Our rent went up again this year. Is it the same where you live, and what is your city doing about it?',
    score: 418,
    hoursAgo: 12,
    comments: [
      { id: 'c21', author: 'slow-heron-9a04', body: 'Same here. The town council held a public meeting on it last month.', score: 77, hoursAgo: 10 },
    ],
  },
]

export function findPost(id: string): Post | undefined {
  return posts.find((p) => p.id === id)
}

export function countComments(list: Comment[]): number {
  return list.reduce((n, c) => n + 1 + countComments(c.replies ?? []), 0)
}

/** Simple hot ranking: score decays with age. */
export function rank(list: Post[]): Post[] {
  return [...list].sort((a, b) => b.score / (b.hoursAgo + 2) ** 1.5 - a.score / (a.hoursAgo + 2) ** 1.5)
}
