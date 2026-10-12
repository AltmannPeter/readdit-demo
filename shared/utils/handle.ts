const ADJECTIVES = [
  'quiet', 'amber', 'brisk', 'calm', 'clever', 'dusty', 'gentle', 'golden',
  'hidden', 'lucky', 'mellow', 'nimble', 'polar', 'rapid', 'silver', 'sunny',
]
const NOUNS = [
  'otter', 'heron', 'lynx', 'maple', 'falcon', 'pine', 'badger', 'comet',
  'willow', 'marten', 'river', 'spruce', 'puffin', 'fjord', 'robin', 'cedar',
]

/** Readable display handle derived from the hex pseudonym. */
export function handleFromPseudonym(hex: string): string {
  const b0 = parseInt(hex.slice(0, 2), 16)
  const b1 = parseInt(hex.slice(2, 4), 16)
  return `${ADJECTIVES[b0 % ADJECTIVES.length]}-${NOUNS[b1 % NOUNS.length]}-${hex.slice(4, 8)}`
}

export function shortHex(hex: string): string {
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`
}
