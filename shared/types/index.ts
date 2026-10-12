/** Age requirement of a community, in whole years. Either bound may be omitted. */
export interface AgeGate {
  minAge?: number
  maxAge?: number
}

/** Interval of birth dates (RFC 3339 full-date), as used by `age_check` (`ge` / `le`). */
export interface BirthDateRange {
  ge?: string
  le?: string
}

export type GateDecision = 'allow' | 'deny' | 'ask'

export interface Community {
  slug: string
  name: string
  description: string
  members: number
  online: number
  color: string
  createdYear: number
  gate: AgeGate | null
  rules: string[]
}

export interface Comment {
  id: string
  author: string
  body: string
  score: number
  hoursAgo: number
  replies?: Comment[]
}

export interface Post {
  id: string
  community: string
  author: string
  title: string
  body: string
  score: number
  hoursAgo: number
  comments: Comment[]
}

export interface AgeProof {
  label: string
  range: BirthDateRange
  at: string
}

export interface Account {
  /** 32-byte pseudonym, hex. The account identifier. */
  pseudonym: string
  handle: string
  joinedAt: string
  /** Intersection of all birth-date intervals proven so far. Time-independent. */
  birthDateRange: BirthDateRange | null
  ageProofs: AgeProof[]
}
