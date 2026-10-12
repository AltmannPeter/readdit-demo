export function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}m`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`
  return String(n)
}

export function formatAgo(hours: number): string {
  if (hours < 1) return 'just now'
  if (hours < 24) return `${hours} h ago`
  const d = Math.floor(hours / 24)
  return `${d} d ago`
}
