export function useJoined() {
  const joined = useState<Record<string, boolean>>('joined', () => ({}))
  const toggle = (slug: string) => (joined.value[slug] = !joined.value[slug])
  return { joined, toggle }
}
