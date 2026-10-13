export function useVotes() {
  const votes = useState<Record<string, -1 | 0 | 1>>('votes', () => ({}))
  const { account } = useAccount()
  const wallet = useWallet()

  function vote(id: string, dir: -1 | 1) {
    if (!account.value) return wallet.start({ kind: 'signin', intent: 'login' })
    votes.value[id] = votes.value[id] === dir ? 0 : dir
  }

  return { votes, vote }
}
