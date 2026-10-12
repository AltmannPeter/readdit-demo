/** Load the account before the first render (server and client). */
export default defineNuxtPlugin(async () => {
  await useAccount().refresh()
})
