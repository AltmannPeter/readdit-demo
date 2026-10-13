/** An HTTP refusal: a plain status text and a code in the error body's `data.error`, as the prover routes send. */
export function refusal(statusCode: number, error: string, statusMessage: string) {
  return createError({ statusCode, statusMessage, data: { error } })
}

/** The JSON body, or `{}` when it is missing or not an object (each route checks its fields). */
export async function readObject<T extends object>(event: Parameters<typeof readBody>[0]): Promise<Partial<T>> {
  let body: unknown
  try {
    body = await readBody(event)
  } catch {
    throw refusal(400, 'bad_request', 'The body is not valid JSON.')
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? (body as Partial<T>) : {}
}
