import { assert } from 'chai'

export default async function (f: () => void | Promise<unknown>) {
  try {
    await f()
  } catch (err) {
    assert(err instanceof Error)
    assert(err.message.includes('Assert Failed'))
  }
}
