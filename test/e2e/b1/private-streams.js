'use strict'

const test = require('../helpers/pending')
const network = require('../helpers/network')
const { exchange } = require('../helpers/traffic')

for (const reverse of [false, true]) {
  test(
    'B1 private-streams: 16 MiB ' +
      (reverse ? 'server-to-client' : 'client-to-server') +
      ' with unequal reverse traffic',
    async (t) => {
      const h = await network(t)
      const server = await h.listen()
      const pair = await h.pair(server)
      const sizes = reverse
        ? { up: 1048583, down: 16 * 1048576 }
        : { up: 16 * 1048576, down: 1048583 }
      t.alike(await exchange(pair.client, pair.remote, sizes), sizes)
    }
  )
}

test('B1 multiplex-isolation: four concurrent 4 MiB duplex streams complete independently', async (t) => {
  const h = await network(t)
  const server = await h.listen()
  const pairs = []
  for (let i = 0; i < 4; i++) pairs.push(await h.pair(server))
  const results = await Promise.all(
    pairs.map(({ client, remote }, index) =>
      exchange(client, remote, {
        up: 4 * 1048576,
        down: 4 * 1048576 + index + 1,
        seed: 70 + index
      })
    )
  )
  t.alike(
    results,
    pairs.map((_, index) => ({ up: 4 * 1048576, down: 4 * 1048576 + index + 1 }))
  )
})
