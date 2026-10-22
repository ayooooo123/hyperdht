'use strict'

const { plan, preflight, provision } = require('./topology')

async function main(t) {
  // Unsupported platforms register an explicit skip before reaching this path.
  preflight()
  const createNetwork = require('./network')
  const directory = require('./directory')
  const DHT = require('../../../..')
  const { deadline, exchange } = createNetwork
  const failures = []

  async function positive(h) {
    const listener = await h.listen()
    const bias = await directory(t, h)
    bias.arm()
    const paths = []
    for (let attempt = 0; attempt < 3; attempt++) {
      const before = h.selections.length
      // Enough diverse capacity must make progress, not merely return the
      // correct unavailable error. Every transfer is required to succeed.
      const pair = await h.pair(listener)
      try {
        const bytes = await exchange(pair.client, pair.remote, {
          id: 'private-diversity-' + attempt,
          seed: 17 + attempt,
          up: 49157 + attempt,
          down: 32771 + attempt
        })
        const evidence = h.assertPath(before)
        paths.push({ attempt, bytes, ...evidence })
      } finally {
        await h.closePair(pair)
      }
    }
    t.is(h.privateAccepts, 3, 'all requested private streams reached the private listener')
    return { bias: bias.evidence(), accepted: paths }
  }

  async function negative(h) {
    // Inventory is ordinary setup: every key must be announced and every relay
    // has already completed an authenticated direct handshake before this call.
    await directory(t, h)
    const keyPair = DHT.keyPair()
    let publication = 'published'
    try {
      await h.listen(h.destination, false, keyPair)
    } catch (error) {
      t.is(
        error.code,
        'ERR_PRIVACY_UNAVAILABLE',
        'insufficient diversity may reject publication, but a timeout/setup error is not success'
      )
      publication = error.code
    }
    // Also exercise source connection if publication was refused. This is the
    // private API only, with the explicit service key, never an optional/direct fallback.
    const client = h.track(h.source.privateRouting.connect(keyPair.publicKey))
    const opened = await deadline(client.opened, 'insufficient-diversity private open')
    t.is(opened, false, 'C6: eight keys in one /24 must never establish a collapsed private path')
    const errors = h.errors.get(client)
    t.ok(
      errors.some((error) => error.code === 'ERR_PRIVACY_UNAVAILABLE'),
      'closed private stream reports ERR_PRIVACY_UNAVAILABLE, not a broken fixture or timeout'
    )
    t.is(h.privateAccepts, 0, 'no private application stream was accepted')
    t.alike(h.observationErrors, [], 'negative tuple instrumentation remained usable')
    return {
      publication,
      connection: 'ERR_PRIVACY_UNAVAILABLE',
      privateAccepts: h.privateAccepts,
      tentativeSelections: h.selections.filter((row) => row.node === 'source').length
    }
  }

  for (const diverse of [true, false]) {
    const label = diverse ? 'positive-multiple-prefixes' : 'negative-one-prefix'
    let topology
    let h
    const errors = []
    let interrupted
    let stop = false
    const interruption = new Promise((resolve, reject) => {
      interrupted = reject
    })
    const onSignal = (signal) => {
      stop = true
      interrupted(new Error('interrupted by ' + signal))
    }
    const onInterrupt = () => onSignal('SIGINT')
    const onTerminate = () => onSignal('SIGTERM')
    process.once('SIGINT', onInterrupt)
    process.once('SIGTERM', onTerminate)
    // Observe rejection even if provisioning fails before the race is installed.
    interruption.catch(() => {})
    try {
      topology = provision(t, diverse)
      h = await createNetwork(t, topology.hosts)
      const exercise = async () => {
        await h.start()
        const liveness = await h.liveness()
        const counts = new Map()
        for (const relay of liveness.relayHandshakes) {
          counts.set(relay.prefix, (counts.get(relay.prefix) || 0) + 1)
        }
        t.is(counts.size, diverse ? 5 : 1, 'live relay tuples match the intended topology')
        t.ok(
          Array.from(counts.values()).includes(diverse ? 4 : 8),
          'multiple real authenticated relay identities share the same observed /24'
        )
        t.comment(
          JSON.stringify({ scenario: label, evidence: 'ordinary-setup-liveness', ...liveness })
        )
        const result = await (diverse ? positive(h) : negative(h))
        t.comment(JSON.stringify({ scenario: label, evidence: 'private-routing', ...result }))
      }
      await deadline(Promise.race([exercise(), interruption]), label, 240000)
    } catch (error) {
      errors.push(error)
    } finally {
      try {
        if (h) await h.destroy()
      } catch (error) {
        stop = true
        errors.push(error)
      } finally {
        try {
          if (topology) topology.close()
        } catch (error) {
          stop = true
          errors.push(error)
        }
        process.removeListener('SIGINT', onInterrupt)
        process.removeListener('SIGTERM', onTerminate)
      }
    }
    if (errors.length) {
      const error = new AggregateError(errors, label + ' failed (intended C6 contract)')
      failures.push(error)
      console.error(error)
    } else {
      t.comment(label + ': network exercise and cleanup joined')
    }
    if (stop) break
  }
  if (failures.length) throw new AggregateError(failures, 'peer:diversity failed')
  t.comment('IPv4 /24 local evidence only, not source certification or operator honesty')
}

const args = process.argv.slice(2)
if (args.length === 1 && args[0] === '--describe') {
  console.log(JSON.stringify(plan, null, 2))
} else {
  if (args.length) throw new Error('usage: node test/e2e/c2/diversity/index.js [--describe]')
  const test = require('brittle')
  if (process.platform !== 'linux') {
    test.skip('C2 E7: Linux multi-subnet path diversity', () => {})
  } else {
    test('C2 E7: Linux multi-subnet path diversity', { timeout: 600000 }, main)
  }
}
