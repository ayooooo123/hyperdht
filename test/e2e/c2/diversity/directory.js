'use strict'

const c = require('compact-encoding')
const messages = require('../../../../lib/messages')
const { deadline, hex } = require('./network')

// Observe values only when the production async iterator actually consumes them.
// A data listener would put the query into flowing mode and change its behavior.
module.exports = async function directory(t, h) {
  const targets = new Map()
  const privateTargets = new Set()
  const consumed = []
  let phase = 'ordinary-directory-inventory'
  let injected = null
  const biasedKeys = h.relays
    .slice(0, 4)
    .map((node) => hex(h.controller(node).relayKeyPair.publicKey))
  const biased = h.relays.slice(0, 4).map((node) =>
    c.encode(messages.peer, {
      publicKey: h.controller(node).relayKeyPair.publicKey,
      relayAddresses: []
    })
  )
  const wire = c.encode(messages.lookupRawReply, { peers: biased, bump: 0 })
  const lookup = h.source.lookup
  h.patch(h.source, 'lookup', function (target, ...args) {
    const id = hex(target)
    targets.set(id, Buffer.from(target))
    const purpose = phase
    if (purpose === 'private') privateTargets.add(id)
    const query = lookup.call(this, target, ...args)
    const iterator = query[Symbol.asyncIterator]
    h.patch(query, Symbol.asyncIterator, function () {
      const inner = iterator.call(this)
      return {
        async next(...values) {
          const result = await inner.next(...values)
          try {
            if (!result.done && result.value) {
              const reply = result.value
              consumed.push({
                purpose,
                target: id,
                from: reply.from && { host: reply.from.host, port: reply.from.port },
                keys: Array.isArray(reply.peers)
                  ? reply.peers.map((peer) => hex(peer.publicKey))
                  : []
              })
            }
          } catch (error) {
            h.observationErrors.push(error)
          }
          return result
        },
        return(...values) {
          return inner.return(...values)
        },
        throw(...values) {
          return inner.throw(...values)
        },
        [Symbol.asyncIterator]() {
          return this
        }
      }
    })
    return query
  })

  await deadline(
    h.controller(h.source).descriptors.discoverRelays(),
    'ordinary directory discovery'
  )
  t.ok(targets.size, 'production discovery issued a real directory lookup')
  const announced = new Set()
  // Read actual production-selected directory targets to completion, without
  // pinning any wire version, candidate order, target constants or query options.
  for (const target of Array.from(targets.values())) {
    await deadline(
      (async () => {
        for await (const reply of h.source.lookup(target)) {
          for (const peer of reply.peers || []) announced.add(hex(peer.publicKey))
        }
      })(),
      'ordinary announcement inventory'
    )
  }
  for (const node of h.relays) {
    t.ok(
      announced.has(hex(h.controller(node).relayKeyPair.publicKey)),
      'every fixture relay key is actually announced in the live directory'
    )
  }

  const responders = h.net.nodes.filter((node) => node._persistent !== null)
  t.ok(responders.length >= 3, 'live persistent responders exist; the first root may not persist')
  const origin = h.source.address()
  for (const node of responders) {
    const storage = node._persistent
    const onlookup = storage.onlookup
    h.patch(storage, 'onlookup', function (request) {
      // Choose a genuinely persistent responder by its first real source lookup,
      // rather than guessing index zero or changing the source's candidate list.
      if (
        phase !== 'private' ||
        injected ||
        !request.target ||
        !privateTargets.has(hex(request.target)) ||
        request.from.host !== origin.host ||
        request.from.port !== origin.port
      ) {
        return onlookup.call(this, request)
      }
      const address = node.address()
      injected = {
        responder: { host: address.host, port: address.port },
        requester: { host: request.from.host, port: request.from.port },
        target: hex(request.target),
        keys: biasedKeys.slice()
      }
      // Exactly one on-wire DHT response is biased, with real, already-announced
      // keys. Every other request keeps the original production storage handler.
      return request.reply(wire)
    })
  }

  return {
    arm() {
      phase = 'private'
      h.controller(h.source).descriptors.directoryExpiresAt = 0
    },
    evidence() {
      t.ok(injected, 'one real persistent responder injected the biased lookup response')
      const matches = consumed.filter(
        (row) =>
          row.purpose === 'private' &&
          row.target === injected.target &&
          row.from &&
          row.from.host === injected.responder.host &&
          row.from.port === injected.responder.port &&
          row.keys.length === biasedKeys.length &&
          row.keys.every((key, i) => key === biasedKeys[i])
      )
      t.is(
        matches.length,
        1,
        'production discovery consumed the exact biased storage response, not just an attempted send'
      )
      return { injected, consumed: matches[0], privateLookupTargets: Array.from(privateTargets) }
    }
  }
}
