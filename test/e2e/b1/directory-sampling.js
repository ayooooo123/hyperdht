'use strict'

const test = require('../helpers/pending')
const b4a = require('b4a')
const c = require('compact-encoding')
const messages = require('../../../lib/messages')
const network = require('../helpers/network')
const { exchange } = require('../helpers/traffic')

test('B1 E7 sampling: a biased storage reply does not reduce discovery to one directory target', async (t) => {
  const h = await network(t)
  const storageNode = h.net.nodes.find((node) => node._persistent !== null)
  if (!storageNode) throw new Error('No persistent lookup responder is ready')
  const storage = storageNode._persistent
  const original = storage.onlookup
  const biased = h.relays.slice(0, 4).map((relay) =>
    c.encode(messages.peer, {
      publicKey: h.controller(relay).relayKeyPair.publicKey,
      relayAddresses: []
    })
  )
  let injected = 0
  storage.onlookup = function (request) {
    injected++
    request.reply(c.encode(messages.lookupRawReply, { peers: biased, bump: 0 }))
  }
  const source = h.create()
  const targets = new Set()
  const lookup = source.lookup
  source.lookup = function (target, ...args) {
    targets.add(b4a.toString(target, 'hex'))
    return lookup.call(this, target, ...args)
  }
  t.teardown(() => {
    storage.onlookup = original
    source.lookup = lookup
  })
  await source.privateRouting.ready()
  const server = await h.listen()
  try {
    const pair = await h.pair(server, {}, source)
    await exchange(pair.client, pair.remote)
  } catch (error) {
    t.is(error.code, 'ERR_PRIVACY_UNAVAILABLE', 'a refused route fails closed')
  }
  t.ok(injected > 0, 'a real storage node returned the biased relay set over the DHT')
  t.ok(
    targets.size >= 2,
    'the client samples distinct directory targets rather than trusting one target'
  )
  t.comment(
    'This is directory-sampling evidence only. Equal-prefix path rejection requires the C2 Linux multi-subnet gate and B1 address-policy unit tests.'
  )
})
