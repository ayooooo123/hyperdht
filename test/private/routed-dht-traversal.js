'use strict'

const test = require('brittle')
const b4a = require('b4a')
const DHT = require('dht-rpc')

const { COMMANDS } = require('../../lib/constants')
const { createQueryContexts } = require('../../lib/private/query-context')
const { RoutedDHTIO } = require('../../lib/private/routed-dht-io')
const { encodeDestinationRef } = require('../../lib/private/routed-dht')
const { BRANCH_CLASS, M3_MESSAGE_ID } = require('../../lib/private/protocol')
const { FakeRouteAuthority } = require('./fake-route-authority')

const DIRECT_FIELDS = ['udx', 'socket', 'host', 'port', 'bootstrap', 'nodes']

function bytes(byte, size) {
  return b4a.alloc(size, byte)
}

function trappedPrototype(fields = DIRECT_FIELDS) {
  const prototype = {}
  for (const field of fields) {
    Object.defineProperty(prototype, field, {
      get() {
        throw new Error(`direct field read: ${field}`)
      }
    })
  }
  return prototype
}

function record(idByte, handleByte) {
  const result = Object.create(trappedPrototype())
  const id = bytes(idByte, 32)
  result.id = id
  result.destinationRef = encodeDestinationRef({ id, handle: bytes(handleByte, 130) })
  return result
}

function topology(branch) {
  const offset = branch === BRANCH_CLASS.LOOKUP ? 0x20 : 0x60
  const records = [1, 2, 3, 4, 5].map((id) => record(id, offset + id))
  return {
    records,
    seeds: [4],
    closer: [[], [0], [0], [1], [2, 3]],
    parents: [2, 3, 4, 4, 4],
    values: records.map((_, index) => bytes(offset + 0x10 + index, 8))
  }
}

function queryOptions(context, overrides = {}) {
  const options = Object.create(trappedPrototype(['udx', 'socket', 'host', 'port', 'bootstrap']))
  options.transportContext = context
  options.concurrency = 1
  options.retries = 2
  for (const [name, value] of Object.entries(overrides)) options[name] = value
  return options
}

function createHarness(t) {
  const authority = new FakeRouteAuthority()
  const contexts = createQueryContexts()
  const requested = []
  const routedDHTIO = new RoutedDHTIO({
    authority,
    contexts,
    now: () => 1_000,
    randomBytes(buffer) {
      buffer.fill(0x44)
    }
  })
  const request = routedDHTIO.request.bind(routedDHTIO)
  routedDHTIO.request = (message) => {
    requested.push({ context: message.context, destination: message.to, attempt: message.attempt })
    return request(message)
  }

  const constructorOptions = Object.create(trappedPrototype())
  constructorOptions.outboundPolicy = 'transport-only'
  constructorOptions.requestTransport = routedDHTIO
  constructorOptions.requestTimeout = 1000
  constructorOptions.concurrency = 1
  const dht = new DHT(constructorOptions)
  t.teardown(() => dht.destroy())
  return { authority, contexts, dht, requested, routedDHTIO }
}

async function runTraversal(dht, context, target = bytes(0, 32)) {
  const query = dht.query(
    { target, command: COMMANDS.IMMUTABLE_GET, value: null },
    queryOptions(context)
  )
  const replies = []
  for await (const reply of query) replies.push(reply)
  return { query, replies }
}

async function rejection(promise) {
  try {
    await promise
  } catch (error) {
    return error
  }
  return null
}

function thrown(operation) {
  try {
    operation()
  } catch (error) {
    return error
  }
  return null
}

async function waitFor(check) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (check()) return
    await Promise.resolve()
  }
  throw new Error('condition was not reached')
}

function assertOpaque(t, destination) {
  t.ok(Object.isFrozen(destination))
  t.alike(Object.keys(destination), [])
}

function containsDirectField(root) {
  const seen = new Set()
  return visit(root)

  function visit(value) {
    if (value === null || typeof value !== 'object' || seen.has(value)) return false
    seen.add(value)
    if (value instanceof Map) {
      for (const [key, entry] of value) {
        if (visit(key) || visit(entry)) return true
      }
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key === 'string' && /host|port/i.test(key)) return true
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        if (visit(descriptor.value)) return true
      }
    }
    return false
  }
}

test('direct field audit traverses nested Map data without reading inherited traps', (t) => {
  const trapped = Object.create(trappedPrototype())
  trapped.id = bytes(1, 32)

  t.ok(containsDirectField({ nested: new Map([['branch', new Map([[trapped, { host: 1 }]])]]) }))
  t.ok(containsDirectField({ nested: new Map([[{ port: 1 }, trapped]]) }))
  t.absent(containsDirectField({ nested: new Map([[trapped, { id: bytes(2, 32) }]]) }))
})

test('iterative immutable get traverses independent lookup and announce branches', async (t) => {
  const { authority, contexts, dht, requested, routedDHTIO } = createHarness(t)
  const lookup = topology(BRANCH_CLASS.LOOKUP)
  const announce = topology(BRANCH_CLASS.ANNOUNCE)
  lookup.retryOnce = [4]
  authority.installTopology(BRANCH_CLASS.LOOKUP, lookup)
  authority.installTopology(BRANCH_CLASS.ANNOUNCE, announce)

  const lookupStart = requested.length
  const lookupResult = await runTraversal(dht, contexts.immutableGet.lookup)
  const lookupRequests = requested.slice(lookupStart)
  const announceStart = requested.length
  const announceResult = await runTraversal(dht, contexts.immutableGet.announce)
  const announceRequests = requested.slice(announceStart)

  for (const result of [lookupResult, announceResult]) {
    t.is(result.replies.length, 5)
    t.alike(
      result.query.closestNodes.map((destination) => routedDHTIO.id(destination)[0]),
      [1, 2, 3, 4, 5]
    )
    for (const destination of result.query.closestNodes) assertOpaque(t, destination)
    for (const reply of result.replies) {
      t.alike(Object.keys(reply), ['rtt', 'from', 'to', 'token', 'closerNodes', 'error', 'value'])
      assertOpaque(t, reply.from)
      for (const destination of reply.closerNodes || []) assertOpaque(t, destination)
    }
  }

  t.is(lookupRequests[0].context, contexts.immutableGet.lookup)
  t.is(lookupRequests[1].context, contexts.immutableGet.lookup)
  t.is(lookupRequests[0].destination, lookupRequests[1].destination)
  t.alike(
    lookupRequests.slice(0, 2).map(({ attempt }) => attempt),
    [1, 2]
  )
  t.ok(lookupRequests.every(({ context }) => context === contexts.immutableGet.lookup))
  t.ok(announceRequests.every(({ context }) => context === contexts.immutableGet.announce))
  t.ok(lookupRequests.every(({ destination }) => Object.keys(destination).length === 0))
  t.ok(announceRequests.every(({ destination }) => Object.keys(destination).length === 0))
  t.ok(
    lookupRequests.every(
      ({ destination }) => !announceRequests.some((other) => other.destination === destination)
    )
  )

  t.is(authority.semanticEdges.length, 11)
  t.ok(
    authority.semanticEdges.every(
      (edge) =>
        Object.keys(edge).join(',') === 'branch,fromId,toId,commandId,attempt' &&
        edge.fromId.byteLength === 32 &&
        edge.toId.byteLength === 32 &&
        edge.fromId[0] >= 1 &&
        edge.fromId[0] <= 5 &&
        edge.toId[0] >= 1 &&
        edge.toId[0] <= 5 &&
        edge.commandId === M3_MESSAGE_ID.IMMUTABLE_GET_V1 &&
        (edge.branch === BRANCH_CLASS.LOOKUP || edge.branch === BRANCH_CLASS.ANNOUNCE)
    )
  )
  t.is(authority.semanticEdges.filter((edge) => edge.branch === BRANCH_CLASS.LOOKUP).length, 6)
  t.is(authority.semanticEdges.filter((edge) => edge.branch === BRANCH_CLASS.ANNOUNCE).length, 5)
  t.not(lookup.records[0].destinationRef, announce.records[0].destinationRef)
  t.not(
    lookup.records[0].destinationRef.toString('hex'),
    announce.records[0].destinationRef.toString('hex')
  )
  t.absent(containsDirectField(authority))
})

test('traversal cancellation revokes the active routed operation', async (t) => {
  const { authority, contexts, dht } = createHarness(t)
  const lookup = topology(BRANCH_CLASS.LOOKUP)
  lookup.pending = [4]
  authority.installTopology(BRANCH_CLASS.LOOKUP, lookup)

  const query = dht.query(
    { target: bytes(0, 32), command: COMMANDS.IMMUTABLE_GET, value: null },
    queryOptions(contexts.immutableGet.lookup)
  )
  const finished = query.finished()
  await waitFor(() => authority.calls.request === 1)
  query.destroy()
  await finished

  t.is(authority.calls.cancel, 1)
  t.ok(authority.requests[0].cancelled)
  t.ok(authority.requests[0].encodedRequest.every((byte) => byte === 0))
  t.ok(authority.requests[0].destinationRef.every((byte) => byte === 0))
})

test('missing and forged capabilities fail before discovery and wrong commands fail before request', async (t) => {
  const { authority, contexts, dht, routedDHTIO } = createHarness(t)
  const lookup = topology(BRANCH_CLASS.LOOKUP)
  authority.installTopology(BRANCH_CLASS.LOOKUP, lookup)
  const foreign = createQueryContexts()

  for (const context of [null, {}, foreign.immutableGet.lookup]) {
    for (const method of ['closest', 'bootstrap']) {
      const adapterError = thrown(() =>
        routedDHTIO[method]({ target: bytes(0, 32), limit: 1, context })
      )
      t.is(adapterError && adapterError.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
    }
    const query = dht.query(
      { target: bytes(0, 32), command: COMMANDS.IMMUTABLE_GET, value: null },
      queryOptions(context)
    )
    const error = await rejection(query.finished())
    t.is(error && error.code, 'TRANSPORT_INVALID_RESPONSE')
  }
  t.is(authority.calls.closest, 0)
  t.is(authority.calls.bootstrap, 0)

  const [destination] = routedDHTIO.closest({
    target: bytes(0, 32),
    limit: 1,
    context: contexts.immutableGet.lookup
  })
  const before = authority.calls.request
  const destinationTrap = Object.create(trappedPrototype())
  const error = await rejection(
    dht.request(
      {
        target: bytes(0, 32),
        command: COMMANDS.MUTABLE_GET,
        value: null
      },
      destination,
      { retry: false, transportContext: contexts.immutableGet.lookup }
    )
  )
  t.is(error && error.code, 'TRANSPORT_UNAVAILABLE')
  t.is(error && error.cause && error.cause.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
  t.is(authority.calls.request, before)

  let trappedError = null
  try {
    routedDHTIO.request({
      context: {},
      command: COMMANDS.IMMUTABLE_GET,
      to: destinationTrap,
      token: null,
      internal: false,
      target: bytes(0, 32),
      value: null,
      attempt: 1
    })
  } catch (caught) {
    trappedError = caught
  }
  t.is(trappedError && trappedError.code, 'ERR_PRIVATE_COMMAND_UNSUPPORTED')
  t.is(authority.calls.request, before)
})

test('Gate 3A creates capabilities for immutable get only', (t) => {
  const contexts = createQueryContexts()
  t.alike(Object.keys(contexts), ['immutableGet', 'classify'])
  t.alike(Object.keys(contexts.immutableGet), ['lookup', 'announce'])
  for (const name of [
    'immutablePut',
    'mutableGet',
    'mutablePut',
    'privateFindNode',
    'privateLookup',
    'privatePrepare',
    'privateAnnounce',
    'privateUnannounce',
    'peerHandshake',
    'findPeer',
    'plugin'
  ]) {
    t.is(contexts[name], undefined)
  }
})
