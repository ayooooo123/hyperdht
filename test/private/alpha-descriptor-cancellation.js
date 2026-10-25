'use strict'

const test = require('brittle')
const b4a = require('b4a')
const HyperDHT = require('../..')
const createTestnet = require('../../testnet')
const { COMMANDS } = require('../../lib/constants')
const { PrivateRouteError } = require('../../lib/private/errors')
const { periodOf } = require('../../lib/private/blinded-presence')
const {
  OverlayDescriptorService,
  descriptorTarget,
  encodeDescriptor
} = require('../../lib/private/overlay-descriptor-service')

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function until(predicate, milliseconds = 2000) {
  const deadline = Date.now() + milliseconds
  while (!predicate()) {
    if (Date.now() >= deadline) return false
    await delay(5)
  }
  return true
}

function operationOwner() {
  const resources = new Set()
  let failure = null
  return {
    track(resource) {
      if (failure) {
        resource.destroy(failure)
        throw failure
      }
      resources.add(resource)
      return () => resources.delete(resource)
    },
    cancel() {
      if (failure) return
      failure = PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      for (const resource of resources) resource.destroy(failure)
    }
  }
}

function observeResult(promise) {
  const result = { settled: false, value: null, error: null, done: null }
  result.done = promise.then(
    (value) => {
      result.value = value
      result.settled = true
    },
    (error) => {
      result.error = error.code || error.message
      result.settled = true
    }
  )
  return result
}

async function network(t) {
  const net = await createTestnet(5, { bootstrap: [] })
  const services = []
  const queries = []
  const held = []
  const received = []
  let phase = null
  const now = Date.now()
  const period = periodOf(now)
  const identity = HyperDHT.keyPair()
  const target = descriptorTarget(identity.publicKey, period)
  const wire = encodeDescriptor({
    destinationKeyPair: identity,
    entryRelayPublicKey: HyperDHT.keyPair().publicKey,
    destinationGuardPublicKey: HyperDHT.keyPair().publicKey,
    routeToken: b4a.alloc(32, 0x4a),
    seq: BigInt(now),
    expiresAt: BigInt(now + 120_000),
    period
  })
  function release() {
    phase = null
    for (const reply of held.splice(0)) reply()
  }
  t.teardown(
    async () => {
      release()
      for (const query of queries) query.destroy()
      await Promise.all(services.map((service) => service.destroy()))
      await Promise.allSettled(net.nodes.map((node) => node.destroy({ force: true })))
      target.fill(0)
      wire.fill(0)
      identity.secretKey.fill(0)
    },
    { force: true }
  )
  for (const node of net.nodes) {
    const service = new OverlayDescriptorService(node)
    services.push(service)
    const query = service.plugin.query.bind(service.plugin)
    service.plugin.query = (...args) => {
      const actual = query(...args)
      queries.push(actual)
      return actual
    }
    const respond = service.plugin.onrequest.bind(service.plugin)
    service.plugin.onrequest = (request, outer) => {
      if (!outer.target || !b4a.equals(outer.target, target)) return respond(request, outer)
      received.push({ node, command: request.command })
      const writeSeen = received.some((event) => event.command === 1)
      const defer =
        (phase === 'query' && request.command === 0) ||
        (phase === 'write' && request.command === 1) ||
        (phase === 'readback' && request.command === 0 && writeSeen)
      if (defer) held.push(() => respond(request, outer))
      else respond(request, outer)
    }
  }
  function liveRequests(node) {
    return node.io.inflight.filter(
      (request) =>
        request.command === COMMANDS.PLUGIN && request.target && b4a.equals(request.target, target)
    )
  }
  return {
    net,
    services,
    queries,
    held,
    received,
    target,
    wire,
    period,
    liveRequests,
    release,
    hold(value) {
      received.length = 0
      phase = value
    }
  }
}

async function settleAfterLateReplies(t, fixture, result) {
  fixture.release()
  t.ok(
    await until(() => result.settled, 10_000),
    'the attempted operation settles after deferred responders are released'
  )
  if (!result.settled) {
    for (const query of fixture.queries) query.destroy()
    for (const node of fixture.net.nodes) {
      for (const request of fixture.liveRequests(node)) request.destroy()
    }
  }
  await result.done
  t.is(
    result.error,
    'ERR_PRIVACY_UNAVAILABLE',
    'late real replies cannot turn a cancelled operation into success'
  )
  if (result.value && result.value.wire) result.value.wire.fill(0)
}

async function independentRead(t, fixture, service) {
  const descriptor = await service.getByTarget(fixture.target, fixture.period)
  t.alike(
    descriptor.wire,
    fixture.wire,
    'an independent legitimate operation still resolves the exact published descriptor'
  )
  descriptor.wire.fill(0)
}

test('descriptor owner cancellation stops a real pending plugin query before late quorum replies', async (t) => {
  t.timeout(90_000)
  const fixture = await network(t)
  const [writer, reader, independent] = fixture.services
  t.ok((await writer.put(fixture.wire)) >= 3, 'the fixture publishes to a real storage quorum')
  fixture.hold('query')
  const owner = operationOwner()
  const result = observeResult(reader.getByTarget(fixture.target, fixture.period, { owner }))
  t.ok(
    await until(() => fixture.held.length >= 2),
    'real plugin requests reach deferred storage responders'
  )
  const query = fixture.queries[fixture.queries.length - 1]
  const requests = fixture.liveRequests(reader.dht)
  t.ok(requests.length >= 2, 'the deferred query has real native requests outstanding')
  owner.cancel()
  t.ok(
    await until(() => result.settled, 1000),
    'owner cancellation settles without waiting for network retries'
  )
  t.ok(query.destroyed, 'the actual query closes, preventing later query scheduling')
  t.is(query._session.inflight.length, 0, 'the actual query session owns no remaining requests')
  t.is(
    fixture.liveRequests(reader.dht).length,
    0,
    'cancelled query traffic is removed from native IO'
  )
  await settleAfterLateReplies(t, fixture, result)
  await independentRead(t, fixture, independent)
  const alreadyCancelled = operationOwner()
  alreadyCancelled.cancel()
  const refused = observeResult(
    reader.getByTarget(fixture.target, fixture.period, { owner: alreadyCancelled })
  )
  await refused.done
  t.is(
    refused.error,
    'ERR_PRIVACY_UNAVAILABLE',
    'an already cancelled owner cannot start another operation'
  )
  if (refused.value && refused.value.wire) refused.value.wire.fill(0)
})

for (const phase of ['write', 'readback']) {
  test(
    'descriptor owner cancellation stops real pending ' +
      phase +
      ' requests without later publication phases',
    async (t) => {
      t.timeout(90_000)
      const fixture = await network(t)
      const [writer, independent] = fixture.services
      fixture.hold(phase)
      const owner = operationOwner()
      const result = observeResult(writer.put(fixture.wire, { owner }))
      t.ok(
        await until(() => fixture.held.length >= (phase === 'readback' ? 3 : 1), 10_000),
        'the requested real publication phase reaches deferred responders'
      )
      const pending = fixture.liveRequests(writer.dht)
      t.ok(
        pending.length >= (phase === 'readback' ? 3 : 1),
        'the publication phase has native requests outstanding'
      )
      const writesBeforeCancel = fixture.received.filter((event) => event.command === 1).length
      owner.cancel()
      t.ok(
        await until(() => result.settled, 1000),
        'owner cancellation settles the publication while responders remain deferred'
      )
      t.is(
        fixture.liveRequests(writer.dht).length,
        0,
        'no direct publication request remains alive in native IO'
      )
      t.ok(
        pending.every((request) => !writer.dht.io.inflight.includes(request)),
        'all original direct requests are detached from IO before slot release'
      )
      await settleAfterLateReplies(t, fixture, result)
      await delay(50)
      t.is(
        fixture.received.filter((event) => event.command === 1).length,
        writesBeforeCancel,
        'a cancelled operation cannot resume writes on a reusable root session'
      )
      if (phase === 'write') {
        t.is(
          fixture.received.filter((event) => event.command === 0).length,
          fixture.received
            .slice(
              0,
              fixture.received.findIndex((event) => event.command === 1)
            )
            .filter((event) => event.command === 0).length,
          'a cancelled write cannot advance into readback'
        )
      }
      t.ok(
        (await independent.put(fixture.wire)) >= 3,
        'an independent publication succeeds after cancellation'
      )
      await independentRead(t, fixture, fixture.services[2])
    }
  )
}

for (const lifecycle of ['suspend', 'destroy']) {
  test(
    'descriptor service ' + lifecycle + ' cancels its real unowned query without late success',
    async (t) => {
      t.timeout(90_000)
      const fixture = await network(t)
      const [writer, reader, independent] = fixture.services
      await writer.put(fixture.wire)
      fixture.hold('query')
      const result = observeResult(reader.getByTarget(fixture.target, fixture.period))
      t.ok(
        await until(() => fixture.held.length >= 2),
        'service lifecycle interrupts genuinely pending plugin requests'
      )
      const closing = observeResult(reader[lifecycle]())
      t.ok(
        await until(() => result.settled && closing.settled, 1000),
        'service lifecycle joins cancellation of the pending operation'
      )
      t.is(
        fixture.liveRequests(reader.dht).length,
        0,
        'service lifecycle leaves no descriptor requests in native IO'
      )
      await settleAfterLateReplies(t, fixture, result)
      await closing.done
      if (lifecycle === 'suspend') reader.resume()
      await independentRead(t, fixture, lifecycle === 'suspend' ? reader : independent)
    }
  )
}
