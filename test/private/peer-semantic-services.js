'use strict'

const test = require('brittle')
const b4a = require('b4a')
const SecretStream = require('@hyperswarm/secret-stream')
const NoiseWrap = require('../../lib/noise-wrap')
const NoiseHandshake = require('noise-handshake')
const curve = require('noise-curve-ed')
const { NS } = require('../../lib/constants')
const { createPeerSemanticServices } = require('../../lib/private/peer-semantic-services')
const { PeerReliableLanes } = require('../../lib/private/peer-reliable-lanes')
const { PEER_MESSAGE_ID: ID } = require('../../lib/private/peer-protocol')
const {
  decodePeerTransport,
  encodePeerTransport
} = require('../../lib/private/peer-transport-wire')

const payload = { error: 0, firewall: 0 }
const limits = { maxFrames: 8, maxBytes: 7816n, idleMs: 5000 }
const fill = (size, byte) => b4a.alloc(size, byte)

function privateNoise(keyPair, remotePublicKey) {
  const initiator = !!remotePublicKey
  const noise = new NoiseHandshake('IK', initiator, keyPair, { curve })
  noise.initialise(NS.PEER_HANDSHAKE, remotePublicKey)
  return {
    send: () => noise.send(b4a.from([2, 0, 0, 0, 0])),
    recv(raw) {
      const opened = noise.recv(raw)
      if (!b4a.equals(opened, b4a.from([2, 0, 0, 0, 0])))
        throw new Error('Wrong private Noise payload')
    },
    final: () => ({
      isInitiator: initiator,
      publicKey: keyPair.publicKey,
      remotePublicKey: b4a.toBuffer(noise.rs),
      hash: b4a.toBuffer(noise.hash),
      tx: b4a.toBuffer(noise.tx),
      rx: b4a.toBuffer(noise.rx)
    })
  }
}

function confirmWithErasureProbe(lease, binding, events) {
  const original = b4a.from
  events.ownedSecrets = []
  events.callerSecrets = [binding.tx, binding.rx, binding.hash]
  events.callerCopies = events.callerSecrets.map((value) => original(value))
  b4a.from = function (value, ...args) {
    const result = original(value, ...args)
    if (events.callerSecrets.includes(value)) events.ownedSecrets.push(result)
    return result
  }
  try {
    return lease.confirmHandshake(binding)
  } finally {
    b4a.from = original
  }
}
function clock() {
  let time = 0n
  const timers = new Set()
  const cancelled = []
  return {
    now: () => time,
    timers,
    cancelled,
    schedule(delay, callback) {
      const row = { at: time + BigInt(delay), callback }
      timers.add(row)
      return () => {
        if (timers.delete(row)) cancelled.push(row.callback)
      }
    },
    advance(ms) {
      time += BigInt(ms)
      for (const row of Array.from(timers)) {
        if (row.at > time || !timers.delete(row)) continue
        row.callback()
      }
    }
  }
}

function network(t) {
  const c = clock()
  const h = { c, queue: [], sent: [], sides: [], filter: null }
  h.pair = async (purpose, left = {}, right = {}) => {
    const routeId = fill(16, h.sides.length + 1)
    const pair = [left, right].map((options, direction) => {
      const side = {
        service: createPeerSemanticServices({ ...limits, ...options }),
        errors: [],
        delivered: []
      }
      const callbacks = side.service.streamCallbacks
      const route = {
        role: direction === 0 ? 'source' : 'terminal',
        routeId,
        circuitId: fill(16, routeId[0] + 10),
        generation: 1n,
        purpose,
        purposeDigest: fill(32, routeId[0] + 20),
        finalTranscriptDigest: fill(32, routeId[0] + 30),
        wireExpiresAt: 20000n,
        localDeadline: 10000n,
        clockIdentity: c,
        limits: { maxStreams: 16, receiveFrames: 24, receiveBytes: 23448 },
        schedule: c.schedule,
        monotonicNow: c.now,
        wallNow: () => 10000n + c.now()
      }
      side.route = route
      side.lanes = new PeerReliableLanes({
        routeId,
        generation: 1n,
        purpose,
        localDirection: direction,
        clockIdentity: c,
        monotonicNow: c.now,
        schedule: c.schedule,
        localDeadline: 10000n,
        ...callbacks,
        onTransmit(wire) {
          const record = { from: side, wire: b4a.from(wire) }
          h.sent.push(record)
          if (!h.filter || h.filter(record) !== false) h.queue.push(record)
          return Promise.resolve(true)
        },
        onDeliver(meta, nested) {
          side.delivered.push({
            meta: { ...meta, nestedDigest: b4a.from(meta.nestedDigest) },
            wire: b4a.from(nested)
          })
          return callbacks.onDeliver(meta, nested)
        }
      })
      side.owner = {
        whenActive: () => Promise.resolve(),
        route: () => ({
          ...route,
          routeId: b4a.from(routeId),
          circuitId: b4a.from(route.circuitId),
          purposeDigest: b4a.from(route.purposeDigest),
          finalTranscriptDigest: b4a.from(route.finalTranscriptDigest)
        }),
        transport: () => side.lanes,
        destroy(error) {
          side.errors.push(error)
          side.lanes.destroy()
        }
      }
      h.sides.push(side)
      return side
    })
    pair[0].other = pair[1]
    pair[1].other = pair[0]
    await Promise.all(pair.map((side) => side.service.attachOwner(side.owner)))
    return pair
  }
  h.settle = async () => {
    let quiet = 0
    for (let turn = 0; turn < 400; turn++) {
      await Promise.resolve()
      const records = h.queue.splice(0)
      for (const record of records) record.from.other.lanes.receive(record.wire)
      if (records.length || h.queue.length) quiet = 0
      else if (++quiet === 8) {
        const soon = Array.from(c.timers).some((row) => row.at <= c.now() + 10n)
        if (!soon) return
        c.advance(10)
        quiet = 0
      }
    }
    throw new Error('Semantic network did not settle')
  }
  t.teardown(() => {
    for (const side of h.sides) side.service.destroy()
  })
  return h
}

function endpoint(overrides = {}) {
  const state = { handshakes: [], opens: [], data: [], views: [], fins: 0, resets: [], writable: 0 }
  state.hooks = {
    onHandshake: (raw) => state.handshakes.push(b4a.from(raw)),
    onAuthenticatedOpen: (context) => state.opens.push(context),
    onCiphertext(raw) {
      state.views.push(raw)
      state.data.push(b4a.from(raw))
      return raw.length
    },
    onRemoteFin: () => {
      state.fins++
    },
    onReset: (error) => state.resets.push(error),
    onWritable: () => {
      state.writable++
    },
    ...overrides
  }
  return state
}

function legacyAdapter(key) {
  const state = {
    resolves: 0,
    reserves: 0,
    confirms: 0,
    destroyed: 0,
    resolutionsDestroyed: 0,
    data: [],
    views: [],
    hooks: null,
    pause: false,
    resolveLater: null
  }
  const noise = new NoiseWrap(key)
  const native = {
    sessionCapability: fill(32, 80),
    egressRawUdxId: 42,
    sendHandshake(raw) {
      noise.recv(raw)
      return { ciphertext: noise.send(payload), pendingRemoteUdxId: 77 }
    },
    confirmHandshake(id) {
      state.confirms++
      return id === 77
    },
    trySendCiphertext(raw) {
      state.views.push(raw)
      if (state.pause) return false
      state.data.push(b4a.from(raw))
      return true
    },
    drain() {},
    finish() {
      state.hooks.onRemoteFin()
    },
    destroy() {
      state.destroyed++
    }
  }
  const resolution = {
    egressRef: fill(32, 81),
    candidateCount: 1,
    expiresAtUnixMs: 18000n,
    reserve(request, hooks) {
      state.reserves++
      state.hooks = hooks
      return native
    },
    destroy() {
      state.resolutionsDestroyed++
    }
  }
  state.adapter = {
    resolve() {
      state.resolves++
      return state.resolveLater || resolution
    }
  }
  state.resolution = resolution
  return state
}

async function legacyFixture(t, options = {}) {
  const h = network(t)
  const key = SecretStream.keyPair()
  const initiator = new NoiseWrap(SecretStream.keyPair(), key.publicKey)
  const native = legacyAdapter(key)
  if (options.resolveLater) native.resolveLater = options.resolveLater
  const [source, terminal] = await h.pair(
    1,
    { egressServiceIdentity: fill(32, 90) },
    { legacy: native.adapter, egressServiceIdentity: fill(32, 90) }
  )
  const events = endpoint({
    onHandshake(raw) {
      events.handshakes.push(b4a.from(raw))
      initiator.recv(raw)
      events.confirmed = lease.confirmHandshake({
        ...initiator.final(),
        validatedResponderUdxId: 77
      })
    }
  })
  const session = source.service.openSession({ ...limits, expectedNoiseKey: key.publicKey })
  const lease = session.attachEndpoint(events.hooks)
  const flight = initiator.send(payload)
  lease.sendHandshake(flight)
  await h.settle()
  return { h, source, terminal, events, session, lease, native, flight }
}

function semanticIds(side) {
  return side.delivered.flatMap(({ wire }) => {
    const decoded = decodePeerTransport(wire)
    if (decoded.messageId !== ID.PEER_HANDSHAKE_V2 || decoded.fields.semanticObjectOffset !== 0)
      return []
    return [decoded.fields.bytes.readUInt16BE(4)]
  })
}

function advertisement() {
  return encodePeerTransport(
    ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    {
      relayIdentity: fill(32, 1),
      currentDhtNodeId: fill(32, 2),
      reachableEndpoint: fill(19, 3),
      routeEncryptionPublicKey: fill(32, 4),
      capabilityMask: 11,
      minimumVersion: 2,
      maximumVersion: 2,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 16,
      capacityClass: 0,
      maxCells: 1000,
      maxBytes: 1200000,
      maxCommands: 1000,
      idleTimeoutMs: 5000,
      maxQueuedBytes: 32000,
      epoch: 1n,
      issuedAt: 10000n,
      expiresAt: 20000n,
      policyCount: 0
    },
    fill(64, 5)
  )
}

async function privateFixture(t, options = {}) {
  const h = network(t)
  const ad = advertisement()
  const entry = {
    identity: fill(32, 1),
    epoch: 1n,
    verifyAdvertisement: (wire) => b4a.equals(wire, ad)
  }
  const destinationKey = SecretStream.keyPair()
  const sourceKey = SecretStream.keyPair()
  const destinationNoise = privateNoise(destinationKey)
  const sourceNoise = privateNoise(sourceKey, destinationKey.publicKey)
  let destinationLease
  const destinationEvents = endpoint({
    onHandshake(raw) {
      destinationEvents.handshakes.push(b4a.from(raw))
      destinationNoise.recv(raw)
      destinationLease.sendHandshake(destinationNoise.send(payload))
      destinationEvents.confirmed = confirmWithErasureProbe(
        destinationLease,
        destinationNoise.final(),
        destinationEvents
      )
    }
  })
  const [destination, destinationEntry] = await h.pair(
    3,
    {
      entry,
      onSession(session) {
        destinationLease = session.attachEndpoint(destinationEvents.hooks)
      }
    },
    { entry }
  )
  const registration = destination.service.register({
    ...limits,
    destinationNoiseKey: destinationKey.publicKey,
    advertisement: ad,
    expiresAtUnixMs: 18000n
  })
  await h.settle()
  const registered = semanticIds(destination).includes(ID.ENTRY_REGISTERED_V2)
  if (!registered)
    throw new Error(
      'Registration failed: ' + JSON.stringify(destinationEntry.errors.map((e) => e.stack))
    )
  const descriptor = await registration.whenRegistered()
  const [source, sourceEntry] = await h.pair(2, {}, { entry })
  const sourceEvents = endpoint({
    onHandshake(raw) {
      sourceEvents.handshakes.push(b4a.from(raw))
      sourceNoise.recv(raw)
      sourceEvents.confirmed = confirmWithErasureProbe(
        sourceLease,
        sourceNoise.final(),
        sourceEvents
      )
    }
  })
  const session = source.service.openSession({
    ...limits,
    maxFrames: 4,
    maxBytes: 3908n,
    descriptor,
    expiresAtUnixMs: 17000n
  })
  const sourceLease = session.attachEndpoint(sourceEvents.hooks)
  if (options.filter) h.filter = (record) => options.filter(record, h)
  if (!options.deferHandshake) {
    sourceLease.sendHandshake(sourceNoise.send(payload))
    await h.settle()
  }
  return {
    h,
    entry,
    registration,
    descriptor,
    source,
    sourceEntry,
    destination,
    destinationEntry,
    sourceEvents,
    destinationEvents,
    session,
    sourceLease,
    sourceNoise,
    get destinationLease() {
      return destinationLease
    }
  }
}

test('semantic endpoint lease is one-shot, snapshots hooks, and cannot outlive revoke', async (t) => {
  const h = network(t)
  const [source] = await h.pair(1, { egressServiceIdentity: fill(32, 90) })
  const session = source.service.openSession({ ...limits, expectedNoiseKey: fill(32, 91) })
  const events = endpoint()
  let reads = 0
  const bad = { ...events.hooks }
  Object.defineProperty(bad, 'onHandshake', {
    get() {
      reads++
      return () => {}
    }
  })
  t.exception(() => session.attachEndpoint(bad), { code: 'INVALID_ROUTE' })
  t.is(reads, 0, 'no accessor runs at the lease boundary')
  const lease = session.attachEndpoint(events.hooks)
  t.exception(() => session.attachEndpoint(events.hooks), { code: 'INVALID_ROUTE' })
  events.hooks.onReset = () => {
    throw new Error('mutated hook')
  }
  t.is(lease.revoke(), true)
  t.is(lease.revoke(), false)
  t.is(events.resets.length, 0, 'revocation silences endpoint callbacks')
  t.exception(() => lease.sendHandshake(fill(101, 1)), { code: 'ERR_DESTROYED' })
  t.exception(() => lease.trySendCiphertext(fill(59, 1)), { code: 'ERR_DESTROYED' })
  t.is(source.service.diagnostics().receiveSlots, 0)
})

test('purpose 1 resolves, reserves, authenticates real Noise, then opens on cumulative credit', async (t) => {
  const f = await legacyFixture(t)
  t.alike(
    f.events.resets.map((error) => error.stack),
    []
  )
  t.alike(semanticIds(f.terminal), [
    ID.LEGACY_RESOLVE_V2,
    ID.LEGACY_RESERVE_V2,
    ID.PEER_NOISE_FRAGMENT_V2,
    ID.LEGACY_HANDSHAKE_ACCEPT_V2
  ])
  t.alike(semanticIds(f.source), [
    ID.LEGACY_RESOLVED_V2,
    ID.LEGACY_RESERVED_V2,
    ID.PEER_NOISE_FRAGMENT_V2,
    ID.LEGACY_OPEN_V2
  ])
  t.is(f.lease.diagnostics().ready, true)
  t.is(f.native.confirms, 1)
  t.is(f.events.opens.length, 1)
  t.alike(f.source.errors, [])
  t.alike(f.terminal.errors, [])
  if (f.lease.diagnostics().ready) await f.lease.whenOpen()
})

test('purpose 2/3 registration and real Noise require ready, ack, accepted, receipt and private-open', async (t) => {
  const f = await privateFixture(t)
  t.alike(
    f.sourceEvents.resets.map((error) => error.stack),
    []
  )
  t.alike(
    f.destinationEvents.resets.map((error) => error.stack),
    []
  )
  t.alike(semanticIds(f.sourceEntry), [
    ID.PRIVATE_ACTIVATE_V2,
    ID.PEER_NOISE_FRAGMENT_V2,
    ID.PRIVATE_ACK_V2,
    ID.PRIVATE_SOURCE_RECEIPT_V2
  ])
  t.alike(semanticIds(f.source), [
    ID.PEER_NOISE_FRAGMENT_V2,
    ID.PRIVATE_READY_V2,
    ID.PRIVATE_ACCEPTED_V2,
    ID.PRIVATE_OPEN_V2
  ])
  t.alike(semanticIds(f.destination).slice(1), [
    ID.PRIVATE_ACTIVATE_V2,
    ID.PEER_NOISE_FRAGMENT_V2,
    ID.PRIVATE_ACK_V2,
    ID.PRIVATE_OPEN_V2
  ])
  t.is(f.sourceLease.diagnostics().ready, true)
  t.is(f.destinationLease && f.destinationLease.diagnostics().ready, true)
  t.is(f.sourceEvents.opens.length, 1)
  t.is(f.destinationEvents.opens.length, 1)
  for (const side of f.h.sides) t.alike(side.errors, [])
})

function packetInfo(record) {
  const outer = decodePeerTransport(record.wire)
  if (outer.messageId !== ID.PEER_RELIABLE_PACKET_V2) return { outer }
  const nested = decodePeerTransport(outer.fields.completeNestedObject)
  const semantic =
    nested.messageId === ID.PEER_HANDSHAKE_V2 && nested.fields.semanticObjectOffset === 0
      ? nested.fields.bytes.readUInt16BE(4)
      : null
  return { outer, nested, semantic }
}

test('private source receipt and cumulative credit are separate opening barriers', async (t) => {
  const held = []
  const f = await privateFixture(t, {
    filter(record) {
      if (packetInfo(record).semantic !== ID.PRIVATE_SOURCE_RECEIPT_V2) return true
      held.push(record)
      return false
    }
  })
  t.is(held.length, 1)
  t.is(f.sourceEvents.opens.length, 0, 'accepted alone cannot open the source')
  t.is(f.destinationEvents.opens.length, 0, 'accepted alone cannot open the destination')
  t.is(f.sourceLease.trySendCiphertext(fill(59, 1)), false)
  f.h.filter = (record) => {
    if (packetInfo(record).outer.messageId !== ID.PEER_RELIABLE_ACK_V2) return true
    held.push(record)
    return false
  }
  f.h.queue.push(held.shift())
  await f.h.settle()
  t.is(f.sourceEvents.opens.length, 1)
  t.is(f.destinationEvents.opens.length, 1)
  t.is(
    f.sourceLease.diagnostics().ready,
    false,
    'transport credit is not cumulatively acknowledged'
  )
  t.is(f.sourceLease.trySendCiphertext(fill(59, 2)), false)
  f.h.filter = null
  f.h.queue.push(...held)
  await f.h.settle()
  t.is(f.sourceLease.diagnostics().ready, true)
  t.is(f.destinationLease.diagnostics().ready, true)
})

test('legacy credit pauses at one slot, drains preserved bytes, and FIN waits for consumption', async (t) => {
  const f = await legacyFixture(t)
  const first = fill(977, 11)
  f.native.pause = true
  t.is(f.lease.trySendCiphertext(first), true)
  first.fill(0)
  t.is(f.lease.trySendCiphertext(fill(10, 12)), false)
  await f.h.settle()
  t.alike(f.native.data, [])
  const finished = f.lease.finish()
  let ended = false
  finished.then(() => {
    ended = true
  })
  await f.h.settle()
  t.is(ended, false, 'FIN does not discard unconsumed ciphertext')
  t.is(f.events.fins, 0)
  f.native.pause = false
  f.native.hooks.onWritable()
  await f.h.settle()
  t.alike(f.native.data, [fill(977, 11)])
  t.ok(
    f.native.views.every((raw) => raw.every((byte) => byte === 0)),
    'consumed receive buffers are erased'
  )
  t.is(ended, true)
  t.is(f.events.fins, 1)
  t.is(f.native.destroyed, 1)
  t.is(f.native.resolutionsDestroyed, 1)
  t.is(f.source.service.diagnostics().receiveSlots, 0)
  t.is(f.terminal.service.diagnostics().receiveSlots, 0)
})

test('private bridges carry ciphertext both ways, renew credit, and finish both endpoints', async (t) => {
  const f = await privateFixture(t)
  t.is(f.sourceLease.trySendCiphertext(fill(977, 21)), true)
  t.is(f.sourceLease.trySendCiphertext(fill(977, 22)), false)
  await f.h.settle()
  t.alike(f.destinationEvents.data, [fill(977, 21)])
  t.is(f.sourceLease.trySendCiphertext(fill(23, 22)), true)
  t.is(f.destinationLease.trySendCiphertext(fill(59, 23)), true)
  await f.h.settle()
  t.alike(f.destinationEvents.data, [fill(977, 21), fill(23, 22)])
  t.alike(f.sourceEvents.data, [fill(59, 23)])
  const sourceFin = f.sourceLease.finish()
  await f.h.settle()
  t.is(f.destinationEvents.fins, 1)
  t.is(f.sourceLease.diagnostics().closed, false)
  const destinationFin = f.destinationLease.finish()
  await f.h.settle()
  t.is(f.sourceEvents.fins, 1)
  t.is(f.sourceLease.diagnostics().closed, true)
  t.is(f.destinationLease.diagnostics().closed, true)
  await Promise.all([sourceFin, destinationFin])
  for (const side of f.h.sides) t.is(side.service.diagnostics().receiveSlots, 0)
})

test('registration revoke closes dependent streams and rejects the old descriptor', async (t) => {
  const f = await privateFixture(t)
  f.registration.revoke()
  await f.h.settle()
  t.is(f.sourceLease.diagnostics().closed, true)
  t.is(f.destinationLease.diagnostics().closed, true)
  t.is(f.sourceEvents.resets.length, 1)
  t.is(f.destinationEvents.resets.length, 1)
  t.exception(() => f.registration.revoke(), { code: 'ERR_DESTROYED' })
  const rejected = endpoint()
  const session = f.source.service.openSession({
    ...limits,
    maxFrames: 1,
    maxBytes: 977n,
    descriptor: f.descriptor,
    expiresAtUnixMs: 17000n
  })
  const lease = session.attachEndpoint(rejected.hooks)
  lease.sendHandshake(fill(101, 7))
  await f.h.settle()
  t.is(lease.diagnostics().closed, true)
  t.is(rejected.opens.length, 0)
  t.is(
    f.destination.service.diagnostics().streams,
    2,
    'revoked token cannot allocate a destination stream'
  )
})

test('owner loss revokes registrations and resets their active dependents', async (t) => {
  const f = await privateFixture(t)
  f.destinationEntry.service.destroy()
  await f.h.settle()
  t.is(f.sourceLease.diagnostics().closed, true)
  t.is(f.sourceEntry.service.diagnostics().receiveSlots, 0)
  t.is(f.destinationEntry.service.diagnostics().streams, 0)
})

test('exact semantic replay is idempotent and a conflicting reliable identity fails closed', async (t) => {
  const f = await privateFixture(t)
  const row = f.source.delivered.find(({ wire }) => {
    const d = decodePeerTransport(wire)
    return (
      d.messageId === ID.PEER_HANDSHAKE_V2 &&
      d.fields.bytes.readUInt16BE(4) === ID.PEER_NOISE_FRAGMENT_V2
    )
  })
  t.is(f.source.service.streamCallbacks.onDeliver(row.meta, row.wire), true)
  t.is(
    f.sourceLease.diagnostics().closed,
    false,
    'exact cached Noise flight survives semantic open'
  )
  t.is(f.sourceEvents.handshakes.length, 1)
  t.is(f.sourceEvents.opens.length, 1)
  const packet = f.h.sent.find(
    (record) => record.from === f.sourceEntry && packetInfo(record).semantic === ID.PRIVATE_READY_V2
  )
  const forged = b4a.from(packet.wire)
  forged[forged.length - 1] ^= 1
  f.source.lanes.receive(forged)
  t.is(f.source.service.diagnostics().destroyed, true)
  t.is(f.sourceEvents.resets.length, 1)
})

test('bad confirmation MAC cannot produce private-open', async (t) => {
  const f = await privateFixture(t, {
    filter(record) {
      if (packetInfo(record).semantic === ID.PRIVATE_READY_V2)
        record.wire[record.wire.length - 1] ^= 1
      return true
    }
  })
  t.is(f.sourceLease.diagnostics().closed, true)
  t.is(f.sourceEvents.opens.length, 0)
  t.is(f.destinationEvents.opens.length, 0)
  t.is(semanticIds(f.sourceEntry).includes(ID.PRIVATE_SOURCE_RECEIPT_V2), false)
})

test('handshake deadline disposes late resolver results without reserving native I/O', async (t) => {
  let resolve
  const pending = new Promise((yes) => {
    resolve = yes
  })
  const f = await legacyFixture(t, { resolveLater: pending })
  t.is(f.native.resolves, 1)
  const remaining = 2000n - f.h.c.now()
  f.h.c.advance(Number(remaining - 1n))
  t.is(f.lease.diagnostics().closed, false)
  f.h.c.advance(1)
  await f.h.settle()
  t.is(f.lease.diagnostics().closed, true)
  resolve(f.native.resolution)
  await f.h.settle()
  t.is(f.native.resolutionsDestroyed, 1)
  t.is(f.native.reserves, 0)
  t.is(f.events.opens.length, 0)
  t.is(f.source.service.diagnostics().receiveSlots, 0)
})

test('session revoke erases queued ciphertext and late callbacks cannot regain the lease', async (t) => {
  const f = await legacyFixture(t)
  f.native.pause = true
  t.is(f.lease.trySendCiphertext(fill(59, 33)), true)
  await f.h.settle()
  t.is(f.native.views[0][0], 33)
  t.is(f.lease.revoke(), true)
  await f.h.settle()
  t.alike(f.native.views[0], fill(59, 0))
  t.is(f.native.destroyed, 1)
  t.is(f.native.hooks.onCiphertext(fill(59, 44)), 0)
  f.native.hooks.onWritable()
  f.native.hooks.onRemoteFin()
  f.native.hooks.onReset(new Error('late'))
  for (const callback of f.h.c.cancelled.slice()) callback()
  t.is(f.events.fins, 0)
  t.is(f.events.resets.length, 0)
  t.is(f.lease.diagnostics().pendingCiphertextBytes, 0)
  f.source.service.destroy()
  f.terminal.service.destroy()
  t.is(f.source.service.diagnostics().streams, 0)
  t.is(f.terminal.service.diagnostics().streams, 0)
  t.is(f.h.c.timers.size, 0)
})

test('registration timeout rejects its result and a dropped control cannot retain a live token', async (t) => {
  const h = network(t)
  const ad = advertisement()
  const entry = { identity: fill(32, 1), epoch: 1n, verifyAdvertisement: () => true }
  const [destination] = await h.pair(3, { entry, onSession() {} }, { entry })
  h.filter = () => false
  const registration = destination.service.register({
    ...limits,
    advertisement: ad,
    destinationNoiseKey: fill(32, 8),
    expiresAtUnixMs: 18000n
  })
  let result = null
  registration.whenRegistered().then(
    () => {
      result = 'accepted'
    },
    (error) => {
      result = error.code
    }
  )
  h.c.advance(2000)
  await h.settle()
  t.is(result, 'ERR_PRIVACY_UNAVAILABLE')
  t.is(destination.service.diagnostics().destroyed, true)
})

test('private confirmation clears owned secrets without erasing caller Noise state', async (t) => {
  const f = await privateFixture(t)
  for (const events of [f.sourceEvents, f.destinationEvents]) {
    t.alike(
      events.ownedSecrets.map((value) => value.every((byte) => byte === 0)),
      [true, true, true]
    )
    t.alike(events.callerSecrets, events.callerCopies)
  }
})

test('confirmation secrets are erased on reset while receipt is still pending', async (t) => {
  const f = await privateFixture(t, {
    filter: (record) => packetInfo(record).semantic !== ID.PRIVATE_SOURCE_RECEIPT_V2
  })
  f.sourceLease.reset()
  await f.h.settle()
  for (const events of [f.sourceEvents, f.destinationEvents]) {
    t.alike(
      events.ownedSecrets.map((value) => value.every((byte) => byte === 0)),
      [true, true, true]
    )
    t.alike(events.callerSecrets, events.callerCopies)
  }
})

test('destroyed registration owners release token storage for later routes', async (t) => {
  const h = network(t)
  const ad = advertisement()
  const entry = { identity: fill(32, 1), epoch: 1n, verifyAdvertisement: () => true }
  const options = {
    ...limits,
    advertisement: ad,
    destinationNoiseKey: fill(32, 9),
    expiresAtUnixMs: 18000n
  }
  const [first, firstEntry] = await h.pair(
    3,
    { entry },
    { entry, randomBytes: (size) => fill(size, 90) }
  )
  first.service.register(options)
  await h.settle()
  t.is(semanticIds(first).includes(ID.ENTRY_REGISTERED_V2), true)
  firstEntry.service.destroy()
  first.service.destroy()
  const [second] = await h.pair(3, { entry }, { entry, randomBytes: (size) => fill(size, 90) })
  second.service.register(options)
  await h.settle()
  t.is(semanticIds(second).includes(ID.ENTRY_REGISTERED_V2), true)
})
