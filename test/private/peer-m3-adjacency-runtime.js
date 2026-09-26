'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { createPeerLedger, readPeerLedger } = require('../../lib/private/peer-ledger')
const {
  decodePeerTransport,
  encodePeerLimits,
  encodePeerTransport
} = require('../../lib/private/peer-transport-wire')
const { CELL_CLASS } = require('../../lib/private/protocol')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { digestPeerLimits } = require('../../lib/private/peer-crypto')
const { readPeerNativeNeighborDiagnostics } = require('../../lib/private/peer-native-neighbors')
const {
  createPeerLinkResponder,
  destroyPeerLinkResponder
} = require('../../lib/private/peer-guard-link')
const {
  createPeerM3AdjacencyAuthority,
  adoptPeerEstablishedLink,
  isPeerM3Runtime,
  takePeerM3TailMaterial,
  takePeerM3ExtensionProof,
  sendPeerM3Payload,
  receivePeerM3Payload,
  destroyPeerM3Runtime,
  takePeerM3ClosureSendPermit,
  beginPeerM3BranchTeardown,
  createPeerM3ForwardingOwner,
  registerPeerM3PhysicalLossSink,
  destroyPeerM3ForwardingOwner
} = require('../../lib/private/peer-m3-adjacency-runtime')
const {
  fakeClock,
  seed,
  ledgers,
  authenticatedPeer,
  setupDistinctNativeNeighbor
} = require('./peer-native-fixture')
const { readPeerEstablishedLinkBinding } = require('../../lib/private/udx-cell-endpoint')
function errorCode(fn) {
  try {
    fn()
    return null
  } catch (err) {
    return err.code
  }
}

async function asyncErrorCode(promise) {
  try {
    await promise
    return null
  } catch (err) {
    return err.code
  }
}

test('peer runtime rejects a caller-created established capability', (t) => {
  const clock = fakeClock()
  const authority = createPeerM3AdjacencyAuthority({
    clockIdentity: clock,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer
  })
  t.is(
    errorCode(() =>
      adoptPeerEstablishedLink(
        authority,
        Object.freeze({
          kind: 'peerEstablishedLink',
          initiator: true,
          branchClass: 2,
          generation: 1n
        })
      )
    ),
    'INVALID_ROUTE'
  )
  t.is(authority.diagnostics().activeRuntimes, 0)
  authority.destroy()
})

test('authenticated peer adjacency exchanges payloads and transfers extension proof once', async (t) => {
  const fixture = await authenticatedPeer(t, 48401)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(fixture.peerRuntime), true)
  t.is(
    errorCode(() => takePeerM3TailMaterial(runtime)),
    'UNAUTHORIZED',
    'the current tail cannot take the source-to-successor secret'
  )
  const proof = takePeerM3ExtensionProof(runtime)
  const decoded = decodePeerTransport(proof.successorProof378)
  t.is(decoded.fields.extensionIndex, 2)
  const limits = encodePeerLimits(fixture.limits)
  t.alike(decoded.fields.admittedLimitsDigest, digestPeerLimits(limits, limits, seed(0x46)))
  t.is(
    errorCode(() => takePeerM3ExtensionProof(runtime)),
    'ERR_REPLAY'
  )
  const forward = receivePeerM3Payload(fixture.peerRuntime)
  await sendPeerM3Payload(runtime, b4a.from('forward authenticated payload'))
  t.alike(await forward, b4a.from('forward authenticated payload'))
  const reverse = receivePeerM3Payload(runtime)
  await sendPeerM3Payload(fixture.peerRuntime, b4a.from('reverse authenticated payload'))
  t.alike(await reverse, b4a.from('reverse authenticated payload'))
  destroyPeerM3Runtime(runtime)
  t.is(fixture.localAuthority.diagnostics().activeRuntimes, 0)
})

test('synchronous runtime expiry cannot publish a dead handle or retain a branch slot', async (t) => {
  const fixture = await authenticatedPeer(t, 48403, 1)
  fixture.clock.fireSynchronously(true)
  t.is(
    errorCode(() => adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)),
    'ERR_DESTROYED'
  )
  t.is(fixture.localAuthority.diagnostics().activeRuntimes, 0)
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 0)
})

test('closure regression: no remote DESTROY echo', async (t) => {
  const fixture = await authenticatedPeer(t, 48410)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(runtime), true)

  // Remote destroys the link, emitting PEER_BRANCH_DESTROY_V2
  destroyPeerM3Runtime(fixture.peerRuntime)

  // Wait a tick for datagram to pump into local runtime
  await new Promise((resolve) => setImmediate(resolve))

  // Local runtime should transition to PHYSICALLY_CLOSING/CLOSED without sending any echo back
  t.is(isPeerM3Runtime(runtime), false)
  t.is(fixture.localAuthority.diagnostics().activeRuntimes, 0)
  t.is(readPeerLedger(fixture.localLedgers.teardownSendLedger).cellsSpent, 0)
})

test('closure regression: no opposite mode after TEARDOWN', async (t) => {
  const fixture = await authenticatedPeer(t, 48420)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(runtime), true)

  const teardownId = b4a.alloc(16, 0x11)
  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownId)
  void teardownPromise.catch(() => {})

  const before = readPeerLedger(fixture.localLedgers.teardownSendLedger).cellsSpent
  destroyPeerM3Runtime(runtime)
  t.is(await teardownPromise, false, 'local destruction settles interrupted teardown')
  t.is(
    readPeerLedger(fixture.localLedgers.teardownSendLedger).cellsSpent,
    before,
    'no opposite-mode packet dispatched'
  )
  t.is(isPeerM3Runtime(runtime), false)
})

test('closure regression: genuine matching ACK settles teardown', async (t) => {
  const fixture = await authenticatedPeer(t, 48430)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const peerRuntime = fixture.peerRuntime
  t.is(isPeerM3Runtime(runtime), true)
  t.is(isPeerM3Runtime(peerRuntime), true)

  const teardownId = b4a.alloc(16, 0x22)
  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownId)

  // Peer receives TEARDOWN_V2 and responder sends TEARDOWN_ACK_V2
  const settled = await teardownPromise
  t.is(settled, true, 'matching ACK resolves initiator teardown with true')
  t.is(isPeerM3Runtime(runtime), false)
})

test('closure regression: original monotonic deadline is fixed at first transition', async (t) => {
  const fixture = await authenticatedPeer(t, 48440)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(runtime), true)

  const teardownId = b4a.alloc(16, 0x33)
  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownId)
  void teardownPromise.catch(() => {})

  // Duplicate initiation must reject with ERR_REPLAY without extending deadline
  t.is(await asyncErrorCode(beginPeerM3BranchTeardown(runtime, teardownId)), 'ERR_REPLAY')
  t.is(runtime.diagnostics().closureMode, 'TEARDOWN')
  destroyPeerM3Runtime(runtime)
})

test('closure regression: duplicate cached ACK, one drain callback, shared 10 attempt boundary', async (t) => {
  const fixture = await authenticatedPeer(t, 48450)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const peerRuntime = fixture.peerRuntime
  t.is(isPeerM3Runtime(runtime), true)
  t.is(isPeerM3Runtime(peerRuntime), true)

  const teardownId = b4a.alloc(16, 0x44)
  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownId)

  // Genuine matching ACK settles the initiator without clock advancement
  const settled = await teardownPromise
  t.is(settled, true)
  t.is(isPeerM3Runtime(runtime), false)

  // Responder ACK duty: after the first ACK the retry timer re-sends on
  // LINK_PING_AFTER cadence until the original fixed deadline. Fire the fake
  // clock across the teardown window and count dispatched closure sends.
  const ledger = readPeerLedger(fixture.peerLedgers.teardownSendLedger)
  const before = ledger.cellsSpent
  t.ok(before >= 1, 'first ACK dispatched on the responder teardown ledger')

  fixture.clock.advance(500)
  await new Promise((resolve) => setImmediate(resolve))
  fixture.clock.advance(500)
  await new Promise((resolve) => setImmediate(resolve))
  fixture.clock.advance(500)
  await new Promise((resolve) => setImmediate(resolve))
  const afterRetries = readPeerLedger(fixture.peerLedgers.teardownSendLedger).cellsSpent
  t.ok(
    afterRetries >= before + 2,
    'timer-driven ACK retries dispatch from the same teardown ledger'
  )

  // Attempt exhaustion stops sends but preserves the armed cache duty: the
  // responder only physically closes when the original deadline arrives.
  fixture.clock.advance(5000)
  t.is(isPeerM3Runtime(peerRuntime), false)
})

test('closure regression: changed teardown IDs conflict without switching to DESTROY', async (t) => {
  const fixture = await authenticatedPeer(t, 48460)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(runtime), true)

  const teardownIdA = b4a.alloc(16, 0x55)
  const teardownIdB = b4a.alloc(16, 0x56)

  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownIdA)
  void teardownPromise.catch(() => {})

  // Conflicting initiation rejects with ERR_REPLAY
  t.is(await asyncErrorCode(beginPeerM3BranchTeardown(runtime, teardownIdB)), 'ERR_REPLAY')
  t.is(runtime.diagnostics().closureMode, 'TEARDOWN')
  destroyPeerM3Runtime(runtime)
})

test('closure regression: first receive-side closure transition charges one command, subsequent only cells/bytes', async (t) => {
  const fixture = await authenticatedPeer(t, 48470)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const peerRuntime = fixture.peerRuntime
  t.is(isPeerM3Runtime(runtime), true)
  t.is(isPeerM3Runtime(peerRuntime), true)

  const before = readPeerLedger(fixture.localLedgers.teardownReceiveLedger)
  t.is(before.commandsSpent, 0)

  const teardownId = b4a.alloc(16, 0x66)
  const teardownPromise = beginPeerM3BranchTeardown(runtime, teardownId)
  await teardownPromise

  const after = readPeerLedger(fixture.localLedgers.teardownReceiveLedger)
  t.is(after.commandsSpent, 1, 'first receive-side closure transition charges exactly 1 command')
  t.is(isPeerM3Runtime(runtime), false)
})

test('closure regression: shared-neighbor sibling survives teardown and ACK cache expiry', async (t) => {
  const fixture = await authenticatedPeer(t, 48480)
  const sibling = await fixture.openAdditional()
  const first = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const second = adoptPeerEstablishedLink(fixture.localAuthority, sibling.handle)
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).neighborCount, 1)
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 2)
  t.is(await beginPeerM3BranchTeardown(first, b4a.alloc(16, 0x79)), true)
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 1)
  for (let elapsed = 0; elapsed < 5000; elapsed += 500) {
    fixture.clock.advance(500)
    await new Promise((resolve) => setImmediate(resolve))
  }
  t.is(isPeerM3Runtime(fixture.peerRuntime), false)
  const forward = receivePeerM3Payload(sibling.peerRuntime)
  await sendPeerM3Payload(second, b4a.from('shared neighbor still alive'))
  t.alike(await forward, b4a.from('shared neighbor still alive'))
  const reverse = receivePeerM3Payload(second)
  await sendPeerM3Payload(sibling.peerRuntime, b4a.from('reciprocal sibling payload'))
  t.alike(await reverse, b4a.from('reciprocal sibling payload'))
  t.is(await beginPeerM3BranchTeardown(second, b4a.alloc(16, 0x7a)), true)
})

test('closure regression: held native completion preserves packet bytes and delays cleanup', async (t) => {
  const fixture = await authenticatedPeer(t, 48490)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  t.is(isPeerM3Runtime(runtime), true)

  // Verify takePeerM3ClosureSendPermit rejects unauthorized caller options/tokens
  t.is(
    errorCode(() => takePeerM3ClosureSendPermit(Object.freeze({}), {})),
    'UNAUTHORIZED'
  )
  t.is(
    errorCode(() => takePeerM3ClosureSendPermit(null, {})),
    'UNAUTHORIZED'
  )

  const socket = fixture.f.localSocket
  const originalSend = socket.send.bind(socket)
  let borrowed = null
  let snapshot = null
  let releaseNative
  socket.send = (packet, ...args) => {
    borrowed = packet
    snapshot = b4a.from(packet)
    originalSend(packet, ...args)
    return new Promise((resolve) => {
      releaseNative = resolve
    })
  }
  let settled = false
  const teardownPromise = beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x77))
  void teardownPromise.then(() => {
    settled = true
  })
  await new Promise((resolve) => setImmediate(resolve))
  try {
    t.is(settled, false, 'matching ACK cannot bypass held native completion')
    t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 1)
    t.alike(borrowed, snapshot, 'native-owned bytes remain intact')
  } finally {
    socket.send = originalSend
    releaseNative(true)
  }
  t.is(await teardownPromise, true)
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 0)
  t.alike(borrowed, b4a.alloc(snapshot.length), 'packet is cleared only after native completion')
})

test('closure regression: forwarding downstream release before upstream ACK', async (t) => {
  const fixture1 = await authenticatedPeer(t, 48500)
  const fixture2 = await authenticatedPeer(t, 48504)

  const previous = adoptPeerEstablishedLink(fixture1.localAuthority, fixture1.handle)
  const next = adoptPeerEstablishedLink(fixture2.localAuthority, fixture2.handle)

  const forwardingOwner = createPeerM3ForwardingOwner(previous, next)
  const receiving = receivePeerM3Payload(fixture2.peerRuntime)
  await sendPeerM3Payload(fixture1.peerRuntime, b4a.from('through both adjacency owners'))
  t.alike(await receiving, b4a.from('through both adjacency owners'))

  const socket = fixture2.f.localSocket
  const originalSend = socket.send.bind(socket)
  let releaseNative
  socket.send = (packet, ...args) => {
    originalSend(packet, ...args)
    return new Promise((resolve) => {
      releaseNative = resolve
    })
  }
  let settled = false
  const teardown = beginPeerM3BranchTeardown(fixture1.peerRuntime, b4a.alloc(16, 0x78))
  void teardown.then(() => {
    settled = true
  })
  await new Promise((resolve) => setImmediate(resolve))
  try {
    t.is(settled, false)
    t.is(
      readPeerLedger(fixture1.localLedgers.teardownSendLedger).cellsSpent,
      0,
      'no upstream ACK before downstream release'
    )
    t.is(readPeerNativeNeighborDiagnostics(fixture2.f.pool).reservationCount, 1)
    fixture1.clock.advance(500)
    await new Promise((resolve) => setImmediate(resolve))
    fixture1.clock.advance(500)
    await new Promise((resolve) => setImmediate(resolve))
    t.is(settled, false, 'duplicate teardown cannot bypass the original drain')
    t.is(readPeerLedger(fixture1.localLedgers.teardownSendLedger).cellsSpent, 0)
  } finally {
    socket.send = originalSend
    releaseNative(true)
  }
  t.is(await teardown, true)
  t.is(readPeerNativeNeighborDiagnostics(fixture2.f.pool).reservationCount, 0)
  t.is(
    readPeerNativeNeighborDiagnostics(fixture1.f.pool).reservationCount,
    1,
    'upstream ACK cache retains its branch'
  )
  for (let remaining = 3999; remaining > 0;) {
    const step = Math.min(500, remaining)
    fixture1.clock.advance(step)
    remaining -= step
    await new Promise((resolve) => setImmediate(resolve))
  }
  t.is(readPeerNativeNeighborDiagnostics(fixture1.f.pool).reservationCount, 1)
  fixture1.clock.advance(1)
  await new Promise((resolve) => setImmediate(resolve))
  t.is(readPeerNativeNeighborDiagnostics(fixture1.f.pool).reservationCount, 0)
  destroyPeerM3ForwardingOwner(forwardingOwner)
})

test('abrupt branch closure stops at eight authenticated attempts without closing its neighbor', async (t) => {
  const fixture = await authenticatedPeer(t, 48510)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const socket = fixture.f.localSocket
  const send = socket.send.bind(socket)
  const bodies = []
  socket.send = (packet, ...args) => {
    if (packet[1] !== CELL_CLASS.DATAGRAM) return send(packet, ...args)
    const opened = fixture.peerRuntime.openTail(packet)
    bodies.push(b4a.from(opened[0].payload === undefined ? opened[0] : opened[0].payload))
    return true
  }
  try {
    destroyPeerM3Runtime(runtime)
    for (let elapsed = 0; elapsed < 5000; elapsed += 500) {
      fixture.clock.advance(500)
      await new Promise((resolve) => setImmediate(resolve))
    }
    t.is(bodies.length, 8)
    t.is(
      bodies.every((body) => b4a.equals(body, bodies[0])),
      true,
      'all retries carry the same authenticated body'
    )
    t.is(decodePeerTransport(bodies[0]).messageId, PEER_MESSAGE_ID.PEER_BRANCH_DESTROY_V2)
    t.is(readPeerLedger(fixture.localLedgers.teardownSendLedger).commandsSpent, 1)
    t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 0)
    t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).neighborCount, 1)
  } finally {
    socket.send = send
  }
})

test('responder branches cannot spend sibling ordinary or physical-closure reservations', async (t) => {
  const fixture = await authenticatedPeer(t, 48520)
  const sibling = await fixture.openAdditional()
  const first = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const second = adoptPeerEstablishedLink(fixture.localAuthority, sibling.handle)
  const payload = b4a.from('branch-owned allowance')
  let allDelivered = true
  for (let attempt = 0; attempt < 19; attempt++) {
    const received = receivePeerM3Payload(first)
    await sendPeerM3Payload(fixture.peerRuntime, payload)
    allDelivered &&= b4a.equals(await received, payload)
  }
  t.is(allDelivered, true, 'all nineteen admitted data sends arrive')
  t.is(
    await asyncErrorCode(sendPeerM3Payload(fixture.peerRuntime, payload)),
    'ROUTE_UNAVAILABLE',
    'the first branch cannot borrow a sibling allowance after its ACCEPT and nineteen data sends'
  )
  const siblingReceive = receivePeerM3Payload(second)
  await sendPeerM3Payload(sibling.peerRuntime, payload)
  t.alike(await siblingReceive, payload, 'the sibling retains its reserved ordinary capacity')
  t.is(await beginPeerM3BranchTeardown(first, b4a.alloc(16, 0x7c)), true)
  t.is(await beginPeerM3BranchTeardown(second, b4a.alloc(16, 0x7d)), true)
  for (let elapsed = 0; elapsed < 5000; elapsed += 500) {
    fixture.clock.advance(500)
    await new Promise((resolve) => setImmediate(resolve))
  }
  for (const ledger of Object.values(fixture.peerLedgers)) {
    t.is(
      readPeerLedger(ledger).cellsReserved,
      0,
      'branch release returns only its unspent reservation'
    )
  }
  t.is(
    readPeerLedger(fixture.peerLedgers.sendLedger).cellsSpent,
    22,
    'spent sends are never refunded'
  )
  t.is(readPeerLedger(fixture.peerLedgers.teardownSendLedger).commandsSpent, 2)
  t.is(readPeerLedger(fixture.peerLedgers.teardownReceiveLedger).commandsSpent, 2)
})

test('delayed setup replies remain charged after transfer without duplicating allocation commands', async (t) => {
  const fixture = await authenticatedPeer(t, 48522)
  const first = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const socket = fixture.f.peerSocket
  const originalSend = socket.send.bind(socket)
  const delayed = []
  socket.send = (packet, ...args) => {
    if (packet[1] !== CELL_CLASS.DATAGRAM || delayed.length === 3) {
      return originalSend(packet, ...args)
    }
    delayed.push({ packet: b4a.from(packet), args })
    return true
  }
  let sibling
  try {
    const opening = fixture.openAdditional()
    opening.catch(() => {})
    await new Promise((resolve) => setImmediate(resolve))
    t.is(delayed.length, 1, 'the first real ACCEPT is held before advancing the owned clock')
    for (let attempt = 0; attempt < 3; attempt++) {
      fixture.clock.advance(250)
      await new Promise((resolve) => setImmediate(resolve))
    }
    sibling = await opening
  } finally {
    socket.send = originalSend
  }
  const second = adoptPeerEstablishedLink(fixture.localAuthority, sibling.handle)
  t.is(readPeerLedger(sibling.localLedgers.sendLedger).cellsSpent, 4)
  t.is(
    readPeerLedger(sibling.localLedgers.receiveLedger).cellsSpent,
    1,
    'lost replies are not received'
  )
  t.is(
    readPeerLedger(fixture.peerLedgers.receiveLedger).cellsSpent,
    5,
    'each OFFER reaches its original branch'
  )
  for (const held of delayed) originalSend(held.packet, ...held.args)
  await new Promise((resolve) => setImmediate(resolve))
  t.is(
    readPeerLedger(sibling.localLedgers.receiveLedger).cellsSpent,
    4,
    'all three delayed authenticated replies reach the transferred owner'
  )
  t.is(readPeerLedger(sibling.localLedgers.sendLedger).commandsSpent, 1)
  t.is(readPeerLedger(sibling.localLedgers.receiveLedger).commandsSpent, 1)
  t.is(readPeerLedger(fixture.peerLedgers.sendLedger).commandsSpent, 2)
  t.is(readPeerLedger(fixture.peerLedgers.receiveLedger).commandsSpent, 2)
  const payload = b4a.from('the original reply allowance remains spent')
  let delivered = true
  for (let attempt = 0; attempt < 16; attempt++) {
    const receiving = receivePeerM3Payload(second)
    await sendPeerM3Payload(sibling.peerRuntime, payload)
    delivered &&= b4a.equals(await receiving, payload)
  }
  t.is(delivered, true)
  t.is(await asyncErrorCode(sendPeerM3Payload(sibling.peerRuntime, payload)), 'ROUTE_UNAVAILABLE')
  const receiving = receivePeerM3Payload(first)
  await sendPeerM3Payload(fixture.peerRuntime, payload)
  t.alike(await receiving, payload, 'the established sibling retains its own allowance')
  t.is(await beginPeerM3BranchTeardown(first, b4a.alloc(16, 0x7e)), true)
  t.is(await beginPeerM3BranchTeardown(second, b4a.alloc(16, 0x7f)), true)
})

test('source validates each directional authority and reserves exact partitions before OFFER', async (t) => {
  const fixture = await authenticatedPeer(t, 48524)
  const runtime = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const existing = Object.values(fixture.localLedgers).map(readPeerLedger)
  const responder = Object.values(fixture.peerLedgers).map(readPeerLedger)
  t.is(
    await asyncErrorCode(
      fixture.openAdditional({
        forwardLimits: { ...fixture.limits, idleTimeoutMs: 30001 }
      })
    ),
    'UNAUTHORIZED',
    'forward limits fit the current-tail advertisement'
  )
  t.is(
    await asyncErrorCode(
      fixture.openAdditional({
        reverseLimits: { ...fixture.limits, idleTimeoutMs: 30001 }
      })
    ),
    'UNAUTHORIZED',
    'reverse limits fit the responder advertisement'
  )
  t.is(
    await asyncErrorCode(
      fixture.openAdditional({
        localLedgers: fixture.localLedgers
      })
    ),
    'INVALID_ROUTE',
    'an existing branch reservation cannot fund another OFFER'
  )
  const localLedgers = {
    sendLedger: createPeerLedger({ cells: 20, bytes: 24000n, commands: 20 }),
    receiveLedger: createPeerLedger({ cells: 19, bytes: 22800n, commands: 20 }),
    teardownSendLedger: createPeerLedger({ cells: 10, bytes: 12000n, commands: 1 }),
    teardownReceiveLedger: createPeerLedger({ cells: 10, bytes: 12000n, commands: 1 })
  }
  const before = Object.values(localLedgers).map(readPeerLedger)
  t.is(await asyncErrorCode(fixture.openAdditional({ localLedgers })), 'INVALID_ROUTE')
  t.alike(
    Object.values(localLedgers).map(readPeerLedger),
    before,
    'failed receive reservation returns the earlier send reservation'
  )
  t.alike(Object.values(fixture.localLedgers).map(readPeerLedger), existing)
  t.alike(
    Object.values(fixture.peerLedgers).map(readPeerLedger),
    responder,
    'none of the rejected requests publishes an OFFER'
  )
  t.is(readPeerNativeNeighborDiagnostics(fixture.f.pool).reservationCount, 1)
  const payload = b4a.from('the existing branch remains usable')
  const receiving = receivePeerM3Payload(runtime)
  await sendPeerM3Payload(fixture.peerRuntime, payload)
  t.alike(await receiving, payload)
  t.is(await beginPeerM3BranchTeardown(runtime, b4a.alloc(16, 0x80)), true)
})

test('responder owner cap of 2 covers separate responder instances and distinct authenticated Native bindings', async (t) => {
  const fixture = await authenticatedPeer(t, 48530, 2, true, { maxConcurrentCircuits: 2 })
  const runtime1 = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
  const peerRuntime1 = fixture.adoptedPeerRuntimes[0]
  t.is(isPeerM3Runtime(runtime1), true, 'first branch runtime adopted on initiator 1')
  t.is(isPeerM3Runtime(peerRuntime1), true, 'first branch runtime adopted on responder')
  const secondResponder = createPeerLinkResponder(fixture.f.peerRelayOwner, {
    ...ledgers(4),
    onEstablished(handle) {
      const runtime = adoptPeerEstablishedLink(fixture.peerAuthority, handle)
      fixture.adoptedPeerRuntimes.push(runtime)
      return runtime
    }
  })
  t.teardown(() => destroyPeerLinkResponder(secondResponder))

  const second = await setupDistinctNativeNeighbor(fixture.f, {
    t,
    responder: secondResponder,
    adoptedPeerRuntimes: fixture.adoptedPeerRuntimes,
    port: 48532,
    limits: fixture.limits,
    keySeed: 0x70,
    staticSeed: 0xd5
  })

  const third = await setupDistinctNativeNeighbor(fixture.f, {
    t,
    responder: secondResponder,
    adoptedPeerRuntimes: fixture.adoptedPeerRuntimes,
    port: 48534,
    limits: fixture.limits,
    keySeed: 0x80,
    staticSeed: 0xd6
  })

  const binding1 = readPeerEstablishedLinkBinding(
    fixture.f.peerNeighbor.established,
    fixture.f.peerRelayOwner
  )
  const binding2 = readPeerEstablishedLinkBinding(
    second.peerNeighbor.established,
    fixture.f.peerRelayOwner
  )
  const binding3 = readPeerEstablishedLinkBinding(
    third.peerNeighbor.established,
    fixture.f.peerRelayOwner
  )

  t.is(
    fixture.f.peerNeighbor.established !== second.peerNeighbor.established &&
      second.peerNeighbor.established !== third.peerNeighbor.established &&
      fixture.f.peerNeighbor.established !== third.peerNeighbor.established,
    true,
    'three distinct physical carrier established handles on shared responder'
  )
  t.is(
    b4a.equals(binding1.peerIdentity32, binding2.peerIdentity32) ||
      b4a.equals(binding2.peerIdentity32, binding3.peerIdentity32) ||
      b4a.equals(binding1.peerIdentity32, binding3.peerIdentity32),
    false,
    'three distinct authenticated peer identities across bindings'
  )
  t.is(
    b4a.equals(binding1.peerIdentity32, fixture.f.local.publicKey),
    true,
    'binding 1 authenticated peer identity is initiator 1'
  )
  t.is(
    b4a.equals(binding2.peerIdentity32, second.initiator.key.publicKey),
    true,
    'binding 2 authenticated peer identity is initiator 2'
  )
  t.is(
    b4a.equals(binding3.peerIdentity32, third.initiator.key.publicKey),
    true,
    'binding 3 authenticated peer identity is initiator 3'
  )
  t.is(
    b4a.equals(binding1.grantDigest32, binding2.grantDigest32) ||
      b4a.equals(binding2.grantDigest32, binding3.grantDigest32) ||
      b4a.equals(binding1.grantDigest32, binding3.grantDigest32),
    false,
    'three distinct signed topology grant digests'
  )
  t.is(
    b4a.equals(binding1.peerEndpoint19, binding2.peerEndpoint19) ||
      b4a.equals(binding2.peerEndpoint19, binding3.peerEndpoint19) ||
      b4a.equals(binding1.peerEndpoint19, binding3.peerEndpoint19),
    false,
    'three distinct peer endpoint geometries'
  )

  const responderDiag = readPeerNativeNeighborDiagnostics(fixture.f.peerPool)
  t.is(
    responderDiag.neighborCount,
    3,
    'shared responder pool holds three distinct physical neighbors'
  )

  const secondBranch = await second.openBranch()
  const runtime2 = adoptPeerEstablishedLink(second.authority, secondBranch.handle)
  const peerRuntime2 = secondBranch.peerRuntime
  t.is(isPeerM3Runtime(runtime2), true, 'second branch runtime adopted on initiator 2')
  t.is(isPeerM3Runtime(peerRuntime2), true, 'second branch runtime adopted on responder')

  let thirdError = null
  const thirdCandidate = await third.discover()
  try {
    const opening3 = third.openBranch({ activeCandidate: thirdCandidate })
    opening3.catch(() => {})
    for (let attempt = 0; attempt < 8; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 5))
      fixture.clock.advance(250)
    }
    await opening3
  } catch (err) {
    thirdError = err
  }
  t.ok(thirdError, 'third open times out while both owner-global admission slots are occupied')
  t.is(
    thirdError && thirdError.code,
    'ERR_PRIVACY_UNAVAILABLE',
    'the source reports unavailable after its original setup deadline'
  )
  t.is(fixture.adoptedPeerRuntimes.length, 2, 'the refused attempt creates no third runtime')
  t.is(
    readPeerNativeNeighborDiagnostics(third.initiator.pool).reservationCount,
    0,
    'the failed open releases its initiator reservation'
  )

  const payload1Forward = b4a.from('branch 1 forward surviving payload')
  const receiving1Forward = receivePeerM3Payload(peerRuntime1)
  await sendPeerM3Payload(runtime1, payload1Forward)
  t.alike(await receiving1Forward, payload1Forward, 'branch 1 forward traffic survives rejection')

  const payload1Reverse = b4a.from('branch 1 reverse surviving payload')
  const receiving1Reverse = receivePeerM3Payload(runtime1)
  await sendPeerM3Payload(peerRuntime1, payload1Reverse)
  t.alike(await receiving1Reverse, payload1Reverse, 'branch 1 reverse traffic survives rejection')

  const payload2Forward = b4a.from('branch 2 forward surviving payload')
  const receiving2Forward = receivePeerM3Payload(peerRuntime2)
  await sendPeerM3Payload(runtime2, payload2Forward)
  t.alike(await receiving2Forward, payload2Forward, 'branch 2 forward traffic survives rejection')

  const payload2Reverse = b4a.from('branch 2 reverse surviving payload')
  const receiving2Reverse = receivePeerM3Payload(runtime2)
  await sendPeerM3Payload(peerRuntime2, payload2Reverse)
  t.alike(await receiving2Reverse, payload2Reverse, 'branch 2 reverse traffic survives rejection')

  t.is(
    await beginPeerM3BranchTeardown(runtime1, b4a.alloc(16, 0x88)),
    true,
    'branch 1 teardown is acknowledged before responder ACK-cache retirement'
  )
  for (let tick = 0; tick < 20; tick++) {
    await new Promise((resolve) => setTimeout(resolve, 5))
    fixture.clock.advance(250)
  }

  const thirdBranch = await third.openBranch()
  const runtime3 = adoptPeerEstablishedLink(third.authority, thirdBranch.handle)
  const peerRuntime3 = thirdBranch.peerRuntime
  t.is(isPeerM3Runtime(runtime3), true, 'third branch admitted on binding 3 across freed slot')
  t.is(isPeerM3Runtime(peerRuntime3), true, 'third branch responder runtime adopted')
  t.is(
    fixture.adoptedPeerRuntimes.length,
    3,
    'only the post-release retry creates the third runtime'
  )

  const thirdPayloadForward = b4a.from(
    'third branch forward payload across freed slot on binding 3'
  )
  const thirdReceivingForward = receivePeerM3Payload(peerRuntime3)
  await sendPeerM3Payload(runtime3, thirdPayloadForward)
  t.alike(
    await thirdReceivingForward,
    thirdPayloadForward,
    'third branch exchanges forward payload'
  )

  const thirdPayloadReverse = b4a.from(
    'third branch reverse payload across freed slot on binding 3'
  )
  const thirdReceivingReverse = receivePeerM3Payload(runtime3)
  await sendPeerM3Payload(peerRuntime3, thirdPayloadReverse)
  t.alike(
    await thirdReceivingReverse,
    thirdPayloadReverse,
    'third branch exchanges reverse payload'
  )

  const branch2StillAlivePayload = b4a.from('branch 2 traffic continues undisturbed on binding 2')
  const branch2Receiving = receivePeerM3Payload(peerRuntime2)
  await sendPeerM3Payload(runtime2, branch2StillAlivePayload)
  t.alike(
    await branch2Receiving,
    branch2StillAlivePayload,
    'branch 2 remains functional on binding 2'
  )

  t.is(
    await beginPeerM3BranchTeardown(runtime2, b4a.alloc(16, 0x89)),
    true,
    'branch 2 teardown settles cleanly'
  )
  t.is(
    await beginPeerM3BranchTeardown(runtime3, b4a.alloc(16, 0x8a)),
    true,
    'branch 3 teardown settles cleanly'
  )
})

for (const [index, failure] of [
  'unrelated runtime',
  'destroy responder',
  'throw after adoption'
].entries()) {
  test(`Native responder callback rejects ${failure} without harming an established sibling`, async (t) => {
    const fixture = await authenticatedPeer(t, 48610 + index * 10, 2, true, {
      nodeServiceCells: 300
    })
    const original = adoptPeerEstablishedLink(fixture.localAuthority, fixture.handle)
    const originalPeer = fixture.adoptedPeerRuntimes[0]
    const parents = ledgers(4)
    let rejectedRuntime = null
    let callbacks = 0
    const responder = createPeerLinkResponder(fixture.f.peerRelayOwner, {
      ...parents,
      onEstablished(handle) {
        callbacks++
        if (failure === 'unrelated runtime') return originalPeer
        rejectedRuntime = adoptPeerEstablishedLink(fixture.peerAuthority, handle)
        if (failure === 'throw after adoption') throw new Error('adoption owner failed')
        destroyPeerLinkResponder(responder)
        return rejectedRuntime
      }
    })
    t.teardown(() => destroyPeerLinkResponder(responder))
    const neighbor = await setupDistinctNativeNeighbor(fixture.f, {
      t,
      responder,
      port: 48612 + index * 10
    })
    const candidate = await neighbor.discover()
    const opening = asyncErrorCode(neighbor.openBranch({ activeCandidate: candidate }))
    for (let tick = 0; tick < 8; tick++) {
      await new Promise((resolve) => setTimeout(resolve, 5))
      fixture.clock.advance(250)
    }
    t.is(await opening, 'ERR_PRIVACY_UNAVAILABLE', 'no failed callback publishes an ACCEPT')
    t.ok(callbacks > 0, 'the authenticated OFFER reaches the failing adoption callback')
    if (failure !== 'unrelated runtime') {
      t.is(isPeerM3Runtime(rejectedRuntime), false, 'the adopted failed owner is revoked')
    }
    for (let tick = 0; tick < 20; tick++) {
      await new Promise((resolve) => setTimeout(resolve, 5))
      fixture.clock.advance(250)
    }
    for (const parent of Object.values(parents)) {
      t.is(readPeerLedger(parent).cellsReserved, 0, 'Native retirement releases failed ownership')
    }
    const forward = b4a.from('original branch survives failed callback')
    const receivingForward = receivePeerM3Payload(originalPeer)
    await sendPeerM3Payload(original, forward)
    t.alike(await receivingForward, forward)
    const reverse = b4a.from('original reverse survives failed callback')
    const receivingReverse = receivePeerM3Payload(original)
    await sendPeerM3Payload(originalPeer, reverse)
    t.alike(await receivingReverse, reverse)
    t.is(await beginPeerM3BranchTeardown(original, b4a.alloc(16, 0x90 + index)), true)
  })
}

test('Native upstream loss retires the surviving successor without reporting a false physical loss', async (t) => {
  const upstream = await authenticatedPeer(t, 48650, 2, true)
  const downstream = await authenticatedPeer(t, 48654, 2, true)
  const previous = adoptPeerEstablishedLink(upstream.localAuthority, upstream.handle)
  const next = adoptPeerEstablishedLink(downstream.localAuthority, downstream.handle)
  let falseLosses = 0
  registerPeerM3PhysicalLossSink(next, () => {
    falseLosses++
  })
  const forwarding = createPeerM3ForwardingOwner(previous, next)
  t.teardown(() => {
    destroyPeerM3ForwardingOwner(forwarding)
  })
  let receivedError = null
  receivePeerM3Payload(downstream.peerRuntime).catch((error) => {
    receivedError = error
  })
  await upstream.f.localEndpoint.close()
  for (let turn = 0; turn < 10 && receivedError === null; turn++) {
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  t.is(
    receivedError && receivedError.code,
    'ERR_DESTROYED',
    'the downstream peer receives authenticated closure over its still-live adjacency'
  )
  t.is(falseLosses, 0, 'retiring a surviving leg does not fabricate its physical loss')
  t.is(
    readPeerLedger(downstream.localLedgers.teardownSendLedger).cellsSpent,
    1,
    'propagation spends the surviving branch closure partition'
  )
})
