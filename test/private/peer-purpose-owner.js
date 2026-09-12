'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  computePeerQueuedBytes,
  computePeerSemanticOwnedBytes,
  createPeerLedger,
  createPeerMemoryPool,
  readPeerLedger,
  readPeerMemory
} = require('../../lib/private/peer-ledger')
const {
  CARRIER_BRAND,
  createPeerPurposeSource,
  createPeerPurposeTerminal
} = require('../../lib/private/peer-purpose-owner')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const {
  decodePeerTransport,
  encodePeerTransport
} = require('../../lib/private/peer-transport-wire')
const { openPeerContextFrame, sealPeerContextFrame } = require('../../lib/private/peer-m3-context')

const MAX_U64 = 0xffff_ffff_ffff_ffffn

function seed(value, size = 32) {
  return b4a.alloc(size, value)
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve))
}

function createClock(start = 0n) {
  let now = start
  return {
    clock: {
      wallNow: () => now,
      monotonicNow: () => now
    },
    get now() {
      return now
    },
    set(value) {
      now = BigInt(value)
    }
  }
}

function createCarrierPair(clock, options = {}) {
  const endpoints = []
  function endpoint(index) {
    const queue = []
    const waiters = []
    const timers = []
    let peer = null
    let destroyed = false
    let activated = false
    let sequence = 0
    const sentFinalize = []
    const sentRoute = []

    const carrier = {
      [CARRIER_BRAND]: true,
      clock: clock.clock,
      sentFinalize,
      sentRoute,
      setPeer(value) {
        peer = value
      },
      sendFinalizeFrame(frame) {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        sentFinalize.push(b4a.from(frame))
        if (options.dropFinalize && options.dropFinalize(index, sentFinalize.length)) return true
        if (options.throwFinalize && options.throwFinalize(index, sentFinalize.length))
          throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
        if (options.rejectFinalize && options.rejectFinalize(index, sentFinalize.length))
          return Promise.reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
        if (options.falseFinalize && options.falseFinalize(index, sentFinalize.length)) return false
        if (
          options.promiseFalseFinalize &&
          options.promiseFalseFinalize(index, sentFinalize.length)
        )
          return Promise.resolve(false)
        peer.enqueue({ contextClass: 5, frame: b4a.from(frame) })
        return true
      },
      sendFrame(frame) {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        sentRoute.push(b4a.from(frame))
        if (options.dropRoute && options.dropRoute(index, sentRoute.length)) return true
        if (options.throwRoute && options.throwRoute(index, sentRoute.length))
          throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
        if (options.rejectRoute && options.rejectRoute(index, sentRoute.length))
          return Promise.reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
        if (options.falseRoute && options.falseRoute(index, sentRoute.length)) return false
        if (options.promiseFalseRoute && options.promiseFalseRoute(index, sentRoute.length))
          return Promise.resolve(false)
        peer.enqueue({ contextClass: 6, frame: b4a.from(frame) })
        return true
      },
      reserveReceive() {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        sequence++
        return { sequence }
      },
      receiveEnvelope(token) {
        if (destroyed) return Promise.reject(PrivateRouteError.ERR_DESTROYED())
        if (queue.length > 0) return Promise.resolve(queue.shift())
        return new Promise((resolve, reject) => waiters.push({ token, resolve, reject }))
      },
      cancelReceive(token) {
        const index = waiters.findIndex((waiter) => waiter.token === token)
        if (index !== -1) waiters.splice(index, 1)[0].reject(PrivateRouteError.ERR_DESTROYED())
      },
      activate() {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        activated = true
      },
      get activated() {
        return activated
      },
      schedule(delay, callback) {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        if (options.throwSchedule && options.throwSchedule(index, delay))
          throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
        const timer = { at: clock.now + BigInt(delay), callback, cancelled: false }
        timers.push(timer)
        return () => {
          timer.cancelled = true
        }
      },
      enqueue(envelope) {
        if (destroyed) return
        const waiter = waiters.shift()
        if (waiter) waiter.resolve(envelope)
        else queue.push(envelope)
      },
      destroy() {
        if (destroyed) return
        destroyed = true
        for (const waiter of waiters.splice(0)) waiter.reject(PrivateRouteError.ERR_DESTROYED())
        queue.length = 0
      },
      advanceTimers(target) {
        while (true) {
          let next = null
          for (const timer of timers) {
            if (!timer.cancelled && timer.at <= target && (!next || timer.at < next.at))
              next = timer
          }
          if (!next) break
          next.cancelled = true
          clock.set(next.at)
          next.callback()
        }
        clock.set(target)
      }
    }
    endpoints[index] = carrier
    return carrier
  }

  const left = endpoint(0)
  const right = endpoint(1)
  left.setPeer(right)
  right.setPeer(left)
  return {
    left,
    right,
    advance(ms) {
      left.advanceTimers(clock.now + BigInt(ms))
      right.advanceTimers(clock.now)
    }
  }
}

function limits({ semanticOwnedBytes, maxQueuedBytes, expiresAt = 10_000n, cells = 96 } = {}) {
  const semantic = semanticOwnedBytes || 40_000_000
  return {
    forwardCells: cells,
    forwardBytes: 120_000n,
    forwardCommands: 20,
    reverseCells: cells,
    reverseBytes: 120_000n,
    reverseCommands: 20,
    maxStreams: 1,
    receiveFrames: 4,
    receiveBytes: 1_000,
    semanticOwnedBytes: semantic,
    maxQueuedBytes:
      maxQueuedBytes ||
      computePeerQueuedBytes({ maxStreams: 1, receiveBytes: 1_000, semanticOwnedBytes: semantic }),
    expiresAt
  }
}

function ownerOptions(carrier, pair, route, localLimits, extras = {}) {
  const finalKeys = {
    finalizeForwardKey: seed(0x41),
    finalizeForwardNoncePrefix: seed(0x51, 16),
    finalizeReverseKey: seed(0x61),
    finalizeReverseNoncePrefix: seed(0x71, 16)
  }
  return {
    carrier,
    routeId: route.routeId,
    circuitId: route.circuitId,
    generation: 7n,
    purpose: 2,
    limits: localLimits,
    ledger: createPeerLedger({ cells: 500, bytes: 1_000_000n, commands: 200 }),
    memoryPool: createPeerMemoryPool(100_000_000),
    parentWireExpiresAt: 20_000n,
    parentLocalDeadline: 20_000n,
    clockIdentity: { name: 'fake-clock' },
    tailControlTranscriptDigest: seed(0x11),
    terminalAdvertisementDigest: seed(0x22),
    queryNonce: seed(0x33),
    terminalRoutePublicKey: pair.terminal.publicKey,
    clientEphemeralPublicKey: pair.client.publicKey,
    clientEphemeralSecret: pair.client.secretKey,
    finalizeKeys: finalKeys,
    randomBytes: (size) => seed(0x81, size),
    ...extras
  }
}

function fixture(options = {}) {
  const clock = createClock(options.clockStart || 0n)
  const carriers = createCarrierPair(clock, options.carrier)
  const route = { routeId: seed(0x91, 16), circuitId: seed(0xa1, 16) }
  const client = cryptoSuite.encryptionKeyPair(seed(0xc1))
  const terminal = cryptoSuite.encryptionKeyPair(seed(0xd1))
  const pair = { client, terminal }
  const sourceLimits = limits({
    expiresAt: options.sourceExpiresAt || options.expiresAt || 10_000n,
    cells: options.sourceCells || 96
  })
  const terminalLimits = limits({
    semanticOwnedBytes: 35_000_000,
    expiresAt: options.terminalExpiresAt || options.expiresAt || 10_000n,
    cells: options.terminalCells || 64
  })
  const sourceOptions = ownerOptions(carriers.left, pair, route, sourceLimits, {
    offerNonce: seed(0xe1, 16),
    clockIdentity: { name: 'fake-clock' },
    ...(options.sourceOverrides || {})
  })
  const terminalOptions = ownerOptions(carriers.right, pair, route, terminalLimits, {
    clientEphemeralSecret: undefined,
    acceptNonce: seed(0xf1, 16),
    terminalRouteSecretKey: terminal.secretKey,
    clockIdentity: { name: 'fake-clock' },
    ...(options.terminalOverrides || {})
  })
  delete terminalOptions.clientEphemeralSecret
  return {
    clock,
    carriers,
    route,
    sourceLimits,
    terminalLimits,
    source: createPeerPurposeSource(sourceOptions),
    terminal: createPeerPurposeTerminal(terminalOptions),
    sourceLedger: sourceOptions.ledger,
    terminalLedger: terminalOptions.ledger,
    sourceMemory: sourceOptions.memoryPool,
    terminalMemory: terminalOptions.memoryPool,
    pair
  }
}

async function startHandshake(f) {
  f.terminal.start()
  f.source.start()
  await Promise.all([f.source.whenActive(), f.terminal.whenActive()])
  await tick()
}

test('purpose owner activates after offer, accept, and two reliable sentinels', async (t) => {
  const f = fixture()
  await startHandshake(f)

  t.is(f.source.diagnostics().status, 'ACTIVE')
  t.is(f.terminal.diagnostics().status, 'ACTIVE')
  t.ok(f.carriers.left.activated)
  t.ok(f.carriers.right.activated)
  const sourceAccounting = readPeerLedger(f.sourceLedger)
  const terminalAccounting = readPeerLedger(f.terminalLedger)
  t.is(sourceAccounting.cellsSpent, 2)
  t.is(sourceAccounting.bytesSpent, 2_400n)
  t.is(sourceAccounting.commandsSpent, 0)
  t.is(terminalAccounting.cellsSpent, 2)
  t.is(terminalAccounting.bytesSpent, 2_400n)
  t.is(terminalAccounting.commandsSpent, 1)
  t.is(f.source.route().purposeDigest.byteLength, 32)
  t.is(f.source.route().finalTranscriptDigest.byteLength, 32)
  t.alike(f.source.route().finalTranscriptDigest, f.terminal.route().finalTranscriptDigest)
  t.ok(
    readPeerLedger(f.sourceLedger).cellsReserved <
      f.sourceLimits.forwardCells + f.sourceLimits.reverseCells
  )
  t.ok(readPeerMemory(f.terminalMemory).takenBytes > 0)

  f.source.destroy()
  f.terminal.destroy()
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.sourceMemory).reservedBytes, 0)
})
test('purpose owner expires active routes and releases the transferred owner', async (t) => {
  const f = fixture({ expiresAt: 1_000n })
  await startHandshake(f)
  f.carriers.advance(1_000)
  await tick()

  t.exception(() => f.source.route(), /destroyed/i)
  t.exception(() => f.terminal.route(), /destroyed/i)
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.sourceMemory).reservedBytes, 0)
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
})
test('purpose owner projects the negotiated minimum expiry and limits', async (t) => {
  const f = fixture({
    sourceCells: 64,
    terminalCells: 96,
    sourceExpiresAt: 10_000n,
    terminalExpiresAt: 5_000n
  })
  await startHandshake(f)
  const sourceRoute = f.source.route()
  const terminalRoute = f.terminal.route()
  t.is(sourceRoute.wireExpiresAt, 5_000n)
  t.is(terminalRoute.wireExpiresAt, 5_000n)
  t.is(sourceRoute.localDeadline, 5_000n)
  t.is(terminalRoute.localDeadline, 5_000n)
  f.source.destroy()
  f.terminal.destroy()
})
test('purpose owner rejects nonce accessors and rolls back failed preparation', (t) => {
  const build = (offerNonce) => {
    const clock = createClock()
    const carriers = createCarrierPair(clock)
    const route = { routeId: seed(0x91, 16), circuitId: seed(0xa1, 16) }
    const pair = {
      client: cryptoSuite.encryptionKeyPair(seed(0xc1)),
      terminal: cryptoSuite.encryptionKeyPair(seed(0xd1))
    }
    const ledger = createPeerLedger({ cells: 500, bytes: 1_000_000n, commands: 200 })
    const memoryPool = createPeerMemoryPool(100_000_000)
    const options = ownerOptions(carriers.left, pair, route, limits(), {
      ledger,
      memoryPool,
      offerNonce
    })
    return { ledger, memoryPool, options }
  }

  const accessor = build(undefined)
  let getterCalls = 0
  Object.defineProperty(accessor.options, 'offerNonce', {
    get() {
      getterCalls++
      return seed(0xe1, 16)
    }
  })
  t.exception(() => createPeerPurposeSource(accessor.options), /invalid/i)
  t.is(getterCalls, 0)
  t.is(readPeerLedger(accessor.ledger).cellsReserved, 0)
  t.is(readPeerMemory(accessor.memoryPool).reservedBytes, 0)

  const failed = build(b4a.alloc(16))
  t.exception(() => createPeerPurposeSource(failed.options), /invalid/i)
  t.is(readPeerLedger(failed.ledger).cellsReserved, 0)
  t.is(readPeerMemory(failed.memoryPool).reservedBytes, 0)
})
test('purpose owner clears staged copies on late constructor faults', (t) => {
  const isZero = (value) => {
    for (const byte of value) {
      if (byte !== 0) return false
    }
    return true
  }
  const failed = (mutate, matcher) => {
    const clock = createClock()
    const carriers = createCarrierPair(clock)
    const route = { routeId: seed(0x91, 16), circuitId: seed(0xa1, 16) }
    const pair = {
      client: cryptoSuite.encryptionKeyPair(seed(0xc1)),
      terminal: cryptoSuite.encryptionKeyPair(seed(0xd1))
    }
    const ledger = createPeerLedger({ cells: 500, bytes: 1_000_000n, commands: 200 })
    const memoryPool = createPeerMemoryPool(100_000_000)
    const options = ownerOptions(carriers.left, pair, route, limits(), {
      ledger,
      memoryPool
    })
    mutate(options)

    const copies = []
    const originalFrom = b4a.from
    b4a.from = function (value) {
      const result = originalFrom.call(b4a, value)
      copies.push(result)
      return result
    }
    try {
      t.exception(() => createPeerPurposeSource(options), matcher)
    } finally {
      b4a.from = originalFrom
    }
    t.ok(copies.length > 0)
    t.ok(copies.every(isZero))
    t.is(readPeerLedger(ledger).cellsReserved, 0)
    t.is(readPeerMemory(memoryPool).reservedBytes, 0)
  }

  failed((options) => {
    options.circuitId = b4a.alloc(15)
  }, /invalid/i)
  failed((options) => {
    options.queryNonce = b4a.alloc(31)
  }, /invalid/i)
  failed((options) => {
    options.finalizeKeys.finalizeReverseNoncePrefix = b4a.alloc(15)
  }, /invalid/i)
  failed((options) => {
    options.terminalRoutePublicKey = b4a.alloc(32)
  }, /invalid|key/i)
  failed((options) => {
    options.carrier.clock = {
      wallNow() {
        throw new Error('scheduler fault')
      },
      monotonicNow() {
        return 0n
      }
    }
  }, /unavailable|privacy/i)
})
test('purpose owner clears accept derivation staging on failure', async (t) => {
  const allocations = []
  const copies = []
  const isZero = (value) => {
    if (!b4a.isBuffer(value)) return false
    return value.every((byte) => byte === 0)
  }
  const originalAlloc = b4a.allocUnsafeSlow
  const originalFrom = b4a.from
  const originalFinal = sodium.crypto_generichash_final
  let faultInjected = false
  const f = fixture()
  const sourceAcceptPhase = () => f.carriers.right.sentFinalize.length > 0
  b4a.allocUnsafeSlow = function (size) {
    const value = originalAlloc.call(b4a, size)
    if (sourceAcceptPhase()) allocations.push(value)
    return value
  }
  b4a.from = function (value) {
    const result = originalFrom.call(b4a, value)
    if (
      sourceAcceptPhase() &&
      b4a.isBuffer(result) &&
      (result.byteLength === 260 || result.byteLength === 284)
    ) {
      copies.push(result)
    }
    return result
  }
  sodium.crypto_generichash_final = function (state, output) {
    if (sourceAcceptPhase() && !faultInjected) {
      faultInjected = true
      throw PrivateRouteError.INVALID_KEY()
    }
    return originalFinal.call(sodium, state, output)
  }
  const pending = f.source.whenActive().catch((error) => error)
  try {
    f.terminal.start()
    f.source.start()
    const error = await pending
    t.is(error && error.code, 'INVALID_KEY')
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
    b4a.from = originalFrom
    sodium.crypto_generichash_final = originalFinal
    f.source.destroy()
    f.terminal.destroy()
  }
  t.is(faultInjected, true)
  const bodies = copies.filter((value) => value.byteLength === 260)
  const wires = copies.filter((value) => value.byteLength === 284)
  const purposeLength =
    2 + 'hyperdht-private-routes/m3/peer-route-prepurpose/v2'.length + 4 + 32 * 5 + 212 + 236 + 260
  const purposes = allocations.filter((value) => value.byteLength === purposeLength)
  const decodedBodies = allocations.filter((value) => value.byteLength === 260)
  t.ok(decodedBodies.length > 0)
  t.ok(decodedBodies.every(isZero))
  t.is(bodies.length, 1)
  t.ok(isZero(bodies[0]))
  t.ok(wires.length > 0)
  t.ok(wires.every(isZero))
  t.is(purposes.length, 1)
  t.ok(isZero(purposes[0]))
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.sourceMemory).reservedBytes, 0)
})
test('purpose owner erases pre-shared state after sentinel authentication', async (t) => {
  const agreementResults = []
  const retainedCopies = []
  const originalAlloc = b4a.allocUnsafeSlow
  const originalFrom = b4a.from
  const originalScalarmult = sodium.crypto_scalarmult
  const isZero = (value) => value.every((byte) => byte === 0)
  let captureAgreementCopy = false
  let f = null
  b4a.allocUnsafeSlow = function (size) {
    const value = originalAlloc.call(b4a, size)
    if (captureAgreementCopy && size === 32) {
      agreementResults.push(value)
      captureAgreementCopy = false
    }
    return value
  }
  b4a.from = function (value) {
    const result = originalFrom.call(b4a, value)
    if (agreementResults.some((shared) => value === shared)) retainedCopies.push(result)
    return result
  }
  sodium.crypto_scalarmult = function (...args) {
    const result = originalScalarmult.apply(sodium, args)
    captureAgreementCopy = true
    return result
  }
  try {
    f = fixture()
    await startHandshake(f)
    t.is(agreementResults.length, 2)
    t.is(retainedCopies.length, 1)
    t.ok(isZero(agreementResults[0]))
    t.ok(isZero(agreementResults[1]))
    t.ok(isZero(retainedCopies[0]))
  } finally {
    if (f) {
      f.source.destroy()
      f.terminal.destroy()
    }
    b4a.allocUnsafeSlow = originalAlloc
    b4a.from = originalFrom
    sodium.crypto_scalarmult = originalScalarmult
  }
})

test('purpose owner caches and authenticates a terminal rejection', async (t) => {
  const terminalLedger = createPeerLedger({ cells: 1, bytes: 1_200n, commands: 1 })
  const terminalMemory = createPeerMemoryPool(1)
  const f = fixture({ terminalOverrides: { ledger: terminalLedger, memoryPool: terminalMemory } })
  const terminalPending = f.terminal.whenActive().catch((error) => error)
  f.terminal.start()
  f.source.start()
  const pending = f.source.whenActive().catch((error) => error)
  await tick()
  const error = await pending

  t.is(error && error.code, 'ERR_QUOTA_EXCEEDED')
  t.is(f.terminal.diagnostics().status, 'TERMINAL_REJECT')
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(readPeerLedger(terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(terminalMemory).reservedBytes, 0)
  t.is(readPeerLedger(terminalLedger).cellsSpent, 1)
  t.is(readPeerLedger(terminalLedger).bytesSpent, 1_200n)
  f.terminal.destroy()
  const terminalError = await terminalPending
  t.is(terminalError && terminalError.code, 'ERR_DESTROYED')
})
test('purpose owner rejects a conflicting replay and rolls back reservations', async (t) => {
  const f = fixture({ carrier: { dropFinalize: (index) => index === 1 } })
  f.terminal.start()
  f.source.start()
  f.terminal.whenActive().catch(() => {})
  f.source.whenActive().catch(() => {})
  await tick()
  await tick()
  t.is(f.terminal.diagnostics().status, 'TERMINAL_WAIT_SOURCE')

  const captured = f.carriers.left.sentFinalize[0]
  const opened = openPeerContextFrame(
    {
      contextClass: 5,
      circuitId: f.route.circuitId,
      generation: 7n,
      direction: 0,
      counter: captured.readBigUInt64BE(0),
      key: seed(0x41),
      noncePrefix: seed(0x51, 16)
    },
    captured
  )
  const exact = sealPeerContextFrame({
    contextClass: 5,
    circuitId: f.route.circuitId,
    generation: 7n,
    direction: 0,
    counter: 1n,
    key: seed(0x41),
    noncePrefix: seed(0x51, 16),
    payload: opened.payload
  })
  f.carriers.right.enqueue({ contextClass: 5, frame: exact })
  await tick()
  await tick()
  t.is(f.terminal.diagnostics().status, 'TERMINAL_WAIT_SOURCE')
  const mutated = b4a.from(opened.payload)
  mutated[20] ^= 1
  const forged = sealPeerContextFrame({
    contextClass: 5,
    circuitId: f.route.circuitId,
    generation: 7n,
    direction: 0,
    counter: 2n,
    key: seed(0x41),
    noncePrefix: seed(0x51, 16),
    payload: mutated
  })
  f.carriers.left.setPeer(f.carriers.right)
  f.carriers.right.enqueue({ contextClass: 5, frame: forged })
  await tick()
  await tick()

  t.exception(() => f.terminal.diagnostics(), /destroyed/i)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
  opened.plaintext.fill(0)
  exact.fill(0)
  mutated.fill(0)
  forged.fill(0)
})

test('purpose owner bounds the retry train at eight attempts and projects the deadline', async (t) => {
  const f = fixture({ expiresAt: 10_000n, clockStart: 100n, carrier: { dropFinalize: () => true } })
  const source = f.source
  source.start()
  await tick()
  source.whenActive().catch(() => {})
  f.carriers.advance(250)
  f.carriers.advance(250)
  f.carriers.advance(250)
  f.carriers.advance(250)
  f.carriers.advance(250)
  f.carriers.advance(250)
  f.carriers.advance(250)
  await tick()

  t.is(f.carriers.left.sentFinalize.length, 8)
  t.is(source.diagnostics().attempts, 8)
  t.is(source.diagnostics().localDeadline, 10_000n)
  f.carriers.advance(250)
  await tick()
  t.exception(() => source.route(), /destroyed/i)
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
})
test('purpose owner converges after first offer, accept, and sentinel loss', async (t) => {
  const f = fixture({
    carrier: {
      dropFinalize: (index, count) => count === 1,
      dropRoute: (index, count) => count === 1
    }
  })
  const sourceActive = f.source.whenActive()
  const terminalActive = f.terminal.whenActive()
  f.terminal.start()
  f.source.start()
  for (let index = 0; index < 8; index++) {
    await tick()
    f.carriers.advance(250)
    await tick()
  }
  await Promise.all([sourceActive, terminalActive])
  t.is(f.source.diagnostics().status, 'ACTIVE')
  t.is(f.terminal.diagnostics().status, 'ACTIVE')
  t.alike(f.source.route().finalTranscriptDigest, f.terminal.route().finalTranscriptDigest)
  t.ok(f.carriers.left.sentFinalize.length >= 2)
  t.ok(f.carriers.right.sentFinalize.length >= 2)
  t.ok(f.carriers.left.sentRoute.length >= 2)
  t.ok(f.carriers.right.sentRoute.length >= 2)
  f.source.destroy()
  f.terminal.destroy()
})
test('purpose owner destroys on retry scheduler failure', async (t) => {
  const f = fixture({ carrier: { dropFinalize: () => true, throwSchedule: () => true } })
  const pending = f.source.whenActive().catch((error) => error)
  t.is(f.source.start(), true)
  const error = await pending
  t.is(error && error.code, 'ERR_PRIVACY_UNAVAILABLE')
  t.exception(() => f.source.route(), /destroyed/i)
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
})
test('purpose owner waits for synchronous and asynchronous transport acceptance', async (t) => {
  for (const mode of ['throw', 'reject']) {
    const carrier =
      mode === 'throw'
        ? { throwRoute: (index, count) => index === 1 && count === 1 }
        : { rejectRoute: (index, count) => index === 1 && count === 1 }
    const f = fixture({ carrier })
    f.terminal.start()
    f.source.start()
    await tick()
    await tick()

    t.is(f.terminal.diagnostics().status, 'TERMINAL_SENTINEL_PENDING')
    t.exception(() => f.terminal.route(), /circuit/i)
    t.is(f.carriers.right.sentRoute.length, 1)

    f.carriers.advance(250)
    await tick()
    await Promise.all([f.source.whenActive(), f.terminal.whenActive()])
    t.is(f.terminal.diagnostics().status, 'ACTIVE')
    t.ok(f.carriers.right.sentRoute.length >= 2)

    f.source.destroy()
    f.terminal.destroy()
  }
})
test('purpose owner requires exact true from finalize and sentinel carriers', async (t) => {
  const cases = [
    {
      label: 'sync finalize false',
      carrier: { falseFinalize: (index, count) => index === 0 && count === 1 }
    },
    {
      label: 'promise finalize false',
      carrier: { promiseFalseFinalize: (index, count) => index === 0 && count === 1 }
    },
    {
      label: 'sync sentinel false',
      sentinel: true,
      carrier: { falseRoute: (index, count) => index === 1 && count === 1 }
    },
    {
      label: 'promise sentinel false',
      sentinel: true,
      carrier: { promiseFalseRoute: (index, count) => index === 1 && count === 1 }
    }
  ]
  for (const item of cases) {
    const f = fixture({ carrier: item.carrier })
    const sourceActive = f.source.whenActive()
    const terminalActive = f.terminal.whenActive()
    f.terminal.start()
    f.source.start()
    if (item.sentinel) {
      await tick()
      await tick()
      t.is(f.terminal.diagnostics().status, 'TERMINAL_SENTINEL_PENDING', item.label)
      t.exception(() => f.terminal.route(), /circuit/i, item.label)
      f.carriers.advance(250)
      await tick()
      await Promise.all([sourceActive, terminalActive])
    } else {
      for (let index = 0; index < 8; index++) {
        await tick()
        f.carriers.advance(250)
        await tick()
      }
      await Promise.all([sourceActive, terminalActive])
    }
    t.is(f.source.diagnostics().status, 'ACTIVE', item.label)
    t.is(f.terminal.diagnostics().status, 'ACTIVE', item.label)
    f.source.destroy()
    f.terminal.destroy()
  }
})
test('purpose owner binds active reliable transport in both directions', async (t) => {
  const sourceDelivered = []
  const terminalDelivered = []
  const sourceCallbacks = {
    onAdmit() {
      return true
    },
    onDeliver(meta, nested) {
      sourceDelivered.push({ meta, nested: b4a.from(nested) })
      return true
    }
  }
  const terminalCallbacks = {
    onAdmit() {
      return true
    },
    onDeliver(meta, nested) {
      terminalDelivered.push({ meta, nested: b4a.from(nested) })
      return true
    }
  }
  const f = fixture({
    sourceOverrides: { streamCallbacks: sourceCallbacks },
    terminalOverrides: { streamCallbacks: terminalCallbacks }
  })
  await startHandshake(f)

  const sourceTransport = f.source.transport()
  const terminalTransport = f.terminal.transport()
  const nested = encodePeerTransport(PEER_MESSAGE_ID.PEER_OPEN_V2, {
    common: {
      routeId: f.route.routeId,
      streamId: 3n,
      streamEpoch: 1,
      direction: 0,
      flags: 0,
      reserved: 0,
      position: 0n
    },
    semanticFirstId: 0x0360,
    semanticClass: 2,
    reservedZero: 0,
    firstSemanticWireBytes: 757,
    requestedHandshakeFrames: 4,
    requestedHandshakeBytes: 1_297n,
    requestedDataFrames: 4,
    requestedDataBytes: 3_908n,
    openNonce: seed(0x5a, 16)
  })
  const sent = sourceTransport.trySend(nested)
  t.is(sent.lane, 1)
  t.is(sent.sequence, 0n)
  await tick()
  await tick()

  t.is(terminalDelivered.length, 1)
  t.is(decodePeerTransport(terminalDelivered[0].nested).messageId, PEER_MESSAGE_ID.PEER_OPEN_V2)
  t.ok(sourceTransport.isCumulativelyAcknowledged(sent.lane, sent.sequence))
  t.ok(f.carriers.right.sentRoute.length >= 2)

  sourceCallbacks.onAdmit = () => false
  sourceCallbacks.onDeliver = () => false
  terminalCallbacks.onAdmit = () => false
  terminalCallbacks.onDeliver = () => false
  const second = sourceTransport.trySend(nested)
  await tick()
  await tick()
  t.is(terminalDelivered.length, 2)
  t.ok(sourceTransport.isCumulativelyAcknowledged(second.lane, second.sequence))

  const reverse = encodePeerTransport(PEER_MESSAGE_ID.PEER_OPEN_V2, {
    common: {
      routeId: f.route.routeId,
      streamId: 5n,
      streamEpoch: 1,
      direction: 1,
      flags: 0,
      reserved: 0,
      position: 0n
    },
    semanticFirstId: 0x0360,
    semanticClass: 2,
    reservedZero: 0,
    firstSemanticWireBytes: 757,
    requestedHandshakeFrames: 4,
    requestedHandshakeBytes: 1_297n,
    requestedDataFrames: 4,
    requestedDataBytes: 3_908n,
    openNonce: seed(0x6a, 16)
  })
  const reverseSent = terminalTransport.trySend(reverse)
  t.is(reverseSent.lane, 1)
  t.is(reverseSent.sequence, 0n)
  await tick()
  await tick()
  t.is(sourceDelivered.length, 1)
  t.is(decodePeerTransport(sourceDelivered[0].nested).messageId, PEER_MESSAGE_ID.PEER_OPEN_V2)
  t.ok(terminalTransport.isCumulativelyAcknowledged(reverseSent.lane, reverseSent.sequence))

  nested.fill(0)
  reverse.fill(0)
  terminalDelivered[0].nested.fill(0)
  terminalDelivered[1].nested.fill(0)
  sourceDelivered[0].nested.fill(0)
  f.source.destroy()
  f.terminal.destroy()
})

test('purpose owner erases route state on explicit destroy', async (t) => {
  const f = fixture()
  const source = f.source
  source.start()
  await tick()
  let rejection = null
  const pending = source.whenActive().catch((error) => {
    rejection = error
  })
  source.destroy()
  await pending
  t.is(rejection && rejection.code, 'ERR_DESTROYED')
  t.exception(() => source.whenActive(), /destroyed/i)
  t.is(readPeerMemory(f.sourceMemory).reservedBytes, 0)
  t.is(readPeerMemory(f.sourceMemory).takenBytes, 0)
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(computePeerSemanticOwnedBytes({ purpose: 2, isInitiator: true, maxStreams: 1 }), 33_557_016)
  t.is(MAX_U64, 0xffff_ffff_ffff_ffffn)
})
