'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  clearPeerPurposeKeys,
  computePeerPurposeMac,
  createPeerPurposePreTranscript,
  createPeerPurposeTranscript,
  derivePeerPurposeKeys,
  derivePeerPurposeSharedSecret
} = require('../../lib/private/peer-crypto')
const {
  computePeerQueuedBytes,
  computePeerSemanticOwnedBytes,
  createPeerLedger,
  createPeerMemoryPool,
  chargePeerLedger,
  isPeerLedgerWithin,
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
const {
  encodePeerRouteAD,
  encodePeerTailFinalizeAD,
  openPeerContextFrame,
  sealPeerContextFrame
} = require('../../lib/private/peer-m3-context')

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
    const ledgers = {
      sendLedger: createPeerLedger(
        index === 1 && options.terminalSend
          ? options.terminalSend
          : { cells: 500, bytes: 1_000_000n, commands: 200 }
      ),
      receiveLedger: createPeerLedger({ cells: 500, bytes: 1_000_000n, commands: 200 })
    }
    let bound = null

    const carrier = {
      [CARRIER_BRAND]: true,
      clock: clock.clock,
      sentFinalize,
      sentRoute,
      ledgers,
      bindLedgers(partitions) {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        if (bound) throw PrivateRouteError.ERR_REPLAY()
        if (
          !isPeerLedgerWithin(partitions.sendLedger, ledgers.sendLedger) ||
          !isPeerLedgerWithin(partitions.receiveLedger, ledgers.receiveLedger)
        )
          throw PrivateRouteError.INVALID_ROUTE()
        bound = partitions
        return true
      },
      setPeer(value) {
        peer = value
      },
      sendFinalizeFrame(frame) {
        if (destroyed) throw PrivateRouteError.ERR_DESTROYED()
        chargePeerLedger((bound || ledgers).sendLedger, {
          cells: 1,
          bytes: 1200n,
          commands: 0
        })
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
        chargePeerLedger((bound || ledgers).sendLedger, {
          cells: 1,
          bytes: 1200n,
          commands: 0
        })
        sentRoute.push(b4a.from(frame))
        if (options.dropRoute && options.dropRoute(index, sentRoute.length)) return true
        if (options.throwRoute && options.throwRoute(index, sentRoute.length))
          throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
        if (options.rejectRoute && options.rejectRoute(index, sentRoute.length))
          return Promise.reject(PrivateRouteError.ERR_PRIVACY_UNAVAILABLE())
        if (options.falseRoute && options.falseRoute(index, sentRoute.length)) return false
        if (options.promiseFalseRoute && options.promiseFalseRoute(index, sentRoute.length))
          return Promise.resolve(false)
        if (options.dropInactiveRoute && !peer.activated) return true
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
        chargePeerLedger((bound || ledgers).receiveLedger, {
          cells: 1,
          bytes: 1200n,
          commands: 0
        })
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
    sendLedger: carrier.ledgers.sendLedger,
    receiveLedger: carrier.ledgers.receiveLedger,
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
  delete terminalOptions.routeId
  delete terminalOptions.purpose
  delete terminalOptions.queryNonce
  delete terminalOptions.clientEphemeralPublicKey
  return {
    clock,
    carriers,
    route,
    sourceLimits,
    terminalLimits,
    source: createPeerPurposeSource(sourceOptions),
    terminal: createPeerPurposeTerminal(terminalOptions),
    sourceLedger: sourceOptions.sendLedger,
    sourceReceiveLedger: sourceOptions.receiveLedger,
    terminalLedger: terminalOptions.sendLedger,
    terminalReceiveLedger: terminalOptions.receiveLedger,
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
function finalizeContext(f, direction, counter) {
  return {
    contextClass: 5,
    circuitId: f.route.circuitId,
    generation: 7n,
    direction,
    counter,
    key: seed(direction === 0 ? 0x41 : 0x61),
    noncePrefix: seed(direction === 0 ? 0x51 : 0x71, 16)
  }
}

function capturedFinalize(f, direction) {
  const carrier = direction === 0 ? f.carriers.left : f.carriers.right
  const frame = carrier.sentFinalize[0]
  const opened = openPeerContextFrame(
    finalizeContext(f, direction, frame.readBigUInt64BE(0)),
    frame
  )
  const wire = b4a.from(opened.payload)
  opened.plaintext.fill(0)
  return wire
}

function fixturePurposeKeys(f, offer, acceptBody = b4a.alloc(260)) {
  const body = offer.subarray(8, 220)
  const pre = createPeerPurposePreTranscript({
    tailControlTranscriptDigest: seed(0x11),
    terminalAdvertisementDigest: body.subarray(52, 84),
    queryNonce: body.subarray(84, 116),
    clientEphemeralPublicKey: body.subarray(116, 148),
    terminalRoutePublicKey: f.pair.terminal.publicKey,
    offerBody: body
  })
  const transcript = createPeerPurposeTranscript(pre, offer, acceptBody)
  const shared = derivePeerPurposeSharedSecret(f.pair.client.secretKey, f.pair.terminal.publicKey)
  try {
    return derivePeerPurposeKeys(shared, pre, transcript)
  } finally {
    pre.fill(0)
    transcript.fill(0)
    shared.fill(0)
  }
}

function signOffer(f, offer) {
  const keys = fixturePurposeKeys(f, offer)
  try {
    const mac = computePeerPurposeMac(keys.preSourceMacKey, offer.subarray(0, 220))
    offer.set(mac, 220)
    mac.fill(0)
    return offer
  } finally {
    clearPeerPurposeKeys(keys)
  }
}

function routeContext(f, keys, direction, counter) {
  return {
    contextClass: 6,
    routeId: f.route.routeId,
    circuitId: f.route.circuitId,
    generation: 7n,
    purpose: 2,
    direction,
    counter,
    key: direction === 0 ? keys.forwardKey : keys.reverseKey,
    noncePrefix: direction === 0 ? keys.forwardNoncePrefix : keys.reverseNoncePrefix
  }
}

function sealInvalidPlaintext(context, mutate) {
  const ad =
    context.contextClass === 5 ? encodePeerTailFinalizeAD(context) : encodePeerRouteAD(context)
  const nonce = b4a.alloc(24)
  nonce.set(context.noncePrefix)
  nonce.writeBigUInt64BE(context.counter, 16)
  const plaintext = b4a.alloc(1076)
  plaintext[0] = 2
  mutate(plaintext)
  const frame = b4a.alloc(1100)
  frame.writeBigUInt64BE(context.counter, 0)
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    frame.subarray(8),
    plaintext,
    ad,
    null,
    nonce,
    context.key
  )
  ad.fill(0)
  nonce.fill(0)
  plaintext.fill(0)
  return frame
}

test('terminal learns each supported purpose from the authenticated first offer', async (t) => {
  for (const purpose of [1, 2, 3]) {
    const f = fixture({
      carrier: { dropInactiveRoute: true },
      sourceOverrides: {
        purpose,
        routeId: seed(0x90 + purpose, 16),
        queryNonce: seed(0x30 + purpose)
      }
    })
    t.is(f.terminal.diagnostics().status, 'WAITING_OFFER')
    t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
    t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
    await startHandshake(f)
    t.is(f.terminal.route().purpose, purpose)
    t.alike(f.terminal.route().routeId, seed(0x90 + purpose, 16))
    t.alike(f.terminal.route().purposeDigest, f.source.route().purposeDigest)
    t.alike(f.terminal.route().finalTranscriptDigest, f.source.route().finalTranscriptDigest)
    t.is(f.carriers.left.sentRoute.length, 1)
    t.is(f.carriers.right.sentRoute.length, 1)
    const { maxStreams, receiveBytes, semanticOwnedBytes } = f.terminal.route().limits
    t.is(
      readPeerMemory(f.terminalMemory).takenBytes,
      computePeerQueuedBytes({ maxStreams, receiveBytes, semanticOwnedBytes })
    )
    t.is(f.terminal.destroy(), true)
    const ledger = readPeerLedger(f.terminalLedger)
    const memory = readPeerMemory(f.terminalMemory)
    t.is(ledger.cellsReserved, 0)
    t.is(memory.reservedBytes, 0)
    t.is(memory.takenBytes, 0)
    t.is(f.terminal.destroy(), false)
    t.alike(readPeerLedger(f.terminalLedger), ledger)
    t.alike(readPeerMemory(f.terminalMemory), memory)
    f.source.destroy()
  }
})

test('terminal rejects invalid authenticated first offers before reservation', async (t) => {
  const cases = [
    [
      'parent circuit',
      (body) => {
        body[16] ^= 1
      }
    ],
    [
      'parent generation',
      (body) => {
        body.writeBigUInt64BE(8n, 32)
      }
    ],
    [
      'advertisement',
      (body) => {
        body[52] ^= 1
      }
    ],
    [
      'direction',
      (body) => {
        body[41] = 1
      }
    ],
    [
      'zero purpose',
      (body) => {
        body[40] = 0
      }
    ],
    [
      'presence purpose',
      (body) => {
        body[40] = 4
      }
    ],
    ['purpose MAC', null]
  ]
  for (const [name, mutate] of cases) {
    const f = fixture({ carrier: { dropFinalize: () => true } })
    const pending = f.terminal.whenActive().catch((error) => error)
    f.terminal.start()
    f.source.start()
    const offer = capturedFinalize(f, 0)
    if (mutate) {
      mutate(offer.subarray(8, 220))
      signOffer(f, offer)
    } else {
      offer[235] ^= 1
    }
    const frame = sealPeerContextFrame({ ...finalizeContext(f, 0, 0n), payload: offer })
    f.carriers.right.enqueue({ contextClass: 5, frame })
    const error = await pending
    t.ok(error instanceof PrivateRouteError, name)
    t.is(f.carriers.right.sentFinalize.length, 0, name)
    t.is(f.carriers.right.activated, false, name)
    t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0, name)
    t.is(readPeerLedger(f.terminalLedger).cellsSpent, 0, name)
    t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0, name)
    f.source.destroy()
    offer.fill(0)
  }
})

test('terminal authenticates the parent transcript before accepting an offer', async (t) => {
  const f = fixture({ terminalOverrides: { tailControlTranscriptDigest: seed(0x12) } })
  const pending = f.terminal.whenActive().catch((error) => error)
  f.terminal.start()
  f.source.start()
  t.is((await pending).code, 'ERR_AUTHENTICATION')
  t.is(f.carriers.right.sentFinalize.length, 0)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
  f.source.destroy()
})

test('terminal exact offers consume only the original response budget and reservation', async (t) => {
  const f = fixture({ carrier: { dropFinalize: (index) => index === 1 } })
  f.terminal.start()
  f.source.start()
  await tick()
  const offer = capturedFinalize(f, 0)
  const accept = capturedFinalize(f, 1)
  const memory = readPeerMemory(f.terminalMemory)
  const ledger = readPeerLedger(f.terminalLedger)
  const { maxStreams, receiveBytes, semanticOwnedBytes } = f.terminalLimits
  t.is(
    memory.reservedBytes,
    computePeerQueuedBytes({ maxStreams, receiveBytes, semanticOwnedBytes })
  )
  t.is(memory.takenBytes, 0)
  t.is(ledger.commandsSpent, 1)
  f.carriers.right.enqueue({ contextClass: 5, frame: f.carriers.left.sentFinalize[0] })
  await tick()
  t.is(f.carriers.right.sentFinalize.length, 1)
  for (let counter = 1n; counter < 8n; counter++) {
    f.carriers.right.enqueue({
      contextClass: 5,
      frame: sealPeerContextFrame({ ...finalizeContext(f, 0, counter), payload: offer })
    })
    await tick()
    t.alike(readPeerMemory(f.terminalMemory), memory)
    const current = readPeerLedger(f.terminalLedger)
    t.is(current.commandsSpent, 1)
    t.is(current.cellsSpent, ledger.cellsSpent + Number(counter))
    t.is(current.cellsReserved + current.cellsSpent, ledger.cellsReserved + ledger.cellsSpent)
    const response = f.carriers.right.sentFinalize[Number(counter)]
    const opened = openPeerContextFrame(finalizeContext(f, 1, counter), response)
    t.alike(opened.payload, accept)
    opened.plaintext.fill(0)
  }
  t.is(f.terminal.diagnostics().attempts, 8)
  f.carriers.right.enqueue({
    contextClass: 5,
    frame: sealPeerContextFrame({ ...finalizeContext(f, 0, 8n), payload: offer })
  })
  await tick()
  t.is(f.carriers.right.sentFinalize.length, 8)
  t.exception(() => f.terminal.diagnostics(), /destroyed/i)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
  f.source.destroy()
  offer.fill(0)
  accept.fill(0)
})

test('terminal memory refusal rolls back both directional reservations', async (t) => {
  const memoryPool = createPeerMemoryPool(1)
  const f = fixture({ terminalOverrides: { memoryPool } })
  const pending = f.source.whenActive().catch((error) => error)
  f.terminal.start()
  f.source.start()
  t.is((await pending).code, 'ERR_QUOTA_EXCEEDED')
  t.is(f.terminal.diagnostics().status, 'TERMINAL_REJECT')
  t.is(f.carriers.right.activated, false)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerLedger(f.terminalLedger).commandsSpent, 0)
  t.is(readPeerMemory(memoryPool).reservedBytes, 0)
  f.terminal.destroy()
})

test('purpose owner ignores unauthenticated finalize noise without consuming its counter', async (t) => {
  const f = fixture({ carrier: { dropFinalize: () => true } })
  f.terminal.start()
  f.source.start()
  const offer = capturedFinalize(f, 0)
  const context = finalizeContext(f, 0, 1000n)
  const valid = sealPeerContextFrame({ ...context, payload: offer })
  const noise = b4a.from(valid)
  noise[1099] ^= 1
  const ledger = readPeerLedger(f.terminalLedger)
  const memory = readPeerMemory(f.terminalMemory)
  const diagnostic = f.terminal.diagnostics()
  f.carriers.right.enqueue({ contextClass: 5, frame: noise })
  await tick()
  t.alike(f.terminal.diagnostics(), diagnostic)
  t.alike(readPeerLedger(f.terminalLedger), ledger)
  t.alike(readPeerMemory(f.terminalMemory), memory)
  f.carriers.right.enqueue({ contextClass: 5, frame: valid })
  await tick()
  t.is(f.terminal.diagnostics().status, 'TERMINAL_WAIT_SOURCE')
  t.is(f.carriers.right.sentFinalize.length, 1)
  f.source.destroy()
  f.terminal.destroy()
  offer.fill(0)
})

test('purpose owner ignores active route noise but closes on authenticated violations', async (t) => {
  for (const direction of [0, 1]) {
    const f = fixture()
    await startHandshake(f)
    const offer = capturedFinalize(f, 0)
    const accept = capturedFinalize(f, 1)
    const keys = fixturePurposeKeys(f, offer, accept.subarray(8, 268))
    const context = routeContext(f, keys, direction, 1000n)
    const target = direction === 0 ? f.terminal : f.source
    const carrier = direction === 0 ? f.carriers.right : f.carriers.left
    const ledger = direction === 0 ? f.terminalLedger : f.sourceLedger
    const memory = direction === 0 ? f.terminalMemory : f.sourceMemory
    const beforeLedger = readPeerLedger(ledger)
    const beforeMemory = readPeerMemory(memory)
    const diagnostic = target.diagnostics()
    const violation = sealPeerContextFrame({ ...context, payload: offer })
    const noise = b4a.from(violation)
    noise[1099] ^= 1
    const finalizeNoise = sealPeerContextFrame({
      ...finalizeContext(f, direction, 1000n),
      payload: direction === 0 ? offer : accept
    })
    finalizeNoise[1099] ^= 1
    carrier.enqueue({ contextClass: 5, frame: finalizeNoise })
    carrier.enqueue({ contextClass: 6, frame: noise })
    await tick()
    t.alike(target.diagnostics(), diagnostic)
    t.alike(readPeerLedger(ledger), beforeLedger)
    t.alike(readPeerMemory(memory), beforeMemory)
    carrier.enqueue({ contextClass: 6, frame: violation })
    await tick()
    t.exception(() => target.diagnostics(), /destroyed/i)
    t.is(readPeerLedger(ledger).cellsReserved, 0)
    t.is(readPeerMemory(memory).takenBytes, 0)
    f.source.destroy()
    f.terminal.destroy()
    clearPeerPurposeKeys(keys)
    offer.fill(0)
    accept.fill(0)
  }
})

test('purpose owner closes on authenticated context framing violations', async (t) => {
  for (const contextClass of [5, 6]) {
    for (const mutate of [
      (plaintext) => {
        plaintext[0] = 1
      },
      (plaintext) => {
        plaintext.writeUInt16BE(1074, 1)
      }
    ]) {
      const f = fixture()
      await startHandshake(f)
      const offer = capturedFinalize(f, 0)
      const accept = capturedFinalize(f, 1)
      const keys = fixturePurposeKeys(f, offer, accept.subarray(8, 268))
      const context =
        contextClass === 5 ? finalizeContext(f, 0, 10n) : routeContext(f, keys, 0, 10n)
      f.carriers.right.enqueue({ contextClass, frame: sealInvalidPlaintext(context, mutate) })
      await tick()
      t.exception(() => f.terminal.diagnostics(), /destroyed/i)
      t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
      t.is(readPeerMemory(f.terminalMemory).takenBytes, 0)
      f.source.destroy()
      clearPeerPurposeKeys(keys)
      offer.fill(0)
      accept.fill(0)
    }
  }
})

test('purpose owner closes on ordinary authenticated route traffic before the sentinel', async (t) => {
  const f = fixture({ carrier: { dropRoute: () => true } })
  const pending = f.terminal.whenActive().catch((error) => error)
  f.terminal.start()
  f.source.start()
  await tick()
  const offer = capturedFinalize(f, 0)
  const accept = capturedFinalize(f, 1)
  const keys = fixturePurposeKeys(f, offer, accept.subarray(8, 268))
  const payload = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2, {
    routeId: f.route.routeId,
    generation: 7n,
    dataCumulative: MAX_U64,
    dataBitmap: 0n,
    controlCumulative: MAX_U64,
    controlBitmap: 0n,
    ackSnapshot: 1,
    reservedZero: 0
  })
  f.carriers.right.enqueue({
    contextClass: 6,
    frame: sealPeerContextFrame({ ...routeContext(f, keys, 0, 1n), payload })
  })
  t.is((await pending).code, 'ERR_REPLAY')
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
  f.source.destroy()
  clearPeerPurposeKeys(keys)
  offer.fill(0)
  accept.fill(0)
})

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
      sendLedger: ledger,
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
      sendLedger: ledger,
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
  const terminalMemory = createPeerMemoryPool(1)
  const f = fixture({
    carrier: { terminalSend: { cells: 1, bytes: 1_200n, commands: 1 } },
    terminalOverrides: { memoryPool: terminalMemory }
  })
  const terminalLedger = f.terminalLedger
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
  t.is(readPeerLedger(f.terminalReceiveLedger).cellsReserved, 0)
  t.is(
    readPeerLedger(f.terminalReceiveLedger).cellsSpent,
    1,
    'pre-bind receipt remains spent after failed child reservation'
  )
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
  signOffer(f, mutated)
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
  f.source.destroy()
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
  t.is(computePeerSemanticOwnedBytes({ purpose: 2, isInitiator: true, maxStreams: 1 }), 133_692)
})

test('purpose operation admission selects the authenticated outgoing child and rejects incompatible IDs unspent', async (t) => {
  const f = fixture()
  await startHandshake(f)
  const source = readPeerLedger(f.sourceLedger)
  const terminal = readPeerLedger(f.terminalLedger)
  for (const id of [0, 0xffff, PEER_MESSAGE_ID.PEER_DATA_V2, PEER_MESSAGE_ID.ENTRY_REGISTER_V2]) {
    t.exception(() => f.source.admitOperation(id), /invalid/i)
    t.exception(() => f.terminal.admitOperation(id), /invalid/i)
  }
  t.exception(() => f.source.admitOperation(PEER_MESSAGE_ID.PEER_OPEN_V2), /invalid/i)
  t.alike(readPeerLedger(f.sourceLedger), source)
  t.alike(readPeerLedger(f.terminalLedger), terminal)
  const incoming = readPeerLedger(f.terminalReceiveLedger)
  f.terminal.admitOperation(PEER_MESSAGE_ID.PEER_OPEN_V2)
  f.terminal.admitOperation(PEER_MESSAGE_ID.PRIVATE_ACTIVATE_V2)
  t.is(readPeerLedger(f.terminalLedger).commandsSpent, terminal.commandsSpent + 2)
  t.is(readPeerLedger(f.terminalLedger).cellsSpent, terminal.cellsSpent)
  t.alike(readPeerLedger(f.terminalReceiveLedger), incoming)
  f.source.destroy()
  f.terminal.destroy()
  await Promise.all([f.source.whenClosed(), f.terminal.whenClosed()])
})

test('purpose revocation permits only synchronous tombstones and retains children through the carrier join', async (t) => {
  let f
  let closures = 0
  const errors = []
  f = fixture({
    sourceOverrides: {
      streamCallbacks: {
        onAdmit: () => false,
        onDeliver: () => false,
        onFailure() {
          try {
            f.source.admitOperation(PEER_MESSAGE_ID.PEER_OPEN_V2)
          } catch (error) {
            errors.push(error.code)
          }
          f.source.admitOperation(PEER_MESSAGE_ID.PEER_CLOSE_V2)
          closures++
        }
      }
    }
  })
  await startHandshake(f)
  const before = readPeerLedger(f.sourceLedger).commandsSpent
  const reservation = readPeerMemory(f.sourceMemory).reservedBytes
  let release
  const join = new Promise((resolve) => {
    release = resolve
  })
  const destroyCarrier = f.carriers.left.destroy
  f.carriers.left.destroy = () => {
    destroyCarrier()
    return join
  }
  t.is(f.source.destroy(), true)
  t.is(closures, 1)
  t.alike(errors, ['ERR_DESTROYED'])
  t.is(readPeerLedger(f.sourceLedger).commandsSpent, before + 2)
  t.is(
    readPeerMemory(f.sourceMemory).reservedBytes,
    reservation,
    'native work keeps the owned reservation alive'
  )
  t.exception(() => f.source.admitOperation(PEER_MESSAGE_ID.PEER_CLOSE_V2), {
    code: 'ERR_DESTROYED'
  })
  t.is(f.source.destroy(), false)
  release()
  await f.source.whenClosed()
  t.is(readPeerMemory(f.sourceMemory).reservedBytes, 0)
  t.is(readPeerLedger(f.sourceLedger).cellsReserved, 0)
  t.is(readPeerLedger(f.sourceLedger).released, false, 'B2 does not release borrowed parents')
  t.is(readPeerLedger(f.sourceLedger).commandsSpent, before + 2)
  f.terminal.destroy()
})

test('purpose command exhaustion rejects before debit and still completes revoked cleanup', async (t) => {
  let failure
  const f = fixture({
    terminalOverrides: {
      streamCallbacks: {
        onAdmit: () => false,
        onDeliver: () => false,
        onFailure(error) {
          failure = error
        }
      }
    }
  })
  await startHandshake(f)
  for (let index = 1; index < f.terminalLimits.reverseCommands; index++)
    f.terminal.admitOperation(PEER_MESSAGE_ID.PEER_OPEN_V2)
  const spent = readPeerLedger(f.terminalLedger).commandsSpent
  t.exception(() => f.terminal.admitOperation(PEER_MESSAGE_ID.PRIVATE_ACTIVATE_V2), {
    code: 'ERR_QUOTA_EXCEEDED'
  })
  t.is(readPeerLedger(f.terminalLedger).commandsSpent, spent)
  f.terminal.destroy()
  await f.terminal.whenClosed()
  t.is(failure.code, 'ERR_QUOTA_EXCEEDED')
  t.is(readPeerMemory(f.terminalMemory).reservedBytes, 0)
  t.is(readPeerLedger(f.terminalLedger).cellsReserved, 0)
  t.is(readPeerLedger(f.terminalLedger).released, false)
  t.exception(() => f.terminal.admitOperation(PEER_MESSAGE_ID.PEER_CLOSE_V2), {
    code: 'ERR_DESTROYED'
  })
  t.is(readPeerLedger(f.terminalLedger).commandsSpent, spent)
  f.source.destroy()
})
