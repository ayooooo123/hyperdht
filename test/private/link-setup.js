'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  DatagramReplayWindow,
  OrderedReceiver,
  SenderCounter
} = require('../../lib/private/counters')
const { PrivateRouteError } = require('../../lib/private/errors')
const { CELL_CLASS, DOMAIN } = require('../../lib/private/protocol')
const {
  TEST_ONLY_TICKET_OBSERVER,
  createLinkSetupAuthority,
  decodeLinkCreate,
  decodeLinkCreated,
  encodeLinkCreate,
  encodeLinkCreated,
  linkChallengeCipher,
  linkPossessionTag
} = require('../../lib/private/link-setup')

const TEST_ONLY_COUNTER_FACTORY = Symbol.for('hyperdht-private-routes/test-only-counter-factory')

const seed = (value) => b4a.alloc(32, value)

function injectedCounterFactory(failAt, counters) {
  let position = 0
  return (cellClass, sender, now) => {
    if (++position === failAt) throw new Error('injected counter construction failure')
    const counter = sender
      ? new SenderCounter()
      : cellClass === CELL_CLASS.DATAGRAM
        ? new DatagramReplayWindow({ window: 256 })
        : new OrderedReceiver({ window: 256, gapTimeout: 5000, now })
    counters.push(counter)
    return counter
  }
}

function captureOwnedAllocations(operation) {
  const originalAlloc = b4a.allocUnsafeSlow
  const allocations = []
  b4a.allocUnsafeSlow = (size) => {
    const output = originalAlloc(size)
    if (size === 16 || size === 32) allocations.push(output)
    return output
  }
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
  }
  return { allocations, error }
}

function probeAllocationFailure(arm, operation, failAt = Infinity) {
  const originalAlloc = b4a.allocUnsafeSlow
  const allocations = []
  let position = 0
  b4a.allocUnsafeSlow = (size) => {
    if (arm.value && (size === 16 || size === 32)) {
      if (++position === failAt) throw new Error('injected allocation failure')
      const output = originalAlloc(size)
      allocations.push(output)
      return output
    }
    return originalAlloc(size)
  }
  let error = null
  let result = null
  try {
    result = operation()
  } catch (err) {
    error = err
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
  }
  return { allocations, error, positions: position, result }
}

function derivedStateCrypto(arm) {
  return {
    ...cryptoSuite,
    deriveKeys(shared, transcript) {
      const keys = cryptoSuite.deriveKeys(shared, transcript)
      if (
        transcript.byteLength >= DOMAIN.LINK_CREATED.byteLength &&
        b4a.equals(transcript.subarray(0, DOMAIN.LINK_CREATED.byteLength), DOMAIN.LINK_CREATED)
      ) {
        arm.value = true
      }
      return keys
    }
  }
}

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  if (error) t.is(error.code, code)
}

function randomSequence(values) {
  let index = 0
  return (size) => {
    if (size !== 32 || index === values.length) throw new Error('unexpected random request')
    return b4a.alloc(32, values[index++])
  }
}

function shadowedAlias(value) {
  const alias = value.subarray(0)
  Object.defineProperty(alias, 'buffer', { value: new ArrayBuffer(value.byteLength) })
  Object.defineProperty(alias, 'byteOffset', { value: 0 })
  return alias
}

function fixture(observeTickets = true) {
  const initiatorIdentity = cryptoSuite.keyPair(seed(1))
  const responderIdentity = cryptoSuite.keyPair(seed(2))
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(3))
  const observed = new Map()
  const authority = createLinkSetupAuthority({
    crypto: cryptoSuite,
    now: () => 1_000,
    randomBytes: randomSequence([4, 5]),
    ...(observeTickets
      ? {
          [TEST_ONLY_TICKET_OBSERVER](ticket, value) {
            observed.set(ticket, value)
          }
        }
      : {})
  })
  const common = {
    circuitId: b4a.alloc(16, 0x11),
    epoch: 7n,
    initiatorIdentity: initiatorIdentity.publicKey,
    responderIdentity: responderIdentity.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x12),
    responderLocalId: b4a.alloc(16, 0x13),
    expiresAt: 2_000n
  }

  function start(overrides = {}) {
    return authority.initiate({
      ...common,
      responderStaticKey: responderStatic.publicKey,
      initiatorIdentitySecretKey: initiatorIdentity.secretKey,
      ...overrides
    })
  }

  function respond(message, overrides = {}) {
    return authority.respond(message, {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: responderIdentity.secretKey,
      ...overrides
    })
  }

  return {
    authority,
    observed,
    common,
    initiatorIdentity,
    responderIdentity,
    responderStatic,
    start,
    respond
  }
}

test('link challenge and possession known-answer vectors are locked', (t) => {
  const sharedSecret = seed(3)
  const baseHash = seed(4)
  const challenge = seed(5)
  const createHash = seed(6)

  t.is(
    b4a.toString(linkChallengeCipher(sharedSecret, baseHash, challenge), 'hex'),
    '6f712676663138cab149aaaa580a96d2599559a900e6f1985a13f760845f10acbd15b7e929ca7fc3c7bcbb7d687f936b'
  )
  t.is(
    b4a.toString(linkPossessionTag(sharedSecret, baseHash, challenge, createHash), 'hex'),
    '8106cf71313cef2ab00f781e97a2db30'
  )
  t.is(
    b4a.toString(
      cryptoSuite.hash([DOMAIN.LINK_CREATED, seed(6), seed(7), b4a.from([CELL_CLASS.CONTROL])]),
      'hex'
    ),
    'ecb723d81ec8aafec62e286aa33206afc9bb8d893bb633dc0e0abbfd340bd99f'
  )
})

test('authenticated link setup agrees on six peer contexts without exposing tickets', (t) => {
  const f = fixture()
  const started = f.start()
  const accepted = f.respond(started.message)
  const initiatorTicket = f.authority.complete(started.pending, accepted.message)
  const initiator = f.observed.get(initiatorTicket)
  const responder = f.observed.get(accepted.ticket)

  t.alike(Object.keys(initiatorTicket), [])
  t.alike(Object.keys(accepted.ticket), [])
  t.is('key' in initiatorTicket, false)
  t.alike(initiator.localIdentity, f.common.initiatorIdentity)
  t.alike(responder.localIdentity, f.common.responderIdentity)

  const keys = []
  const noncePrefixes = []
  const counters = []
  for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
    const left = initiator.contexts[cellClass]
    const right = responder.contexts[cellClass]
    t.alike(left.tx.key, right.rx.key)
    t.alike(left.tx.noncePrefix, right.rx.noncePrefix)
    t.alike(left.rx.key, right.tx.key)
    t.alike(left.rx.noncePrefix, right.tx.noncePrefix)
    t.is(left.tx.counter === right.tx.counter, false)
    t.is(left.rx.counter === right.rx.counter, false)
    keys.push(left.tx.key, left.rx.key)
    noncePrefixes.push(left.tx.noncePrefix, left.rx.noncePrefix)
    counters.push(left.tx.counter, left.rx.counter, right.tx.counter, right.rx.counter)
  }

  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) t.is(b4a.equals(keys[i], keys[j]), false)
  }
  for (let i = 0; i < noncePrefixes.length; i++) {
    for (let j = i + 1; j < noncePrefixes.length; j++) {
      t.is(b4a.equals(noncePrefixes[i], noncePrefixes[j]), false)
    }
  }
  t.is(new Set(counters).size, 12)
})

test('aborted pending and revoked responder setup state are deeply zeroized', (t) => {
  {
    const f = fixture(false)
    const allocations = []
    const originalAlloc = b4a.allocUnsafeSlow
    let started
    b4a.allocUnsafeSlow = (size) => {
      const value = originalAlloc(size)
      if (size === 16 || size === 32) allocations.push(value)
      return value
    }
    try {
      started = f.start()
      t.is(f.authority.abort(started.pending), true)
      t.is(f.authority.abort(started.pending), false)
    } finally {
      b4a.allocUnsafeSlow = originalAlloc
    }
    t.ok(allocations.length > 0)
    for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    expectCode(t, () => f.authority.complete(started.pending, b4a.alloc(337)), 'REPLAY')
  }

  {
    const f = fixture(false)
    const started = f.start()
    const allocations = []
    const originalAlloc = b4a.allocUnsafeSlow
    let accepted
    b4a.allocUnsafeSlow = (size) => {
      const value = originalAlloc(size)
      if (size === 16 || size === 32) allocations.push(value)
      return value
    }
    try {
      accepted = f.respond(started.message)
      t.is(f.authority.revoke(accepted.ticket), true)
      t.is(f.authority.revoke(accepted.ticket), false)
    } finally {
      b4a.allocUnsafeSlow = originalAlloc
    }
    t.ok(allocations.length > 0)
    for (const value of allocations) t.alike(value, b4a.alloc(value.byteLength))
    expectCode(t, () => f.authority.checker.take(accepted.ticket), 'UNAUTHORIZED')
    f.authority.abort(started.pending)
  }
})

test('throwing ticket observation is passive and clears its snapshot', (t) => {
  const initiatorIdentity = cryptoSuite.keyPair(seed(31))
  const responderIdentity = cryptoSuite.keyPair(seed(32))
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(33))
  const snapshots = []
  const authority = createLinkSetupAuthority({
    crypto: cryptoSuite,
    now: () => 1_000,
    randomBytes: randomSequence([34, 35]),
    [TEST_ONLY_TICKET_OBSERVER](ticket, snapshot) {
      t.alike(Object.keys(ticket), [])
      snapshots.push(snapshot)
      throw new Error('diagnostics must be passive')
    }
  })
  const common = {
    circuitId: b4a.alloc(16, 0x31),
    epoch: 7n,
    initiatorIdentity: initiatorIdentity.publicKey,
    responderIdentity: responderIdentity.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x32),
    responderLocalId: b4a.alloc(16, 0x33),
    expiresAt: 2_000n
  }
  const allocations = []
  const originalAlloc = b4a.allocUnsafeSlow
  let started = null
  let accepted = null
  let initiatorTicket = null
  let responderState = null
  b4a.allocUnsafeSlow = (size) => {
    const output = originalAlloc(size)
    if (size === 16 || size === 32) allocations.push(output)
    return output
  }
  try {
    started = authority.initiate({
      ...common,
      responderStaticKey: responderStatic.publicKey,
      initiatorIdentitySecretKey: initiatorIdentity.secretKey
    })
    accepted = authority.respond(started.message, {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: responderIdentity.secretKey
    })
    initiatorTicket = authority.complete(started.pending, accepted.message)
    responderState = authority.checker.take(accepted.ticket)

    t.is(snapshots.length, 2, 'both throwing observations return control to issuance')
    t.alike(responderState.localIdentity, common.responderIdentity, 'responder ticket is usable')
    t.is(authority.revoke(initiatorTicket), true, 'initiator ticket remains destroyable')
  } finally {
    b4a.allocUnsafeSlow = originalAlloc
    if (responderState) {
      for (const pair of Object.values(responderState.contexts)) {
        for (const context of [pair.tx, pair.rx]) {
          context.key.fill(0)
          context.noncePrefix.fill(0)
          context.counter.destroy()
        }
      }
      for (const name of ['circuitId', 'localIdentity', 'peerIdentity', 'localId', 'peerLocalId'])
        responderState[name].fill(0)
    }
    if (started) started.message.fill(0)
    if (accepted) accepted.message.fill(0)
  }

  for (const snapshot of snapshots) {
    for (const name of ['circuitId', 'localIdentity', 'peerIdentity', 'localId', 'peerLocalId'])
      t.ok(
        snapshot[name].every((byte) => byte === 0),
        `${name} snapshot is zeroized`
      )
    for (const pair of Object.values(snapshot.contexts)) {
      for (const context of [pair.tx, pair.rx]) {
        t.ok(
          context.key.every((byte) => byte === 0),
          'snapshot key is zeroized'
        )
        t.ok(
          context.noncePrefix.every((byte) => byte === 0),
          'snapshot nonce is zeroized'
        )
        t.ok(context.counter.closed, 'snapshot counter is destroyed')
      }
    }
  }
  t.ok(allocations.length > 0)
  t.ok(
    allocations.every((allocation) => allocation.every((byte) => byte === 0)),
    'ticket and observer allocation teardown leaves no retained secret bytes'
  )
})

test('link setup uses different material for every adjacency', (t) => {
  const first = fixture()
  const firstStart = first.start()
  const firstAccepted = first.respond(firstStart.message)
  const firstTicket = first.authority.complete(firstStart.pending, firstAccepted.message)

  const second = fixture()
  const secondStart = second.start({ circuitId: b4a.alloc(16, 0x21) })
  const secondAccepted = second.respond(secondStart.message, {
    circuitId: b4a.alloc(16, 0x21)
  })
  const secondTicket = second.authority.complete(secondStart.pending, secondAccepted.message)

  const left = first.observed.get(firstTicket)
  const right = second.observed.get(secondTicket)
  const leftContexts = []
  const rightContexts = []
  for (const cellClass of [0, 1, 2]) {
    leftContexts.push(left.contexts[cellClass].tx, left.contexts[cellClass].rx)
    rightContexts.push(right.contexts[cellClass].tx, right.contexts[cellClass].rx)
  }
  for (const leftContext of leftContexts) {
    for (const rightContext of rightContexts) {
      t.is(b4a.equals(leftContext.key, rightContext.key), false)
      t.is(b4a.equals(leftContext.noncePrefix, rightContext.noncePrefix), false)
    }
  }
})

test('responder rejects forged identity signatures before challenge decryption', (t) => {
  const f = fixture()
  const started = f.start()
  const value = decodeLinkCreate(started.message)
  value.initiatorIdentitySignature[0] ^= 1
  let opens = 0
  const crypto = { ...cryptoSuite, open: (...args) => (opens++, cryptoSuite.open(...args)) }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([9])
  })

  expectCode(
    t,
    () =>
      authority.respond(encodeLinkCreate(value), {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      }),
    'UNAUTHORIZED'
  )
  t.is(opens, 0)
})

test('link setup fails closed on identity, ids, epoch, expiry, static key, and replay', (t) => {
  for (const [name, override] of [
    ['initiatorIdentity', { initiatorIdentity: seed(91) }],
    ['responderIdentity', { responderIdentity: seed(92) }],
    ['initiatorLocalId', { initiatorLocalId: b4a.alloc(16, 93) }],
    ['responderLocalId', { responderLocalId: b4a.alloc(16, 94) }],
    ['epoch', { epoch: 8n }],
    ['expiresAt', { expiresAt: 2_001n }]
  ]) {
    const f = fixture()
    const started = f.start()
    expectCode(t, () => f.respond(started.message, override), 'INVALID_ROUTE')
    t.pass(name)
  }

  const wrongStatic = fixture()
  const started = wrongStatic.start({ responderStaticKey: seed(99) })
  expectCode(t, () => wrongStatic.respond(started.message), 'UNAUTHORIZED')

  const replay = fixture()
  const replayStart = replay.start()
  replay.respond(replayStart.message)
  expectCode(t, () => replay.respond(replayStart.message), 'REPLAY')
})

test('initiator rejects responder transcript, signature, possession, and ephemeral mutations', (t) => {
  for (const mutate of [
    (value) => (value.responderIdentitySignature[0] ^= 1),
    (value) => (value.staticPossessionTag[0] ^= 1),
    (value) => (value.responderEphemeralKey[0] ^= 1),
    (value) => (value.createHash[0] ^= 1),
    (value) => (value.epoch += 1n),
    (value) => (value.responderLocalId[0] ^= 1)
  ]) {
    const f = fixture()
    const started = f.start()
    const accepted = f.respond(started.message)
    const value = decodeLinkCreated(accepted.message)
    mutate(value)
    expectCode(
      t,
      () => f.authority.complete(started.pending, encodeLinkCreated(value)),
      'UNAUTHORIZED'
    )
    expectCode(t, () => f.authority.complete(started.pending, accepted.message), 'REPLAY')
  }
})

test('expired links and malformed messages fail with stable private-route errors', (t) => {
  const f = fixture()
  const started = f.start({ expiresAt: 999n })
  expectCode(t, () => f.respond(started.message, { expiresAt: 999n }), 'INVALID_ROUTE')

  for (const malformed of [null, {}, b4a.alloc(0), b4a.alloc(272), b4a.alloc(274)]) {
    let error = null
    try {
      f.respond(malformed)
    } catch (err) {
      error = err
    }
    t.ok(error instanceof PrivateRouteError)
  }
})

test('hostile crypto method getters are normalized to private-route errors', (t) => {
  const crypto = { ...cryptoSuite }
  Object.defineProperty(crypto, 'randomBytes', {
    get() {
      throw new Error('hostile getter')
    }
  })

  expectCode(t, () => createLinkSetupAuthority({ crypto, now: () => 1_000 }), 'INVALID_ROUTE')
})

test('sign adapter output cannot alias and erase a caller identity secret', (t) => {
  const f = fixture()
  const secret = b4a.from(f.initiatorIdentity.secretKey)
  const crypto = {
    ...cryptoSuite,
    sign(_message, secretKey) {
      return secretKey
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([31])
  })

  let result = null
  expectCode(
    t,
    () => {
      result = authority.initiate({
        ...f.common,
        responderStaticKey: f.responderStatic.publicKey,
        initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
      })
    },
    'INVALID_ROUTE'
  )

  t.is(result, null)
  t.alike(f.initiatorIdentity.secretKey, secret)
})

test('key-agreement adapter output cannot alias and erase a caller static secret', (t) => {
  const f = fixture()
  const started = f.start()
  const secret = b4a.from(f.responderStatic.secretKey)
  let derives = 0
  const crypto = {
    ...cryptoSuite,
    keyAgreement(secretKey) {
      return secretKey
    },
    deriveKeys(...args) {
      derives++
      return cryptoSuite.deriveKeys(...args)
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([32])
  })

  expectCode(
    t,
    () =>
      authority.respond(started.message, {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      }),
    'UNAUTHORIZED'
  )

  t.is(derives, 0)
  t.alike(f.responderStatic.secretKey, secret)
})

test('sign rejects an aliased identity secret with shadowed extent properties', (t) => {
  const f = fixture()
  const secret = b4a.from(f.initiatorIdentity.secretKey)
  const crypto = {
    ...cryptoSuite,
    sign(_message, secretKey) {
      return shadowedAlias(secretKey)
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([33])
  })

  expectCode(
    t,
    () =>
      authority.initiate({
        ...f.common,
        responderStaticKey: f.responderStatic.publicKey,
        initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
      }),
    'INVALID_ROUTE'
  )
  t.alike(f.initiatorIdentity.secretKey, secret)
})

test('key agreement rejects an aliased static secret with shadowed extent properties', (t) => {
  const f = fixture()
  const started = f.start()
  const secret = b4a.from(f.responderStatic.secretKey)
  const crypto = {
    ...cryptoSuite,
    keyAgreement(secretKey) {
      return shadowedAlias(secretKey)
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([34])
  })

  expectCode(
    t,
    () =>
      authority.respond(started.message, {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      }),
    'UNAUTHORIZED'
  )
  t.alike(f.responderStatic.secretKey, secret)
})

test('ephemeral key-pair adapter fields are snapshotted exactly once', (t) => {
  const f = fixture()
  const reads = { publicKey: 0, secretKey: 0 }
  const crypto = {
    ...cryptoSuite,
    encryptionKeyPair(seedValue) {
      const pair = cryptoSuite.encryptionKeyPair(seedValue)
      return Object.defineProperties(
        {},
        {
          publicKey: {
            get() {
              if (++reads.publicKey > 1) throw new Error('publicKey read twice')
              return pair.publicKey
            }
          },
          secretKey: {
            get() {
              if (++reads.secretKey > 1) throw new Error('secretKey read twice')
              return pair.secretKey
            }
          }
        }
      )
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([35])
  })

  const started = authority.initiate({
    ...f.common,
    responderStaticKey: f.responderStatic.publicKey,
    initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
  })

  t.is(started.message.byteLength, 273)
  t.alike(reads, { publicKey: 1, secretKey: 1 })
})

test('derived-key adapter fields are snapshotted exactly once', (t) => {
  const f = fixture()
  const reads = {
    forwardKey: 0,
    reverseKey: 0,
    forwardNoncePrefix: 0,
    reverseNoncePrefix: 0
  }
  const crypto = {
    ...cryptoSuite,
    deriveKeys(...args) {
      const keys = cryptoSuite.deriveKeys(...args)
      const result = {}
      for (const name of Object.keys(reads)) {
        Object.defineProperty(result, name, {
          get() {
            if (++reads[name] > 1) throw new Error(`${name} read twice`)
            return keys[name]
          }
        })
      }
      return result
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([36])
  })

  const started = authority.initiate({
    ...f.common,
    responderStaticKey: f.responderStatic.publicKey,
    initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
  })

  t.is(started.message.byteLength, 273)
  t.alike(reads, {
    forwardKey: 1,
    reverseKey: 1,
    forwardNoncePrefix: 1,
    reverseNoncePrefix: 1
  })
})

test('hash rejects a shadowed alias before deriving from its input', (t) => {
  const f = fixture()
  let aliased = false
  let derives = 0
  const crypto = {
    ...cryptoSuite,
    hash(parts) {
      const part = parts.find((value) => b4a.isBuffer(value) && value.byteLength === 32)
      if (!aliased && part) {
        aliased = true
        return shadowedAlias(part)
      }
      return cryptoSuite.hash(parts)
    },
    deriveKeys(...args) {
      derives++
      return cryptoSuite.deriveKeys(...args)
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([37])
  })

  expectCode(
    t,
    () =>
      authority.initiate({
        ...f.common,
        responderStaticKey: f.responderStatic.publicKey,
        initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
      }),
    'INVALID_ROUTE'
  )
  t.is(derives, 0)
})

test('responder and completion construction failures clear every prior TX/RX secret', (t) => {
  t.is(typeof TEST_ONLY_COUNTER_FACTORY, 'symbol')

  for (let failure = 1; failure <= 6; failure++) {
    const f = fixture(false)
    const started = f.start()
    const counters = []
    const observed = new Map()
    const responderSecret = b4a.from(f.responderStatic.secretKey)
    const authority = createLinkSetupAuthority({
      crypto: cryptoSuite,
      now: () => 1_000,
      randomBytes: randomSequence([40 + failure]),
      [TEST_ONLY_COUNTER_FACTORY]: injectedCounterFactory(failure, counters),
      [TEST_ONLY_TICKET_OBSERVER](ticket, state) {
        observed.set(ticket, state)
      }
    })
    const attempt = captureOwnedAllocations(() =>
      authority.respond(started.message, {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      })
    )
    t.ok(attempt.error, `responder counter ${failure} fails`)
    t.is(observed.size, 0, `responder counter ${failure} publishes no ticket`)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      `responder counter ${failure} clears prior context bytes`
    )
    t.ok(
      counters.every((counter) => counter.closed),
      `responder counter ${failure} closes prior counters`
    )
    t.alike(
      f.responderStatic.secretKey,
      responderSecret,
      `responder counter ${failure} preserves caller secret`
    )
    f.authority.abort(started.pending)
  }

  for (let failure = 1; failure <= 6; failure++) {
    const initiatorIdentity = cryptoSuite.keyPair(seed(51))
    const responderIdentity = cryptoSuite.keyPair(seed(52))
    const responderStatic = cryptoSuite.encryptionKeyPair(seed(53))
    const observed = new Map()
    const counters = []
    const common = {
      circuitId: b4a.alloc(16, 0x51),
      epoch: 9n,
      initiatorIdentity: initiatorIdentity.publicKey,
      responderIdentity: responderIdentity.publicKey,
      initiatorLocalId: b4a.alloc(16, 0x52),
      responderLocalId: b4a.alloc(16, 0x53),
      expiresAt: 2_000n
    }
    const authority = createLinkSetupAuthority({
      crypto: cryptoSuite,
      now: () => 1_000,
      randomBytes: randomSequence([54, 55]),
      [TEST_ONLY_COUNTER_FACTORY]: injectedCounterFactory(6 + failure, counters),
      [TEST_ONLY_TICKET_OBSERVER](ticket, state) {
        observed.set(ticket, state)
      }
    })
    const started = authority.initiate({
      ...common,
      responderStaticKey: responderStatic.publicKey,
      initiatorIdentitySecretKey: initiatorIdentity.secretKey
    })
    const accepted = authority.respond(started.message, {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: responderIdentity.secretKey
    })
    const acceptedSnapshot = b4a.from(accepted.message)
    const attempt = captureOwnedAllocations(() =>
      authority.complete(started.pending, accepted.message)
    )
    t.ok(attempt.error, `completion counter ${failure} fails`)
    t.is(observed.size, 1, `completion counter ${failure} publishes no initiator ticket`)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      `completion counter ${failure} clears prior context bytes`
    )
    t.ok(
      counters.slice(6).every((counter) => counter.closed),
      `completion counter ${failure} closes prior counters`
    )
    t.alike(
      accepted.message,
      acceptedSnapshot,
      `completion counter ${failure} preserves caller message`
    )
    authority.revoke(accepted.ticket)
  }
})

test('initiate, responder, and completion copies are atomic at every allocation', (t) => {
  function initiateAttempt(failure = Infinity) {
    const f = fixture(false)
    const arm = { value: false }
    const crypto = {
      ...cryptoSuite,
      sign(...args) {
        const signature = cryptoSuite.sign(...args)
        arm.value = true
        return signature
      }
    }
    const authority = createLinkSetupAuthority({
      crypto,
      now: () => 1_000,
      randomBytes: randomSequence([61])
    })
    const secret = b4a.from(f.initiatorIdentity.secretKey)
    const attempt = probeAllocationFailure(
      arm,
      () =>
        authority.initiate({
          ...f.common,
          responderStaticKey: f.responderStatic.publicKey,
          initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
        }),
      failure
    )
    if (attempt.result) authority.abort(attempt.result.pending)
    return { ...attempt, caller: f.initiatorIdentity.secretKey, secret }
  }

  const initiateCount = initiateAttempt().positions
  for (let failure = 1; failure <= initiateCount; failure++) {
    const attempt = initiateAttempt(failure)
    t.ok(attempt.error, `initiate allocation ${failure} fails`)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      `initiate allocation ${failure} clears prior secrets`
    )
    t.alike(attempt.caller, attempt.secret, `initiate allocation ${failure} preserves caller`)
  }

  function responderAttempt(failure = Infinity) {
    const f = fixture(false)
    const started = f.start()
    const arm = { value: false }
    const authority = createLinkSetupAuthority({
      crypto: derivedStateCrypto(arm),
      now: () => 1_000,
      randomBytes: randomSequence([62])
    })
    const secret = b4a.from(f.responderStatic.secretKey)
    const attempt = probeAllocationFailure(
      arm,
      () =>
        authority.respond(started.message, {
          ...f.common,
          responderStaticSecretKey: f.responderStatic.secretKey,
          responderIdentitySecretKey: f.responderIdentity.secretKey
        }),
      failure
    )
    if (attempt.result) authority.revoke(attempt.result.ticket)
    f.authority.abort(started.pending)
    return { ...attempt, caller: f.responderStatic.secretKey, secret }
  }

  const responderCount = responderAttempt().positions
  for (let failure = 1; failure <= responderCount; failure++) {
    const attempt = responderAttempt(failure)
    t.ok(attempt.error, `responder allocation ${failure} fails`)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      `responder allocation ${failure} clears prior secrets`
    )
    t.alike(attempt.caller, attempt.secret, `responder allocation ${failure} preserves caller`)
  }

  function completionAttempt(failure = Infinity) {
    const f = fixture(false)
    const arm = { value: false }
    const authority = createLinkSetupAuthority({
      crypto: derivedStateCrypto(arm),
      now: () => 1_000,
      randomBytes: randomSequence([63, 64])
    })
    const started = authority.initiate({
      ...f.common,
      responderStaticKey: f.responderStatic.publicKey,
      initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
    })
    const accepted = authority.respond(started.message, {
      ...f.common,
      responderStaticSecretKey: f.responderStatic.secretKey,
      responderIdentitySecretKey: f.responderIdentity.secretKey
    })
    arm.value = false
    const message = b4a.from(accepted.message)
    const attempt = probeAllocationFailure(
      arm,
      () => authority.complete(started.pending, accepted.message),
      failure
    )
    if (attempt.result) authority.revoke(attempt.result)
    authority.revoke(accepted.ticket)
    return { ...attempt, caller: accepted.message, message }
  }

  const completionCount = completionAttempt().positions
  for (let failure = 1; failure <= completionCount; failure++) {
    const attempt = completionAttempt(failure)
    t.ok(attempt.error, `completion allocation ${failure} fails`)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      `completion allocation ${failure} clears prior secrets`
    )
    t.alike(attempt.caller, attempt.message, `completion allocation ${failure} preserves caller`)
  }
})

test('responder signature and completion possession failures clear adjacent secret artifacts', (t) => {
  {
    const f = fixture(false)
    const started = f.start()
    const authority = createLinkSetupAuthority({
      crypto: {
        ...cryptoSuite,
        sign() {
          throw new Error('injected responder signature failure')
        }
      },
      now: () => 1_000,
      randomBytes: randomSequence([71])
    })
    const attempt = captureOwnedAllocations(() =>
      authority.respond(started.message, {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      })
    )
    t.ok(attempt.error)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      'responder clears challenge hash, possession tag, and derived material'
    )
    f.authority.abort(started.pending)
  }

  {
    const f = fixture(false)
    const crypto = {
      ...cryptoSuite,
      seal(options) {
        if (options.counter === 1n) throw new Error('injected possession failure')
        return cryptoSuite.seal(options)
      }
    }
    const authority = createLinkSetupAuthority({
      crypto,
      now: () => 1_000,
      randomBytes: randomSequence([72])
    })
    const localStart = authority.initiate({
      ...f.common,
      responderStaticKey: f.responderStatic.publicKey,
      initiatorIdentitySecretKey: f.initiatorIdentity.secretKey
    })
    const responderAuthority = createLinkSetupAuthority({
      crypto: cryptoSuite,
      now: () => 1_000,
      randomBytes: randomSequence([73])
    })
    const accepted = responderAuthority.respond(localStart.message, {
      ...f.common,
      responderStaticSecretKey: f.responderStatic.secretKey,
      responderIdentitySecretKey: f.responderIdentity.secretKey
    })
    const message = b4a.from(accepted.message)
    const attempt = captureOwnedAllocations(() =>
      authority.complete(localStart.pending, accepted.message)
    )
    t.ok(attempt.error)
    t.ok(
      attempt.allocations.every((value) => value.every((byte) => byte === 0)),
      'completion clears base hash and prior derived material'
    )
    t.alike(accepted.message, message)
    responderAuthority.revoke(accepted.ticket)
  }
})

test('failed ticket derivation erases the untransferred transcript', (t) => {
  const f = fixture(false)
  const started = f.start()
  let transcript = null
  const crypto = {
    ...cryptoSuite,
    deriveKeys(shared, value) {
      if (
        value.byteLength >= DOMAIN.LINK_CREATED.byteLength &&
        b4a.equals(value.subarray(0, DOMAIN.LINK_CREATED.byteLength), DOMAIN.LINK_CREATED)
      ) {
        transcript = value
        throw new Error('injected ticket derivation failure')
      }
      return cryptoSuite.deriveKeys(shared, value)
    }
  }
  const authority = createLinkSetupAuthority({
    crypto,
    now: () => 1_000,
    randomBytes: randomSequence([81])
  })
  expectCode(
    t,
    () =>
      authority.respond(started.message, {
        ...f.common,
        responderStaticSecretKey: f.responderStatic.secretKey,
        responderIdentitySecretKey: f.responderIdentity.secretKey
      }),
    'INVALID_ROUTE'
  )
  t.ok(transcript)
  t.ok(
    transcript.every((byte) => byte === 0),
    'failed derived transcript is zeroized'
  )
  f.authority.abort(started.pending)
})
