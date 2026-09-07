'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  LinkBootstrapSession,
  readEstablishedLink,
  TEST_ONLY_LINK_BOOTSTRAP_SESSION_OBSERVER
} = require('../../lib/private/link-bootstrap-session')
const linkBootstrapModule = require('../../lib/private/link-bootstrap-session')
const {
  LINK_BOOTSTRAP_REGISTER_ESTABLISHED
} = require('../../lib/private/link-bootstrap-ownership')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const {
  UDX_LINK_CLOSE,
  UDX_LINK_OPEN,
  UDX_SEND_DISPATCH
} = require('../../lib/private/udx-adapter')

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169.

const seed = (value) => b4a.alloc(32, value)
const createDynamicResponderSetup =
  linkBootstrapModule[Symbol.for('hyperdht-private-routes/dynamic-responder-setup-factory')]

test('established links expose no raw endpoint reservation reader', (t) => {
  t.is('readEstablishedLinkReservation' in linkBootstrapModule, false)
})

function roleIdentity(role, start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
  throw new Error('missing deterministic role identity')
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

function abortController() {
  const listeners = new Set()
  const signal = {
    aborted: false,
    addEventListener(name, listener) {
      if (name === 'abort') listeners.add(listener)
    },
    removeEventListener(name, listener) {
      if (name === 'abort') listeners.delete(listener)
    }
  }
  return {
    signal,
    abort() {
      if (signal.aborted) return
      signal.aborted = true
      for (const listener of Array.from(listeners)) listener()
    }
  }
}

function clock(start) {
  let now = start
  let next = 1
  const timers = new Map()
  const run = () => {
    let found = true
    while (found) {
      found = false
      for (const [id, timer] of timers) {
        if (timer.at > now) continue
        timers.delete(id)
        timer.callback()
        found = true
        break
      }
    }
  }
  return {
    now: () => now,
    schedule(callback, delay) {
      const id = next++
      timers.set(id, { callback, at: now + delay })
      return id
    },
    cancel(id) {
      timers.delete(id)
    },
    advance(delta) {
      now += delta
      run()
    },
    pending: () => timers.size
  }
}

function directory({ local, peer, localRole, peerRole, operation, authority, grant, now }) {
  const value = new LinkDirectory({
    localIdentity32: local.publicKey,
    localRole,
    authorityPublicKey: authority.publicKey,
    epoch: 9n,
    runId32: seed(254),
    now: () => BigInt(now()),
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })
  const digest32 = value.add(grant)
  return {
    value,
    handle: value.authorize({
      digest32,
      operation,
      localIdentity32: local.publicKey,
      localRole,
      peerIdentity32: peer.publicKey,
      peerRole,
      epoch: 9n,
      runId32: seed(254)
    })
  }
}

function fixture({
  start = 0,
  absoluteDeadline = 10_000,
  signedExpiry = 60_000,
  authorizedExpiry = 60_000,
  transcriptExpiry = 60_000n,
  dynamic = false,
  dynamicSetup = null,
  responderLinkSetup = null,
  initiatorClaim = null,
  commonEpoch = 9n,
  drop = false,
  dropFirstRight = false
} = {}) {
  const time = clock(start)
  const authority = cryptoSuite.keyPair(seed(250))
  const initiator = cryptoSuite.keyPair(seed(251))
  const responder = roleIdentity(ROLE.SAFETY, 252)
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(253))
  const expiresAt = transcriptExpiry
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(255),
      endpointA: {
        identity32: initiator.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: '127.0.0.31',
        port: 46331,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: responder.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: '127.0.0.32',
        port: 46332,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 9n,
      notBefore: 0n,
      expiresAt,
      runId32: seed(254)
    },
    authority.secretKey
  )
  const left = directory({
    local: initiator,
    peer: responder,
    localRole: TOPOLOGY_ROLE.SOURCE,
    peerRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    operation: LINK_OPERATION.INITIATE,
    authority,
    grant,
    now: time.now
  })
  const right = directory({
    local: responder,
    peer: initiator,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerRole: TOPOLOGY_ROLE.SOURCE,
    operation: LINK_OPERATION.ACCEPT,
    authority,
    grant,
    now: time.now
  })
  const common = {
    circuitId: b4a.alloc(16, 0x51),
    epoch: commonEpoch,
    initiatorIdentity: initiatorClaim || initiator.publicKey,
    responderIdentity: responder.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x52),
    responderLocalId: b4a.alloc(16, 0x53),
    expiresAt
  }
  const leftPackets = []
  const rightPackets = []
  let rightSends = 0
  let leftSession = null
  let rightSession = null
  const leftHandle = Object.freeze({})
  const rightHandle = Object.freeze({})
  const endpoint = (side) => ({
    send(handle, packet, options = {}) {
      if (options[UDX_SEND_DISPATCH]) options[UDX_SEND_DISPATCH]()
      if (side === 'left') leftPackets.push(b4a.from(packet))
      else {
        rightPackets.push(b4a.from(packet))
        rightSends++
      }
      const selectedDrop = drop || (side === 'right' && dropFirstRight && rightSends === 1)
      if (!selectedDrop) {
        const peer = side === 'left' ? rightSession : leftSession
        const owned = b4a.from(packet)
        queueMicrotask(() => void peer.receive(owned))
      }
      return Promise.resolve(true)
    },
    [UDX_LINK_OPEN]() {},
    [LINK_BOOTSTRAP_REGISTER_ESTABLISHED]() {},
    [UDX_LINK_CLOSE]() {}
  })
  const sessionOptions = {
    now: time.now,
    schedule: time.schedule,
    cancel: time.cancel,
    absoluteDeadline,
    signedExpiry,
    authorizedExpiry
  }
  leftSession = new LinkBootstrapSession({
    ...sessionOptions,
    mode: 'initiate',
    endpoint: endpoint('left'),
    sendHandle: leftHandle,
    linkHandle: left.handle,
    codec: new BootstrapEnvelopeCodec({
      linkHandle: left.handle,
      localIdentitySecretKey: initiator.secretKey,
      padding: sequence(0x81)
    }),
    linkSetup: createLinkSetupAuthority({ now: time.now, randomBytes: sequence(0x61) }),
    setup: {
      ...common,
      responderStaticKey: responderStatic.publicKey,
      initiatorIdentitySecretKey: initiator.secretKey
    },
    randomBytes: sequence(1)
  })
  const responderSetup = dynamic
    ? dynamicSetup ||
      createDynamicResponderSetup({
        responderStaticSecretKey: responderStatic.secretKey,
        responderIdentitySecretKey: responder.secretKey
      })
    : {
        ...common,
        responderStaticSecretKey: responderStatic.secretKey,
        responderIdentitySecretKey: responder.secretKey
      }
  try {
    rightSession = new LinkBootstrapSession({
      ...sessionOptions,
      mode: 'accept',
      endpoint: endpoint('right'),
      sendHandle: rightHandle,
      linkHandle: right.handle,
      codec: new BootstrapEnvelopeCodec({
        linkHandle: right.handle,
        localIdentitySecretKey: responder.secretKey,
        padding: sequence(0x91)
      }),
      linkSetup:
        responderLinkSetup ||
        createLinkSetupAuthority({ now: time.now, randomBytes: sequence(0x71) }),
      setup: responderSetup,
      randomBytes: sequence(11)
    })
  } catch (err) {
    void leftSession.close()
    left.value.destroy()
    right.value.destroy()
    throw err
  }
  return {
    time,
    leftSession,
    rightSession,
    leftPackets,
    rightPackets,
    left,
    right,
    dynamicSetup: responderSetup
  }
}

test('link bootstrap opens once and installs an opaque established link', async (t) => {
  const f = fixture()
  const established = await f.leftSession.open()
  await Promise.resolve()
  t.is(f.leftSession.state, 'OPEN')
  t.is(f.rightSession.state, 'OPEN')
  t.is(Object.keys(established).length, 0)
  t.ok(readEstablishedLink(established))
  await f.leftSession.close()
  await f.rightSession.close()
  t.alike(f.leftSession[TEST_ONLY_LINK_BOOTSTRAP_SESSION_OBSERVER](), {
    retainedReferences: 0,
    cancelSends: 0,
    closed: true,
    state: 'TOMBSTONE'
  })
  t.alike(f.rightSession[TEST_ONLY_LINK_BOOTSTRAP_SESSION_OBSERVER](), {
    retainedReferences: 0,
    cancelSends: 0,
    closed: true,
    state: 'TOMBSTONE'
  })
  f.left.value.destroy()
  f.right.value.destroy()
})

test('link CREATE retries semantic bytes within inherited remaining deadline', async (t) => {
  const f = fixture({ start: 3_500, absoluteDeadline: 5_000, drop: true })
  const opening = f.leftSession.open()
  await Promise.resolve()
  for (let elapsed = 250; elapsed < 1_500; elapsed += 250) {
    f.time.advance(250)
    await Promise.resolve()
  }
  t.ok(f.leftPackets.length > 1)
  for (const packet of f.leftPackets) t.alike(packet, f.leftPackets[0])
  t.is(f.time.pending(), 2)
  f.time.advance(250)
  let error = null
  try {
    await opening
  } catch (err) {
    error = err
  }
  t.is(error && error.code, 'ROUTE_UNAVAILABLE')
  t.is(f.time.pending(), 1)
  await f.leftSession.close()
  t.is(f.time.pending(), 0)
  await f.rightSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
})

test('link CREATED is cached byte-for-byte and recovered by an exact CREATE retry', async (t) => {
  const f = fixture({ dropFirstRight: true })
  const opening = f.leftSession.open()
  await Promise.resolve()

  await Promise.resolve()
  t.is(f.rightSession.state, 'OPEN')
  t.is(f.leftSession.state, 'CREATING')
  t.is(f.rightPackets.length, 1)
  f.time.advance(250)
  const established = await opening
  t.ok(readEstablishedLink(established))
  t.is(f.leftSession.state, 'OPEN')
  t.is(f.rightPackets.length, 2)
  t.alike(f.rightPackets[1], f.rightPackets[0])
  await f.leftSession.close()
  await f.rightSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
})
async function rejectDynamic(t, options) {
  const { reachesResponder = false, ...fixtureOptions } = options
  const f = fixture({ dynamic: true, ...fixtureOptions })
  const opening = f.leftSession.open()
  const rejected = t.exception(opening)
  for (let i = 0; i < 20 && f.rightSession.state === 'IDLE'; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  t.is(f.rightSession.state, reachesResponder ? 'TOMBSTONE' : 'IDLE')
  await f.leftSession.close()
  await rejected
  await f.rightSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
  return f.dynamicSetup
}

test('dynamic responder fails closed on claims, wall expiry, replay, and local expiry', async (t) => {
  await rejectDynamic(t, { initiatorClaim: seed(7) })
  await rejectDynamic(t, { commonEpoch: 10n })
  const spent = await rejectDynamic(t, {
    transcriptExpiry: 60_001n,
    authorizedExpiry: 60_000,
    reachesResponder: true
  })
  t.exception(() => fixture({ dynamic: true, dynamicSetup: spent }))
  await rejectDynamic(t, { start: 1_000, signedExpiry: 1_000 })
})

test('closing before dynamic responder setup consumption zeroizes owned secrets', async (t) => {
  const responderStaticSecretKey = b4a.alloc(32, 0xa1)
  const responderIdentitySecretKey = b4a.alloc(64, 0xa2)
  const captured = []
  const originalFrom = b4a.from
  let dynamicSetup
  b4a.from = function trackedFrom(value, ...args) {
    const copied = originalFrom(value, ...args)
    if (value === responderStaticSecretKey || value === responderIdentitySecretKey) {
      captured.push(copied)
    }
    return copied
  }
  try {
    dynamicSetup = createDynamicResponderSetup({
      responderStaticSecretKey,
      responderIdentitySecretKey
    })
  } finally {
    b4a.from = originalFrom
  }
  const f = fixture({ dynamic: true, dynamicSetup })
  await f.rightSession.close()
  t.is(captured.length, 2)
  for (const secret of captured) t.alike(secret, b4a.alloc(secret.byteLength))
  t.exception(() => fixture({ dynamic: true, dynamicSetup }))
  await f.leftSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
})

test('bad dynamic responder challenge zeroizes consumed setup secrets', async (t) => {
  let consumedSetup = null
  const time = clock()
  const authority = createLinkSetupAuthority({ now: time.now, randomBytes: sequence(0x71) })
  const responderLinkSetup = {
    checker: authority.checker,
    initiate: (...args) => authority.initiate(...args),
    complete: (...args) => authority.complete(...args),
    abort: (...args) => authority.abort(...args),
    revoke: (...args) => authority.revoke(...args),
    respond(message, setup) {
      consumedSetup = setup
      const malformed = b4a.from(message)
      malformed[malformed.byteLength - 1] ^= 1
      try {
        return authority.respond(malformed, setup)
      } finally {
        b4a.fill(malformed, 0)
      }
    }
  }
  const f = fixture({ dynamic: true, responderLinkSetup })
  const rejected = t.exception(f.leftSession.open())
  for (let i = 0; i < 20 && consumedSetup === null; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  t.ok(consumedSetup)
  t.alike(consumedSetup.responderStaticSecretKey, b4a.alloc(32))
  t.alike(consumedSetup.responderIdentitySecretKey, b4a.alloc(64))
  await f.leftSession.close()
  await rejected
  await f.rightSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
})

test('link bootstrap takes the earliest signed, inherited, and five-second local deadline', async (t) => {
  for (const [name, options, remaining] of [
    ['signed expiry', { start: 3_500, absoluteDeadline: 20_000, signedExpiry: 4_000 }, 500],
    ['inherited branch', { start: 3_500, absoluteDeadline: 5_000, signedExpiry: 60_000 }, 1_500],
    ['five-second cap', { start: 0, absoluteDeadline: 10_000, signedExpiry: 60_000 }, 5_000]
  ]) {
    const f = fixture({ ...options, drop: true })
    const opening = f.leftSession.open()
    await Promise.resolve()
    f.time.advance(remaining - 1)
    t.is(f.leftSession.state, 'CREATING', `${name} remains live one millisecond before expiry`)
    f.time.advance(1)
    let error = null
    try {
      await opening
    } catch (err) {
      error = err
    }
    t.is(error && error.code, 'ROUTE_UNAVAILABLE', `${name} fails at its exact bound`)
    t.is(f.leftSession.state, 'TOMBSTONE')
    await f.leftSession.close()
    await f.rightSession.close()
    f.left.value.destroy()
    f.right.value.destroy()
  }
})

test('abort after CREATE dispatch sends authenticated cancellation and tombstones both sides', async (t) => {
  const f = fixture()
  const controller = abortController()
  const opening = f.leftSession.open({ signal: controller.signal })
  controller.abort()
  await t.exception(opening)
  await Promise.resolve()
  await Promise.resolve()
  t.is(f.leftSession.state, 'TOMBSTONE')
  t.is(f.rightSession.state, 'TOMBSTONE')
  t.ok(f.leftPackets.length >= 2, 'CREATE and LINK_CANCEL crossed the endpoint')
  await f.leftSession.close()
  await f.rightSession.close()
  f.left.value.destroy()
  f.right.value.destroy()
})
