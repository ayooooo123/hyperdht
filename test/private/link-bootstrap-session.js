'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  LinkBootstrapSession,
  readEstablishedLink
} = require('../../lib/private/link-bootstrap-session')
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

function fixture({ start = 0, absoluteDeadline = 10_000, drop = false } = {}) {
  const time = clock(start)
  const authority = cryptoSuite.keyPair(seed(250))
  const initiator = cryptoSuite.keyPair(seed(251))
  const responder = roleIdentity(ROLE.SAFETY, 252)
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(253))
  const expiresAt = 60_000n
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
    epoch: 9n,
    initiatorIdentity: initiator.publicKey,
    responderIdentity: responder.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x52),
    responderLocalId: b4a.alloc(16, 0x53),
    expiresAt
  }
  const leftPackets = []
  let leftSession = null
  let rightSession = null
  const leftHandle = Object.freeze({})
  const rightHandle = Object.freeze({})
  const endpoint = (side) => ({
    send(handle, packet, options = {}) {
      if (options[UDX_SEND_DISPATCH]) options[UDX_SEND_DISPATCH]()
      if (side === 'left') leftPackets.push(b4a.from(packet))
      if (!drop) {
        const peer = side === 'left' ? rightSession : leftSession
        queueMicrotask(() => void peer.receive(b4a.from(packet)))
      }
      return Promise.resolve(true)
    },
    [UDX_LINK_OPEN]() {},
    [UDX_LINK_CLOSE]() {}
  })
  const sessionOptions = {
    now: time.now,
    schedule: time.schedule,
    cancel: time.cancel,
    absoluteDeadline,
    signedExpiry: Number(expiresAt)
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
    linkSetup: createLinkSetupAuthority({ now: time.now, randomBytes: sequence(0x71) }),
    setup: {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: responder.secretKey
    },
    randomBytes: sequence(11)
  })
  return { time, leftSession, rightSession, leftPackets, left, right }
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
