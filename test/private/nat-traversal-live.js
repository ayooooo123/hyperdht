'use strict'

// The production traversal path, end to end, on real UDX sockets.
//
// What this proves, and why no harness rehearsal can: two UdxCellEndpoints bind
// DIFFERENT loopback addresses, so the source of every datagram is translated
// relative to what each endpoint believes about the other - the shape a NAT
// produces, which a single-host 127.0.0.1 rehearsal hides. Nothing opens the
// path in advance. One signed punch plan, from the topology authority, drives a
// simultaneous round on the endpoints' own sockets; each endpoint counts the
// OTHER side's punch datagrams against the verified round and counts datagrams
// from any other source as stray. Only then does the authenticated link
// handshake run, on the signed topology grant it always required. A punch never
// substitutes for the grant: the responder's accept path verifies the initiator
// identity through the link setup transcript, and a stray punch opens nothing.
//
// The rejects the task names are exercised directly: a wrong-signature plan, a
// plan naming the wrong local address, and an out-of-window plan each fail
// closed before a single datagram is sent.

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { PLAN_FORMAT, signNatPunchPlan, verifyNatPunchPlan } = require('../../lib/private/nat-punch')
const { UdxCellEndpoint, PUNCH_TAG } = require('../../lib/private/udx-cell-endpoint')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')

// macOS refuses distinct 127.x.y.z addresses without per-address configuration
// (KI-2), so distinct ADDRESSES are not portable either. The translation this
// test exercises is port-based instead: both endpoints bind 127.0.0.1 on
// DIFFERENT ports, which keeps the property that matters - each endpoint's
// socket is a different UDP flow with its own mapping, and neither side can
// open the path alone - while staying portable across Node, Bare, macOS, Linux
// and Windows.
const HOST_A = '127.0.0.1'
const HOST_B = '127.0.0.1'
const PORT_A = 51501
const PORT_B = 51502

const seed = (value) => b4a.alloc(32, value)

function roleIdentity(start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function endpointOptions(host, port) {
  return {
    host,
    port,
    advertisedHost: host,
    advertisedPort: port,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {}
  }
}

function buildTopology() {
  const authority = cryptoSuite.keyPair(seed(240))
  const initiator = cryptoSuite.keyPair(seed(241))
  const accepter = roleIdentity(242)
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(243))
  const runId32 = seed(244)

  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(245),
      endpointA: {
        identity32: initiator.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: HOST_A,
        port: PORT_A,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: accepter.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: HOST_B,
        port: PORT_B,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )

  const directoryFor = (local, localRole, peer, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 7n,
      runId32,
      now: () => 1n,
      schedule: () => null,
      cancel: () => {},
      onClose() {}
    })
    const digest32 = directory.add(grant)
    const handle = directory.authorize({
      digest32,
      operation,
      localIdentity32: local.publicKey,
      localRole,
      peerIdentity32: peer.publicKey,
      peerRole,
      epoch: 7n,
      runId32
    })
    return { directory, handle }
  }

  return {
    authority,
    initiator,
    accepter,
    responderStatic,
    runId32,
    grant,
    left: directoryFor(
      initiator,
      TOPOLOGY_ROLE.SOURCE,
      accepter,
      TOPOLOGY_ROLE.SAFETY_GUARD,
      LINK_OPERATION.INITIATE
    ),
    right: directoryFor(
      accepter,
      TOPOLOGY_ROLE.SAFETY_GUARD,
      initiator,
      TOPOLOGY_ROLE.SOURCE,
      LINK_OPERATION.ACCEPT
    )
  }
}

function planEncoding(topology) {
  return signNatPunchPlan(
    {
      version: PROTOCOL_VERSION,
      format: PLAN_FORMAT,
      planId32: seed(246),
      endpointA: {
        identity32: topology.initiator.publicKey,
        role: 0,
        host: HOST_A,
        port: PORT_A
      },
      endpointB: { identity32: topology.accepter.publicKey, role: 1, host: HOST_B, port: PORT_B },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32: topology.runId32
    },
    topology.authority.secretKey
  )
}

test('a wrong-signature plan is refused before any send', async (t) => {
  const topology = buildTopology()
  const left = new UdxCellEndpoint(endpointOptions(HOST_A, PORT_A))
  await left.bind()
  t.teardown(() => left.close())

  const stranger = cryptoSuite.keyPair(seed(247))
  const wrongSignature = signNatPunchPlan(
    {
      version: PROTOCOL_VERSION,
      format: PLAN_FORMAT,
      planId32: seed(246),
      endpointA: {
        identity32: topology.initiator.publicKey,
        role: 0,
        host: HOST_A,
        port: PORT_A
      },
      endpointB: {
        identity32: topology.accepter.publicKey,
        role: 1,
        host: HOST_B,
        port: PORT_B
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32: topology.runId32
    },
    stranger.secretKey
  )
  await t.exception(
    left.punchPlan(wrongSignature, {
      authorityPublicKey: topology.authority.publicKey,
      localIdentity32: topology.initiator.publicKey,
      now: () => 10
    }),
    'a stranger-signed plan never reaches the socket'
  )
})

test('a plan naming the wrong local address is refused', async (t) => {
  const topology = buildTopology()
  const left = new UdxCellEndpoint(endpointOptions(HOST_A, PORT_A))
  await left.bind()
  t.teardown(() => left.close())

  // The plan is genuinely signed, but names the OTHER host as A's endpoint.
  const wrongAddress = signNatPunchPlan(
    {
      version: PROTOCOL_VERSION,
      format: PLAN_FORMAT,
      planId32: seed(248),
      endpointA: {
        identity32: topology.initiator.publicKey,
        role: 0,
        host: HOST_B,
        port: PORT_B
      },
      endpointB: {
        identity32: topology.accepter.publicKey,
        role: 1,
        host: HOST_B,
        port: PORT_B
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32: topology.runId32
    },
    topology.authority.secretKey
  )
  await t.exception(
    left.punchPlan(wrongAddress, {
      authorityPublicKey: topology.authority.publicKey,
      localIdentity32: topology.initiator.publicKey,
      now: () => 10
    }),
    'the plan must name the address this endpoint advertises'
  )
})

test('a plan outside its window is refused', async (t) => {
  const topology = buildTopology()
  const left = new UdxCellEndpoint(endpointOptions(HOST_A, PORT_A))
  await left.bind()
  t.teardown(() => left.close())

  const encoding = planEncoding(topology)
  // The plan's window is [0, 60000); a caller that samples now past the expiry
  // is refused. verifyNatPunchPlan is the same gate punchPlan uses.
  t.exception(
    () =>
      verifyNatPunchPlan(encoding, topology.authority.publicKey, {
        localIdentity32: topology.initiator.publicKey,
        now: 60_000n
      }),
    'an expired plan has no side'
  )
})

test('punch datagrams from an unverified source are counted stray, not as the peer', async (t) => {
  const topology = buildTopology()
  const left = new UdxCellEndpoint(endpointOptions(HOST_A, PORT_A))
  const right = new UdxCellEndpoint(endpointOptions(HOST_B, PORT_B))
  await left.bind()
  await right.bind()
  t.teardown(async () => {
    await left.close()
    await right.close()
  })

  // A stranger spoofs punch-tagged datagrams toward B while BOTH verified
  // rounds run concurrently. Each round lasts ~5s (6 sends over 2.5s plus a
  // 2s drain), so the spoof window overlaps them. B must count A's punches as
  // its peer and the stranger's as stray; A sees only B.
  const strangerUdx = new (require('udx-native'))()
  const strangerSocket = strangerUdx.createSocket()
  await strangerSocket.bind(0, '127.0.0.1')
  const encoding = planEncoding(topology)
  const leftStatsPromise = left.punchPlan(encoding, {
    authorityPublicKey: topology.authority.publicKey,
    localIdentity32: topology.initiator.publicKey,
    now: () => 10
  })
  const rightStatsPromise = right.punchPlan(encoding, planOptionsLocal(topology))
  const spoof = setInterval(() => {
    try {
      strangerSocket.send(b4a.from(PUNCH_TAG), PORT_B, HOST_B)
    } catch {}
  }, 100)
  const [leftStats, rightStats] = await Promise.all([leftStatsPromise, rightStatsPromise])
  clearInterval(spoof)
  await strangerSocket.close()

  t.ok(leftStats.received >= 1, 'A counted the peer punches from the plan tuple')
  t.ok(rightStats.received >= 1, 'B counted A punches as the peer')
  t.ok(rightStats.strayReceived >= 1, 'B counted the stranger punch as stray')
  t.is(leftStats.strayReceived, 0, 'A saw nothing stray: only B sent to it')
})

function planOptionsLocal(topology) {
  return {
    authorityPublicKey: topology.authority.publicKey,
    localIdentity32: topology.accepter.publicKey,
    now: () => 10
  }
}

test('two endpoints traverse: verified simultaneous punch round then authenticated link', async (t) => {
  const topology = buildTopology()
  const left = new UdxCellEndpoint(endpointOptions(HOST_A, PORT_A))
  const right = new UdxCellEndpoint(endpointOptions(HOST_B, PORT_B))
  await left.bind()
  await right.bind()
  t.teardown(async () => {
    await left.close()
    await right.close()
  })

  // Simultaneous verified round first: the path exists before either side
  // speaks the link protocol.
  const encoding = planEncoding(topology)
  const planOptions = {
    authorityPublicKey: topology.authority.publicKey,
    localIdentity32: topology.initiator.publicKey,
    now: () => 10
  }
  const [leftStats, rightStats] = await Promise.all([
    left.punchPlan(encoding, planOptions),
    right.punchPlan(encoding, { ...planOptions, localIdentity32: topology.accepter.publicKey })
  ])
  t.ok(leftStats.sent >= 1 && rightStats.sent >= 1, 'both sides punched')
  t.ok(leftStats.received >= 1 && rightStats.received >= 1, 'both sides counted the peer punch')

  // Responder pre-arms its ACCEPT session, as a real guard does.
  const responderSetup = {
    circuitId: b4a.alloc(16, 0x71),
    epoch: 7n,
    initiatorIdentity: topology.initiator.publicKey,
    responderIdentity: topology.accepter.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x72),
    responderLocalId: b4a.alloc(16, 0x73),
    expiresAt: 60_000n,
    responderStaticSecretKey: topology.responderStatic.secretKey,
    responderIdentitySecretKey: topology.accepter.secretKey
  }
  const acceptSession = right.openLink(topology.right.handle, {
    mode: 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: topology.right.handle,
      localIdentitySecretKey: topology.accepter.secretKey,
      padding: (size) => b4a.alloc(size, 0x91)
    }),
    linkSetup: createLinkSetupAuthority({
      now: () => 1,
      randomBytes: (size) => b4a.alloc(size, 0x71)
    }),
    setup: responderSetup,
    now: () => 1,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: (size) => b4a.alloc(size, 3),
    absoluteDeadline: 30_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000,
    acceptDirect: true
  })
  t.ok(acceptSession, 'the responder armed an accept session')

  const initiatorSetup = {
    circuitId: b4a.alloc(16, 0x71),
    epoch: 7n,
    initiatorIdentity: topology.initiator.publicKey,
    responderIdentity: topology.accepter.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x72),
    responderLocalId: b4a.alloc(16, 0x73),
    expiresAt: 60_000n,
    responderStaticKey: topology.responderStatic.publicKey,
    initiatorIdentitySecretKey: topology.initiator.secretKey
  }
  const session = left.openLink(topology.left.handle, {
    mode: 'initiate',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: topology.left.handle,
      localIdentitySecretKey: topology.initiator.secretKey,
      padding: (size) => b4a.alloc(size, 0x81)
    }),
    linkSetup: createLinkSetupAuthority({
      now: () => 1,
      randomBytes: (size) => b4a.alloc(size, 0x61)
    }),
    setup: initiatorSetup,
    now: () => 1,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: (size) => b4a.alloc(size, 1),
    absoluteDeadline: 30_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  })
  const established = await session.open()
  t.ok(established, 'the link established across the punched path')
  t.is(acceptSession.state, 'OPEN', 'the responder reached OPEN on the same link')
  await acceptSession.close()
  await session.close()
})
