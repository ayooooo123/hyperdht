'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  CELL_CLASS,
  DIRECTION,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const { TEST_ONLY_UDX_ADAPTER_ISSUER, UdxCellEndpoint } = endpointModule

// Adapted from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const seed = (value) => b4a.alloc(32, value)

function safetyIdentity() {
  for (let value = 130; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function handles(hostA, portA, hostB, portB) {
  const authority = cryptoSuite.keyPair(seed(120))
  const a = cryptoSuite.keyPair(seed(121))
  const b = safetyIdentity()
  const runId32 = seed(122)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(123),
      endpointA: {
        identity32: a.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: hostA,
        port: portA,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: b.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: hostB,
        port: portB,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 8n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  const make = (local, peer, localRole, peerRole, operation) => {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 8n,
      runId32,
      now: () => 1n,
      schedule: setTimeout,
      cancel: clearTimeout,
      onClose() {}
    })
    const digest32 = directory.add(grant)
    return {
      directory,
      handle: directory.authorize({
        digest32,
        operation,
        localIdentity32: local.publicKey,
        localRole,
        peerIdentity32: peer.publicKey,
        peerRole,
        epoch: 8n,
        runId32
      })
    }
  }
  return {
    left: make(a, b, TOPOLOGY_ROLE.SOURCE, TOPOLOGY_ROLE.SAFETY_GUARD, LINK_OPERATION.INITIATE),
    right: make(b, a, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SOURCE, LINK_OPERATION.ACCEPT),
    a,
    b
  }
}

function sequence(first) {
  let value = first
  return (size) => b4a.alloc(size, value++)
}

test('default UdxAdapter completes link bootstrap and established cells on loopback', async (t) => {
  const platform = global.Bare ? Bare.platform : process.platform
  const [leftHost, rightHost] = selectUdxLoopbackHosts({ platform })
  const processId = global.Bare ? 211 : process.pid
  const leftPort = 48_000 + (processId % 1_000) * 2
  const rightPort = leftPort + 1
  const pair = handles(leftHost, leftPort, rightHost, rightPort)
  let leftSession = null
  let rightSession = null
  const received = []
  let resolveCells
  const cells = new Promise((resolve) => {
    resolveCells = resolve
  })
  const left = new UdxCellEndpoint({
    host: leftHost,
    port: leftPort,
    onBootstrap(packet) {
      if (leftSession) void leftSession.receive(packet)
    },
    onCell() {},
    onLinkFailure() {}
  })
  const right = new UdxCellEndpoint({
    host: rightHost,
    port: rightPort,
    onBootstrap(packet) {
      if (rightSession) void rightSession.receive(packet)
    },
    onCell(packet, handle, metadata) {
      received.push({ packet: b4a.from(packet), metadata })
      if (received.length === 2) resolveCells(true)
      return true
    },
    onLinkFailure() {}
  })
  t.teardown(async () => {
    await left.close().catch(() => {})
    await right.close().catch(() => {})
    pair.left.directory.destroy()
    pair.right.directory.destroy()
  })
  await left.bind()
  await right.bind()
  const started = Date.now()
  const now = () => Date.now() - started
  const responderStatic = cryptoSuite.encryptionKeyPair(seed(124))
  const common = {
    circuitId: b4a.alloc(16, 0x51),
    epoch: 8n,
    initiatorIdentity: pair.a.publicKey,
    responderIdentity: pair.b.publicKey,
    initiatorLocalId: b4a.alloc(16, 0x52),
    responderLocalId: b4a.alloc(16, 0x53),
    expiresAt: 60_000n
  }
  leftSession = left.openLink(pair.left.handle, {
    mode: 'initiate',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: pair.left.handle,
      localIdentitySecretKey: pair.a.secretKey,
      padding: sequence(0x81)
    }),
    linkSetup: createLinkSetupAuthority({ now, randomBytes: sequence(0x61) }),
    setup: {
      ...common,
      responderStaticKey: responderStatic.publicKey,
      initiatorIdentitySecretKey: pair.a.secretKey
    },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(1),
    absoluteDeadline: 10_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  })
  rightSession = right.openLink(pair.right.handle, {
    mode: 'accept',
    codec: new BootstrapEnvelopeCodec({
      linkHandle: pair.right.handle,
      localIdentitySecretKey: pair.b.secretKey,
      padding: sequence(0x91)
    }),
    linkSetup: createLinkSetupAuthority({ now, randomBytes: sequence(0x71) }),
    setup: {
      ...common,
      responderStaticSecretKey: responderStatic.secretKey,
      responderIdentitySecretKey: pair.b.secretKey
    },
    now,
    schedule: setTimeout,
    cancel: clearTimeout,
    randomBytes: sequence(11),
    absoluteDeadline: 10_000,
    signedExpiry: 60_000,
    authorizedExpiry: 60_000
  })
  const established = await leftSession.open()
  t.is(leftSession.state, 'OPEN')
  t.is(rightSession.state, 'OPEN')
  const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]
  t.is(
    await issuer.sendEstablishedForTest(left, established, {
      class: CELL_CLASS.STREAM,
      direction: DIRECTION.FORWARD,
      generation: 1n,
      payload: b4a.from('native-stream')
    }),
    true
  )
  t.is(
    await issuer.sendEstablishedForTest(left, established, {
      class: CELL_CLASS.DATAGRAM,
      direction: DIRECTION.FORWARD,
      generation: 1n,
      payload: b4a.from('native-datagram')
    }),
    true
  )
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 2_000))
  t.is(await Promise.race([cells, timeout]), true)
  t.alike(
    received.map((value) => [value.metadata.class, b4a.toString(value.packet)]),
    [
      [CELL_CLASS.STREAM, 'native-stream'],
      [CELL_CLASS.DATAGRAM, 'native-datagram']
    ]
  )
})
