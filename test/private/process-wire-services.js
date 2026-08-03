'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { signTopologyGrant } = require('../../lib/private/topology-grant')
const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')
const { createProjectedLinkService } = require('./process/wire-services')

const HOST = '127.0.0.1'
let nextPort = 49_600

function identityFor(role, value) {
  for (let index = value; index < value + 512; index++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, index & 0xff))
    if (roleForIdentity(pair.publicKey) === role) return pair
    pair.secretKey.fill(0)
    pair.publicKey.fill(0)
  }
  throw new Error('identity role unavailable')
}

function grantFixture() {
  const left = identityFor(ROLE.SAFETY, 0x11)
  const right = identityFor(ROLE.PRIVATE, 0x71)
  const authority = cryptoSuite.keyPair(b4a.alloc(32, 0xa1))
  const route = cryptoSuite.encryptionKeyPair(b4a.alloc(32, 0xa2))
  const runId32 = b4a.alloc(32, 0xa3)
  const leftPort = nextPort++
  const rightPort = nextPort++
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: b4a.alloc(32, 0xa4),
      endpointA: {
        identity32: left.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_FINAL,
        host: HOST,
        port: leftPort,
        operations: LINK_OPERATION.KNOWN
      },
      endpointB: {
        identity32: right.publicKey,
        role: TOPOLOGY_ROLE.PRIVATE_ENTRY,
        host: HOST,
        port: rightPort,
        operations: LINK_OPERATION.KNOWN
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  return { authority, grant, left, leftPort, right, rightPort, route, runId32 }
}

function endpoint(host, port, dispatch) {
  return new UdxCellEndpoint({
    host,
    port,
    onBootstrap: (packet) => dispatch.bootstrap(packet),
    onCell: (packet, handle, metadata) => dispatch.cell(packet, handle, metadata),
    onLinkFailure: (handle, direction, reason) => dispatch.failure(handle, direction, reason)
  })
}

test('projected link service opens exact signed UDX adjacency on native loopback', async (t) => {
  const fixture = grantFixture()
  const leftDispatch = {}
  const rightDispatch = {}
  const leftEndpoint = endpoint(HOST, fixture.leftPort, leftDispatch)
  const rightEndpoint = endpoint(HOST, fixture.rightPort, rightDispatch)
  const clock = {
    wallNow: () => 1_000n,
    monotonicNow: () => 1_000n,
    schedule: setTimeout,
    cancelScheduled: clearTimeout
  }
  const left = createProjectedLinkService({
    ...clock,
    endpoint: leftEndpoint,
    authorityPublicKey: fixture.authority.publicKey,
    epoch: 1n,
    localIdentity: fixture.left.publicKey,
    localIdentitySecretKey: fixture.left.secretKey,
    localRouteSecretKey: null,
    runId32: fixture.runId32
  })
  const right = createProjectedLinkService({
    ...clock,
    endpoint: rightEndpoint,
    authorityPublicKey: fixture.authority.publicKey,
    epoch: 1n,
    localIdentity: fixture.right.publicKey,
    localIdentitySecretKey: fixture.right.secretKey,
    localRouteSecretKey: fixture.route.secretKey,
    runId32: fixture.runId32
  })
  leftDispatch.bootstrap = left.receiveBootstrap
  leftDispatch.cell = left.receiveCell
  leftDispatch.failure = left.receiveLinkFailure
  rightDispatch.bootstrap = right.receiveBootstrap
  rightDispatch.cell = right.receiveCell
  rightDispatch.failure = right.receiveLinkFailure

  try {
    await Promise.all([leftEndpoint.bind(), rightEndpoint.bind()])
    const accepted = right.prearmAccept(fixture.grant)
    const opened = await left.initiate(fixture.grant, {
      circuitId: b4a.alloc(16, 0xb1),
      generation: 1n,
      responderStaticKey: fixture.route.publicKey
    })
    const responder = await accepted
    t.ok(opened.established, 'initiator owns authenticated established handle')
    t.ok(responder.established, 'responder owns authenticated established handle')
    t.is(left.snapshot().openLinks, 1)
    t.is(right.snapshot().openLinks, 1)
    const leftSetup = left.openSetupTransport(opened)
    const rightSetup = right.openSetupTransport(responder)
    const offer = b4a.alloc(313, 0xc1)
    const response = b4a.alloc(427, 0xc2)
    await leftSetup.send(offer)
    t.alike(await rightSetup.receive(), offer, 'extension offer crosses authenticated UDX stream')
    await rightSetup.send(response)
    t.alike(
      await leftSetup.receive(),
      response,
      'extension response crosses authenticated UDX stream'
    )
    t.ok(leftSetup.takePhysicalChannel(), 'initiator transfers the exact established link')
    t.ok(rightSetup.takePhysicalChannel(), 'responder transfers the exact established link')
    t.ok(leftSetup.finish(), 'initiator setup transport relinquishes setup ownership')
    t.ok(rightSetup.finish(), 'responder setup transport relinquishes setup ownership')
    await t.exception(
      left.initiate(fixture.grant, {
        circuitId: b4a.alloc(16, 0xb2),
        generation: 2n,
        responderStaticKey: fixture.route.publicKey
      }),
      'signed grant handle is one-shot'
    )
  } finally {
    await Promise.allSettled([left.destroy(), right.destroy()])
    await Promise.allSettled([leftEndpoint.close(), rightEndpoint.close()])
  }
})
