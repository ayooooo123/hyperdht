'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { BOOTSTRAP_CLASS, BOOTSTRAP_SIZE } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')

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
    right: make(b, a, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SOURCE, LINK_OPERATION.ACCEPT)
  }
}

test('default UdxAdapter sends one reserved native bootstrap packet on loopback', async (t) => {
  const platform = global.Bare ? Bare.platform : process.platform
  const [leftHost, rightHost] = selectUdxLoopbackHosts({ platform })
  const processId = global.Bare ? 211 : process.pid
  const leftPort = 48_000 + (processId % 1_000) * 2
  const rightPort = leftPort + 1
  const pair = handles(leftHost, leftPort, rightHost, rightPort)
  let resolveReceived
  const received = new Promise((resolve) => {
    resolveReceived = resolve
  })
  const left = new UdxCellEndpoint({
    host: leftHost,
    port: leftPort,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {}
  })
  const right = new UdxCellEndpoint({
    host: rightHost,
    port: rightPort,
    onBootstrap(packet) {
      resolveReceived(b4a.from(packet))
    },
    onCell() {},
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
  const send = left.openLink(pair.left.handle)
  right.openLink(pair.right.handle)
  const packet = b4a.alloc(BOOTSTRAP_SIZE, 0x5a)
  packet[0] = 0
  packet[1] = BOOTSTRAP_CLASS
  t.is(await left.send(send, packet), true)
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 2_000))
  t.alike(await Promise.race([received, timeout]), packet)
})
