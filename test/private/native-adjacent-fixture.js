'use strict'
const b4a = require('b4a')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { encodeCanonicalEndpoint } = require('../../lib/private/relay-capability')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const { selectUdxLoopbackHosts } = require('../../lib/private/udx-adapter')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
let port = 49300
const seed = (value) => b4a.alloc(32, value)
function hostBytes(host) {
  return host.includes(':')
    ? b4a.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    : b4a.from(host.split('.').map(Number))
}
async function nativeAdjacentPair(current, next, currentRole = TOPOLOGY_ROLE.SAFETY_GUARD) {
  const platform = global.Bare ? Bare.platform : process.platform
  const [leftHost, rightHost] = selectUdxLoopbackHosts({ platform })
  const leftPort = port++,
    rightPort = port++
  const authority = cryptoSuite.keyPair(seed(0xd1)),
    runId32 = seed(0xd2)
  const leftRole = currentRole
  const rightRole =
    roleForIdentity(next.publicKey) === ROLE.SAFETY
      ? TOPOLOGY_ROLE.SAFETY_FINAL
      : TOPOLOGY_ROLE.PRIVATE_ENTRY
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(port & 255),
      endpointA: {
        identity32: current.publicKey,
        role: leftRole,
        host: leftHost,
        port: leftPort,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: next.publicKey,
        role: rightRole,
        host: rightHost,
        port: rightPort,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 1n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  function make(local, peer, localRole, peerRole, operation) {
    const directory = new LinkDirectory({
      localIdentity32: local.publicKey,
      localRole,
      authorityPublicKey: authority.publicKey,
      epoch: 1n,
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
        epoch: 1n,
        runId32
      })
    }
  }
  const lh = make(current, next, leftRole, rightRole, LINK_OPERATION.INITIATE)
  const rh = make(next, current, rightRole, leftRole, LINK_OPERATION.ACCEPT)
  let ls = null,
    rs = null
  const left = new endpointModule.UdxCellEndpoint({
    host: leftHost,
    port: leftPort,
    onBootstrap(packet) {
      if (ls) void ls.receive(packet)
    },
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  const right = new endpointModule.UdxCellEndpoint({
    host: rightHost,
    port: rightPort,
    onBootstrap(packet) {
      if (rs) void rs.receive(packet)
    },
    onCell() {
      return true
    },
    onLinkFailure() {}
  })
  await left.bind()
  await right.bind()
  const staticPair = cryptoSuite.encryptionKeyPair(seed(0xd4)),
    started = Date.now()
  const now = () => Date.now() - started
  let random = 0xd5
  const randomBytes = (size) => b4a.alloc(size, random++)
  function options(handle, mode, common) {
    const initiate = mode === 'initiate'
    const currentNow = now()
    return {
      mode,
      codec: new BootstrapEnvelopeCodec({
        linkHandle: handle,
        localIdentitySecretKey: initiate ? current.secretKey : next.secretKey,
        padding: randomBytes
      }),
      linkSetup: createLinkSetupAuthority({ now, randomBytes }),
      setup: initiate
        ? {
            ...common,
            responderStaticKey: staticPair.publicKey,
            initiatorIdentitySecretKey: current.secretKey
          }
        : {
            ...common,
            responderStaticSecretKey: staticPair.secretKey,
            responderIdentitySecretKey: next.secretKey
          },
      now,
      schedule: setTimeout,
      cancel: clearTimeout,
      randomBytes,
      absoluteDeadline: currentNow + 10_000,
      signedExpiry: 60_000,
      authorizedExpiry: 60_000
    }
  }
  return {
    endpoint: encodeCanonicalEndpoint({
      addressFamily: rightHost.includes(':') ? 6 : 4,
      addressBytes: hostBytes(rightHost),
      port: rightPort
    }),
    predecessorEndpoint: encodeCanonicalEndpoint({
      addressFamily: leftHost.includes(':') ? 6 : 4,
      addressBytes: hostBytes(leftHost),
      port: leftPort
    }),
    async open(branch) {
      const common = {
        circuitId: b4a.from(branch.circuitId),
        epoch: 1n,
        initiatorIdentity: current.publicKey,
        responderIdentity: next.publicKey,
        initiatorLocalId: b4a.alloc(16, 0xd6),
        responderLocalId: b4a.alloc(16, 0xd7),
        expiresAt: 60_000n
      }
      rs = right.openLink(rh.handle, options(rh.handle, 'accept', common))
      ls = left.openLink(lh.handle, options(lh.handle, 'initiate', common))
      const established = await ls.open()
      if (!rs.established) throw new Error('adjacent responder not OPEN')
      return {
        initiator: endpointModule.createM3CellLinkTransferIssuer(left, established),
        responder: endpointModule.createM3CellLinkTransferIssuer(right, rs.established)
      }
    },
    async closeLink() {
      await Promise.allSettled([
        ls ? ls.close() : Promise.resolve(),
        rs ? rs.close() : Promise.resolve()
      ])
    },
    async destroy() {
      lh.directory.destroy()
      rh.directory.destroy()
      await Promise.allSettled([left.close(), right.close()])
    }
  }
}
module.exports = { nativeAdjacentPair }
