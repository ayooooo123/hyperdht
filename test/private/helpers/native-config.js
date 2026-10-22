'use strict'

const b4a = require('b4a')
const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../../lib/private/protocol')
const {
  encodeUnsignedTopologyGrantV1,
  decodeUnsignedTopologyGrantV1,
  signTopologyGrantV1,
  assembleTopologyGrantV1
} = require('../../../lib/private/topology-grant')

function identity(role = ROLE.SAFETY) {
  for (;;) {
    const pair = cryptoSuite.keyPair()
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
}

function endpoint(port, role) {
  return {
    identity: identity(),
    authority: cryptoSuite.keyPair(),
    role,
    host: '127.0.0.1',
    port,
    operations: LINK_OPERATION.KNOWN
  }
}

function grant(local, peer, options = {}) {
  const side = (end) => ({
    identity32: end.identity.publicKey,
    authority32: end.authority.publicKey,
    role: end.role,
    host: end.host,
    port: end.port,
    operations: end.operations
  })
  const unsigned = encodeUnsignedTopologyGrantV1({
    version: PROTOCOL_VERSION,
    format: 1,
    grantId32: cryptoSuite.randomBytes(32),
    endpointA: side(local),
    endpointB: side(peer),
    epoch: 7n,
    notBefore: BigInt(Date.now()) - 1000n,
    expiresAt: BigInt(Date.now()) + 3600000n,
    runId32: b4a.alloc(32, 0x52),
    ...options
  })
  const decoded = decodeUnsignedTopologyGrantV1(unsigned)
  const signer = (key) =>
    b4a.equals(key, local.authority.publicKey) ? local.authority : peer.authority
  return assembleTopologyGrantV1(
    unsigned,
    signTopologyGrantV1(unsigned, signer(decoded.endpointA.authority32)),
    signTopologyGrantV1(unsigned, signer(decoded.endpointB.authority32))
  )
}

function sourceOptions() {
  return {
    release: 'alpha',
    acknowledgeAlpha: true,
    mode: 'optional',
    profile: 'native-v2',
    relay: false
  }
}

function fixture() {
  const local = endpoint(41001, TOPOLOGY_ROLE.SAFETY_GUARD)
  const peer = endpoint(41002, TOPOLOGY_ROLE.SAFETY_FINAL)
  return {
    local,
    peer,
    options: {
      ...sourceOptions(),
      relay: true,
      relayConfig: {
        identityKeyPair: local.identity,
        authorityPublicKeys: [local.authority.publicKey],
        epoch: 7n,
        runId32: b4a.alloc(32, 0x52),
        grants: [grant(local, peer)]
      }
    }
  }
}

function jsonOptions(options) {
  const { relayConfig: config } = options
  const hex = (buffer) => b4a.toString(buffer, 'hex')
  return {
    ...options,
    relayConfig: {
      identityKeyPair: {
        publicKey: hex(config.identityKeyPair.publicKey),
        secretKey: hex(config.identityKeyPair.secretKey)
      },
      authorityPublicKeys: config.authorityPublicKeys.map(hex),
      epoch: config.epoch.toString(),
      runId32: hex(config.runId32),
      grants: config.grants.map(hex),
      ...(Object.hasOwn(config, 'legacyEgress') ? { legacyEgress: config.legacyEgress } : {})
    }
  }
}

module.exports = { identity, endpoint, grant, sourceOptions, fixture, jsonOptions }
