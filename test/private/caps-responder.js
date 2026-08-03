'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  consumeEndpointBootstrapAuthority,
  createEndpointBootstrapAuthority,
  registerEndpointBootstrapController
} = require('../../lib/private/endpoint-bootstrap-authority')
const endpointModule = require('../../lib/private/udx-cell-endpoint')
const {
  consumeBootstrapGuardPin,
  revokeBootstrapGuardPin
} = require('../../lib/private/bootstrap-io')
const { BootstrapEnvelopeCodec } = require('../../lib/private/bootstrap-envelope')
const { createLinkSetupAuthority } = require('../../lib/private/link-setup')
const { CapsResponder } = require('../../lib/private/caps-responder')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const {
  CAPACITY_CLASS,
  M3_MESSAGE_ID,
  RELAY_CAPABILITY,
  ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../lib/private/relay-capability')
const seed = (value) => b4a.alloc(32, value)
const {
  UdxCellEndpoint,
  bindBootstrapUdxOperation,
  createBootstrapUdxAuthority,
  createLocalIdentitySecretCapability,
  destroyBootstrapUdxAuthority,
  destroyGuardLeaseMaterial,
  sendConfigured
} = endpointModule

function identityFor(role, start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === role) return pair
  }
  throw new Error('missing deterministic identity')
}

function endpoint(host, port) {
  return encodeCanonicalEndpoint({
    addressFamily: 4,
    addressBytes: b4a.from(host.split('.').map(Number)),
    port
  })
}

function advertisement(now, host = '127.0.0.1', port = 47101) {
  const signer = identityFor(ROLE.SAFETY, 20)
  const route = cryptoSuite.encryptionKeyPair(seed(121))
  const reachableEndpoint = endpoint(host, port)
  const capabilityMask = RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  const signed = signRelayCapabilityAdvertisement(
    {
      relayIdentity: signer.publicKey,
      currentDhtNodeId: deriveM3DhtNodeId(reachableEndpoint),
      reachableEndpoint,
      routeEncryptionPublicKey: route.publicKey,
      capabilityMask,
      minimumProtocolVersion: 1,
      maximumProtocolVersion: 1,
      cellSize: 1200,
      maxCellPayload: 1146,
      contextEnvelopeSize: 1101,
      routeFrameSize: 1100,
      maxRoutePayload: 1073,
      datagramReplayWindow: 64,
      maxConcurrentCircuits: 8,
      capacityClass: CAPACITY_CLASS.SMALL,
      maxCellsPerCircuit: 100,
      maxBytesPerCircuit: 100_000,
      maxCommandsPerCircuit: 10,
      idleTimeoutMs: 30_000,
      maxQueuedBytes: 65_536,
      epoch: 1n,
      issuedAtMs: now,
      expiresAtMs: now + 20_000n,
      providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
    },
    signer.secretKey
  )
  return {
    bytes: encodeRelayCapabilityAdvertisement(signed),
    signer,
    route
  }
}

function writeUint32(output, value, offset) {
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function writeUint64(output, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint64(input, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) value = (value << 8n) | BigInt(input[index])
  return value
}

function query(mask, target, nonce, maximumResults, phase, expiresAt = 0n, cookie = b4a.alloc(32)) {
  const body = b4a.alloc(110)
  writeUint32(body, mask, 0)
  body.set(target, 4)
  body.set(nonce, 36)
  body[68] = maximumResults
  body[69] = phase
  writeUint64(body, expiresAt, 70)
  body.set(cookie, 78)
  return encodeM3Object({ messageId: M3_MESSAGE_ID.CAPS_QUERY_V1, body })
}

function challenge(advertisement, nonce, expiresAt, cookie, now) {
  const initiator = cryptoSuite.encryptionKeyPair(seed(222))
  const body = b4a.alloc(176)
  body.set(digestRelayCapabilityAdvertisement(advertisement.bytes, { now }), 0)
  body.set(seed(223), 32)
  body.set(initiator.publicKey, 64)
  writeUint64(body, now + 3_000n, 96)
  body.set(nonce, 104)
  writeUint64(body, expiresAt, 136)
  body.set(cookie, 144)
  return encodeM3Object({ messageId: M3_MESSAGE_ID.ACTIVE_CHALLENGE_V1, body })
}

test('CAPS responder emits exact cookie, signed fragments, and one active response', (t) => {
  let now = 1_000n
  const relay = advertisement(now)
  const source = endpoint('127.0.0.1', 47100)
  const target = seed(31)
  const nonce = seed(32)
  const responder = new CapsResponder({
    now: () => now,
    advertisement: relay.bytes,
    identitySecretKey: relay.signer.secretKey,
    routeEncryptionSecretKey: relay.route.secretKey,
    selectAdvertisements: () => [
      relay.bytes,
      relay.bytes,
      relay.bytes,
      relay.bytes,
      relay.bytes,
      relay.bytes
    ],
    setTimeout: () => Object.freeze({}),
    clearTimeout() {}
  })

  const [cookiePacket] = responder.receive(
    query(RELAY_CAPABILITY.CIRCUIT_RELAY_V1, target, nonce, 6, 0),
    source
  )
  const cookieObject = decodeM3Object(cookiePacket)
  t.is(cookieObject.messageId, M3_MESSAGE_ID.CAPS_COOKIE_CHALLENGE_V1)
  t.is(cookiePacket.byteLength, 80)
  t.alike(cookieObject.body.subarray(0, 32), nonce)
  const cookieExpiresAtMs = readUint64(cookieObject.body, 32)
  const cookie = b4a.from(cookieObject.body.subarray(40, 72))
  t.ok(cookieExpiresAtMs > now)

  const responsePackets = responder.receive(
    query(RELAY_CAPABILITY.CIRCUIT_RELAY_V1, target, nonce, 6, 1, cookieExpiresAtMs, cookie),
    source
  )
  t.ok(responsePackets.length > 1, 'large signed CAPS response is fragmented')
  for (const packet of responsePackets) {
    const object = decodeM3Object(packet)
    t.is(object.messageId, M3_MESSAGE_ID.CORE_FRAGMENT_V1)
    t.ok(packet.byteLength <= 1_200)
  }

  const active = challenge(relay, nonce, cookieExpiresAtMs, cookie, now)
  const activeResponses = responder.receive(active, source)
  t.is(activeResponses.length, 1)
  t.is(decodeM3Object(activeResponses[0]).messageId, M3_MESSAGE_ID.ACTIVE_CHALLENGE_RESPONSE_V1)
  t.alike(responder.receive(active, source), [], 'active challenge replay is dropped')
  t.is(responder.destroy(), true)
  t.is(responder.destroy(), false)
})

test('CAPS responder drops malformed, wrong-source, and expired retries', (t) => {
  let now = 1_000n
  const relay = advertisement(now)
  const source = endpoint('127.0.0.1', 47100)
  const target = seed(41)
  const nonce = seed(42)
  const responder = new CapsResponder({
    now: () => now,
    advertisement: relay.bytes,
    identitySecretKey: relay.signer.secretKey,
    routeEncryptionSecretKey: relay.route.secretKey,
    setTimeout: () => Object.freeze({}),
    clearTimeout() {}
  })
  t.alike(responder.receive(b4a.alloc(12), source), [])
  const [packet] = responder.receive(
    query(RELAY_CAPABILITY.CIRCUIT_RELAY_V1, target, nonce, 1, 0),
    source
  )
  const object = decodeM3Object(packet)
  const expiresAt = readUint64(object.body, 32)
  const cookie = b4a.from(object.body.subarray(40, 72))
  t.alike(
    responder.receive(
      query(RELAY_CAPABILITY.CIRCUIT_RELAY_V1, target, nonce, 1, 1, expiresAt, cookie),
      endpoint('127.0.0.1', 47109)
    ),
    []
  )
  now = expiresAt
  t.alike(
    responder.receive(
      query(RELAY_CAPABILITY.CIRCUIT_RELAY_V1, target, nonce, 1, 1, expiresAt, cookie),
      source
    ),
    []
  )
  responder.destroy()
})

test('native BootstrapIO returns a consumable guard pin over framed CAPS and a live link', async (t) => {
  const now = 1_000n
  const monotonicNow = () => 1_000n
  const leftPort = 48100
  const rightPort = 48101
  const local = identityFor(ROLE.SAFETY, 2)
  const relay = advertisement(now, '127.0.0.1', rightPort)
  const random16 = []
  let randomValue = 0x31
  let random16Index = 0
  const leftRandom = (size) => {
    if (size === 16) {
      const value = b4a.alloc(size, 0x51 + random16Index++)
      random16.push(b4a.from(value))
      return value
    }
    return b4a.alloc(size, randomValue++)
  }
  const localSecret = b4a.from(local.secretKey)
  const authority = createEndpointBootstrapAuthority({
    bootstrapEndpoints: [{ host: '127.0.0.1', port: rightPort }],
    localIdentity: local.publicKey,
    localSecretKey: localSecret,
    host: '127.0.0.1',
    port: leftPort,
    wallNow: () => now,
    monotonicNow,
    schedule: setTimeout,
    cancelScheduled: clearTimeout,
    randomBytes: leftRandom
  })
  const receivedIds = []
  const registration = registerEndpointBootstrapController(authority, Object.freeze({}))
  const resources = consumeEndpointBootstrapAuthority(authority, registration)
  const issuer = endpointModule[endpointModule.TEST_ONLY_UDX_ADAPTER_ISSUER]
  let rightAuthority = null
  let rightSession = null
  let guardMaterial = null
  let receives = 0
  let linkPackets = 0
  let callbackError = null
  const responder = new CapsResponder({
    now: () => now,
    advertisement: relay.bytes,
    identitySecretKey: relay.signer.secretKey,
    routeEncryptionSecretKey: relay.route.secretKey
  })
  let responderHandle = null
  const rightEndpoint = new UdxCellEndpoint({
    host: '127.0.0.1',
    port: rightPort,
    async onBootstrap(packet) {
      if (((packet[0] << 8) | packet[1]) === 0xd301) {
        const bytes = (packet[2] << 8) | packet[3]
        receivedIds.push(decodeM3Object(packet.subarray(4, 4 + bytes)).messageId)
        receives++
        const responses = responder.receive(packet, endpoint('127.0.0.1', leftPort))
        for (const response of responses) await sendConfigured(rightAuthority, 0, response)
        return
      }
      if (!rightSession) throw new Error('responder session is not installed')
      linkPackets++
      try {
        await rightSession.receive(packet)
      } catch (err) {
        callbackError = err
        throw err
      }
    },
    onCell() {},
    onLinkFailure() {}
  })
  const rightSecret = createLocalIdentitySecretCapability({
    localIdentity: relay.signer.publicKey,
    localSecretKey: relay.signer.secretKey
  })
  rightAuthority = createBootstrapUdxAuthority({
    endpoint: rightEndpoint,
    configuredEndpoints: [{ host: '127.0.0.1', port: leftPort }],
    localSecretCapability: rightSecret,
    maxProspectiveGuards: 1,
    monotonicDeadline: monotonicNow
  })
  responderHandle = issuer.createTestBootstrapResponderLinkHandle({
    localIdentity32: relay.signer.publicKey,
    localAddress: { host: '127.0.0.1', port: rightPort },
    peerIdentity32: local.publicKey,
    peerAddress: { host: '127.0.0.1', port: leftPort },
    epoch: 1n,
    expiresAt: 21_000n,
    now: () => 1_000
  })
  try {
    await Promise.all([resources.endpoint.bind(), rightEndpoint.bind()])
    let responderRandom = 0x71
    const randomBytes = (size) => b4a.alloc(size, responderRandom++)
    rightSession = rightEndpoint.openLink(responderHandle, {
      mode: 'accept',
      codec: new BootstrapEnvelopeCodec({
        linkHandle: responderHandle,
        localIdentitySecretKey: relay.signer.secretKey,
        padding: randomBytes
      }),
      linkSetup: createLinkSetupAuthority({ now: () => 1_000, randomBytes }),
      setup: {
        circuitId: b4a.alloc(16, 0x51),
        epoch: 1n,
        initiatorIdentity: local.publicKey,
        responderIdentity: relay.signer.publicKey,
        initiatorLocalId: b4a.alloc(16, 0x52),
        responderLocalId: b4a.alloc(16, 0x53),
        expiresAt: 21_000n,
        responderStaticSecretKey: relay.route.secretKey,
        responderIdentitySecretKey: relay.signer.secretKey
      },
      now: () => 1_000,
      schedule: setTimeout,
      cancel: clearTimeout,
      randomBytes,
      absoluteDeadline: 11_000,
      signedExpiry: 21_000,
      authorizedExpiry: 21_000
    })
    let startError = null
    const generation = Object.freeze({})
    t.ok(bindBootstrapUdxOperation(rightAuthority, 11_000, generation, monotonicNow, 1_000n))
    let guardPin = null
    try {
      guardPin = await resources.bootstrapIO.start()
    } catch (err) {
      startError = err
    }
    if (startError) throw startError
    guardMaterial = consumeBootstrapGuardPin(guardPin)
    t.ok(guardMaterial)
    t.alike(receivedIds, [2, 2, 2, 2, 4], 'link reservation emits no extra CAPS RPC')
    t.is(receives, 5)
  } finally {
    if (guardMaterial) destroyGuardLeaseMaterial(guardMaterial)
    resources.bootstrapIO.destroy()
    destroyBootstrapUdxAuthority(rightAuthority)
    responder.destroy()
    if (rightSession) await rightSession.close()
    await Promise.all([resources.endpoint.close(), rightEndpoint.close()])
  }
})
