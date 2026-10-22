'use strict'

const test = require('brittle')
const b4a = require('b4a')
const createTestnet = require('../../testnet')
const { PrivateRouteError } = require('../../lib/private/errors')
const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { ROLE, TOPOLOGY_ROLE } = require('../../lib/private/protocol')
const { computePeerRouteBudget } = require('../../lib/private/peer-ledger')
const {
  validatePeerNativeOptions,
  decodePeerNativeConfig,
  createPeerNativeRuntimeConfig,
  peerNativeProfile
} = require('../../lib/private/peer-native-config')
const {
  createPeerNativeRuntime,
  readNativeConfig
} = require('../../lib/private/peer-native-runtime')
const {
  endpoint,
  grant,
  identity,
  sourceOptions,
  fixture,
  jsonOptions
} = require('./helpers/native-config')

function rejects(t, value, message) {
  t.exception(() => validatePeerNativeOptions(value), PrivateRouteError.INVALID_ROUTE(), message)
}

function without(value, field) {
  const copy = { ...value }
  delete copy[field]
  return copy
}

function exoticObjects(value) {
  const field = Object.keys(value)[0]
  const accessor = { ...value }
  Object.defineProperty(accessor, field, {
    get() {
      throw new Error('accessor invoked')
    },
    enumerable: true
  })
  const symbol = without(value, field)
  symbol[Symbol(field)] = value[field]
  return [
    without(value, field),
    { ...value, unexpected: true },
    Object.assign(Object.create({ inherited: true }), value),
    Object.assign(Object.create(null), value),
    Object.assign(Object.create({ [field]: value[field] }), without(value, field)),
    accessor,
    symbol
  ]
}

test('native options require the exact acknowledged optional profile', (t) => {
  for (const [field, value] of [
    ['release', 'stable'],
    ['acknowledgeAlpha', false],
    ['mode', 'required'],
    ['profile', 'standard'],
    ['relay', 1]
  ])
    rejects(t, { ...sourceOptions(), [field]: value }, field)
  for (const value of exoticObjects(sourceOptions())) rejects(t, value, 'exact own-data object')
  rejects(
    t,
    { ...sourceOptions(), relayConfig: {} },
    'an endpoint cannot supply relay configuration'
  )
  rejects(t, { ...sourceOptions(), relay: true }, 'a relay must supply configuration')
  t.alike(validatePeerNativeOptions(sourceOptions()), sourceOptions())
})

test('native nested configuration rejects accessors, inherited fields, symbols and extra authority', (t) => {
  const { options } = fixture()
  for (const value of exoticObjects(options.relayConfig))
    rejects(t, { ...options, relayConfig: value })
  for (const value of exoticObjects(options.relayConfig.identityKeyPair)) {
    rejects(t, { ...options, relayConfig: { ...options.relayConfig, identityKeyPair: value } })
  }
  for (const field of ['authorityPublicKeys', 'grants']) {
    const original = options.relayConfig[field]
    const withProperty = [...original]
    withProperty.unexpected = true
    const accessor = [...original]
    Object.defineProperty(accessor, '0', {
      get() {
        throw new Error('accessor invoked')
      }
    })
    const inherited = [...original]
    Object.setPrototypeOf(inherited, Object.create(Array.prototype))
    for (const value of [[], new Array(1), withProperty, accessor, inherited]) {
      rejects(t, { ...options, relayConfig: { ...options.relayConfig, [field]: value } }, field)
    }
  }
  let invoked = false
  const accessor = { ...options }
  Object.defineProperty(accessor, 'relay', {
    get() {
      invoked = true
      return true
    }
  })
  rejects(t, accessor)
  t.is(invoked, false, 'accessor is rejected without evaluation')
})

test('native relay opt-in accepts only an own-data boolean and defaults closed', (t) => {
  const { options } = fixture()
  t.is(validatePeerNativeOptions(options).relayConfig.legacyEgress, false)
  for (const legacyEgress of [false, true]) {
    const value = {
      ...options,
      relayConfig: { ...options.relayConfig, legacyEgress }
    }
    t.is(validatePeerNativeOptions(value).relayConfig.legacyEgress, legacyEgress)
    t.is(
      decodePeerNativeConfig(JSON.stringify(jsonOptions(value))).relayConfig.legacyEgress,
      legacyEgress
    )
  }
  for (const legacyEgress of [undefined, null, 0, 1, 'true', 'false', new Boolean(true)]) {
    rejects(t, { ...options, relayConfig: { ...options.relayConfig, legacyEgress } })
  }
  let invoked = false
  const accessor = { ...options.relayConfig }
  Object.defineProperty(accessor, 'legacyEgress', {
    get() {
      invoked = true
      return true
    }
  })
  rejects(t, { ...options, relayConfig: accessor })
  t.is(invoked, false, 'opt-in accessors are never evaluated')
  rejects(t, {
    ...options,
    relayConfig: Object.assign(Object.create({ legacyEgress: true }), options.relayConfig)
  })
})

test('native configuration retains independent key, grant and trust bytes', (t) => {
  const { options } = fixture()
  const accepted = validatePeerNativeOptions(options)
  const before = jsonOptions(accepted)
  options.relayConfig.identityKeyPair.secretKey.fill(0)
  options.relayConfig.identityKeyPair.publicKey.fill(0)
  options.relayConfig.authorityPublicKeys[0].fill(0)
  options.relayConfig.runId32.fill(0)
  options.relayConfig.grants[0].fill(0)
  t.alike(
    jsonOptions(validatePeerNativeOptions(accepted)),
    before,
    'caller mutation cannot change retained admission'
  )
})

test('native configuration verifies both signatures, identity, epoch, run and local trust', (t) => {
  const { options, local, peer } = fixture()
  const config = options.relayConfig
  const badSignature = b4a.from(config.grants[0])
  badSignature[badSignature.length - 1] ^= 1
  const wrongPair = {
    publicKey: local.identity.publicKey,
    secretKey: cryptoSuite.keyPair().secretKey
  }
  for (const changed of [
    { identityKeyPair: wrongPair },
    { identityKeyPair: cryptoSuite.keyPair() },
    { authorityPublicKeys: [peer.authority.publicKey] },
    { authorityPublicKeys: [local.authority.publicKey, local.authority.publicKey] },
    { authorityPublicKeys: [b4a.alloc(32)] },
    { epoch: 8n },
    { epoch: 7 },
    { epoch: 0n },
    { epoch: 1n << 64n },
    { runId32: b4a.alloc(32) },
    { runId32: b4a.alloc(32, 1) },
    { grants: [badSignature] },
    { grants: [grant(local, peer, { expiresAt: BigInt(Date.now()) - 1n, notBefore: 0n })] },
    { grants: [grant(local, peer, { notBefore: BigInt(Date.now()) + 60000n })] }
  ])
    rejects(t, { ...options, relayConfig: { ...config, ...changed } })
})

test('native grant sets reject duplicate peers, conflicting tuples and non-native role pairs', (t) => {
  const { options, local, peer } = fixture()
  const second = endpoint(41003, TOPOLOGY_ROLE.SAFETY_FINAL)
  for (const grants of [
    [options.relayConfig.grants[0], options.relayConfig.grants[0]],
    [options.relayConfig.grants[0], grant(local, peer)],
    [options.relayConfig.grants[0], grant({ ...local, port: local.port + 10 }, second)],
    [options.relayConfig.grants[0], grant(local, { ...second, port: peer.port })],
    [grant(local, { ...peer, port: local.port })],
    [
      grant(
        { ...local, role: TOPOLOGY_ROLE.SAFETY_FINAL },
        {
          ...peer,
          identity: identity(ROLE.PRIVATE),
          role: TOPOLOGY_ROLE.PRIVATE_ENTRY
        }
      )
    ]
  ])
    rejects(t, { ...options, relayConfig: { ...options.relayConfig, grants } })
  const middle = { ...local, role: TOPOLOGY_ROLE.SAFETY_FINAL }
  const upstream = { ...peer, role: TOPOLOGY_ROLE.SAFETY_GUARD }
  const admitted = validatePeerNativeOptions({
    ...options,
    relayConfig: { ...options.relayConfig, grants: [grant(middle, upstream), grant(local, second)] }
  })
  t.alike(
    admitted.relayConfig.identityKeyPair.publicKey,
    local.identity.publicKey,
    'one safety identity may occupy either grant position'
  )
})

test('relay JSON decoding uses strict hex and decimal fields without revealing input', (t) => {
  const { options } = fixture()
  const json = jsonOptions(options)
  t.alike(decodePeerNativeConfig(JSON.stringify(json)), validatePeerNativeOptions(options))
  const inputs = [
    '{"secret":"confidential input",',
    JSON.stringify({ ...json, sockets: [] }),
    JSON.stringify({ ...json, relay: false }),
    ...[7, '07', '+7', '7.0', '18446744073709551616'].map((epoch) =>
      JSON.stringify({ ...json, relayConfig: { ...json.relayConfig, epoch } })
    ),
    ...[null, 0, 1, 'true', 'false'].map((legacyEgress) =>
      JSON.stringify({ ...json, relayConfig: { ...json.relayConfig, legacyEgress } })
    ),
    JSON.stringify({ ...json, relayConfig: { ...json.relayConfig, runId32: 'gg'.repeat(32) } }),
    JSON.stringify({ ...json, relayConfig: { ...json.relayConfig, runId32: '0'.repeat(63) } }),
    JSON.stringify({
      ...json,
      relayConfig: {
        ...json.relayConfig,
        identityKeyPair: { ...json.relayConfig.identityKeyPair, secretKey: 'confidential input' }
      }
    })
  ]
  for (const input of inputs) {
    t.exception(() => decodePeerNativeConfig(input), PrivateRouteError.INVALID_ROUTE())
  }
})

test('native profile funds private records and exact worst-case circuit work', (t) => {
  const profile = peerNativeProfile()
  t.is(profile.sourceDataFrames, 111852)
  t.is(profile.registrationDataFrames, 111791)
  const firstApplication =
    profile.registrationDataFrames -
    profile.applicationFrameFloor * (profile.registration.maxStreams - 2)
  t.is(firstApplication, 96431, 'first OPEN preserves fifteen nonrefundable floors')
  const registrationBudget = computePeerRouteBudget({
    purpose: 3,
    maxStreams: 17,
    applications: Array.from({ length: 16 }, (_, index) => {
      const frames = index === 0 ? firstApplication : profile.applicationFrameFloor
      return {
        forwardFrames: frames,
        reverseFrames: frames,
        forwardBytes: BigInt(frames) * 977n,
        reverseBytes: BigInt(frames) * 977n,
        forwardWindow: 1,
        reverseWindow: 1
      }
    })
  })
  t.alike(
    profile.registration.budget,
    registrationBudget,
    'all sixteen application windows fit the shared twenty-four-frame receive pool'
  )
  t.is(profile.source.semanticOwnedBytes, 133692)
  t.is(profile.registration.semanticOwnedBytes, 2137750)
  t.is(profile.source.maxQueuedBytes, 315413)
  t.is(profile.registration.maxQueuedBytes, 2336639)
  t.is(profile.limits.maxCells, 3579138)
  t.is(profile.limits.maxBytes, 4294965600)
  t.is(profile.limits.maxCommands, 52, 'the largest actual directional row includes discovery')
  t.is(profile.limits.maxQueuedBytes, 2336639)
  t.is(profile.relayCircuits, 24)
  t.is(profile.limits.maxConcurrentCircuits, 24)
  t.is(profile.sourceSlots, 16, 'applications and management share the native16 ceiling')
  t.is(profile.sourceMemoryBytes, 37457344)
  t.is(profile.forwardingMemoryBytes, 768704)
  t.is(profile.terminalMemoryBytes, 56848040)
  t.ok(profile.limits.maxBytes <= 0xffffffff, 'all reserved send attempts fit the wire')
  t.ok((profile.limits.maxCells + 2) * 1200 > 0xffffffff, 'an extra two cells do not fit')
  t.is(
    profile.sourceMemoryBytes,
    profile.sourceSlots * (4445 + profile.registration.maxQueuedBytes)
  )
  t.is(peerNativeProfile(16).sourceMemoryBytes, 37457344)
})

test('relay mapping binds every signed local tuple to verified DHT reachability before startup', async (t) => {
  const network = await createTestnet(3, { host: '127.0.0.1' })
  t.teardown(() => network.destroy())
  const node = network.nodes[1]
  const { options, local, peer } = fixture()
  local.port = node.port
  peer.port = network.nodes[2].port
  options.relayConfig.grants = [grant(local, peer)]
  const config = createPeerNativeRuntimeConfig(options, node)
  t.alike(config.relay.reachable, node.remoteAddress())
  t.is(
    readNativeConfig(config).relay.capabilityMask,
    9,
    'upstream grant position derives forwarding capability'
  )
  for (const changed of [
    { ...local, host: '127.0.0.2' },
    { ...local, port: local.port === 65535 ? 65534 : local.port + 1 }
  ]) {
    const bad = {
      ...options,
      relayConfig: { ...options.relayConfig, grants: [grant(changed, peer)] }
    }
    t.exception(() => createPeerNativeRuntimeConfig(bad, node), PrivateRouteError.INVALID_ROUTE())
  }
  const expiring = {
    ...options,
    relayConfig: {
      ...options.relayConfig,
      grants: [grant(local, peer, { expiresAt: BigInt(Date.now()) + 30000n })]
    }
  }
  t.exception(
    () => createPeerNativeRuntimeConfig(expiring, node),
    PrivateRouteError.INVALID_ROUTE(),
    'advertisement cannot outlive a grant'
  )
  options.relayConfig.grants = [
    grant(
      { ...local, role: TOPOLOGY_ROLE.SAFETY_FINAL },
      { ...peer, role: TOPOLOGY_ROLE.SAFETY_GUARD }
    )
  ]
  const terminal = createPeerNativeRuntimeConfig(options, node)
  t.is(
    readNativeConfig(terminal).relay.capabilityMask,
    11,
    'downstream-only grants derive terminal capability'
  )
  config.identity.secretKey.fill(0)
  terminal.identity.secretKey.fill(0)
})

test('validated source mapping leases the real DHT socket without contacting guard locators', async (t) => {
  const network = await createTestnet(2, { host: '127.0.0.1' })
  t.teardown(() => network.destroy())
  const node = network.nodes[1]
  const guards = [{ host: '127.0.0.1', port: network.nodes[0].port }]
  const config = createPeerNativeRuntimeConfig(sourceOptions(), node, guards)
  guards[0].port = 1
  const runtime = createPeerNativeRuntime({ dht: node, config })
  t.teardown(() => runtime.destroy())
  let sends = 0
  runtime.observeSendAttempts((event) => {
    if (event.kind === 'attempt') sends++
  })
  await runtime.ready()
  t.is(runtime.diagnostics().leased, true)
  t.is(sends, 0, 'base source readiness does not bootstrap or send private traffic')
  t.is(
    config.source.guards[0].port,
    network.nodes[0].port,
    'locator tuple is retained independently'
  )
  await runtime.destroy()
  const pong = await node.ping(network.nodes[0].remoteAddress())
  t.ok(pong, 'ordinary DHT remains usable after private socket lease destruction')
})
