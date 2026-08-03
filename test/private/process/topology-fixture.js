'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { deriveDhtExitPeerId } = require('../../../lib/private/dht-exit-destination-table')
const { digestExitOriginServicePolicy } = require('../../../lib/private/exit-policy')
const {
  digestTestIsolatedAddressTuple,
  encodeTestIsolatedAddressGrant
} = require('../../../lib/private/dht-exit-test-topology-grant')
const { digestPayloadParameters } = require('../../../lib/private/link-parameters')
const {
  CAPACITY_CLASS,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  RELAY_CAPABILITY,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../../lib/private/protocol')
const {
  deriveM3DhtNodeId,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint,
  encodeRelayCapabilityAdvertisement,
  providerServicePolicyForCapabilities,
  signRelayCapabilityAdvertisement
} = require('../../../lib/private/relay-capability')
const { TOPOLOGY_GRANT_FORMAT, signTopologyGrant } = require('../../../lib/private/topology-grant')
const { encodeCanonicalBody } = require('./control-channel')

const ROLES = Object.freeze([
  'endpoint',
  'guard',
  'lookup-middle-a',
  'lookup-exit-a',
  'lookup-middle-b',
  'lookup-exit-b',
  'announce-middle',
  'announce-exit',
  'dht-seed',
  'dht-referral',
  'dht-value'
])

// Initial build, rotation, resume, and a network-change resume each rediscover the
// same learned closers, and every isolated-address grant is one-shot.
const LEARNED_GRANT_USES = 6

const ALLOW_EDGES = Object.freeze([
  Object.freeze([1, 2]),
  Object.freeze([2, 3]),
  Object.freeze([2, 5]),
  Object.freeze([2, 7]),
  Object.freeze([3, 4]),
  Object.freeze([5, 6]),
  Object.freeze([7, 8]),
  Object.freeze([4, 9]),
  Object.freeze([4, 10]),
  Object.freeze([4, 11]),
  Object.freeze([6, 9]),
  Object.freeze([6, 10]),
  Object.freeze([6, 11]),
  Object.freeze([8, 9]),
  Object.freeze([8, 10]),
  Object.freeze([8, 11]),
  Object.freeze([9, 10]),
  // The three DHT roles are ordinary DHT nodes, not route positions. Kademlia
  // gossips closer-node records, so a node will contact any peer it learns
  // about; under real isolation a missing seed-to-value edge leaves that probe
  // unroutable and stalls setup. Their mesh carries no route cells and no
  // anonymity property depends on it.
  Object.freeze([9, 11]),
  Object.freeze([10, 11])
])

const PORTABLE_LOOPBACK = Object.freeze({ name: 'portable-loopback' })
const LINUX_NAMESPACE = Object.freeze({ name: 'linux-namespace' })
const PROCESS_PLANS = Object.freeze({
  LINUX_NAMESPACE,
  PORTABLE_LOOPBACK
})
const GENERATIONS = Object.freeze([1n, 1n, 1n, 1n, 2n, 2n, 1n, 1n, 1n, 1n, 1n])
const CLOCK_CAPABILITIES = new WeakMap()
const ENTROPY_CAPABILITIES = new WeakMap()
const PROCESS_PHASE_GATES = new WeakMap()
const SPENT_PROCESS_PHASE_GATES = new WeakSet()
const REVOKABLE_ARRAYS = new WeakSet()
const MAX_U64 = 0xffff_ffff_ffff_ffffn

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectOwnKeys = Reflect.ownKeys

class ProcessConfigError extends Error {
  constructor(code = 'PROCESS_CONFIG_INVALID') {
    super(code)
    this.code = code
  }
}

function invalid() {
  throw new ProcessConfigError()
}

function length(value) {
  try {
    if (!b4a.isBuffer(value)) return -1
    return byteLengthGetter.call(value)
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (length(value) >= 0) bufferFill.call(value, 0)
  } catch {}
}

function copy(value, size = null) {
  const bytes = length(value)
  if (bytes < 0 || (size !== null && bytes !== size)) invalid()
  const output = b4a.allocUnsafeSlow(bytes)
  bufferSet.call(output, value)
  return output
}

function sameBytes(left, right) {
  return length(left) >= 0 && length(right) >= 0 && b4a.equals(left, right)
}

function exactObject(value, fields) {
  if (
    value === null ||
    typeof value !== 'object' ||
    objectGetPrototypeOf(value) !== Object.prototype
  )
    invalid()
  const keys = reflectOwnKeys(value)
  if (keys.length !== fields.length || keys.some((key) => typeof key !== 'string')) invalid()
  const actual = keys.slice().sort()
  const expected = fields.slice().sort()
  for (let index = 0; index < expected.length; index++)
    if (actual[index] !== expected[index]) invalid()
  for (const field of fields) {
    const descriptor = objectGetOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
  }
}

function deepFreeze(value, seen = new Set()) {
  if (value === null || typeof value !== 'object' || length(value) >= 0 || seen.has(value))
    return value
  seen.add(value)
  if (Array.isArray(value)) {
    for (const entry of value) deepFreeze(entry, seen)
  } else {
    for (const key of reflectOwnKeys(value)) {
      const descriptor = objectGetOwnPropertyDescriptor(value, key)
      if (descriptor && 'value' in descriptor) deepFreeze(descriptor.value, seen)
    }
  }
  if (REVOKABLE_ARRAYS.has(value)) return value
  return Object.freeze(value)
}

function numericTuple(value) {
  exactObject(value, ['host', 'port'])
  if (
    typeof value.host !== 'string' ||
    !Number.isSafeInteger(value.port) ||
    value.port < 1 ||
    value.port > 0xffff
  )
    invalid()
  const parts = value.host.split('.')
  if (parts.length !== 4) invalid()
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) invalid()
  }
  return Object.freeze({ host: value.host, port: value.port })
}

function issueClocks(value) {
  exactObject(value, ['monotonicNow', 'wallNow'])
  if (typeof value.monotonicNow !== 'function' || typeof value.wallNow !== 'function') invalid()
  const wall = value.wallNow()
  const monotonic = value.monotonicNow()
  if (
    typeof wall !== 'bigint' ||
    wall < 0n ||
    wall > MAX_U64 ||
    typeof monotonic !== 'bigint' ||
    monotonic < 0n ||
    monotonic > MAX_U64
  )
    invalid()
  const capability = Object.freeze({})
  CLOCK_CAPABILITIES.set(
    capability,
    Object.freeze({ monotonicNow: value.monotonicNow, wallNow: value.wallNow })
  )
  return capability
}

function issueEntropy(seed) {
  const owned = copy(seed, 32)
  const capability = Object.freeze({})
  ENTROPY_CAPABILITIES.set(capability, { counter: 0n, seed: owned })
  return capability
}

function entropyBytes(state, size) {
  if (!Number.isSafeInteger(size) || size < 1 || size > 65_536) invalid()
  const output = b4a.allocUnsafeSlow(size)
  let offset = 0
  while (offset < size) {
    const input = b4a.allocUnsafeSlow(40)
    bufferSet.call(input, state.seed, 0)
    let counter = state.counter++
    for (let index = 39; index >= 32; index--) {
      input[index] = Number(counter & 0xffn)
      counter >>= 8n
    }
    const block = b4a.allocUnsafeSlow(32)
    sodium.crypto_generichash(block, input)
    const take = Math.min(32, size - offset)
    bufferSet.call(output, block.subarray(0, take), offset)
    offset += take
    clear(input)
    clear(block)
  }
  return output
}

function planTuple(plan, roleIndex) {
  if (plan === PORTABLE_LOOPBACK)
    return Object.freeze({ host: `127.64.${roleIndex}.1`, port: 42_000 + roleIndex })
  if (plan === LINUX_NAMESPACE)
    return Object.freeze({ host: `10.203.${roleIndex}.2`, port: 42_000 + roleIndex })
  invalid()
}

function issueAuthority(plan) {
  if (plan !== PORTABLE_LOOPBACK && plan !== LINUX_NAMESPACE) invalid()
  return networkAuthority(ROLES.map((role, index) => planTuple(plan, index + 1)))
}

function issueProcessPhaseGate(run, generation) {
  const capability = Object.freeze({})
  PROCESS_PHASE_GATES.set(capability, {
    generation,
    plan: LINUX_NAMESPACE.name,
    role: ROLES[0],
    roleIndex: 1,
    run: copy(run, 16)
  })
  return capability
}

function consumeProcessPhaseGate(capability, expected) {
  if (capability === null || typeof capability !== 'object') return 'invalid'
  const binding = PROCESS_PHASE_GATES.get(capability)
  if (!binding) return SPENT_PROCESS_PHASE_GATES.has(capability) ? 'replay' : 'invalid'
  try {
    exactObject(expected, ['generation', 'plan', 'role', 'roleIndex', 'run'])
    if (
      expected.generation !== binding.generation ||
      expected.plan !== binding.plan ||
      expected.role !== binding.role ||
      expected.roleIndex !== binding.roleIndex ||
      !sameBytes(expected.run, binding.run)
    )
      return 'invalid'
  } catch {
    return 'invalid'
  }
  PROCESS_PHASE_GATES.delete(capability)
  SPENT_PROCESS_PHASE_GATES.add(capability)
  clear(binding.run)
  return 'ok'
}

function revokeProcessPhaseGate(capability) {
  const binding = PROCESS_PHASE_GATES.get(capability)
  if (!binding) return
  PROCESS_PHASE_GATES.delete(capability)
  SPENT_PROCESS_PHASE_GATES.add(capability)
  clear(binding.run)
}

const TEST_ONLY_PROCESS_TOPOLOGY_ISSUER = Object.freeze({
  authority: issueAuthority,
  clocks: issueClocks,
  entropy: issueEntropy
})

function endpointBytes(tuple) {
  const addressBytes = b4a.from(tuple.host.split('.').map((part) => Number(part)))
  try {
    return encodeCanonicalEndpoint({ addressFamily: 4, addressBytes, port: tuple.port })
  } finally {
    clear(addressBytes)
  }
}

function identity(entropy, expectedRole = null) {
  for (let attempt = 0; attempt < 512; attempt++) {
    const seed = entropyBytes(entropy, 32)
    const pair = cryptoSuite.keyPair(seed)
    clear(seed)
    if (expectedRole === null || roleForIdentity(pair.publicKey) === expectedRole) return pair
    clear(pair.secretKey)
    clear(pair.publicKey)
  }
  invalid()
}

function encryptionIdentity(entropy) {
  const seed = entropyBytes(entropy, 32)
  try {
    return cryptoSuite.encryptionKeyPair(seed)
  } finally {
    clear(seed)
  }
}

function advertisement(tuple, signing, route, role, now) {
  const reachableEndpoint = endpointBytes(tuple)
  const capabilityMask =
    role === ROLE.PRIVATE
      ? RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
      : RELAY_CAPABILITY.CIRCUIT_RELAY_V1
  const value = {
    relayIdentity: signing.publicKey,
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
    maxConcurrentCircuits: 32,
    capacityClass: CAPACITY_CLASS.MEDIUM,
    maxCellsPerCircuit: 10_000,
    maxBytesPerCircuit: 10_000_000,
    maxCommandsPerCircuit: 256,
    idleTimeoutMs: 30_000,
    maxQueuedBytes: 262_144,
    epoch: 1n,
    issuedAtMs: now,
    expiresAtMs: now + 60_000n,
    providerServicePolicyEntries: providerServicePolicyForCapabilities(capabilityMask)
  }
  const signed = signRelayCapabilityAdvertisement(value, signing.secretKey)
  const bytes = encodeRelayCapabilityAdvertisement(signed)
  const digest = digestRelayCapabilityAdvertisement(bytes, { now })
  clear(reachableEndpoint)
  return Object.freeze({ bytes, digest })
}

function contact(role, identityPublicKey, tuple) {
  return Object.freeze({
    identity: copy(identityPublicKey, 32),
    role,
    tuple: Object.freeze({ host: tuple.host, port: tuple.port })
  })
}

function makeLinkGrant(
  entropy,
  authority,
  runId32,
  tuples,
  identities,
  left,
  right,
  leftRole,
  rightRole,
  now
) {
  const grantId32 = entropyBytes(entropy, 32)
  try {
    return signTopologyGrant(
      {
        endpointA: {
          host: tuples[left - 1].host,
          identity32: identities[left - 1].publicKey,
          operations: LINK_OPERATION.KNOWN,
          port: tuples[left - 1].port,
          role: leftRole
        },
        endpointB: {
          host: tuples[right - 1].host,
          identity32: identities[right - 1].publicKey,
          operations: LINK_OPERATION.KNOWN,
          port: tuples[right - 1].port,
          role: rightRole
        },
        epoch: 1n,
        expiresAt: now + 60_000n,
        format: TOPOLOGY_GRANT_FORMAT,
        grantId32,
        notBefore: now,
        runId32,
        version: PROTOCOL_VERSION
      },
      authority.secretKey
    )
  } finally {
    clear(grantId32)
  }
}

function projectionDigest(value) {
  const encoding = encodeCanonicalBody(value)
  try {
    return cryptoSuite.hash(encoding)
  } finally {
    clear(encoding)
  }
}

function networkAuthority(tuples) {
  const indexes = new Map(tuples.map((tuple, index) => [`${tuple.host}:${tuple.port}`, index + 1]))
  const permitted = new Set()
  for (const [left, right] of ALLOW_EDGES) {
    permitted.add(`${left}:${right}`)
    permitted.add(`${right}:${left}`)
  }
  return Object.freeze({
    permits(from, to) {
      try {
        const left = numericTuple(from)
        const right = numericTuple(to)
        const leftIndex = indexes.get(`${left.host}:${left.port}`)
        const rightIndex = indexes.get(`${right.host}:${right.port}`)
        return permitted.has(`${leftIndex}:${rightIndex}`)
      } catch {
        return false
      }
    }
  })
}

// An exit role owns two sockets: its cell endpoint on the tuple port, and a
// dedicated DHT-exit socket on 43_000 + roleIndex that it uses to reach DHT
// nodes. Pinning both in the firewall keeps the rule set an exact description
// of which socket may reach which peer.
const EXIT_ROLE_INDICES = Object.freeze(new Set([4, 6, 8]))
const DHT_ROLE_INDICES = Object.freeze(new Set([9, 10, 11]))

function socketPort(tuples, roleIndex, peerIndex) {
  if (EXIT_ROLE_INDICES.has(roleIndex) && DHT_ROLE_INDICES.has(peerIndex)) {
    return 43_000 + roleIndex
  }
  return tuples[roleIndex - 1].port
}

function namespaceProjection(tuples) {
  const neighbors = Array.from({ length: 11 }, () => [])
  for (const [left, right] of ALLOW_EDGES) {
    neighbors[left - 1].push(right)
    neighbors[right - 1].push(left)
  }
  const roles = tuples.map((tuple, index) => {
    const roleIndex = index + 1
    const gateway = `10.203.${roleIndex}.1`
    const device = `pr-veth-${roleIndex}`
    const routes = neighbors[index]
      .sort((left, right) => left - right)
      .map((peer) =>
        Object.freeze({
          destination: `${tuples[peer - 1].host}/32`,
          device,
          gateway
        })
      )
    return Object.freeze({
      device,
      gateway,
      host: tuple.host,
      prefix: 24,
      role: ROLES[index],
      roleIndex,
      routes: Object.freeze(routes)
    })
  })
  const firewall = []
  for (const [left, right] of ALLOW_EDGES) {
    for (const [source, destination] of [
      [left, right],
      [right, left]
    ]) {
      firewall.push(
        Object.freeze({
          destination: tuples[destination - 1].host,
          destinationPort: socketPort(tuples, destination, source),
          egress: `pr-veth-${destination}`,
          ingress: `pr-veth-${source}`,
          protocol: 'udp',
          source: tuples[source - 1].host,
          sourcePort: socketPort(tuples, source, destination)
        })
      )
    }
  }
  const marker = Object.freeze({
    auditor: Object.freeze({
      device: 'pr-veth-auditor',
      gateway: '10.204.1.1',
      host: '10.204.1.2',
      port: 42_990,
      routes: Object.freeze([
        Object.freeze({
          destination: '10.204.2.2/32',
          device: 'pr-veth-auditor',
          gateway: '10.204.1.1'
        })
      ])
    }),
    decoy: Object.freeze({
      device: 'pr-veth-decoy',
      gateway: '10.204.2.1',
      host: '10.204.2.2',
      port: 42_991,
      routes: Object.freeze([
        Object.freeze({
          destination: '10.204.1.2/32',
          device: 'pr-veth-decoy',
          gateway: '10.204.2.1'
        })
      ])
    })
  })
  firewall.push(
    Object.freeze({
      destination: marker.decoy.host,
      destinationPort: marker.decoy.port,
      egress: marker.decoy.device,
      ingress: marker.auditor.device,
      protocol: 'udp',
      source: marker.auditor.host,
      sourcePort: marker.auditor.port
    }),
    Object.freeze({
      destination: marker.auditor.host,
      destinationPort: marker.auditor.port,
      egress: marker.auditor.device,
      ingress: marker.decoy.device,
      protocol: 'udp',
      source: marker.decoy.host,
      sourcePort: marker.decoy.port
    })
  )
  return Object.freeze({
    firewall: Object.freeze(firewall),
    forwarding: Object.freeze({ bridge: 'pr-test-bridge', defaultPolicy: 'deny', ipv4: true }),
    marker,
    roles: Object.freeze(roles)
  })
}

function canonicalRoute(value) {
  return `${value.destination}|${value.device}|${value.gateway}`
}

function canonicalRule(value) {
  return `${value.source}|${value.sourcePort}|${value.destination}|${value.destinationPort}|${value.protocol}|${value.ingress}|${value.egress}`
}

function exactArrayValues(value, expectedLength) {
  if (!Array.isArray(value)) invalid()
  const keys = reflectOwnKeys(value)
  if (keys.length !== expectedLength + 1 || keys.some((key) => typeof key !== 'string')) invalid()
  const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length')
  if (
    !lengthDescriptor ||
    !('value' in lengthDescriptor) ||
    lengthDescriptor.value !== expectedLength
  )
    invalid()
  const values = []
  for (let index = 0; index < expectedLength; index++) {
    const descriptor = objectGetOwnPropertyDescriptor(value, String(index))
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
    values.push(descriptor.value)
  }
  return values
}

function validateMarkerEndpoint(value, expected) {
  exactObject(value, ['device', 'gateway', 'host', 'port', 'routes'])
  if (
    value.device !== expected.device ||
    value.gateway !== expected.gateway ||
    value.host !== expected.host ||
    value.port !== expected.port
  )
    invalid()
  const routes = exactArrayValues(value.routes, 1)
  exactObject(routes[0], ['destination', 'device', 'gateway'])
  if (canonicalRoute(routes[0]) !== canonicalRoute(expected.routes[0])) invalid()
}

function validateNamespaceProjection(value) {
  try {
    exactObject(value, ['firewall', 'forwarding', 'marker', 'roles'])
    const roles = exactArrayValues(value.roles, 11)
    const firewall = exactArrayValues(value.firewall, ALLOW_EDGES.length * 2 + 2)
    const tuples = ROLES.map((role, index) =>
      Object.freeze({ host: `10.203.${index + 1}.2`, port: 42_001 + index })
    )
    const expected = namespaceProjection(tuples)
    exactObject(value.forwarding, ['bridge', 'defaultPolicy', 'ipv4'])
    if (
      value.forwarding.bridge !== 'pr-test-bridge' ||
      value.forwarding.defaultPolicy !== 'deny' ||
      value.forwarding.ipv4 !== true
    )
      invalid()
    exactObject(value.marker, ['auditor', 'decoy'])
    validateMarkerEndpoint(value.marker.auditor, expected.marker.auditor)
    validateMarkerEndpoint(value.marker.decoy, expected.marker.decoy)
    for (let index = 0; index < 11; index++) {
      const role = roles[index]
      exactObject(role, ['device', 'gateway', 'host', 'prefix', 'role', 'roleIndex', 'routes'])
      const wanted = expected.roles[index]
      if (
        role.device !== wanted.device ||
        role.gateway !== wanted.gateway ||
        role.host !== wanted.host ||
        role.prefix !== 24 ||
        role.role !== wanted.role ||
        role.roleIndex !== wanted.roleIndex
      )
        invalid()
      const wantedRoutes = wanted.routes.map(canonicalRoute).sort()
      const actualRoutes = exactArrayValues(role.routes, wantedRoutes.length)
        .map((route) => {
          exactObject(route, ['destination', 'device', 'gateway'])
          if (route.destination === '0.0.0.0/0' || !route.destination.endsWith('/32')) invalid()
          return canonicalRoute(route)
        })
        .sort()
      if (actualRoutes.some((route, offset) => route !== wantedRoutes[offset])) invalid()
    }
    const actualRules = firewall
      .map((rule) => {
        exactObject(rule, [
          'destination',
          'destinationPort',
          'egress',
          'ingress',
          'protocol',
          'source',
          'sourcePort'
        ])
        if (rule.protocol !== 'udp') invalid()
        return canonicalRule(rule)
      })
      .sort()
    const expectedRules = expected.firewall.map(canonicalRule).sort()
    if (actualRules.some((rule, offset) => rule !== expectedRules[offset])) invalid()
    return true
  } catch (err) {
    if (err instanceof ProcessConfigError) throw err
    invalid()
  }
}

function dhtOptions(tuple, nodes, bootstrap = []) {
  return Object.freeze({
    anyPort: false,
    bootstrap: Object.freeze(
      bootstrap.map((node) => Object.freeze({ host: node.host, port: node.port }))
    ),
    ephemeral: false,
    firewalled: false,
    host: tuple.host,
    nodes: Object.freeze(nodes.map((node) => Object.freeze({ host: node.host, port: node.port }))),
    port: tuple.port
  })
}

function createLiveProcessTopology(options) {
  exactObject(options, ['clocks', 'entropy', 'plan'])
  const clocks = CLOCK_CAPABILITIES.get(options.clocks)
  const entropy = ENTROPY_CAPABILITIES.get(options.entropy)
  if (
    !clocks ||
    !entropy ||
    (options.plan !== PORTABLE_LOOPBACK && options.plan !== LINUX_NAMESPACE)
  )
    invalid()
  ENTROPY_CAPABILITIES.delete(options.entropy)
  const plan = options.plan
  const now = clocks.wallNow()
  const monotonic = clocks.monotonicNow()
  if (
    typeof now !== 'bigint' ||
    now < 0n ||
    now > MAX_U64 ||
    typeof monotonic !== 'bigint' ||
    monotonic < 0n ||
    monotonic > MAX_U64
  )
    invalid()
  let phaseGate = null
  let projectionBytes = null
  const secrets = []
  const track = (value) => {
    secrets.push(value)
    return value
  }
  try {
    const tuples = ROLES.map((role, index) => planTuple(plan, index + 1))
    const identities = []
    identities.push(identity(entropy))
    identities.push(identity(entropy, ROLE.SAFETY))
    identities.push(identity(entropy, ROLE.SAFETY))
    identities.push(identity(entropy, ROLE.PRIVATE))
    identities.push(identity(entropy, ROLE.SAFETY))
    identities.push(identity(entropy, ROLE.PRIVATE))
    identities.push(identity(entropy, ROLE.SAFETY))
    identities.push(identity(entropy, ROLE.PRIVATE))
    identities.push(identity(entropy))
    identities.push(identity(entropy))
    identities.push(identity(entropy))
    for (const pair of identities) track(pair.secretKey)

    const routes = Array(11).fill(null)
    const advertisements = Array(11).fill(null)
    for (const index of [1, 2, 3, 4, 5, 6, 7]) {
      routes[index] = encryptionIdentity(entropy)
      track(routes[index].secretKey)
      advertisements[index] = advertisement(
        tuples[index],
        identities[index],
        routes[index],
        [3, 5, 7].includes(index) ? ROLE.PRIVATE : ROLE.SAFETY,
        now
      )
    }

    const run = track(entropyBytes(entropy, 16))
    if (plan === LINUX_NAMESPACE) phaseGate = issueProcessPhaseGate(run, GENERATIONS[0])
    const runId32 = track(entropyBytes(entropy, 32))
    const immutableValue = track(entropyBytes(entropy, 128))
    const targetHash = cryptoSuite.hash(immutableValue)
    const leakSentinel = track(entropyBytes(entropy, 32))
    const roleMacKeys = ROLES.map(() => track(entropyBytes(entropy, 32)))
    const oracleMacKeys = roleMacKeys.map((key) => track(copy(key, 32)))
    const topologyAuthority = identity(entropy)
    track(topologyAuthority.secretKey)
    track(topologyAuthority.publicKey)
    const topologyVerificationContext = () => ({
      topologyAuthorityPublicKey: track(copy(topologyAuthority.publicKey, 32)),
      topologyEpoch: 1n,
      topologyRunId: track(copy(runId32, 32))
    })
    const isolatedAuthority = identity(entropy)
    track(isolatedAuthority.secretKey)
    const auditorMarkerKey = track(entropyBytes(entropy, 32))
    const decoyMarkerKey = track(entropyBytes(entropy, 32))

    const linkSpecs = [
      [1, 2, TOPOLOGY_ROLE.SOURCE, TOPOLOGY_ROLE.SAFETY_GUARD],
      [2, 3, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SAFETY_FINAL],
      [2, 5, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SAFETY_FINAL],
      [2, 7, TOPOLOGY_ROLE.SAFETY_GUARD, TOPOLOGY_ROLE.SAFETY_FINAL],
      [3, 4, TOPOLOGY_ROLE.SAFETY_FINAL, TOPOLOGY_ROLE.PRIVATE_ENTRY],
      [5, 6, TOPOLOGY_ROLE.SAFETY_FINAL, TOPOLOGY_ROLE.PRIVATE_ENTRY],
      [7, 8, TOPOLOGY_ROLE.SAFETY_FINAL, TOPOLOGY_ROLE.PRIVATE_ENTRY]
    ]
    const linkGrants = linkSpecs.map(([left, right, leftRole, rightRole]) =>
      makeLinkGrant(
        entropy,
        topologyAuthority,
        runId32,
        tuples,
        identities,
        left,
        right,
        leftRole,
        rightRole,
        now
      )
    )
    const grantFor = (left, right) =>
      linkGrants[linkSpecs.findIndex((edge) => edge[0] === left && edge[1] === right)]

    const parametersDigest = digestPayloadParameters({
      cellSize: 1200,
      contextEnvelopeSize: 1101,
      datagramReplayWindow: 64,
      idleTimeoutMs: 30_000,
      maxCellPayload: 1146,
      maxQueuedBytes: 262_144,
      maxRoutePayload: 1073,
      routeFrameSize: 1100
    })
    const policyDigest = digestExitOriginServicePolicy()
    const dhtIds = identities.slice(8).map((pair) => copy(pair.publicKey, 32))

    const common = (index) => ({
      bind: tuples[index],
      controlAuditMacKey: roleMacKeys[index],
      generation: GENERATIONS[index],
      plan: plan.name,
      role: ROLES[index],
      roleIndex: index + 1,
      run: copy(run, 16)
    })

    const projections = []
    projections.push(
      deepFreeze({
        ...common(0),
        ...topologyVerificationContext(),
        ...(phaseGate === null ? {} : { phaseGate }),
        guardBootstrap: { ...tuples[1] },
        guardGrant: copy(grantFor(1, 2)),
        identityPublicKey: copy(identities[0].publicKey, 32),
        leakSentinel: copy(leakSentinel, 32),
        localIdentitySecretKey: identities[0].secretKey,
        targetHash: copy(targetHash, 32)
      })
    )
    projections.push(
      deepFreeze({
        ...common(1),
        ...topologyVerificationContext(),
        advertisement: copy(advertisements[1].bytes),
        advertisementDigest: copy(advertisements[1].digest, 32),
        // Branch builds consume these in order, so the pairs are listed the way the
        // scenario names them: lookup A first, then announce, leaving lookup B as the
        // reserve that a faulted lookup branch rotates onto.
        candidateAdvertisements: [2, 3, 6, 7, 4, 5].map((index) =>
          copy(advertisements[index].bytes)
        ),
        endpointAdjacentBinding: { ...tuples[0] },
        identityPublicKey: copy(identities[1].publicKey, 32),
        identitySecretKey: identities[1].secretKey,
        middleAdjacencies: [2, 4, 6].map((index) =>
          contact(ROLES[index], identities[index].publicKey, tuples[index])
        ),
        middleGrants: [grantFor(2, 3), grantFor(2, 5), grantFor(2, 7)].map((grant) => copy(grant)),
        routePublicKey: copy(routes[1].publicKey, 32),
        routeSecretKey: routes[1].secretKey
      })
    )

    for (const [middleIndex, exitIndex] of [
      [2, 3],
      [4, 5],
      [6, 7]
    ]) {
      projections.push(
        deepFreeze({
          ...common(middleIndex),
          ...topologyVerificationContext(),
          adjacencies: [
            contact('guard', identities[1].publicKey, tuples[1]),
            contact(ROLES[exitIndex], identities[exitIndex].publicKey, tuples[exitIndex])
          ],
          advertisement: copy(advertisements[middleIndex].bytes),
          advertisementDigest: copy(advertisements[middleIndex].digest, 32),
          grants: [
            copy(grantFor(2, middleIndex + 1)),
            copy(grantFor(middleIndex + 1, exitIndex + 1))
          ],
          identityPublicKey: copy(identities[middleIndex].publicKey, 32),
          identitySecretKey: identities[middleIndex].secretKey,
          routePublicKey: copy(routes[middleIndex].publicKey, 32),
          routeSecretKey: routes[middleIndex].secretKey
        })
      )
      const tupleDigest = digestTestIsolatedAddressTuple({
        exitRole: exitIndex + 1,
        generation: GENERATIONS[exitIndex],
        id: dhtIds[0],
        tuple: tuples[8]
      })
      const initialSeedGrant = encodeTestIsolatedAddressGrant(
        {
          expiresAt: now + 60_000n,
          exitRole: exitIndex + 1,
          generation: GENERATIONS[exitIndex],
          grantSequence: BigInt(exitIndex + 1),
          runNonce: run,
          tupleDigest
        },
        isolatedAuthority.secretKey
      )
      // Each isolated-address grant is one-shot, and a rebuilt branch rediscovers the
      // same closers at advancing generations, so every learned tuple gets a pool of
      // distinct grants across generations 1 through 5.
      const learnedGrants = (tuple, sequenceBase) => {
        const peerId = deriveDhtExitPeerId(tuple)
        const pools = {}
        for (let gen = 1; gen <= 5; gen++) {
          const digest = digestTestIsolatedAddressTuple({
            exitRole: exitIndex + 1,
            generation: BigInt(gen),
            id: peerId,
            tuple
          })
          const grants = []
          for (let use = 0; use < LEARNED_GRANT_USES; use++) {
            grants.push(
              encodeTestIsolatedAddressGrant(
                {
                  expiresAt: now + 60_000n,
                  exitRole: exitIndex + 1,
                  generation: BigInt(gen),
                  grantSequence: BigInt(sequenceBase + (gen - 1) * LEARNED_GRANT_USES + use),
                  runNonce: run,
                  tupleDigest: digest
                },
                isolatedAuthority.secretKey
              )
            )
          }
          pools[gen] = grants
          clear(digest)
        }
        clear(peerId)
        return pools
      }
      const learnedReferralGrants = learnedGrants(tuples[9], exitIndex * 100 + 100)
      const learnedValueGrants = learnedGrants(tuples[10], exitIndex * 100 + 200)
      const learnedSeedGrants = learnedGrants(tuples[8], exitIndex * 100 + 300)
      clear(tupleDigest)
      const terminalKeys = track(entropyBytes(entropy, 32))
      projections.push(
        deepFreeze({
          ...common(exitIndex),
          ...topologyVerificationContext(),
          advertisement: copy(advertisements[exitIndex].bytes),
          advertisementDigest: copy(advertisements[exitIndex].digest, 32),
          dhtSeed: { ...tuples[8] },
          dhtSeedId: copy(dhtIds[0], 32),
          identityPublicKey: copy(identities[exitIndex].publicKey, 32),
          identitySecretKey: identities[exitIndex].secretKey,
          immutableGetAuthority: exitIndex === 3 || exitIndex === 5,
          initialSeedGrant,
          learnedReferralGrants,
          learnedValueGrants,
          learnedSeedGrants,
          isolatedGrantVerifier: {
            publicKey: copy(isolatedAuthority.publicKey, 32),
            run: copy(run, 16)
          },
          middleAdjacency: contact(
            ROLES[middleIndex],
            identities[middleIndex].publicKey,
            tuples[middleIndex]
          ),
          middleGrant: copy(grantFor(middleIndex + 1, exitIndex + 1)),
          payloadParametersDigest: copy(parametersDigest, 32),
          routePublicKey: copy(routes[exitIndex].publicKey, 32),
          routeSecretKey: routes[exitIndex].secretKey,
          terminalKeys,
          terminalPolicyDigest: copy(policyDigest, 32)
        })
      )
    }

    projections.push(
      deepFreeze({
        ...common(8),
        dhtId: dhtIds[0],
        dhtOptions: dhtOptions(tuples[8], [tuples[9]])
      })
    )
    projections.push(
      deepFreeze({
        ...common(9),
        dhtId: dhtIds[1],
        dhtOptions: dhtOptions(tuples[9], [tuples[10]])
      })
    )
    projections.push(
      deepFreeze({
        ...common(10),
        dhtId: dhtIds[2],
        dhtOptions: dhtOptions(tuples[10], [], [tuples[10]])
      })
    )

    if (
      projections.length !== 11 ||
      projections.some((projection, index) => projection.role !== ROLES[index])
    )
      invalid()
    const projectionDigests = projections.map(projectionDigest)
    projectionBytes = projections.map((projection) => encodeCanonicalBody(projection))
    REVOKABLE_ARRAYS.add(projectionBytes)
    const tupleEncoding = encodeCanonicalBody(tuples)
    const tupleDigest = cryptoSuite.hash(tupleEncoding)
    const tupleSignature = cryptoSuite.sign(tupleDigest, topologyAuthority.secretKey)
    clear(tupleEncoding)
    const namespace = plan === LINUX_NAMESPACE ? namespaceProjection(tuples) : null
    if (namespace !== null) validateNamespaceProjection(namespace)

    const eventForbiddenBytes = [
      leakSentinel,
      immutableValue,
      ...identities.map((pair) => pair.secretKey),
      ...routes.filter(Boolean).map((pair) => pair.secretKey),
      ...projections
        .filter((projection) => projection.terminalKeys)
        .map((projection) => projection.terminalKeys),
      ...roleMacKeys,
      ...oracleMacKeys,
      auditorMarkerKey,
      decoyMarkerKey
    ].map((value) => copy(value))

    const oracle = deepFreeze({
      auditorMarkerKey,
      branches: {
        announce: {
          exit: 'announce-exit',
          generation: 1n,
          middle: 'announce-middle',
          state: 'ready'
        },
        lookup: {
          exit: 'lookup-exit-a',
          generation: 1n,
          middle: 'lookup-middle-a',
          state: 'selected'
        },
        lookupStandby: {
          exit: 'lookup-exit-b',
          generation: 2n,
          middle: 'lookup-middle-b',
          rotations: 1,
          state: 'standby'
        }
      },
      decoyMarkerKey,
      endpointAddress: tuples[0].host,
      eventForbiddenBytes,
      immutableValue,
      leakSentinel,
      linkGrants: linkGrants.map((grant) => copy(grant)),
      namespace,
      networkAuthority: networkAuthority(tuples),
      plan: plan.name,
      projectionBytes,
      projectionDigests,
      roleMacKeys: oracleMacKeys,
      run: copy(run, 16),
      targetHash: copy(targetHash, 32),
      tupleAuthorization: {
        digest: tupleDigest,
        publicKey: copy(topologyAuthority.publicKey, 32),
        signature: tupleSignature
      },
      tuples: tuples.map((tuple) => ({ ...tuple }))
    })

    let stopped = false
    const result = Object.freeze({
      oracle,
      projections: Object.freeze(projections),
      stop() {
        if (stopped) return
        stopped = true
        revokeProcessPhaseGate(phaseGate)
        for (const secret of secrets) clear(secret)
        for (const projection of projections) clear(projection.run)
        clear(oracle.run)
        for (const value of oracle.eventForbiddenBytes) clear(value)
        for (const value of projectionBytes) clear(value)
        projectionBytes.length = 0
      }
    })
    clear(entropy.seed)
    return result
  } catch (err) {
    clear(entropy.seed)
    for (const secret of secrets) clear(secret)
    revokeProcessPhaseGate(phaseGate)
    if (projectionBytes !== null) {
      for (const value of projectionBytes) clear(value)
      projectionBytes.length = 0
    }
    if (err instanceof ProcessConfigError) throw err
    throw err
  }
}

module.exports = Object.freeze({
  ALLOW_EDGES,
  PROCESS_PLANS,
  ProcessConfigError,
  ROLES,
  TEST_ONLY_PROCESS_TOPOLOGY_ISSUER,
  consumeProcessPhaseGate,
  createLiveProcessTopology,
  validateNamespaceProjection
})
