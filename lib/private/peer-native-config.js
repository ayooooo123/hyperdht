'use strict'

const b4a = require('b4a')
const UDX = require('udx-native')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { LINK_OPERATION, TOPOLOGY_ROLE } = require('./protocol')
const {
  DEFAULT_MAX_TOPOLOGY_GRANTS,
  MAX_TOPOLOGY_AUTHORITIES,
  readVerifiedTopologyGrant,
  verifyTopologyGrantV1
} = require('./topology-grant')
const {
  computePeerSemanticOwnedBytes,
  computePeerQueuedBytes,
  computePeerRouteBudget
} = require('./peer-ledger')

// Public native profile (packet §§7.2, 7.3 and 8.3; council R31–R40).
const SOURCE_SLOTS = 16
const RELAY_CIRCUITS = 24
const ADVERTISEMENT_LIFETIME_MS = 600_000
const IDLE_TIMEOUT_MS = 30_000
const SOURCE_DATA_FRAMES = 111_852
const REGISTRATION_DATA_FRAMES = 111_791
const LEGACY_DATA_FRAMES = 20_000
const REGISTRATION_APPLICATIONS = 16
const APPLICATION_FRAME_FLOOR = 1024
const RECEIVE_FRAMES = 24
const RECEIVE_BYTES = RECEIVE_FRAMES * 977
const SOURCE_TAIL_BYTES = 4445
const RESPONDER_TAIL_BYTES = 3696
const RESPONDER_STARTUP_BYTES = 680_000

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const OPTION_FIELDS = ['release', 'acknowledgeAlpha', 'mode', 'profile', 'relay']
const RELAY_FIELDS = ['identityKeyPair', 'authorityPublicKeys', 'epoch', 'runId32', 'grants']
const KEY_FIELDS = ['publicKey', 'secretKey']
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const byteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const setBytes = Uint8Array.prototype.set

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function ownData(object, name) {
  if (object === null || typeof object !== 'object') invalid()
  const descriptor = Object.getOwnPropertyDescriptor(object, name)
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid()
  return descriptor.value
}

function exactObject(object, fields) {
  if (
    object === null ||
    typeof object !== 'object' ||
    Object.getPrototypeOf(object) !== Object.prototype ||
    Reflect.ownKeys(object).length !== fields.length
  )
    invalid()
  const copy = {}
  for (const field of fields) copy[field] = ownData(object, field)
  return copy
}

function exactArray(value, maximum, map) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid()
  const length = ownData(value, 'length')
  if (length < 1 || length > maximum || Reflect.ownKeys(value).length !== length + 1) invalid()
  const result = []
  for (let index = 0; index < length; index++) result.push(map(ownData(value, String(index))))
  return Object.freeze(result)
}

function bytes(value, size, nonzero = false) {
  if (!b4a.isBuffer(value)) invalid()
  const length = byteLength.call(value)
  if ((size !== null && length !== size) || length === 0) invalid()
  const copy = b4a.allocUnsafeSlow(length)
  setBytes.call(copy, value)
  if (nonzero && copy.every((byte) => byte === 0)) invalid()
  return copy
}

function keyPair(value) {
  const pair = exactObject(value, KEY_FIELDS)
  const publicKey = bytes(pair.publicKey, 32, true)
  const secretKey = bytes(pair.secretKey, 64)
  let derived = null
  let accepted = false
  try {
    derived = cryptoSuite.keyPair(secretKey.subarray(0, 32))
    if (!b4a.equals(derived.publicKey, publicKey) || !b4a.equals(derived.secretKey, secretKey))
      invalid()
    accepted = true
    return Object.freeze({ publicKey, secretKey })
  } finally {
    if (derived) derived.secretKey.fill(0)
    if (!accepted) secretKey.fill(0)
  }
}

function authorityKeys(value) {
  const seen = new Set()
  return exactArray(value, MAX_TOPOLOGY_AUTHORITIES, (value) => {
    const key = bytes(value, 32, true)
    const hex = b4a.toString(key, 'hex')
    if (seen.has(hex)) invalid()
    seen.add(hex)
    return key
  })
}

function validateGrantSet(config, now) {
  let local = null
  let expiresAt = MAX_U64
  let capabilityMask = 11
  const peers = new Set()
  const addresses = new Set()
  for (const encoding of config.grants) {
    const verified = verifyTopologyGrantV1(encoding, config.authorityPublicKeys, {
      localIdentity32: config.identityKeyPair.publicKey,
      now
    })
    const grant = readVerifiedTopologyGrant(verified)
    if (grant.epoch !== config.epoch || !b4a.equals(grant.runId32, config.runId32)) invalid()
    if (
      local !== null &&
      (grant.local.address.host !== local.address.host ||
        grant.local.address.port !== local.address.port)
    )
      invalid()
    local = grant.local
    if (capabilityForRoles(local.role, grant.peer.role) === 9) capabilityMask = 9
    const localInitiates = (local.operations & LINK_OPERATION.INITIATE) !== 0
    const peerInitiates = (grant.peer.operations & LINK_OPERATION.INITIATE) !== 0
    const dialer =
      localInitiates && (!peerInitiates || b4a.compare(local.identity32, grant.peer.identity32) < 0)
    if (
      (!localInitiates && !peerInitiates) ||
      (dialer && !(grant.peer.operations & LINK_OPERATION.ACCEPT)) ||
      (!dialer && !(local.operations & LINK_OPERATION.ACCEPT))
    )
      invalid()
    const peer = b4a.toString(grant.peer.identity32, 'hex')
    const address = grant.peer.address.host + ':' + grant.peer.address.port
    if (peers.has(peer) || addresses.has(address)) invalid()
    if (
      local.address.host === grant.peer.address.host &&
      local.address.port === grant.peer.address.port
    )
      invalid()
    peers.add(peer)
    addresses.add(address)
    if (grant.expiresAt < expiresAt) expiresAt = grant.expiresAt
  }
  return { local, expiresAt, capabilityMask }
}

// Roles are positions on one granted edge, not permanent circuit-hop labels (R31).
function capabilityForRoles(local, peer) {
  if (local === TOPOLOGY_ROLE.SAFETY_GUARD && peer === TOPOLOGY_ROLE.SAFETY_FINAL) return 9
  if (local === TOPOLOGY_ROLE.SAFETY_FINAL && peer === TOPOLOGY_ROLE.SAFETY_GUARD) return 11
  invalid()
}

function relayInput(value) {
  const hasLegacyEgress =
    value !== null && typeof value === 'object' && Object.hasOwn(value, 'legacyEgress')
  const input = exactObject(
    value,
    hasLegacyEgress ? [...RELAY_FIELDS, 'legacyEgress'] : RELAY_FIELDS
  )
  if (hasLegacyEgress && typeof input.legacyEgress !== 'boolean') invalid()
  if (!hasLegacyEgress) input.legacyEgress = false
  return input
}

function relayConfig(value) {
  const input = relayInput(value)
  if (typeof input.epoch !== 'bigint' || input.epoch < 1n || input.epoch > MAX_U64) invalid()
  const identityKeyPair = keyPair(input.identityKeyPair)
  let accepted = false
  try {
    const result = Object.freeze({
      identityKeyPair,
      authorityPublicKeys: authorityKeys(input.authorityPublicKeys),
      epoch: input.epoch,
      runId32: bytes(input.runId32, 32, true),
      legacyEgress: input.legacyEgress,
      grants: exactArray(input.grants, DEFAULT_MAX_TOPOLOGY_GRANTS, (grant) => {
        // Format-1 canonical endpoints occupy 4 or 16 address bytes: 367..391 total.
        const length = b4a.isBuffer(grant) ? byteLength.call(grant) : 0
        if (length !== 367 && length !== 379 && length !== 391) invalid()
        return bytes(grant, length)
      })
    })
    validateGrantSet(result, BigInt(Date.now()))
    accepted = true
    return result
  } finally {
    if (!accepted) identityKeyPair.secretKey.fill(0)
  }
}

function validatePeerNativeOptions(value) {
  try {
    const relay = ownData(value, 'relay')
    const options = exactObject(
      value,
      relay === true ? [...OPTION_FIELDS, 'relayConfig'] : OPTION_FIELDS
    )
    if (
      options.release !== 'alpha' ||
      options.acknowledgeAlpha !== true ||
      options.mode !== 'optional' ||
      options.profile !== 'native-v2' ||
      typeof relay !== 'boolean'
    )
      invalid()
    if (relay) options.relayConfig = relayConfig(options.relayConfig)
    return Object.freeze(options)
  } catch {
    // Public errors never include a key, grant, file path, or caller-provided value.
    invalid()
  }
}

function hex(value, size) {
  if (typeof value !== 'string' || value.length !== size * 2 || !/^[0-9a-f]+$/i.test(value))
    invalid()
  return b4a.from(value, 'hex')
}

// A relay file has the public option shape. Bytes are hex; epoch is a decimal u64 string.
function decodePeerNativeConfig(text) {
  let secret = null
  try {
    if (typeof text !== 'string') invalid()
    const options = exactObject(JSON.parse(text), [...OPTION_FIELDS, 'relayConfig'])
    if (options.relay !== true) invalid()
    const config = relayInput(options.relayConfig)
    const pair = exactObject(config.identityKeyPair, KEY_FIELDS)
    if (typeof config.epoch !== 'string' || !/^[1-9][0-9]{0,19}$/.test(config.epoch)) invalid()
    secret = hex(pair.secretKey, 64)
    config.identityKeyPair = { publicKey: hex(pair.publicKey, 32), secretKey: secret }
    config.authorityPublicKeys = exactArray(
      config.authorityPublicKeys,
      MAX_TOPOLOGY_AUTHORITIES,
      (value) => hex(value, 32)
    )
    config.epoch = BigInt(config.epoch)
    config.runId32 = hex(config.runId32, 32)
    config.grants = exactArray(config.grants, DEFAULT_MAX_TOPOLOGY_GRANTS, (value) => {
      if (typeof value !== 'string' || ![734, 758, 782].includes(value.length)) invalid()
      return hex(value, value.length / 2)
    })
    return validatePeerNativeOptions({ ...options, relayConfig: config })
  } catch {
    invalid()
  } finally {
    if (secret) secret.fill(0)
  }
}

function applicationBudget(frames, window) {
  return Object.freeze({
    forwardFrames: frames,
    reverseFrames: frames,
    forwardBytes: BigInt(frames * 977),
    reverseBytes: BigInt(frames * 977),
    forwardWindow: window,
    reverseWindow: window
  })
}

function purposeProfile(purpose, applications) {
  const maxStreams = applications.length + (purpose === 3 ? 1 : 0)
  const semanticOwnedBytes = computePeerSemanticOwnedBytes({
    purpose,
    isInitiator: true,
    maxStreams
  })
  const maxQueuedBytes = computePeerQueuedBytes({
    maxStreams,
    receiveBytes: RECEIVE_BYTES,
    semanticOwnedBytes
  })
  return Object.freeze({
    purpose,
    maxStreams,
    semanticOwnedBytes,
    maxQueuedBytes,
    receiveFrames: RECEIVE_FRAMES,
    receiveBytes: RECEIVE_BYTES,
    budget: computePeerRouteBudget({ purpose, maxStreams, applications })
  })
}

function peerNativeProfile(sourceSlots = SOURCE_SLOTS) {
  if (!Number.isSafeInteger(sourceSlots) || sourceSlots < 1 || sourceSlots > 16) invalid()
  const source = purposeProfile(2, [applicationBudget(SOURCE_DATA_FRAMES, RECEIVE_FRAMES)])
  const legacy = purposeProfile(1, [applicationBudget(LEGACY_DATA_FRAMES, RECEIVE_FRAMES)])
  // This vector proves the aggregate reservation, not a fixed per-stream allocation.
  // OPEN draws from the unrefunded remainder while preserving each unused slot's floor.
  const applicationWindow = Math.floor(RECEIVE_FRAMES / REGISTRATION_APPLICATIONS)
  const applications = Array.from({ length: REGISTRATION_APPLICATIONS }, (_, index) =>
    applicationBudget(
      index === 0
        ? REGISTRATION_DATA_FRAMES - APPLICATION_FRAME_FLOOR * (REGISTRATION_APPLICATIONS - 1)
        : APPLICATION_FRAME_FLOOR,
      applicationWindow
    )
  )
  const registration = purposeProfile(3, applications)
  let maxCells = 0
  let maxBytes = 0n
  let maxCommands = 0
  for (const profile of [source, registration]) {
    for (let i = 0; i < profile.budget.adjacencies.length; i++) {
      const row = profile.budget.adjacencies[i]
      const discovery = profile.budget.directDiscovery[i]
      for (const direction of ['forward', 'reverse']) {
        const work = row[direction]
        const bootstrap = discovery[direction]
        // Discovery belongs to the requesting circuit and its actual direction.
        maxCells = Math.max(maxCells, work.cells + bootstrap.cells)
        const bytes = work.bytes + bootstrap.bytes
        if (bytes > maxBytes) maxBytes = bytes
        maxCommands = Math.max(maxCommands, work.commands + bootstrap.commands)
      }
    }
  }
  const maxQueuedBytes = Math.max(source.maxQueuedBytes, registration.maxQueuedBytes)
  const legacyTerminalQueuedBytes = computePeerQueuedBytes({
    maxStreams: registration.maxStreams,
    receiveBytes: RECEIVE_BYTES,
    semanticOwnedBytes: Math.max(registration.semanticOwnedBytes, legacy.semanticOwnedBytes)
  })
  return Object.freeze({
    sourceSlots,
    relayCircuits: RELAY_CIRCUITS,
    source,
    registration,
    legacy,
    legacyDataFrames: LEGACY_DATA_FRAMES,
    legacyTerminalQueuedBytes,
    sourceDataFrames: SOURCE_DATA_FRAMES,
    registrationDataFrames: REGISTRATION_DATA_FRAMES,
    applicationFrameFloor: APPLICATION_FRAME_FLOOR,
    sourceMemoryBytes: sourceSlots * (SOURCE_TAIL_BYTES + maxQueuedBytes),
    forwardingMemoryBytes: RESPONDER_STARTUP_BYTES + RELAY_CIRCUITS * RESPONDER_TAIL_BYTES,
    terminalMemoryBytes:
      RESPONDER_STARTUP_BYTES + RELAY_CIRCUITS * (RESPONDER_TAIL_BYTES + maxQueuedBytes),
    lifetimeMs: ADVERTISEMENT_LIFETIME_MS,
    limits: Object.freeze({
      maxConcurrentCircuits: RELAY_CIRCUITS,
      capacityClass: 1,
      maxCells,
      maxBytes: Number(maxBytes),
      maxCommands,
      idleTimeoutMs: IDLE_TIMEOUT_MS,
      maxQueuedBytes
    })
  })
}

function guardTuple(value) {
  const tuple = exactObject(value, ['host', 'port'])
  if (
    typeof tuple.host !== 'string' ||
    !UDX.isIPv4(tuple.host) ||
    tuple.host === '0.0.0.0' ||
    !Number.isInteger(tuple.port) ||
    tuple.port < 1 ||
    tuple.port > 65535
  )
    invalid()
  return Object.freeze(tuple)
}

// Called only after base readiness. Guard locators belong to ordinary DHT discovery,
// never the public options; a relay's advertised tuple belongs to DHT reachability.
function createPeerNativeRuntimeConfig(value, dht, guards = null) {
  const options = validatePeerNativeOptions(value)
  let transferred = false
  try {
    const profile = peerNativeProfile()
    if (!options.relay) {
      const seen = new Set()
      const locators = exactArray(guards, 3, (value) => {
        const tuple = guardTuple(value)
        const key = tuple.host + ':' + tuple.port
        if (seen.has(key)) invalid()
        seen.add(key)
        return tuple
      })
      return Object.freeze({
        role: 'source',
        memoryBytes: profile.sourceMemoryBytes,
        source: Object.freeze({ guards: locators, maxProspectiveGuards: 3 })
      })
    }
    const config = options.relayConfig
    const { local, expiresAt, capabilityMask } = validateGrantSet(config, BigInt(Date.now()))
    const reachable = dht.remoteAddress()
    if (!reachable) throw PrivateRouteError.ROUTE_UNAVAILABLE()
    if (
      reachable.host !== local.address.host ||
      reachable.port !== local.address.port ||
      reachable.host === '0.0.0.0' ||
      reachable.host === '::' ||
      (capabilityMask === 9 && !UDX.isIPv4(reachable.host)) ||
      expiresAt <= BigInt(Date.now()) + BigInt(profile.lifetimeMs)
    )
      invalid()
    const result = Object.freeze({
      role: 'relay',
      identity: config.identityKeyPair,
      memoryBytes:
        capabilityMask === 9 ? profile.forwardingMemoryBytes : profile.terminalMemoryBytes,
      relay: Object.freeze({
        reachable: Object.freeze({ host: reachable.host, port: reachable.port }),
        limits:
          config.legacyEgress && capabilityMask === 11
            ? Object.freeze({
                ...profile.limits,
                maxQueuedBytes: Math.max(
                  profile.limits.maxQueuedBytes,
                  profile.legacyTerminalQueuedBytes
                )
              })
            : profile.limits,
        lifetimeMs: profile.lifetimeMs,
        epoch: config.epoch,
        legacyEgress: config.legacyEgress,
        admission: Object.freeze({
          authorityPublicKeys: config.authorityPublicKeys,
          runId32: config.runId32,
          grants: config.grants,
          maxNeighbors: DEFAULT_MAX_TOPOLOGY_GRANTS
        })
      })
    })
    transferred = true
    return result
  } finally {
    if (options.relay && !transferred) options.relayConfig.identityKeyPair.secretKey.fill(0)
  }
}

function peerNativePurposeLimits(profile, expiry) {
  const row = profile.budget.purpose
  return {
    forwardCells: row.forward.cells,
    forwardBytes: row.forward.bytes,
    forwardCommands: row.forward.commands,
    reverseCells: row.reverse.cells,
    reverseBytes: row.reverse.bytes,
    reverseCommands: row.reverse.commands,
    maxStreams: profile.maxStreams,
    receiveFrames: profile.receiveFrames,
    receiveBytes: profile.receiveBytes,
    semanticOwnedBytes: profile.semanticOwnedBytes,
    maxQueuedBytes: profile.maxQueuedBytes,
    expiresAt: expiry
  }
}

function peerNativeBuildLimits(profile, idleTimeoutMs) {
  const result = {}
  for (const direction of ['forward', 'reverse']) {
    let maxCells = 0
    let maxCommands = 0
    for (let hop = 0; hop < profile.budget.adjacencies.length; hop++) {
      const row = profile.budget.adjacencies[hop][direction]
      const discovery = profile.budget.directDiscovery[hop][direction]
      maxCells = Math.max(maxCells, row.cells + discovery.cells)
      maxCommands = Math.max(maxCommands, row.commands + discovery.commands)
    }
    result[direction + 'Limits'] = { maxCells, maxCommands, idleTimeoutMs }
  }
  return result
}

module.exports = {
  validatePeerNativeOptions,
  decodePeerNativeConfig,
  createPeerNativeRuntimeConfig,
  peerNativeProfile,
  peerNativePurposeLimits,
  peerNativeBuildLimits
}
