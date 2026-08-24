'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS, RELAY_CAPABILITY, ROLE, roleForIdentity } = require('./protocol')
const {
  CAPABILITY_ADVERTISEMENT_MAX_BYTES,
  CAPABILITY_ADVERTISEMENT_MIN_BYTES,
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement
} = require('./relay-capability')

const MAX_IDENTITIES = 16
const MAX_TRANSFER_RECORDS = 32
const MAX_TRANSFER_BYTES = MAX_TRANSFER_RECORDS * CAPABILITY_ADVERTISEMENT_MAX_BYTES
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_WALL_ROLLBACK = 30_000n
// Minimum lifetime of a fault demotion, independent of anything the faulted
// relay advertised. A relay signs its own `expiresAt`, and the only bounds on
// that number are `expiresAt > now` at admission here and
// `MAX_CAPABILITY_LIFETIME` (30 minutes) as a ceiling in `relay-capability.js`.
// There is no minimum, so an unfloored demotion is a penalty whose duration the
// penalised party chooses. 60s is four `MAX_ROUTE_LIFETIME_MS` route lifetimes
// and twelve `BRANCH_ROTATION_LEAD_MS` rotation leads, so a demotion binds
// several consecutive rotations instead of lapsing inside the one that earned
// it; and it is a thirtieth of the capability ceiling, so it stays far under the
// longest demotion an honest long-lived advertisement already accepts. Minted
// here rather than derived from those two: duplicating a number is cheaper than
// coupling this module to the route manager's and the extension's clocks.
const FAULT_DEMOTION_MS = 60_000n
const CLOCK_ROLLBACK_SINKS = new WeakMap()

const RECORD_FIELDS = Object.freeze([
  'canonicalBytes',
  'digest',
  'identity',
  'canonicalEndpointBytes',
  'routePublicKey',
  'role',
  'capabilityMask',
  'epoch',
  'issuedAt',
  'expiresAt'
])
const SCOPE_FIELDS = Object.freeze([
  'guardIdentity',
  'guardEndpoint',
  'guardAdvertisementDigest',
  'guardEpoch',
  'guardExpiresAt'
])
const CLOCK_FIELDS = Object.freeze(['wallNow', 'monotonicNow'])
const INITIAL_FIELDS = Object.freeze(['lookupGeneration', 'announceGeneration'])
const REPLACEMENT_FIELDS = Object.freeze(['branchClass', 'generation'])
const FAULT_FIELDS = Object.freeze(['branchClass'])
const EVIDENCE_FIELDS = Object.freeze(['transaction', 'branchClass', 'position', 'generation'])

const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetOwnPropertyNames = Object.getOwnPropertyNames
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectApply = Reflect.apply
const b4aAllocUnsafeSlow = b4a.allocUnsafeSlow
const b4aEquals = b4a.equals
const b4aIsBuffer = b4a.isBuffer
const b4aToString = b4a.toString

const sinkStates = new WeakMap()
const sealedStates = new WeakMap()
const directoryStates = new WeakMap()
const reservationStates = new WeakMap()
const transactionStates = new WeakMap()
const selectionStates = new WeakMap()

const kConstruct = Object.freeze({})
const kInspectRelayCandidateDirectory = Symbol('inspectRelayCandidateDirectory')

function incompatible() {
  throw PrivateRouteError.ERR_INCOMPATIBLE_RELAY()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function bufferLength(value) {
  try {
    return b4aIsBuffer(value) ? reflectApply(byteLengthGetter, value, []) : -1
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {}
}

function allocate(size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > CAPABILITY_ADVERTISEMENT_MAX_BYTES) {
    incompatible()
  }
  return b4aAllocUnsafeSlow(size)
}

function copy(value, expected = null) {
  const size = bufferLength(value)
  if (size < 0 || (expected !== null && size !== expected)) incompatible()
  const output = allocate(size)
  try {
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch {
    clear(output)
    incompatible()
  }
}

function equal(left, right) {
  try {
    return bufferLength(left) === bufferLength(right) && b4aEquals(left, right)
  } catch {
    return false
  }
}

function ownData(object, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(object, name)
  } catch {
    incompatible()
  }
  if (!descriptor || !('value' in descriptor)) incompatible()
  return descriptor.value
}

function exactObject(value, fields) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) incompatible()
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) incompatible()
    if (objectGetOwnPropertySymbols(value).length !== 0) incompatible()
    const names = objectGetOwnPropertyNames(value)
    if (names.length !== fields.length) incompatible()
    for (const field of fields) {
      const descriptor = objectGetOwnPropertyDescriptor(value, field)
      if (!descriptor || !('value' in descriptor)) incompatible()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function recordObject(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) incompatible()
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) incompatible()
    if (objectGetOwnPropertySymbols(value).length !== 0) incompatible()
    const names = objectGetOwnPropertyNames(value)
    for (const field of RECORD_FIELDS) {
      if (!names.includes(field)) incompatible()
      const descriptor = objectGetOwnPropertyDescriptor(value, field)
      if (!descriptor || !('value' in descriptor)) incompatible()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function generation(value) {
  if (typeof value !== 'bigint' || value === 0n || value > MAX_U64) incompatible()
  return value
}

function branch(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) incompatible()
  return value
}

function position(value) {
  if (value !== 'middle' && value !== 'exit') incompatible()
  return value
}

function clearDecoded(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function clearRecord(record) {
  if (!record) return
  clear(record.canonicalBytes)
  clear(record.digest)
  clear(record.identity)
  clear(record.endpoint)
  record.canonicalBytes = null
  record.digest = null
  record.identity = null
  record.endpoint = null
}

function clearScope(scope) {
  if (!scope) return
  clear(scope.guardIdentity)
  clear(scope.guardEndpoint)
  clear(scope.guardAdvertisementDigest)
  scope.guardIdentity = null
  scope.guardEndpoint = null
  scope.guardAdvertisementDigest = null
}

function sampleFunction(state, name) {
  if (state.sampling || typeof state[name] !== 'function') {
    invalidateClockOwner(state)
    incompatible()
  }
  state.sampling = true
  let value
  try {
    value = state[name]()
  } catch {
    invalidateClockOwner(state)
    incompatible()
  } finally {
    state.sampling = false
  }
  if (!clockOwnerIsLive(state)) {
    invalidateClockOwner(state)
    incompatible()
  }
  if (typeof value !== 'bigint' || value < 0n) {
    invalidateClockOwner(state)
    incompatible()
  }
  return value
}

function clockOwnerIsLive(state) {
  if (state.kind === 'sink') return sinkIsActive(state)
  if (state.kind === 'sealed') return sealedIsActive(state)
  return (
    state.kind === 'directory' &&
    !state.destroyed &&
    !state.invalidated &&
    state.scope !== null &&
    typeof state.wallNow === 'function' &&
    typeof state.monotonicNow === 'function'
  )
}

function invalidateClockOwner(state) {
  if (state.kind === 'sink') {
    poisonSinkState(state)
    return
  }
  if (state.kind === 'sealed') {
    clearSealedState(state)
    return
  }
  invalidate(state)
}

function poisonSinkState(state) {
  if (!state) return
  state.active = false
  state.consumed = true
  state.invalidated = true
  state.poisoned = true
  state.wallNow = null
  state.monotonicNow = null
  state.lastWall = null
  state.lastMonotonic = null
}

function sinkIsActive(state) {
  return (
    state !== null &&
    state.active &&
    !state.consumed &&
    !state.invalidated &&
    !state.poisoned &&
    typeof state.wallNow === 'function' &&
    typeof state.monotonicNow === 'function'
  )
}

function sealedIsActive(state) {
  return (
    state !== null &&
    state.active &&
    !state.consumed &&
    !state.invalidated &&
    !state.poisoned &&
    state.records !== null &&
    state.quarantine !== null &&
    state.scope !== null &&
    typeof state.wallNow === 'function' &&
    typeof state.monotonicNow === 'function'
  )
}

function invalidateForClockRollback(state) {
  const sink = CLOCK_ROLLBACK_SINKS.get(state)
  CLOCK_ROLLBACK_SINKS.delete(state)
  invalidateClockOwner(state)
  if (sink) {
    try {
      const { issuePrivateRoutingControllerSignal } = require('./private-routing-controller')
      issuePrivateRoutingControllerSignal(sink)
    } catch {}
  }
}

function sampleWall(state) {
  const now = sampleFunction(state, 'wallNow')
  if (state.lastWall !== null && now + MAX_WALL_ROLLBACK < state.lastWall) {
    invalidateForClockRollback(state)
    incompatible()
  }
  if (state.lastWall === null || now > state.lastWall) state.lastWall = now
  return now
}

function sampleMonotonic(state) {
  const now = sampleFunction(state, 'monotonicNow')
  if (state.lastMonotonic !== null && now < state.lastMonotonic) {
    invalidateForClockRollback(state)
    incompatible()
  }
  state.lastMonotonic = now
  return now
}

function endpointSubnetEqual(left, right) {
  if (equal(left, right)) return true
  if (bufferLength(left) !== 19 || bufferLength(right) !== 19) return false
  // Gate 3B1 accepts canonical IPv4 only. Bytes 13..16 are the address.
  return (
    left[0] === 4 &&
    right[0] === 4 &&
    left[13] === right[13] &&
    left[14] === right[14] &&
    left[15] === right[15]
  )
}

function recordsDiverse(records) {
  for (let left = 0; left < records.length; left++) {
    for (let right = left + 1; right < records.length; right++) {
      if (
        equal(records[left].identity, records[right].identity) ||
        endpointSubnetEqual(records[left].endpoint, records[right].endpoint)
      ) {
        return false
      }
    }
  }
  return true
}

function ownScope(value, now) {
  exactObject(value, SCOPE_FIELDS)
  let guardIdentity = null
  let guardEndpoint = null
  let guardAdvertisementDigest = null
  let canonicalGuardEndpoint = null
  try {
    guardIdentity = copy(ownData(value, 'guardIdentity'), 32)
    guardEndpoint = copy(ownData(value, 'guardEndpoint'), 19)
    canonicalGuardEndpoint = decodeCanonicalEndpoint(guardEndpoint)
    guardAdvertisementDigest = copy(ownData(value, 'guardAdvertisementDigest'), 32)
    const guardEpoch = ownData(value, 'guardEpoch')
    const guardExpiresAt = ownData(value, 'guardExpiresAt')
    generation(guardEpoch)
    if (typeof guardExpiresAt !== 'bigint' || guardExpiresAt <= now || guardExpiresAt > MAX_U64) {
      incompatible()
    }
    const scope = {
      guardIdentity,
      guardEndpoint,
      guardAdvertisementDigest,
      guardEpoch,
      guardExpiresAt
    }
    guardIdentity = null
    guardEndpoint = null
    guardAdvertisementDigest = null
    return scope
  } finally {
    clear(guardIdentity)
    clear(guardEndpoint)
    clear(guardAdvertisementDigest)
    clear(canonicalGuardEndpoint)
  }
}

function verifyAndOwnRecord(value, now) {
  recordObject(value)
  let canonicalBytes = null
  let digest = null
  let identity = null
  let endpoint = null
  let computedDigest = null
  let decoded = null
  try {
    canonicalBytes = copy(ownData(value, 'canonicalBytes'))
    if (
      bufferLength(canonicalBytes) < CAPABILITY_ADVERTISEMENT_MIN_BYTES ||
      bufferLength(canonicalBytes) > CAPABILITY_ADVERTISEMENT_MAX_BYTES
    ) {
      incompatible()
    }
    digest = copy(ownData(value, 'digest'), 32)
    identity = copy(ownData(value, 'identity'), 32)
    endpoint = copy(ownData(value, 'canonicalEndpointBytes'), 19)
    const routePublicKey = ownData(value, 'routePublicKey')
    if (bufferLength(routePublicKey) !== 32) incompatible()
    const role = ownData(value, 'role')
    const capabilityMask = ownData(value, 'capabilityMask')
    const epoch = ownData(value, 'epoch')
    const issuedAt = ownData(value, 'issuedAt')
    const expiresAt = ownData(value, 'expiresAt')
    decoded = decodeRelayCapabilityAdvertisement(canonicalBytes, { now })
    computedDigest = digestRelayCapabilityAdvertisement(canonicalBytes, { now })
    if (
      !equal(digest, computedDigest) ||
      !equal(identity, decoded.relayIdentity) ||
      !equal(endpoint, decoded.reachableEndpoint) ||
      !equal(routePublicKey, decoded.routeEncryptionPublicKey) ||
      role !== roleForIdentity(decoded.relayIdentity) ||
      role !== ownData(value, 'role') ||
      capabilityMask !== decoded.capabilityMask ||
      epoch !== decoded.epoch ||
      issuedAt !== decoded.issuedAtMs ||
      expiresAt !== decoded.expiresAtMs ||
      epoch === 0n ||
      expiresAt <= now
    ) {
      incompatible()
    }
    const record = {
      canonicalBytes,
      digest,
      identity,
      endpoint,
      role,
      capabilityMask,
      epoch,
      issuedAt,
      expiresAt
    }
    canonicalBytes = null
    digest = null
    identity = null
    endpoint = null
    return record
  } finally {
    clear(canonicalBytes)
    clear(digest)
    clear(identity)
    clear(endpoint)
    clear(computedDigest)
    clearDecoded(decoded)
  }
}

function preflightRecords(values) {
  if (!Array.isArray(values)) incompatible()
  const length = ownData(values, 'length')
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_TRANSFER_RECORDS) incompatible()
  const records = new Array(length)
  let totalBytes = 0
  for (let i = 0; i < length; i++) {
    const value = ownData(values, String(i))
    recordObject(value)
    const size = bufferLength(ownData(value, 'canonicalBytes'))
    if (size < CAPABILITY_ADVERTISEMENT_MIN_BYTES || size > CAPABILITY_ADVERTISEMENT_MAX_BYTES) {
      incompatible()
    }
    totalBytes += size
    if (totalBytes > MAX_TRANSFER_BYTES) incompatible()
    records[i] = value
  }
  return records
}

function ownRecords(values, now) {
  const transferRecords = preflightRecords(values)
  const byIdentity = new Map()
  const quarantine = new Map()
  const seenIdentities = new Set()
  try {
    for (const value of transferRecords) {
      const record = verifyAndOwnRecord(value, now)
      const key = b4aToString(record.identity, 'hex')
      if (!seenIdentities.has(key)) {
        if (seenIdentities.size === MAX_IDENTITIES) {
          clearRecord(record)
          incompatible()
        }
        seenIdentities.add(key)
      }
      if (quarantine.has(key)) {
        clearRecord(record)
        continue
      }
      const current = byIdentity.get(key)
      if (!current) {
        byIdentity.set(key, record)
        continue
      }
      if (record.epoch < current.epoch) {
        clearRecord(record)
        continue
      }
      if (record.epoch === current.epoch) {
        if (!equal(record.digest, current.digest)) {
          const quarantinedUntil =
            record.expiresAt > current.expiresAt ? record.expiresAt : current.expiresAt
          clearRecord(record)
          clearRecord(current)
          byIdentity.delete(key)
          quarantine.set(key, quarantinedUntil)
          continue
        }
        clearRecord(record)
        continue
      }
      clearRecord(current)
      byIdentity.set(key, record)
    }
    const records = [...byIdentity.values()]
    byIdentity.clear()
    return { records, quarantine }
  } finally {
    for (const record of byIdentity.values()) clearRecord(record)
    byIdentity.clear()
    seenIdentities.clear()
  }
}

function revalidateRecord(record, now) {
  let decoded = null
  let digest = null
  try {
    decoded = decodeRelayCapabilityAdvertisement(record.canonicalBytes, { now })
    digest = digestRelayCapabilityAdvertisement(record.canonicalBytes, { now })
    return (
      equal(digest, record.digest) &&
      equal(decoded.relayIdentity, record.identity) &&
      equal(decoded.reachableEndpoint, record.endpoint) &&
      decoded.epoch === record.epoch &&
      decoded.issuedAtMs === record.issuedAt &&
      decoded.expiresAtMs === record.expiresAt &&
      decoded.capabilityMask === record.capabilityMask &&
      roleForIdentity(decoded.relayIdentity) === record.role &&
      record.expiresAt > now
    )
  } catch {
    return false
  } finally {
    clear(digest)
    clearDecoded(decoded)
  }
}

function clearEvidence(evidence) {
  if (!evidence) return
  clear(evidence.canonicalAdvertisement)
  clear(evidence.advertisementDigest)
}

function releaseTransaction(transaction, committed) {
  if (!transaction || transaction.done) return
  transaction.done = true
  const state = transaction.directory
  for (const evidence of transaction.evidence) clearEvidence(evidence)
  transaction.evidence.clear()
  for (const selection of transaction.selections) {
    const selected = selectionStates.get(selection)
    if (selected) selected.done = true
  }
  transaction.selections.clear()
  if (state) {
    for (const claim of transaction.claims) {
      if (state.pending.get(claim.branchClass) === transaction) {
        state.pending.delete(claim.branchClass)
      }
      if (committed) state.highestCommitted.set(claim.branchClass, claim.generation)
    }
    state.transactions.delete(transaction)
  }
}

function invalidate(state) {
  if (!state || state.invalidated) return
  CLOCK_ROLLBACK_SINKS.delete(state)
  state.invalidated = true
  for (const transaction of [...state.transactions]) releaseTransaction(transaction, false)
  for (const record of state.records) clearRecord(record)
  state.records.length = 0
  clearScope(state.scope)
  state.scope = null
  state.committed.clear()
  state.pending.clear()
  state.highestCommitted.clear()
  state.quarantine.clear()
  state.faulted.clear()
  state.wallNow = null
  state.monotonicNow = null
  state.lastWall = null
  state.lastMonotonic = null
  state.suspended = false
}

function ensureDirectory(directory, allowSuspended = false) {
  const state = directoryStates.get(directory)
  if (!state || state.destroyed) destroyed()
  if (state.invalidated) incompatible()
  if (state.suspended && !allowSuspended) incompatible()
  return state
}

function requireDirectoryState(directory, state, suspended) {
  if (
    directoryStates.get(directory) !== state ||
    !clockOwnerIsLive(state) ||
    state.suspended !== suspended
  ) {
    incompatible()
  }
}

function sampleDirectoryWall(directory, state, suspended) {
  const now = sampleWall(state)
  requireDirectoryState(directory, state, suspended)
  return now
}

function sampleDirectoryMonotonic(directory, state, suspended) {
  const now = sampleMonotonic(state)
  requireDirectoryState(directory, state, suspended)
  return now
}
function readRelayCandidateDirectoryScope(directory) {
  const state = ensureDirectory(directory)
  return objectFreeze({
    guardIdentity: copy(state.scope.guardIdentity, 32),
    guardEndpoint: copy(state.scope.guardEndpoint, 19),
    guardAdvertisementDigest: copy(state.scope.guardAdvertisementDigest, 32),
    guardEpoch: state.scope.guardEpoch,
    guardExpiresAt: state.scope.guardExpiresAt
  })
}

function sampleDirectoryHandoff(directory, state, suspended) {
  sampleDirectoryWall(directory, state, suspended)
  sampleDirectoryMonotonic(directory, state, suspended)
  return sampleDirectoryWall(directory, state, suspended)
}

// Fault demotion is a PARTITION, not a position in this list. A caller must
// exhaust `preferred` before admitting anything from `all`: that ordering
// between the two tiers, not record order within one, is what stops a
// just-failed hop being handed to the sibling branch. A future KI-6 fix that
// randomises selection keeps the property so long as it draws within a tier;
// one that draws from `all` directly silently discards it. See KI-14.
function validCandidates(state, role, mask) {
  const preferred = []
  const all = []
  for (const record of state.records) {
    if (record.role !== role || record.capabilityMask !== mask) continue
    if (
      equal(record.identity, state.scope.guardIdentity) ||
      endpointSubnetEqual(record.endpoint, state.scope.guardEndpoint)
    ) {
      continue
    }
    all.push(record)
    if (!state.faulted.has(b4aToString(record.identity, 'hex'))) preferred.push(record)
  }
  return { preferred, all }
}

// With nothing demoted the second tier searches the same records as the first,
// so the fallback is skipped rather than doubling the worst case on the path
// every healthy selection takes.
function demotionApplies(middles, exits) {
  return (
    middles.preferred.length !== middles.all.length || exits.preferred.length !== exits.all.length
  )
}

function pruneInvalidRecords(state, now) {
  const retained = []
  for (const record of state.records) {
    if (revalidateRecord(record, now)) retained.push(record)
    else clearRecord(record)
  }
  state.records = retained
  for (const [identity, expiresAt] of state.quarantine) {
    if (expiresAt <= now) state.quarantine.delete(identity)
  }
  // Every caller of `validCandidates` prunes first, which is what lets the
  // demotion test there be a bare `has` with no clock of its own.
  for (const [identity, expiresAt] of state.faulted) {
    if (expiresAt <= now) state.faulted.delete(identity)
  }
}

function requireLiveGuard(state, now) {
  if (state.scope.guardExpiresAt > now) return
  invalidate(state)
  incompatible()
}

function searchPairs(middles, exits, excluded) {
  for (const firstMiddle of middles) {
    for (const firstExit of exits) {
      for (const secondMiddle of middles) {
        for (const secondExit of exits) {
          const selected = [firstMiddle, firstExit, secondMiddle, secondExit]
          if (!recordsDiverse([...excluded, ...selected])) continue
          return [
            { middle: firstMiddle, exit: firstExit },
            { middle: secondMiddle, exit: secondExit }
          ]
        }
      }
    }
  }
  return null
}

function choosePairs(state, now, excluded = []) {
  requireLiveGuard(state, now)
  pruneInvalidRecords(state, now)
  const middles = validCandidates(state, ROLE.SAFETY, RELAY_CAPABILITY.CIRCUIT_RELAY_V1)
  const exits = validCandidates(
    state,
    ROLE.PRIVATE,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
  // DELIBERATELY UNTIERED, unlike `chooseReplacementPair`. This builds BOTH pairs
  // at once: the initial route, and the bootstrap pair after a reconnect. KI-14's
  // defect is a ROTATION handing the sibling branch the hop it just rotated away
  // from, and a two-pair build from scratch has no sibling to protect - there is
  // no live branch for a demoted hop to gain a second view of.
  //
  // Applying the tier here also breaks the eleven-role gate, and the cause is NOT
  // this fix. Measured on pristine HEAD with no demotion anywhere, reversing the
  // candidate order alone deadlocks that scenario at its first routed get, so the
  // fixture cannot tolerate ANY change to which pair first-match returns. Tiering
  // here does not fail closed - it succeeds and returns a different, equally valid
  // pair, which the fixture then cannot service. See KI-14 and KI-6.
  //
  // The demotion is NOT forgotten across a reconnect: it survives in `state.faulted`
  // and still binds every subsequent rotation. Only this two-pair build ignores it.
  const chosen = searchPairs(middles.all, exits.all, excluded)
  if (chosen === null) incompatible()
  return chosen
}

function searchPair(middles, exits, excluded) {
  for (const middle of middles) {
    for (const exit of exits) {
      if (recordsDiverse([...excluded, middle, exit])) return { middle, exit }
    }
  }
  return null
}

function chooseReplacementPair(state, now, excluded) {
  requireLiveGuard(state, now)
  pruneInvalidRecords(state, now)
  const middles = validCandidates(state, ROLE.SAFETY, RELAY_CAPABILITY.CIRCUIT_RELAY_V1)
  const exits = validCandidates(
    state,
    ROLE.PRIVATE,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
  let chosen = searchPair(middles.preferred, exits.preferred, excluded)
  if (chosen === null && demotionApplies(middles, exits)) {
    chosen = searchPair(middles.all, exits.all, excluded)
  }
  if (chosen === null) incompatible()
  return chosen
}

function revalidateSelection(state, now, selected) {
  requireLiveGuard(state, now)
  pruneInvalidRecords(state, now)
  for (const record of selected) {
    if (!state.records.includes(record)) incompatible()
  }
}

function makeReservation(state, kind, branches, claims) {
  const transaction = {
    directory: state,
    kind,
    branches,
    claims,
    taken: false,
    split: false,
    done: false,
    selections: new Set(),
    evidence: new Set()
  }
  const capability = objectFreeze({})
  reservationStates.set(capability, transaction)
  for (const claim of claims) state.pending.set(claim.branchClass, transaction)
  state.transactions.add(transaction)
  return capability
}

function claimAllowed(state, branchClass, value) {
  const highest = state.highestCommitted.get(branchClass) || 0n
  if (value <= highest || state.pending.has(branchClass)) replay()
}

function transactionIsLive(transaction, directory) {
  if (
    !transaction ||
    transaction.done ||
    transaction.directory !== directory ||
    !directory ||
    directory.destroyed ||
    directory.invalidated ||
    directory.suspended ||
    directory.scope === null
  ) {
    return false
  }
  for (const claim of transaction.claims) {
    if (directory.pending.get(claim.branchClass) !== transaction) return false
  }
  return true
}

function createSelection(transaction, branchClass, selectedPosition, selectedRecord, value) {
  const capability = objectFreeze({})
  selectionStates.set(capability, {
    transaction,
    branchClass,
    position: selectedPosition,
    generation: value,
    record: selectedRecord,
    done: false
  })
  transaction.selections.add(capability)
  return capability
}

class RelayCandidateDirectory {
  constructor(key, installed) {
    if (key !== kConstruct || installed === null || typeof installed !== 'object') incompatible()
    directoryStates.set(this, installed)
    objectFreeze(this)
  }

  reserveInitialPair(options) {
    const state = ensureDirectory(this)
    exactObject(options, INITIAL_FIELDS)
    const lookupGeneration = generation(ownData(options, 'lookupGeneration'))
    const announceGeneration = generation(ownData(options, 'announceGeneration'))
    if (state.committed.size !== 0) replay()
    claimAllowed(state, BRANCH_CLASS.LOOKUP, lookupGeneration)
    claimAllowed(state, BRANCH_CLASS.ANNOUNCE, announceGeneration)
    let now = sampleDirectoryHandoff(this, state, false)
    const pairs = choosePairs(state, now)
    now = sampleDirectoryWall(this, state, false)
    revalidateSelection(state, now, [
      pairs[0].middle,
      pairs[0].exit,
      pairs[1].middle,
      pairs[1].exit
    ])
    requireDirectoryState(this, state, false)
    return makeReservation(
      state,
      'initial',
      new Map([
        [BRANCH_CLASS.LOOKUP, pairs[0]],
        [BRANCH_CLASS.ANNOUNCE, pairs[1]]
      ]),
      [
        { branchClass: BRANCH_CLASS.LOOKUP, generation: lookupGeneration },
        { branchClass: BRANCH_CLASS.ANNOUNCE, generation: announceGeneration }
      ]
    )
  }

  reserveReplacement(options) {
    const state = ensureDirectory(this)
    exactObject(options, REPLACEMENT_FIELDS)
    const branchClass = branch(ownData(options, 'branchClass'))
    const value = generation(ownData(options, 'generation'))
    claimAllowed(state, branchClass, value)
    const opposite =
      branchClass === BRANCH_CLASS.LOOKUP ? BRANCH_CLASS.ANNOUNCE : BRANCH_CLASS.LOOKUP
    let oppositePair = state.committed.get(opposite)
    let currentPair = state.committed.get(branchClass)
    if (!oppositePair || !currentPair) incompatible()
    let now = sampleDirectoryHandoff(this, state, false)
    oppositePair = state.committed.get(opposite)
    currentPair = state.committed.get(branchClass)
    if (!oppositePair || !currentPair) incompatible()
    revalidateSelection(state, now, [oppositePair.middle, oppositePair.exit])
    const excluded = [oppositePair.middle, oppositePair.exit]
    if (state.records.includes(currentPair.middle)) excluded.push(currentPair.middle)
    if (state.records.includes(currentPair.exit)) excluded.push(currentPair.exit)
    const selected = chooseReplacementPair(state, now, excluded)
    now = sampleDirectoryWall(this, state, false)
    revalidateSelection(state, now, [
      oppositePair.middle,
      oppositePair.exit,
      selected.middle,
      selected.exit
    ])
    requireDirectoryState(this, state, false)
    return makeReservation(state, 'replacement', new Map([[branchClass, selected]]), [
      { branchClass, generation: value }
    ])
  }

  // A rotation fires for two unrelated reasons. Material expiry is routine and
  // says nothing about the hop; a loss says the branch failed while this pair
  // was carrying it. Only the second reaches here, from
  // `reportRouteManagerBranchLoss`, which is the manager's sole fault path -
  // expiry reaches the controller through `armBranchExpiry`'s separate
  // `BranchExpiry` sink and never calls this.
  //
  // Attribution is to the BRANCH, not to a hop: nothing in a physical loss or an
  // elapsed deadline says whether the middle or the exit failed, so both hops of
  // the failed branch are demoted. Both were about to be vacated anyway.
  //
  // Deliberately NOT `quarantine`, and the two must not be conflated.
  // Quarantine answers a question about identity: one key advertising two
  // digests at one epoch is proof of equivocation, so a hard bar there has no
  // false positives. A fault is a heuristic - a timeout or a physical loss can
  // be the network, the local host, or an unlucky but honest relay - so it earns
  // a demotion, not a bar. Barring on suspicion would let a transient failure
  // inherit a penalty designed for proven dishonesty, and because the exclusion
  // set already leaves exactly one qualifying pair in the smallest supported
  // pool, it would also let any relay deny the endpoint a route by failing.
  //
  // The bound is the LATER of the record's own `expiresAt` and now plus
  // `FAULT_DEMOTION_MS`. The floor is the point: `expiresAt` is a number the
  // faulted relay signed for itself and nothing requires it to be far away, so
  // without a floor a relay can advertise a two-second capability, blackhole a
  // branch, serve a two-second penalty and re-advertise - while the hop it
  // dragged down with it, whose expiry it does not control, serves up to the
  // full 30-minute ceiling. A fault demotes BOTH hops of the pair, so that
  // asymmetry is an attack rather than an oddity: repeated across partners it
  // drains honest hops out of `preferred` while the attacker cycles back in. For
  // a heuristic penalty the duration IS the entire penalty, so a self-chosen
  // duration is no penalty at all.
  //
  // This deliberately gives up the property that a demotion cannot outlive the
  // record it applies to. That property was worth less than it cost: shedding a
  // penalty by advertising a short-lived capability and re-advertising is
  // precisely the move the floor exists to stop, so the demotion has to be able
  // to outlive the advertisement it was earned on. What is kept is that
  // `pruneInvalidRecords` still sweeps the entry on `expiresAt <= now` so it
  // never becomes a bar, and that the map stays bounded by `MAX_IDENTITIES`:
  // only an identity already in `state.records` is ever inserted, and that set
  // only shrinks. `now` here is the same wall sample the sweep compares against.
  reportBranchFault(options) {
    const state = ensureDirectory(this)
    exactObject(options, FAULT_FIELDS)
    const branchClass = branch(ownData(options, 'branchClass'))
    const pair = state.committed.get(branchClass)
    if (!pair) return false
    const now = sampleDirectoryHandoff(this, state, false)
    pruneInvalidRecords(state, now)
    requireDirectoryState(this, state, false)
    const floor = now + FAULT_DEMOTION_MS
    let demoted = false
    for (const record of [pair.middle, pair.exit]) {
      if (!state.records.includes(record)) continue
      const key = b4aToString(record.identity, 'hex')
      const expiresAt = record.expiresAt > floor ? record.expiresAt : floor
      const current = state.faulted.get(key)
      if (current === undefined || current < expiresAt) state.faulted.set(key, expiresAt)
      demoted = true
    }
    return demoted
  }

  retainForSuspend() {
    if (arguments.length !== 0) incompatible()
    const state = ensureDirectory(this)
    sampleDirectoryHandoff(this, state, false)
    requireDirectoryState(this, state, false)
    for (const transaction of [...state.transactions]) releaseTransaction(transaction, false)
    state.committed.clear()
    state.suspended = true
  }

  resume() {
    if (arguments.length !== 0) incompatible()
    const state = ensureDirectory(this, true)
    if (!state.suspended) replay()
    let now = sampleDirectoryHandoff(this, state, true)
    const pairs = choosePairs(state, now)
    now = sampleDirectoryWall(this, state, true)
    revalidateSelection(state, now, [
      pairs[0].middle,
      pairs[0].exit,
      pairs[1].middle,
      pairs[1].exit
    ])
    requireDirectoryState(this, state, true)
    state.suspended = false
  }

  destroy() {
    if (arguments.length !== 0) incompatible()
    const state = directoryStates.get(this)
    if (!state || state.destroyed) return
    state.destroyed = true
    invalidate(state)
  }

  [kInspectRelayCandidateDirectory]() {
    const state = directoryStates.get(this)
    if (!state) incompatible()
    let bytes = 0
    let digests = 0
    for (const record of state.records) {
      bytes += bufferLength(record.canonicalBytes) > 0 ? 1 : 0
      digests += bufferLength(record.digest) > 0 ? 1 : 0
    }
    return objectFreeze({
      destroyed: state.destroyed,
      identityCount: state.records.length,
      byteBufferCount: bytes,
      digestCount: digests,
      timerCount: 0,
      callbackCount:
        Number(typeof state.wallNow === 'function') +
        Number(typeof state.monotonicNow === 'function'),
      generationRecordCount: state.highestCommitted.size,
      quarantineCount: state.quarantine.size,
      faultedCount: state.faulted.size,
      pendingCount: state.pending.size
    })
  }
}

function createRelayCandidateDirectorySink(options) {
  exactObject(options, CLOCK_FIELDS)
  const wallNow = ownData(options, 'wallNow')
  const monotonicNow = ownData(options, 'monotonicNow')
  if (typeof wallNow !== 'function' || typeof monotonicNow !== 'function') incompatible()
  const sink = objectFreeze({})
  sinkStates.set(sink, {
    kind: 'sink',
    wallNow,
    monotonicNow,
    lastWall: null,
    lastMonotonic: null,
    sampling: false,
    active: false,
    consumed: false,
    invalidated: false,
    poisoned: false
  })
  return sink
}

function sealRelayCandidateDirectorySink(sink, records, scope) {
  const state = sinkStates.get(sink)
  if (!state) replay()
  if (state.active) {
    poisonSinkState(state)
    replay()
  }
  if (state.consumed || state.invalidated || state.poisoned) replay()
  state.active = true
  let ownedRecords = null
  let ownedQuarantine = null
  let ownedScope = null
  let sealed = null
  try {
    sampleWall(state)
    if (!sinkIsActive(state)) replay()
    sampleMonotonic(state)
    if (!sinkIsActive(state)) replay()
    const now = sampleWall(state)
    if (!sinkIsActive(state)) replay()
    const owned = ownRecords(records, now)
    ownedRecords = owned.records
    ownedQuarantine = owned.quarantine
    if (!sinkIsActive(state)) replay()
    ownedScope = ownScope(scope, now)
    if (!sinkIsActive(state)) replay()
    const token = objectFreeze({})
    sealed = {
      kind: 'sealed',
      wallNow: state.wallNow,
      monotonicNow: state.monotonicNow,
      lastWall: state.lastWall,
      lastMonotonic: state.lastMonotonic,
      sampling: false,
      active: false,
      records: ownedRecords,
      quarantine: ownedQuarantine,
      scope: ownedScope,
      consumed: false,
      invalidated: false,
      poisoned: false
    }
    if (!sinkIsActive(state)) replay()
    sealedStates.set(token, sealed)
    ownedRecords = null
    ownedQuarantine = null
    ownedScope = null
    sealed = null
    state.active = false
    state.consumed = true
    state.wallNow = null
    state.monotonicNow = null
    return token
  } catch {
    poisonSinkState(state)
    if (ownedRecords) for (const record of ownedRecords) clearRecord(record)
    if (ownedQuarantine) ownedQuarantine.clear()
    clearScope(ownedScope)
    clearSealedState(sealed)
    replay()
  }
}

function clearSealedState(sealed) {
  if (!sealed || sealed.invalidated) return
  sealed.active = false
  sealed.consumed = true
  sealed.invalidated = true
  sealed.poisoned = true
  if (sealed.records) for (const record of sealed.records) clearRecord(record)
  if (sealed.quarantine) sealed.quarantine.clear()
  clearScope(sealed.scope)
  sealed.records = null
  sealed.quarantine = null
  sealed.scope = null
  sealed.wallNow = null
  sealed.monotonicNow = null
  sealed.lastWall = null
  sealed.lastMonotonic = null
}

function revokeRelayCandidateDirectorySink(sink) {
  const state = sinkStates.get(sink)
  if (!state) replay()
  if (state.active) {
    poisonSinkState(state)
    replay()
  }
  if (state.consumed || state.invalidated || state.poisoned) replay()
  poisonSinkState(state)
}

function consumeSealedRelayCandidateDirectory(token) {
  const sealed = sealedStates.get(token)
  if (!sealed) replay()
  if (sealed.active) {
    clearSealedState(sealed)
    replay()
  }
  if (sealed.consumed || sealed.invalidated || sealed.poisoned) replay()
  sealed.active = true
  try {
    sampleWall(sealed)
    if (!sealedIsActive(sealed)) replay()
    sampleMonotonic(sealed)
    if (!sealedIsActive(sealed)) replay()
    const now = sampleWall(sealed)
    if (!sealedIsActive(sealed) || sealed.scope.guardExpiresAt <= now) replay()
    for (const record of sealed.records) {
      if (!revalidateRecord(record, now)) replay()
      if (!sealedIsActive(sealed)) replay()
    }
    for (const [identity, expiresAt] of sealed.quarantine) {
      if (expiresAt <= now) sealed.quarantine.delete(identity)
    }
    const state = {
      kind: 'directory',
      wallNow: sealed.wallNow,
      monotonicNow: sealed.monotonicNow,
      lastWall: sealed.lastWall,
      lastMonotonic: sealed.lastMonotonic,
      sampling: false,
      records: sealed.records,
      quarantine: sealed.quarantine,
      faulted: new Map(),
      scope: sealed.scope,
      committed: new Map(),
      pending: new Map(),
      highestCommitted: new Map(),
      transactions: new Set(),
      suspended: false,
      invalidated: false,
      destroyed: false
    }
    if (!sealedIsActive(sealed)) replay()
    const directory = new RelayCandidateDirectory(kConstruct, state)
    if (!sealedIsActive(sealed)) {
      directory.destroy()
      replay()
    }
    sealed.active = false
    sealed.consumed = true
    sealed.records = null
    sealed.quarantine = null
    sealed.scope = null
    sealed.wallNow = null
    sealed.monotonicNow = null
    return directory
  } catch {
    clearSealedState(sealed)
    replay()
  }
}

function destroySealedRelayCandidateDirectory(token) {
  const sealed = sealedStates.get(token)
  if (!sealed) replay()
  if (sealed.active) {
    clearSealedState(sealed)
    replay()
  }
  if (sealed.consumed || sealed.invalidated || sealed.poisoned) replay()
  clearSealedState(sealed)
}

function takeRelayPathReservation(reservation) {
  const state = reservationStates.get(reservation)
  if (!state || state.taken || state.done) replay()
  const transaction = objectFreeze({})
  transactionStates.set(transaction, state)
  state.taken = true
  return transaction
}

function splitRelayPathReservation(transaction) {
  const state = transactionStates.get(transaction)
  if (!state || state.done || state.split) replay()
  state.split = true
  try {
    if (state.kind === 'initial') {
      const lookupClaim = state.claims[0]
      const announceClaim = state.claims[1]
      const lookup = state.branches.get(BRANCH_CLASS.LOOKUP)
      const announce = state.branches.get(BRANCH_CLASS.ANNOUNCE)
      return objectFreeze({
        lookup: objectFreeze({
          middle: createSelection(
            state,
            BRANCH_CLASS.LOOKUP,
            'middle',
            lookup.middle,
            lookupClaim.generation
          ),
          exit: createSelection(
            state,
            BRANCH_CLASS.LOOKUP,
            'exit',
            lookup.exit,
            lookupClaim.generation
          )
        }),
        announce: objectFreeze({
          middle: createSelection(
            state,
            BRANCH_CLASS.ANNOUNCE,
            'middle',
            announce.middle,
            announceClaim.generation
          ),
          exit: createSelection(
            state,
            BRANCH_CLASS.ANNOUNCE,
            'exit',
            announce.exit,
            announceClaim.generation
          )
        })
      })
    }
    const claim = state.claims[0]
    const selected = state.branches.get(claim.branchClass)
    return objectFreeze({
      branchClass: claim.branchClass,
      middle: createSelection(
        state,
        claim.branchClass,
        'middle',
        selected.middle,
        claim.generation
      ),
      exit: createSelection(state, claim.branchClass, 'exit', selected.exit, claim.generation)
    })
  } catch (err) {
    releaseTransaction(state, false)
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function duplicateSelectedRelaySelection(selection) {
  const selected = selectionStates.get(selection)
  if (
    !selected ||
    selected.done ||
    !transactionIsLive(selected.transaction, selected.transaction.directory)
  ) {
    replay()
  }
  return createSelection(
    selected.transaction,
    selected.branchClass,
    selected.position,
    selected.record,
    selected.generation
  )
}

function revokeSelectedRelaySelection(selection) {
  const selected = selectionStates.get(selection)
  if (!selected || selected.done) return false
  selected.done = true
  return true
}

function consumeSelectedRelayEvidence(selection, options) {
  const selected = selectionStates.get(selection)
  if (!selected || selected.done) replay()
  exactObject(options, EVIDENCE_FIELDS)
  const transaction = ownData(options, 'transaction')
  const transactionState = transactionStates.get(transaction)
  if (
    transactionState !== selected.transaction ||
    ownData(options, 'branchClass') !== selected.branchClass ||
    ownData(options, 'position') !== selected.position ||
    ownData(options, 'generation') !== selected.generation
  ) {
    replay()
  }
  const directory = selected.transaction.directory
  if (!transactionIsLive(selected.transaction, directory)) replay()
  const now = sampleWall(directory)
  if (
    !transactionIsLive(selected.transaction, directory) ||
    selected.done ||
    selectionStates.get(selection) !== selected
  ) {
    replay()
  }
  requireLiveGuard(directory, now)
  pruneInvalidRecords(directory, now)
  if (
    !transactionIsLive(selected.transaction, directory) ||
    selected.done ||
    !directory.records.includes(selected.record)
  ) {
    releaseTransaction(selected.transaction, false)
    incompatible()
  }
  selected.done = true
  let canonicalAdvertisement = null
  let advertisementDigest = null
  let evidence = null
  try {
    canonicalAdvertisement = copy(selected.record.canonicalBytes)
    advertisementDigest = copy(selected.record.digest, 32)
    evidence = objectFreeze({
      canonicalAdvertisement,
      advertisementDigest,
      role: selected.record.role,
      branchClass: selected.branchClass,
      position: selected.position,
      generation: selected.generation
    })
    selected.transaction.evidence.add(evidence)
    canonicalAdvertisement = null
    advertisementDigest = null
    const result = evidence
    evidence = null
    return result
  } catch (err) {
    clear(canonicalAdvertisement)
    clear(advertisementDigest)
    clearEvidence(evidence)
    releaseTransaction(selected.transaction, false)
    if (err instanceof PrivateRouteError) throw err
    incompatible()
  }
}

function commitRelayPathReservation(transaction) {
  const state = transactionStates.get(transaction)
  if (!state || state.done || !state.split) replay()
  if (state.selections.size === 0) replay()
  for (const selection of state.selections) {
    const selected = selectionStates.get(selection)
    if (!selected || !selected.done) replay()
  }
  const directory = state.directory
  if (!transactionIsLive(state, directory)) replay()
  const now = sampleWall(directory)
  if (!transactionIsLive(state, directory)) replay()
  requireLiveGuard(directory, now)
  pruneInvalidRecords(directory, now)
  if (!transactionIsLive(state, directory)) replay()
  for (const pair of state.branches.values()) {
    if (!directory.records.includes(pair.middle) || !directory.records.includes(pair.exit)) {
      releaseTransaction(state, false)
      incompatible()
    }
  }
  if (state.kind === 'replacement') {
    const claim = state.claims[0]
    const opposite =
      claim.branchClass === BRANCH_CLASS.LOOKUP ? BRANCH_CLASS.ANNOUNCE : BRANCH_CLASS.LOOKUP
    const oppositePair = directory.committed.get(opposite)
    const selectedPair = state.branches.get(claim.branchClass)
    if (
      !oppositePair ||
      !directory.records.includes(oppositePair.middle) ||
      !directory.records.includes(oppositePair.exit) ||
      !recordsDiverse([
        oppositePair.middle,
        oppositePair.exit,
        selectedPair.middle,
        selectedPair.exit
      ])
    ) {
      releaseTransaction(state, false)
      incompatible()
    }
  } else if (directory.committed.size !== 0) {
    releaseTransaction(state, false)
    incompatible()
  }
  if (!transactionIsLive(state, directory)) replay()
  for (const [branchClass, pair] of state.branches) directory.committed.set(branchClass, pair)
  releaseTransaction(state, true)
}

function abortRelayPathReservation(transaction) {
  const state = transactionStates.get(transaction)
  if (!state || state.done) replay()
  releaseTransaction(state, false)
}
function emptyFrozenCapability(value) {
  try {
    return (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.isFrozen(value) &&
      Reflect.ownKeys(value).length === 0
    )
  } catch {
    return false
  }
}

function registerRelayCandidateDirectoryRollbackSink(directory, sink) {
  const state = ensureDirectory(directory)
  if (!emptyFrozenCapability(sink)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  CLOCK_ROLLBACK_SINKS.set(state, sink)
  return true
}

module.exports = {
  MAX_RELAY_CANDIDATE_IDENTITIES: MAX_IDENTITIES,
  RelayCandidateDirectory,
  abortRelayPathReservation,
  commitRelayPathReservation,
  consumeSealedRelayCandidateDirectory,
  consumeSelectedRelayEvidence,
  createRelayCandidateDirectorySink,
  destroySealedRelayCandidateDirectory,
  kInspectRelayCandidateDirectory,
  revokeRelayCandidateDirectorySink,
  readRelayCandidateDirectoryScope,
  duplicateSelectedRelaySelection,
  revokeSelectedRelaySelection,
  registerRelayCandidateDirectoryRollbackSink,
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
}
