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
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_WALL_ROLLBACK = 30_000n

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
  if (typeof value !== 'bigint' || value < 0n) {
    invalidateClockOwner(state)
    incompatible()
  }
  return value
}

function invalidateClockOwner(state) {
  if (state.kind === 'sink') {
    state.invalidated = true
    state.wallNow = null
    state.monotonicNow = null
    state.lastWall = null
    state.lastMonotonic = null
    return
  }
  invalidate(state)
}

function sampleWall(state) {
  const now = sampleFunction(state, 'wallNow')
  if (state.lastWall !== null && now + MAX_WALL_ROLLBACK < state.lastWall) {
    invalidateClockOwner(state)
    incompatible()
  }
  if (state.lastWall === null || now > state.lastWall) state.lastWall = now
  return now
}

function sampleMonotonic(state) {
  const now = sampleFunction(state, 'monotonicNow')
  if (state.lastMonotonic !== null && now < state.lastMonotonic) {
    invalidateClockOwner(state)
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

function ownRecords(values, now) {
  if (!Array.isArray(values)) incompatible()
  const byIdentity = new Map()
  try {
    for (const value of values) {
      const record = verifyAndOwnRecord(value, now)
      const key = b4aToString(record.identity, 'hex')
      const current = byIdentity.get(key)
      if (!current) {
        if (byIdentity.size === MAX_IDENTITIES) {
          clearRecord(record)
          incompatible()
        }
        byIdentity.set(key, record)
        continue
      }
      if (record.epoch < current.epoch) {
        clearRecord(record)
        continue
      }
      if (record.epoch === current.epoch) {
        if (!equal(record.digest, current.digest)) {
          clearRecord(record)
          clearRecord(current)
          byIdentity.delete(key)
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
    return records
  } finally {
    for (const record of byIdentity.values()) clearRecord(record)
    byIdentity.clear()
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
  state.invalidated = true
  for (const transaction of [...state.transactions]) releaseTransaction(transaction, false)
  for (const record of state.records) clearRecord(record)
  state.records.length = 0
  clearScope(state.scope)
  state.scope = null
  state.committed.clear()
  state.pending.clear()
  state.highestCommitted.clear()
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

function validCandidates(state, now, role, mask) {
  const candidates = []
  for (const record of state.records) {
    if (record.role !== role || record.capabilityMask !== mask) continue
    if (
      equal(record.identity, state.scope.guardIdentity) ||
      endpointSubnetEqual(record.endpoint, state.scope.guardEndpoint)
    ) {
      continue
    }
    candidates.push(record)
  }
  return candidates
}

function pruneInvalidRecords(state, now) {
  const retained = []
  for (const record of state.records) {
    if (revalidateRecord(record, now)) retained.push(record)
    else clearRecord(record)
  }
  state.records = retained
}

function requireLiveGuard(state, now) {
  if (state.scope.guardExpiresAt > now) return
  invalidate(state)
  incompatible()
}

function choosePairs(state, now, excluded = []) {
  requireLiveGuard(state, now)
  pruneInvalidRecords(state, now)
  const middles = validCandidates(state, now, ROLE.SAFETY, RELAY_CAPABILITY.CIRCUIT_RELAY_V1)
  const exits = validCandidates(
    state,
    now,
    ROLE.PRIVATE,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
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
  incompatible()
}

function chooseReplacementPair(state, now, excluded) {
  requireLiveGuard(state, now)
  pruneInvalidRecords(state, now)
  const middles = validCandidates(state, now, ROLE.SAFETY, RELAY_CAPABILITY.CIRCUIT_RELAY_V1)
  const exits = validCandidates(
    state,
    now,
    ROLE.PRIVATE,
    RELAY_CAPABILITY.CIRCUIT_RELAY_V1 | RELAY_CAPABILITY.DHT_EXIT_V1
  )
  for (const middle of middles) {
    for (const exit of exits) {
      if (recordsDiverse([...excluded, middle, exit])) return { middle, exit }
    }
  }
  incompatible()
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
    const now = sampleWall(state)
    sampleMonotonic(state)
    const pairs = choosePairs(state, now)
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
    const oppositePair = state.committed.get(opposite)
    const currentPair = state.committed.get(branchClass)
    if (!oppositePair || !currentPair) incompatible()
    const now = sampleWall(state)
    sampleMonotonic(state)
    const selected = chooseReplacementPair(state, now, [
      oppositePair.middle,
      oppositePair.exit,
      currentPair.middle,
      currentPair.exit
    ])
    return makeReservation(state, 'replacement', new Map([[branchClass, selected]]), [
      { branchClass, generation: value }
    ])
  }

  retainForSuspend() {
    if (arguments.length !== 0) incompatible()
    const state = ensureDirectory(this)
    sampleWall(state)
    sampleMonotonic(state)
    for (const transaction of [...state.transactions]) releaseTransaction(transaction, false)
    state.committed.clear()
    state.suspended = true
  }

  resume() {
    if (arguments.length !== 0) incompatible()
    const state = ensureDirectory(this, true)
    if (!state.suspended) replay()
    const now = sampleWall(state)
    sampleMonotonic(state)
    choosePairs(state, now)
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
    consumed: false,
    invalidated: false
  })
  return sink
}

function sealRelayCandidateDirectorySink(sink, records, scope) {
  const state = sinkStates.get(sink)
  if (!state || state.consumed || state.invalidated) replay()
  state.consumed = true
  let ownedRecords = null
  let ownedScope = null
  try {
    const now = sampleWall(state)
    sampleMonotonic(state)
    ownedRecords = ownRecords(records, now)
    ownedScope = ownScope(scope, now)
    const token = objectFreeze({})
    sealedStates.set(token, {
      wallNow: state.wallNow,
      monotonicNow: state.monotonicNow,
      lastWall: state.lastWall,
      lastMonotonic: state.lastMonotonic,
      records: ownedRecords,
      scope: ownedScope,
      consumed: false
    })
    ownedRecords = null
    ownedScope = null
    state.wallNow = null
    state.monotonicNow = null
    return token
  } catch {
    state.invalidated = true
    state.wallNow = null
    state.monotonicNow = null
    if (ownedRecords) for (const record of ownedRecords) clearRecord(record)
    clearScope(ownedScope)
    replay()
  }
}

function revokeRelayCandidateDirectorySink(sink) {
  const state = sinkStates.get(sink)
  if (!state || state.consumed || state.invalidated) replay()
  state.consumed = true
  state.invalidated = true
  state.wallNow = null
  state.monotonicNow = null
}

function consumeSealedRelayCandidateDirectory(token) {
  const sealed = sealedStates.get(token)
  if (!sealed || sealed.consumed) replay()
  sealed.consumed = true
  const state = {
    kind: 'directory',
    wallNow: sealed.wallNow,
    monotonicNow: sealed.monotonicNow,
    lastWall: sealed.lastWall,
    lastMonotonic: sealed.lastMonotonic,
    sampling: false,
    records: sealed.records,
    scope: sealed.scope,
    committed: new Map(),
    pending: new Map(),
    highestCommitted: new Map(),
    transactions: new Set(),
    suspended: false,
    invalidated: false,
    destroyed: false
  }
  let directory = null
  try {
    directory = new RelayCandidateDirectory(kConstruct, state)
    sealed.records = null
    sealed.scope = null
    sealed.wallNow = null
    sealed.monotonicNow = null
    return directory
  } catch (err) {
    invalidate(state)
    sealed.records = null
    sealed.scope = null
    sealed.wallNow = null
    sealed.monotonicNow = null
    if (err instanceof PrivateRouteError) throw err
    replay()
  }
}

function destroySealedRelayCandidateDirectory(token) {
  const sealed = sealedStates.get(token)
  if (!sealed || sealed.consumed) replay()
  sealed.consumed = true
  for (const record of sealed.records) clearRecord(record)
  clearScope(sealed.scope)
  sealed.records = null
  sealed.scope = null
  sealed.wallNow = null
  sealed.monotonicNow = null
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
  if (!directory || directory.invalidated || directory.destroyed || selected.transaction.done)
    replay()
  const now = sampleWall(directory)
  requireLiveGuard(directory, now)
  pruneInvalidRecords(directory, now)
  if (!directory.records.includes(selected.record)) {
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
  if (!directory || directory.destroyed || directory.invalidated || directory.suspended) replay()
  const now = sampleWall(directory)
  requireLiveGuard(directory, now)
  pruneInvalidRecords(directory, now)
  for (const pair of state.branches.values()) {
    if (!directory.records.includes(pair.middle) || !directory.records.includes(pair.exit)) {
      releaseTransaction(state, false)
      incompatible()
    }
  }
  for (const [branchClass, pair] of state.branches) directory.committed.set(branchClass, pair)
  releaseTransaction(state, true)
}

function abortRelayPathReservation(transaction) {
  const state = transactionStates.get(transaction)
  if (!state || state.done) replay()
  releaseTransaction(state, false)
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
  sealRelayCandidateDirectorySink,
  splitRelayPathReservation,
  takeRelayPathReservation
}
