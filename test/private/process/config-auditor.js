'use strict'

const b4a = require('b4a')

let isProxy
try {
  isProxy = require('util').types.isProxy
} catch {
  isProxy = require('bare-utils').types.isProxy
}

const { cryptoSuite } = require('../../../lib/private/crypto-suite')
const { ROLES } = require('./topology-fixture')
const { encodeCanonicalBody } = require('./control-channel')

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectOwnKeys = Reflect.ownKeys
const mapEntries = Map.prototype.entries
const setValues = Set.prototype.values

class ProcessConfigAuditError extends Error {
  constructor(code = 'PROCESS_CONFIG_INVALID') {
    super(code)
    this.code = code
  }
}

function invalid() {
  throw new ProcessConfigAuditError()
}

function closed() {
  throw new ProcessConfigAuditError('PROCESS_CONFIG_CLOSED')
}

function safeProxy(value) {
  try {
    return isProxy(value)
  } catch {
    return true
  }
}

function length(value) {
  try {
    if (!b4a.isBuffer(value) || safeProxy(value)) return -1
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

function exactObject(value, fields) {
  let keys
  try {
    if (
      value === null ||
      typeof value !== 'object' ||
      safeProxy(value) ||
      objectGetPrototypeOf(value) !== Object.prototype
    )
      invalid()
    keys = reflectOwnKeys(value)
  } catch (err) {
    if (err instanceof ProcessConfigAuditError) throw err
    invalid()
  }
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

function own(value, key) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, key)
  } catch {
    invalid()
  }
  if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
  return descriptor.value
}

function contains(haystack, needle) {
  if (needle.byteLength === 0 || haystack.byteLength < needle.byteLength) return false
  outer: for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset++) {
    for (let index = 0; index < needle.byteLength; index++) {
      if (haystack[offset + index] !== needle[index]) continue outer
    }
    return true
  }
  return false
}

function viewBytes(value) {
  try {
    if (value instanceof ArrayBuffer) return new Uint8Array(value)
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer)
  } catch {
    invalid()
  }
  return null
}

function forbiddenName(name) {
  const normalized = name.toLowerCase().replace(/[_-]/g, '')
  return (
    normalized.includes('advertisement') ||
    normalized.includes('hostname') ||
    normalized === 'host' ||
    normalized.includes('rawtable') ||
    normalized.includes('routekey') ||
    normalized === 'tuple' ||
    normalized.includes('secret') ||
    normalized === 'log' ||
    normalized === 'path' ||
    normalized.includes('socket') ||
    normalized.includes('adapter') ||
    normalized.includes('factory') ||
    normalized.includes('handle') ||
    normalized === 'port' ||
    normalized === 'dns' ||
    normalized === 'tcp' ||
    normalized === 'subnet' ||
    normalized === 'route' ||
    normalized === 'address'
  )
}

function forbiddenString(value) {
  return (
    value === 'localhost' ||
    value === '0.0.0.0' ||
    value === '::' ||
    value.startsWith('/') ||
    /\/(?:[0-9]|[12][0-9]|3[01])$/.test(value) ||
    /^tcp(?::|$)/i.test(value) ||
    /^dns(?::|$)/i.test(value)
  )
}

function scanBytes(bytes, state, role) {
  if (contains(bytes, state.leakSentinel) && role !== 'endpoint') invalid()
  if (contains(bytes, state.immutableValue) && role !== 'endpoint') invalid()
  for (const forbidden of state.forbiddenBytes) {
    if (
      role === 'endpoint' &&
      (b4a.equals(forbidden, state.leakSentinel) || b4a.equals(forbidden, state.immutableValue))
    )
      continue
    if (contains(bytes, forbidden)) invalid()
  }
}

const DHT_ROLES = new Set(['dht-seed', 'dht-referral', 'dht-value'])
const DHT_ZERO_SNAPSHOT_FIELDS = Object.freeze([
  'activeExitOperations',
  'activeOperations',
  'endpointSockets',
  'openLinks',
  'isolatedGrantRequestCount',
  'ordinaryRequestCount',
  'pendingGrantRequests',
  'pendingLinks',
  'pendingPackets',
  'queuedBytes',
  'referralProbeCount',
  'tableEntryCount'
])
const DHT_NULL_SNAPSHOT_FIELDS = Object.freeze([
  'announceGeneration',
  'controllerGeneration',
  'lookupGeneration',
  'selectedExitRoleIndex',
  'selectedMiddleRoleIndex'
])

function scanOwnDataProperties(value, state, role, seen, depth) {
  const type = depth === 0 ? objectGetOwnPropertyDescriptor(value, 'type') : null
  const snapshotRoot = type && 'value' in type && type.value === 'snapshot'
  const keys = reflectOwnKeys(value)
  for (const key of keys) {
    const descriptor = objectGetOwnPropertyDescriptor(value, key)
    if (!descriptor || !('value' in descriptor)) invalid()
    scanValue(descriptor.value, state, role, seen, depth + 1)
    const allowedSnapshotName = snapshotRoot && key === 'endpointSockets'
    if (
      typeof key !== 'string' ||
      (forbiddenName(key) && !allowedSnapshotName) ||
      !descriptor.enumerable
    )
      invalid()
    if (key === 'role' && descriptor.value !== role) invalid()
  }
}

function scanValue(value, state, role, seen, depth) {
  if (depth > 64) invalid()
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'number' ||
    typeof value === 'bigint'
  )
    return
  if (typeof value === 'string') {
    if (forbiddenString(value)) invalid()
    if (value === state.endpointAddress && role !== 'endpoint' && role !== 'guard') invalid()
    return
  }
  if (typeof value !== 'object' || safeProxy(value)) invalid()
  if (seen.has(value)) invalid()
  seen.add(value)
  try {
    if (length(value) >= 0) {
      scanBytes(value, state, role)
      return
    }
    const rawView = viewBytes(value)
    if (rawView !== null) {
      scanBytes(rawView, state, role)
      invalid()
    }
    if (Array.isArray(value)) {
      const keys = reflectOwnKeys(value)
      const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length')
      if (!lengthDescriptor || !('value' in lengthDescriptor) || keys.length !== value.length + 1)
        invalid()
      for (let index = 0; index < value.length; index++) {
        const descriptor = objectGetOwnPropertyDescriptor(value, String(index))
        if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid()
        scanValue(descriptor.value, state, role, seen, depth + 1)
      }
      return
    }
    const prototype = objectGetPrototypeOf(value)
    if (prototype === Map.prototype) {
      let iterator
      try {
        iterator = mapEntries.call(value)
      } catch {
        invalid()
      }
      for (const [key, entry] of iterator) {
        scanValue(key, state, role, seen, depth + 1)
        scanValue(entry, state, role, seen, depth + 1)
      }
      scanOwnDataProperties(value, state, role, seen, depth)
      return
    }
    if (prototype === Set.prototype) {
      let iterator
      try {
        iterator = setValues.call(value)
      } catch {
        invalid()
      }
      for (const entry of iterator) scanValue(entry, state, role, seen, depth + 1)
      scanOwnDataProperties(value, state, role, seen, depth)
      return
    }
    const isError =
      prototype === Error.prototype ||
      prototype === TypeError.prototype ||
      prototype === RangeError.prototype
    if (prototype !== Object.prototype && !isError) invalid()
    scanOwnDataProperties(value, state, role, seen, depth)
    if (isError) invalid()
  } finally {
    seen.delete(value)
  }
}

function zeroBytes(value) {
  if (length(value) !== 32) return false
  for (const byte of value) if (byte !== 0) return false
  return true
}

function digestList(value) {
  if (!Array.isArray(value) || safeProxy(value)) invalid()
  const list = []
  for (let index = 0; index < value.length; index++) {
    const digest = own(value, String(index))
    if (length(digest) !== 32) invalid()
    list.push(digest)
  }
  return list
}

function includes(list, digest) {
  return list.some((entry) => b4a.equals(entry, digest))
}

// The storage oracle: a DHT role holds exactly the records the scenario put there.
// The setup value lives on dht-value alone and never leaves it; routed puts land
// wherever the DHT places them, but only records the coordinator announced through
// `expectRoutedRecords` are admissible anywhere.
function checkDhtStorage(role, event, state, closedSnapshot) {
  const count = own(event, 'storedValueCount')
  const digests = digestList(own(event, 'storedValueDigests'))
  const targets = digestList(own(event, 'mutableRecordTargets'))
  if (count !== digests.length) invalid()
  if (closedSnapshot) {
    if (digests.length !== 0 || targets.length !== 0) invalid()
    return
  }
  const holdsSetupValue = includes(digests, state.targetHash)
  if (role === 'dht-value') {
    if (holdsSetupValue) state.dhtValueStored = true
    else if (state.dhtValueStored) invalid()
  } else if (holdsSetupValue) {
    invalid()
  }
  for (const digest of digests) {
    if (b4a.equals(digest, state.targetHash)) continue
    if (!includes(state.routedValueDigests, digest)) invalid()
  }
  for (const target of targets) {
    if (!includes(state.routedMutableTargets, target)) invalid()
  }
  if (role === 'dht-referral' && own(event, 'transientValueBytes') !== 0) invalid()
}

function validateDhtSnapshot(role, event, state) {
  const type = objectGetOwnPropertyDescriptor(event, 'type')
  if (!DHT_ROLES.has(role) || !type || !('value' in type) || type.value !== 'snapshot') return
  for (const field of DHT_ZERO_SNAPSHOT_FIELDS) if (own(event, field) !== 0) invalid()
  for (const field of DHT_NULL_SNAPSHOT_FIELDS) if (own(event, field) !== null) invalid()
  if (own(event, 'guardOnly') !== false) invalid()
  const closedSnapshot = own(event, 'state') === 'CLOSED'
  if (own(event, 'openResources') !== (closedSnapshot ? 0 : 1)) invalid()
  checkDhtStorage(role, event, state, closedSnapshot)
}

const MIDDLE_ROLES = new Set(['lookup-middle-a', 'lookup-middle-b', 'announce-middle'])
const EXIT_ROLES = new Set(['lookup-exit-a', 'lookup-exit-b', 'announce-exit'])

function validateRelationshipSnapshot(role, event) {
  const type = objectGetOwnPropertyDescriptor(event, 'type')
  if (!type || !('value' in type) || type.value !== 'snapshot') return
  const selectedExit = own(event, 'selectedExitRoleIndex')
  const selectedMiddle = own(event, 'selectedMiddleRoleIndex')
  if (MIDDLE_ROLES.has(role)) {
    if (selectedMiddle !== null || (selectedExit !== null && ![4, 6, 8].includes(selectedExit)))
      invalid()
    return
  }
  if (EXIT_ROLES.has(role)) {
    if (selectedExit !== null || (selectedMiddle !== null && ![3, 5, 7].includes(selectedMiddle)))
      invalid()
    return
  }
  if (selectedExit !== null || selectedMiddle !== null) invalid()
}

// A non-snapshot event that claims storage state is held to the same oracle as a
// snapshot; only DHT roles may make the claim, and only with the full field set.
function validatePostSetupState(role, event, state) {
  if (
    event === null ||
    typeof event !== 'object' ||
    safeProxy(event) ||
    objectGetPrototypeOf(event) !== Object.prototype
  )
    return
  const type = objectGetOwnPropertyDescriptor(event, 'type')
  if (type && 'value' in type && type.value === 'snapshot') return
  const claims = [
    'storedValueCount',
    'storedValueDigests',
    'mutableRecordTargets',
    'transientValueBytes'
  ].filter((field) => objectGetOwnPropertyDescriptor(event, field))
  if (claims.length === 0) return
  if (!DHT_ROLES.has(role)) invalid()
  if (claims.includes('transientValueBytes') !== (role === 'dht-referral')) invalid()
  checkDhtStorage(role, event, state, false)
}

function createProcessConfigAuditor(oracle) {
  exactObject(oracle, [
    'auditorMarkerKey',
    'decoyMarkerKey',
    'endpointAddress',
    'eventForbiddenBytes',
    'immutableValue',
    'leakSentinel',
    'linkGrants',
    'namespace',
    'networkAuthority',
    'plan',
    'projectionBytes',
    'projectionDigests',
    'roleMacKeys',
    'run',
    'targetHash',
    'tupleAuthorization',
    'tuples'
  ])
  if (
    typeof oracle.endpointAddress !== 'string' ||
    !Array.isArray(oracle.projectionBytes) ||
    oracle.projectionBytes.length !== 11 ||
    !Array.isArray(oracle.projectionDigests) ||
    oracle.projectionDigests.length !== 11 ||
    !Array.isArray(oracle.eventForbiddenBytes) ||
    length(oracle.leakSentinel) !== 32 ||
    length(oracle.targetHash) !== 32
  )
    invalid()
  const state = {
    closed: false,
    dhtValueStored: false,
    endpointAddress: oracle.endpointAddress,
    forbiddenBytes: oracle.eventForbiddenBytes.map((value) => copy(value)),
    immutableValue: copy(oracle.immutableValue),
    leakSentinel: copy(oracle.leakSentinel, 32),
    targetHash: copy(oracle.targetHash, 32),
    plan: oracle.plan,
    projectionBytes: oracle.projectionBytes.map((value) => copy(value)),
    projectionDigests: oracle.projectionDigests.map((value) => copy(value, 32)),
    routedValueDigests: [],
    routedMutableTargets: []
  }
  return Object.freeze({
    auditProjection(projection) {
      if (state.closed) closed()
      if (projection === null || typeof projection !== 'object' || safeProxy(projection)) invalid()
      const role = own(projection, 'role')
      const roleIndex = own(projection, 'roleIndex')
      const plan = own(projection, 'plan')
      if (!ROLES.includes(role) || roleIndex !== ROLES.indexOf(role) + 1 || plan !== state.plan)
        invalid()
      let encoded = null
      let digest = null
      try {
        encoded = encodeCanonicalBody(projection)
        digest = cryptoSuite.hash(encoded)
        if (
          !b4a.equals(encoded, state.projectionBytes[roleIndex - 1]) ||
          !b4a.equals(digest, state.projectionDigests[roleIndex - 1])
        )
          invalid()
        return true
      } finally {
        clear(encoded)
        clear(digest)
      }
    },
    auditAll(projections) {
      if (state.closed) closed()
      if (
        !Array.isArray(projections) ||
        safeProxy(projections) ||
        projections.length !== 11 ||
        reflectOwnKeys(projections).length !== 12
      )
        invalid()
      const seen = new Set()
      for (let index = 0; index < projections.length; index++) {
        if (seen.has(projections[index])) invalid()
        seen.add(projections[index])
        this.auditProjection(projections[index])
      }
      return true
    },
    auditEvent(role, event) {
      if (state.closed) closed()
      if (!ROLES.includes(role)) invalid()
      scanValue(event, state, role, new Set(), 0)
      validatePostSetupState(role, event, state)
      validateDhtSnapshot(role, event, state)
      validateRelationshipSnapshot(role, event)
      return true
    },
    // The scenario announces a routed put before it issues it; only then may a DHT
    // role report holding that record. Digests are copied, so a caller cannot
    // widen the set later by mutating what it passed.
    expectRoutedRecords(records) {
      if (state.closed) closed()
      exactObject(records, ['mutableTargets', 'valueDigests'])
      for (const digest of digestList(own(records, 'valueDigests'))) {
        if (b4a.equals(digest, state.targetHash)) invalid()
        state.routedValueDigests.push(copy(digest, 32))
      }
      for (const target of digestList(own(records, 'mutableTargets'))) {
        state.routedMutableTargets.push(copy(target, 32))
      }
      return true
    },
    destroy() {
      if (state.closed) return
      state.closed = true
      clear(state.leakSentinel)
      clear(state.immutableValue)
      clear(state.targetHash)
      for (const value of state.forbiddenBytes) clear(value)
      for (const value of state.projectionBytes) clear(value)
      for (const value of state.projectionDigests) clear(value)
      for (const value of state.routedValueDigests) clear(value)
      for (const value of state.routedMutableTargets) clear(value)
      state.forbiddenBytes.length = 0
      state.projectionBytes.length = 0
      state.projectionDigests.length = 0
      state.routedValueDigests.length = 0
      state.routedMutableTargets.length = 0
    }
  })
}

module.exports = Object.freeze({
  ProcessConfigAuditError,
  createProcessConfigAuditor
})
