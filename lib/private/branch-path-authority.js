'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const {
  abortRelayPathReservation,
  commitRelayPathReservation,
  consumeSelectedRelayEvidence,
  readRelayCandidateDirectoryScope,
  splitRelayPathReservation,
  takeRelayPathReservation
} = require('./relay-candidate-directory')
const {
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement
} = require('./relay-capability')
const { issueGuardLeaseM3CellLinkTransferIssuer, readGuardLeaseScope } = require('./guard-lease')

const INITIAL_BRANCH_DRAFTS = new WeakMap()
const DESTROYED_INITIAL_BRANCH_DRAFTS = new WeakSet()
const INITIAL_BRANCH_FIELDS = Object.freeze([
  'guardLease',
  'candidateDirectory',
  'lookupGeneration',
  'announceGeneration',
  'lookupBranchId',
  'announceBranchId',
  'lookupCircuitId',
  'announceCircuitId',
  'absoluteDeadline'
])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function incompatible() {
  throw PrivateRouteError.ERR_INCOMPATIBLE_RELAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactObject(value, fields) {
  if (!isObject(value)) invalid()
  const names = Reflect.ownKeys(value)
  if (names.length !== fields.length) invalid()
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) invalid()
  }
}

function id16(value) {
  if (!b4a.isBuffer(value) || value.byteLength !== 16) invalid()
  return b4a.from(value)
}

function generation(value) {
  if (typeof value !== 'bigint' || value < 1n) invalid()
  return value
}

function deadline(value) {
  if (typeof value !== 'bigint' || value < 1n) invalid()
  return value
}

function same(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function endpointSubnetEqual(left, right) {
  if (same(left, right)) return true
  if (!b4a.isBuffer(left) || !b4a.isBuffer(right)) return false
  if (left.byteLength !== 19 || right.byteLength !== 19) return false
  if (left[0] === 4 && right[0] === 4) {
    return left[13] === right[13] && left[14] === right[14] && left[15] === right[15]
  }
  if (left[0] === 6 && right[0] === 6) {
    for (let i = 1; i < 7; i++) if (left[i] !== right[i]) return false
    return true
  }
  return false
}

function guardEndpoint(scope) {
  return scope.endpointBytes || scope.canonicalEndpointBytes
}
function validateDirectoryScope(guardScope, directory) {
  const directoryScope = readRelayCandidateDirectoryScope(directory)
  if (
    !same(guardScope.identity32, directoryScope.guardIdentity) ||
    !same(guardEndpoint(guardScope), directoryScope.guardEndpoint)
  ) {
    incompatible()
  }
}

function candidateFromEvidence(evidence) {
  const decoded = decodeRelayCapabilityAdvertisement(evidence.canonicalAdvertisement)
  let endpoint = null
  try {
    endpoint = decodeCanonicalEndpoint(decoded.reachableEndpoint)
    return Object.freeze({
      identity: b4a.from(decoded.relayIdentity),
      endpoint,
      digest: b4a.from(evidence.advertisementDigest),
      role: evidence.role,
      branchClass: evidence.branchClass,
      position: evidence.position,
      generation: evidence.generation
    })
  } catch (err) {
    if (endpoint) endpoint.fill(0)
    throw err
  }
}

function validatePathDiversity(guardScope, candidates) {
  const guardIdentity = guardScope.identity32 || guardScope.identity
  const endpoint = guardEndpoint(guardScope)
  if (!same(guardIdentity, guardIdentity) || !b4a.isBuffer(endpoint)) invalid()
  const all = [{ identity: guardIdentity, endpoint }, ...candidates]
  for (let left = 0; left < all.length; left++) {
    for (let right = left + 1; right < all.length; right++) {
      if (same(all[left].identity, all[right].identity)) incompatible()
      if (endpointSubnetEqual(all[left].endpoint, all[right].endpoint)) incompatible()
    }
  }
}

function createBranch(branchClass, generation, branchId, circuitId, middleEvidence, exitEvidence) {
  return Object.freeze({
    branchClass,
    generation,
    branchId,
    circuitId,
    middle: candidateFromEvidence(middleEvidence),
    exit: candidateFromEvidence(exitEvidence)
  })
}

function createInitialBranchDrafts(options) {
  exactObject(options, INITIAL_BRANCH_FIELDS)
  const lookupGeneration = generation(options.lookupGeneration)
  const announceGeneration = generation(options.announceGeneration)
  const lookupBranchId = id16(options.lookupBranchId)
  const announceBranchId = id16(options.announceBranchId)
  const lookupCircuitId = id16(options.lookupCircuitId)
  const announceCircuitId = id16(options.announceCircuitId)
  const absoluteDeadline = deadline(options.absoluteDeadline)
  const guardScope = readGuardLeaseScope(options.guardLease)
  validateDirectoryScope(guardScope, options.candidateDirectory)
  let transaction = null
  const issuers = []
  let drafts = null
  try {
    transaction = takeRelayPathReservation(
      options.candidateDirectory.reserveInitialPair({ lookupGeneration, announceGeneration })
    )
    const split = splitRelayPathReservation(transaction)
    const lookupMiddle = consumeSelectedRelayEvidence(split.lookup.middle, {
      transaction,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'middle',
      generation: lookupGeneration
    })
    const lookupExit = consumeSelectedRelayEvidence(split.lookup.exit, {
      transaction,
      branchClass: BRANCH_CLASS.LOOKUP,
      position: 'exit',
      generation: lookupGeneration
    })
    const announceMiddle = consumeSelectedRelayEvidence(split.announce.middle, {
      transaction,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'middle',
      generation: announceGeneration
    })
    const announceExit = consumeSelectedRelayEvidence(split.announce.exit, {
      transaction,
      branchClass: BRANCH_CLASS.ANNOUNCE,
      position: 'exit',
      generation: announceGeneration
    })
    const lookup = createBranch(
      BRANCH_CLASS.LOOKUP,
      lookupGeneration,
      lookupBranchId,
      lookupCircuitId,
      lookupMiddle,
      lookupExit
    )
    const announce = createBranch(
      BRANCH_CLASS.ANNOUNCE,
      announceGeneration,
      announceBranchId,
      announceCircuitId,
      announceMiddle,
      announceExit
    )
    validatePathDiversity(guardScope, [lookup.middle, lookup.exit, announce.middle, announce.exit])
    for (let i = 0; i < 4; i++)
      issuers.push(issueGuardLeaseM3CellLinkTransferIssuer(options.guardLease))
    drafts = Object.freeze({})
    INITIAL_BRANCH_DRAFTS.set(drafts, {
      transaction,
      lookup,
      announce,
      issuers,
      absoluteDeadline,
      committed: false,
      destroyed: false
    })
    transaction = null
    return drafts
  } catch (err) {
    for (const issuer of issuers) issuer.destroy()
    if (transaction !== null) abortRelayPathReservation(transaction)
    throw err
  }
}

function readInitialBranchDrafts(drafts) {
  const state = isObject(drafts) ? INITIAL_BRANCH_DRAFTS.get(drafts) : null
  if (!state) {
    if (isObject(drafts) && DESTROYED_INITIAL_BRANCH_DRAFTS.has(drafts)) destroyed()
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.destroyed) destroyed()
  return state
}

function inspectInitialBranchDrafts(drafts) {
  const state = readInitialBranchDrafts(drafts)
  return Object.freeze({
    committed: state.committed,
    destroyed: state.destroyed,
    issuerCount: state.issuers.length,
    absoluteDeadline: state.absoluteDeadline,
    lookup: state.lookup,
    announce: state.announce
  })
}

function commitInitialBranchDrafts(drafts) {
  const state = readInitialBranchDrafts(drafts)
  if (state.committed) throw PrivateRouteError.ERR_REPLAY()
  commitRelayPathReservation(state.transaction)
  state.committed = true
  return true
}

function destroyInitialBranchDrafts(drafts) {
  const state = isObject(drafts) ? INITIAL_BRANCH_DRAFTS.get(drafts) : null
  if (!state || state.destroyed) return false
  state.destroyed = true
  INITIAL_BRANCH_DRAFTS.delete(drafts)
  DESTROYED_INITIAL_BRANCH_DRAFTS.add(drafts)
  if (!state.committed) abortRelayPathReservation(state.transaction)
  for (const issuer of state.issuers) issuer.destroy()
  state.issuers.length = 0
  return true
}

module.exports = {
  commitInitialBranchDrafts,
  createInitialBranchDrafts,
  destroyInitialBranchDrafts,
  inspectInitialBranchDrafts,
  readInitialBranchDrafts
}
