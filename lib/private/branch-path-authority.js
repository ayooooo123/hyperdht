'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const {
  abortRelayPathReservation,
  commitRelayPathReservation,
  consumeSelectedRelayEvidence,
  duplicateSelectedRelaySelection,
  readRelayCandidateDirectoryScope,
  splitRelayPathReservation,
  revokeSelectedRelaySelection,
  takeRelayPathReservation
} = require('./relay-candidate-directory')
const {
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement
} = require('./relay-capability')
const { issueGuardLeaseM3CellLinkTransferIssuer, readGuardLeaseScope } = require('./guard-lease')

const INITIAL_BRANCH_DRAFTS = new WeakMap()
const DESTROYED_INITIAL_BRANCH_DRAFTS = new WeakSet()
const BRANCH_BUILD_AUTHORITIES = new WeakMap()
const SPENT_BRANCH_BUILD_AUTHORITIES = new WeakSet()
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
const REPLACEMENT_BRANCH_FIELDS = Object.freeze([
  'guardLease',
  'candidateDirectory',
  'branchClass',
  'generation',
  'branchId',
  'circuitId',
  'absoluteDeadline',
  'wallNow',
  'monotonicNow'
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

function timestamp(readNow) {
  if (typeof readNow !== 'function') invalid()
  const value = readNow()
  if (typeof value === 'bigint' && value >= 0n) return value
  if (Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  invalid()
}

function capDeadlineByWallExpiry(current, wallStart, monotonicStart, expiresAt) {
  if (typeof expiresAt !== 'bigint') invalid()
  if (expiresAt <= wallStart) incompatible()
  const candidate = monotonicStart + (expiresAt - wallStart)
  return candidate < current ? candidate : current
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
  return directoryScope
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
      generation: evidence.generation,
      payloadParameters: decoded,
      expiresAt: decoded.expiresAtMs
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

function verifyBranchPathDiversity(guardLease, branches) {
  if (!Array.isArray(branches) || branches.length !== 2) invalid()
  const first = branches[0]
  const second = branches[1]
  if (
    !first ||
    !second ||
    first.branchClass === second.branchClass ||
    !first.middle ||
    !first.exit ||
    !second.middle ||
    !second.exit
  ) {
    invalid()
  }
  validatePathDiversity(readGuardLeaseScope(guardLease), [
    first.middle,
    first.exit,
    second.middle,
    second.exit
  ])
  return true
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
    const buildSelections = Object.freeze({
      lookup: Object.freeze({
        middle: duplicateSelectedRelaySelection(split.lookup.middle),
        exit: duplicateSelectedRelaySelection(split.lookup.exit)
      }),
      announce: Object.freeze({
        middle: duplicateSelectedRelaySelection(split.announce.middle),
        exit: duplicateSelectedRelaySelection(split.announce.exit)
      })
    })
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
    for (let i = 0; i < 2; i++)
      issuers.push(issueGuardLeaseM3CellLinkTransferIssuer(options.guardLease))
    drafts = Object.freeze({})
    INITIAL_BRANCH_DRAFTS.set(drafts, {
      transaction,
      lookup,
      announce,
      issuers,
      buildSelections,
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

function createReplacementBranchDraft(options) {
  exactObject(options, REPLACEMENT_BRANCH_FIELDS)
  const branchClass = options.branchClass
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  const value = generation(options.generation)
  const branchId = id16(options.branchId)
  const circuitId = id16(options.circuitId)
  let absoluteDeadline = deadline(options.absoluteDeadline)
  const guardScope = readGuardLeaseScope(options.guardLease)
  const directoryScope = validateDirectoryScope(guardScope, options.candidateDirectory)
  let transaction = null
  const issuers = []
  let drafts = null
  try {
    transaction = takeRelayPathReservation(
      options.candidateDirectory.reserveReplacement({
        branchClass,
        generation: value
      })
    )
    const split = splitRelayPathReservation(transaction)
    const buildSelections = Object.freeze({
      branchClass,
      middle: duplicateSelectedRelaySelection(split.middle),
      exit: duplicateSelectedRelaySelection(split.exit)
    })
    const middle = consumeSelectedRelayEvidence(split.middle, {
      transaction,
      branchClass,
      position: 'middle',
      generation: value
    })
    const exit = consumeSelectedRelayEvidence(split.exit, {
      transaction,
      branchClass,
      position: 'exit',
      generation: value
    })
    const branch = createBranch(branchClass, value, branchId, circuitId, middle, exit)
    const wallStart = timestamp(options.wallNow)
    const monotonicStart = timestamp(options.monotonicNow)
    absoluteDeadline = capDeadlineByWallExpiry(
      absoluteDeadline,
      wallStart,
      monotonicStart,
      branch.middle.expiresAt
    )
    absoluteDeadline = capDeadlineByWallExpiry(
      absoluteDeadline,
      wallStart,
      monotonicStart,
      branch.exit.expiresAt
    )
    absoluteDeadline = capDeadlineByWallExpiry(
      absoluteDeadline,
      wallStart,
      monotonicStart,
      directoryScope.guardExpiresAt
    )
    issuers.push(issueGuardLeaseM3CellLinkTransferIssuer(options.guardLease))
    drafts = Object.freeze({})
    INITIAL_BRANCH_DRAFTS.set(drafts, {
      transaction,
      branch,
      issuers,
      buildSelections,
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

function activeIssuerCount(state) {
  let count = 0
  for (const issuer of state.issuers) {
    if (issuer !== null) count++
  }
  return count
}

function releaseBranchDraftIssuer(drafts, branchClass) {
  const state = readInitialBranchDrafts(drafts)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  let index
  if (state.branch) {
    if (state.branch.branchClass !== branchClass) invalid()
    index = 0
  } else {
    index = branchClass === BRANCH_CLASS.LOOKUP ? 0 : 1
  }
  const issuer = state.issuers[index]
  if (issuer === null) return false
  state.issuers[index] = null
  issuer.destroy()
  return true
}

function inspectInitialBranchDrafts(drafts) {
  const state = readInitialBranchDrafts(drafts)
  const snapshot = {
    committed: state.committed,
    destroyed: state.destroyed,
    issuerCount: activeIssuerCount(state),
    absoluteDeadline: state.absoluteDeadline
  }
  if (state.branch) {
    snapshot.branch = state.branch
  } else {
    snapshot.lookup = state.lookup
    snapshot.announce = state.announce
  }
  return Object.freeze(snapshot)
}

function claimInitialBranchBuild(drafts) {
  const state = readInitialBranchDrafts(drafts)
  if (state.buildClaimed) throw PrivateRouteError.ERR_REPLAY()
  const authority = Object.freeze({})
  state.buildClaimed = true
  BRANCH_BUILD_AUTHORITIES.set(authority, state)
  return authority
}

function claimReplacementBranchBuild(drafts) {
  const state = readInitialBranchDrafts(drafts)
  if (!state.branch) invalid()
  if (state.buildClaimed) throw PrivateRouteError.ERR_REPLAY()
  const authority = Object.freeze({})
  state.buildClaimed = true
  BRANCH_BUILD_AUTHORITIES.set(authority, state)
  return authority
}

function consumeInitialBranchBuild(authority) {
  const state = isObject(authority) ? BRANCH_BUILD_AUTHORITIES.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_BRANCH_BUILD_AUTHORITIES.has(authority)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.UNAUTHORIZED()
  }
  BRANCH_BUILD_AUTHORITIES.delete(authority)
  SPENT_BRANCH_BUILD_AUTHORITIES.add(authority)
  const branches = state.branch
    ? Object.freeze({ branch: state.branch })
    : Object.freeze({ lookup: state.lookup, announce: state.announce })
  return Object.freeze({
    transaction: state.transaction,
    selections: state.buildSelections,
    issuers: Object.freeze(state.issuers.slice()),
    branches,
    absoluteDeadline: state.absoluteDeadline
  })
}

function consumeReplacementBranchBuild(authority) {
  const state = isObject(authority) ? BRANCH_BUILD_AUTHORITIES.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_BRANCH_BUILD_AUTHORITIES.has(authority)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (!state.branch) invalid()
  BRANCH_BUILD_AUTHORITIES.delete(authority)
  SPENT_BRANCH_BUILD_AUTHORITIES.add(authority)
  return Object.freeze({
    transaction: state.transaction,
    selections: state.buildSelections,
    issuers: Object.freeze(state.issuers.slice()),
    branch: state.branch,
    absoluteDeadline: state.absoluteDeadline
  })
}

function revokeUnusedBuildSelections(state) {
  const selections = state.buildSelections
  if (Object.hasOwn(selections, 'branchClass')) {
    revokeSelectedRelaySelection(selections.middle)
    revokeSelectedRelaySelection(selections.exit)
    return
  }
  revokeSelectedRelaySelection(selections.lookup.middle)
  revokeSelectedRelaySelection(selections.lookup.exit)
  revokeSelectedRelaySelection(selections.announce.middle)
  revokeSelectedRelaySelection(selections.announce.exit)
}

function commitInitialBranchDrafts(drafts) {
  const state = readInitialBranchDrafts(drafts)
  if (state.committed) throw PrivateRouteError.ERR_REPLAY()
  if (!state.buildClaimed) revokeUnusedBuildSelections(state)
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
  for (const issuer of state.issuers) {
    if (issuer !== null) issuer.destroy()
  }
  state.issuers.length = 0
  return true
}

module.exports = {
  commitInitialBranchDrafts,
  claimInitialBranchBuild,
  claimReplacementBranchBuild,
  consumeInitialBranchBuild,
  consumeReplacementBranchBuild,
  createInitialBranchDrafts,
  createReplacementBranchDraft,
  destroyInitialBranchDrafts,
  inspectInitialBranchDrafts,
  releaseBranchDraftIssuer,
  readInitialBranchDrafts,
  verifyBranchPathDiversity
}
