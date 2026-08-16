'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { BRANCH_CLASS } = require('./protocol')
const { destroyGuardLease, isGuardLease, suspendGuardLease } = require('./guard-lease')
const {
  commitInitialBranchDrafts,
  claimInitialBranchBuild,
  claimReplacementBranchBuild,
  createInitialBranchDrafts,
  createReplacementBranchDraft,
  destroyInitialBranchDrafts,
  inspectInitialBranchDrafts,
  releaseBranchDraftIssuer,
  verifyBranchPathDiversity
} = require('./branch-path-authority')
const { createRouteExtensionFactory, readRouteExtensionFactory } = require('./route-extension')
const {
  createFinalExitActivationFactory,
  readFinalExitActivationFactory
} = require('./final-exit-activation')
const {
  commitDhtSeedAdmission,
  consumeBranchSeedReady,
  createDhtSeedAdmissionAuthority,
  createLiveOpaqueDestinations,
  destroyLiveOpaqueDestinations,
  revokeBranchSeedReady,
  sealDhtSeedAdmission,
  stageDhtSeedAdmission
} = require('./opaque-destination')
const { registerRelayCandidateDirectoryRollbackSink } = require('./relay-candidate-directory')

const BRANCH_ROTATION_LEAD_MS = 5_000n
const INITIAL_PAIR_DEADLINE_MS = 5_000n
const REPLACEMENT_BRANCH_DEADLINE_MS = 5_000n
// A refused expiry delivery is redelivered on this cadence. The controller
// refuses any branch signal outside READY, and a rotation of the other branch
// can hold it out of READY for as long as REPLACEMENT_BRANCH_DEADLINE_MS, so the
// retry has to be well inside BRANCH_ROTATION_LEAD_MS to still rotate the branch
// before its material expires. At this cadence that costs at most twenty wakeups
// per rotation window.
const BRANCH_EXPIRY_RETRY_MS = 250
const MANAGERS = new WeakMap()
const DESTROYED_MANAGERS = new WeakSet()
const LIVE_PAIR_LEASES = new WeakMap()
const LIVE_PAIR_BY_MANAGER = new WeakMap()
const SPENT_LIVE_PAIR_LEASES = new WeakSet()
const BRANCH_PHYSICAL_LOSS_REGISTRATIONS = new WeakMap()
const SPENT_BRANCH_PHYSICAL_LOSS_REGISTRATIONS = new WeakSet()
const SUSPENDED_DIRECTORIES = new WeakMap()
const SUSPENDED_DIRECTORY_CONSUMER = Symbol.for(
  'hyperdht-private-routes/suspended-directory-consumer'
)
const RESUMED_ROUTE_MANAGER_FACTORY = Symbol.for(
  'hyperdht-private-routes/resumed-route-manager-factory'
)
const TEST_ONLY_ROUTE_MANAGER_OBSERVER = Symbol.for(
  'hyperdht-private-routes/test-only-route-manager-observer'
)
const ROUTE_MANAGER_CREATION_OBSERVERS = new Set()
const TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER = Object.freeze({
  observe(listener) {
    if (typeof listener !== 'function') invalid()
    ROUTE_MANAGER_CREATION_OBSERVERS.add(listener)
    return () => ROUTE_MANAGER_CREATION_OBSERVERS.delete(listener)
  }
})
const MANAGER_FIELDS = Object.freeze([
  'guardLease',
  'candidateDirectory',
  'extensionFactory',
  'terminalFactory',
  'monotonicNow',
  'randomBytes'
])
const INITIAL_PAIR_HANDOFF_FIELDS = Object.freeze(['lookup', 'announce'])
const LIFECYCLE_SINK_FIELDS = Object.freeze([
  'lookupBranchLoss',
  'announceBranchLoss',
  'lookupBranchExpiry',
  'announceBranchExpiry',
  'wallClockRollback'
])
const INITIAL_PAIR_SEED_FIELDS = Object.freeze(['lookup', 'announce'])

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function busy() {
  throw PrivateRouteError.ERR_BUSY()
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

function absoluteNow(now) {
  const value = now()
  if (typeof value === 'bigint' && value >= 0n) return value
  if (Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  invalid()
}

function randomId(randomBytes) {
  const value = randomBytes(16)
  if (!b4a.isBuffer(value) || value.byteLength !== 16) invalid()
  return value
}

function readManagerFactory(readFactory, factory) {
  try {
    return readFactory(factory)
  } catch (err) {
    if (err instanceof PrivateRouteError && err.code === 'ERR_AUTHENTICATION') {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    throw err
  }
}

function sameBuffer(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function branchForClass(draft, branchClass) {
  return branchClass === BRANCH_CLASS.LOOKUP ? draft.lookup : draft.announce
}

function destroyOpenMaterial(material) {
  if (!material) return false
  const { destroyOpenRouteMaterial } = require('./open-route-handoff')
  return destroyOpenRouteMaterial(material)
}

function safeDestroyOpenMaterial(material) {
  try {
    return destroyOpenMaterial(material)
  } catch {
    return false
  }
}

function revokeOpenHandoff(handoff) {
  if (!handoff) return false
  const { revokeOpenRouteHandoff } = require('./open-route-handoff')
  return revokeOpenRouteHandoff(handoff)
}

function consumeOpenHandoff(handoff) {
  const { consumeOpenRouteHandoff } = require('./open-route-handoff')
  return consumeOpenRouteHandoff(handoff)
}

function validateOpenMaterial(material, branch) {
  if (
    !isObject(material) ||
    material.branchClass !== branch.branchClass ||
    material.generation !== branch.generation ||
    !sameBuffer(material.exitIdentity, branch.exit.identity) ||
    !sameBuffer(material.branchId, branch.branchId) ||
    !sameBuffer(material.circuitId, branch.circuitId) ||
    typeof material.expiresAt !== 'bigint' ||
    material.expiresAt <= 0n
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
}

function validateSeedReady(material, branchClass, branch) {
  if (
    material.branchClass !== branchClass ||
    material.generation !== branch.material.generation ||
    material.expiresAt !== branch.material.expiresAt ||
    !sameBuffer(material.branchId, branch.material.branchId) ||
    !sameBuffer(material.circuitId, branch.material.circuitId) ||
    !sameBuffer(material.exitIdentity, branch.material.exitIdentity)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
}

function clearSeedReadyMaterial(material) {
  if (!material) return
  if (b4a.isBuffer(material.branchId)) material.branchId.fill(0)
  if (b4a.isBuffer(material.circuitId)) material.circuitId.fill(0)
  if (b4a.isBuffer(material.exitIdentity)) material.exitIdentity.fill(0)
}

function safeDestroyDestinationOwner(owner) {
  if (!owner) return false
  try {
    destroyLiveOpaqueDestinations(owner)
    return true
  } catch {
    return false
  }
}

function cancelScheduled(state, handle) {
  if (handle === null) return
  try {
    state.terminalClock.cancelScheduled(handle)
  } catch {}
}

function abortInitialSeedState(state, cancelTimer = true) {
  if (cancelTimer) cancelScheduled(state, state.initialSeedTimer)
  state.initialSeedTimer = null
  for (const branch of state.branches.values()) {
    safeDestroyDestinationOwner(branch.owner)
    safeDestroyOpenMaterial(branch.material)
  }
  if (state.initialSeedDraft !== null) destroyInitialBranchDrafts(state.initialSeedDraft)
  state.initialSeedDraft = null
  state.branches.clear()
  state.capabilities.clear()
  state.seedPending = false
  state.initialDeadline = null
  state.ready = false
  state.status = 'UNAVAILABLE'
}

function armInitialSeedDeadline(state) {
  const now = absoluteNow(state.monotonicNow)
  if (now >= state.initialDeadline) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  const delay = Number(state.initialDeadline - now)
  let arming = true
  let firedSynchronously = false
  let handle = null
  const expired = () => {
    if (arming) {
      firedSynchronously = true
      return
    }
    state.initialSeedTimer = null
    if (state.destroyed || !state.seedPending) return
    try {
      if (absoluteNow(state.monotonicNow) < state.initialDeadline) {
        armInitialSeedDeadline(state)
        return
      }
    } catch {}
    abortInitialSeedState(state, false)
  }
  try {
    handle = state.terminalClock.schedule(expired, delay)
  } catch {
    arming = false
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  arming = false
  if (firedSynchronously || handle === null || handle === undefined) {
    cancelScheduled(state, handle)
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  state.initialSeedTimer = handle
}

function branchSinkKey(branchClass, suffix) {
  return `${branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'}${suffix}`
}

function issueBranchSink(state, branchClass, suffix) {
  const key = branchSinkKey(branchClass, suffix)
  const sink = state.lifecycleSinks[key]
  state.lifecycleSinks[key] = null
  if (!sink) return false
  const { issuePrivateRoutingControllerSignal } = require('./private-routing-controller')
  return issuePrivateRoutingControllerSignal(sink)
}

function cancelBranchExpiry(state, branchClass) {
  const handle = state.branchExpiryTimers.get(branchClass)
  state.branchExpiryTimers.delete(branchClass)
  cancelScheduled(state, handle)
}
function clearBranchExpiryTimers(state) {
  for (const branchClass of Array.from(state.branchExpiryTimers.keys())) {
    cancelBranchExpiry(state, branchClass)
  }
}

function armBranchExpiry(state, branchClass, minDelayMs = 0) {
  cancelBranchExpiry(state, branchClass)
  if (!state.lifecycleSinks[branchSinkKey(branchClass, 'BranchExpiry')]) return false
  const branch = state.branches.get(branchClass)
  if (!branch) return false
  const now = absoluteNow(state.extensionClock.wallNow)
  const rotateAt =
    branch.material.expiresAt > BRANCH_ROTATION_LEAD_MS
      ? branch.material.expiresAt - BRANCH_ROTATION_LEAD_MS
      : branch.material.expiresAt
  const remaining = rotateAt > now ? Number(rotateAt - now) : 0
  const delay = remaining > minDelayMs ? remaining : minDelayMs
  let arming = true
  let firedSynchronously = false
  let handle = null
  const expired = () => {
    if (arming) {
      firedSynchronously = true
      return
    }
    if (state.destroyed || state.branchExpiryTimers.get(branchClass) !== handle) return
    state.branchExpiryTimers.delete(branchClass)
    try {
      const current = state.branches.get(branchClass)
      const currentNow = absoluteNow(state.extensionClock.wallNow)
      const currentRotateAt =
        current && current.material.expiresAt > BRANCH_ROTATION_LEAD_MS
          ? current.material.expiresAt - BRANCH_ROTATION_LEAD_MS
          : current && current.material.expiresAt
      if (currentRotateAt && currentNow < currentRotateAt) {
        armBranchExpiry(state, branchClass)
        return
      }
      issueBranchSink(state, branchClass, 'BranchExpiry')
    } catch {}
  }
  try {
    handle = state.terminalClock.schedule(expired, delay)
  } catch {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } finally {
    arming = false
  }
  if (firedSynchronously || handle === null || handle === undefined) {
    cancelScheduled(state, handle)
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  state.branchExpiryTimers.set(branchClass, handle)
  return true
}

function issueReadySink(state) {
  const sink = state.readySink
  if (!sink) return false
  state.readySink = null
  const { issuePrivateRoutingControllerSignal } = require('./private-routing-controller')
  return issuePrivateRoutingControllerSignal(sink)
}

function publishInitialSeedPair(manager, readiness) {
  const state = readRouteManager(manager)
  exactObject(readiness, INITIAL_PAIR_SEED_FIELDS)
  if (state.building) busy()
  const pending = [
    { key: 'lookup', branchClass: BRANCH_CLASS.LOOKUP },
    { key: 'announce', branchClass: BRANCH_CLASS.ANNOUNCE }
  ]
  if (!state.seedPending) {
    if (state.initialDrafts === null) busy()
    for (const item of pending) revokeBranchSeedReady(readiness[item.key])
    destroyInitialBranchDrafts(state.initialDrafts)
    state.initialDrafts = null
    state.initialDeadline = null
    state.status = 'UNAVAILABLE'
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const consumed = []
  state.building = true
  try {
    if (absoluteNow(state.monotonicNow) >= state.initialDeadline) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    for (const item of pending) {
      const material = consumeBranchSeedReady(readiness[item.key])
      consumed.push(material)
      validateSeedReady(material, item.branchClass, state.branches.get(item.branchClass))
    }
    verifyBranchPathDiversity(
      state.guardLease,
      Array.from(state.branches.values(), (branch) => branch.path)
    )
    commitInitialBranchDrafts(state.initialSeedDraft)
    state.committedDrafts.add(state.initialSeedDraft)
    state.initialSeedDraft = null
    cancelScheduled(state, state.initialSeedTimer)
    state.initialSeedTimer = null
    state.seedPending = false
    state.initialDeadline = null
    state.ready = true
    state.status = 'READY'
    issueReadySink(state)
    armBranchExpiry(state, BRANCH_CLASS.LOOKUP)
    armBranchExpiry(state, BRANCH_CLASS.ANNOUNCE)
    return true
  } catch (err) {
    for (let index = consumed.length; index < pending.length; index++) {
      revokeBranchSeedReady(readiness[pending[index].key])
    }
    abortInitialSeedState(state)
    throw err
  } finally {
    for (const material of consumed) clearSeedReadyMaterial(material)
    state.building = false
  }
}

function nextGeneration(state, branchClass) {
  return branchClass === BRANCH_CLASS.LOOKUP
    ? state.lookupGeneration + 1n
    : state.announceGeneration + 1n
}

function setGeneration(state, branchClass, generation) {
  if (branchClass === BRANCH_CLASS.LOOKUP) state.lookupGeneration = generation
  else state.announceGeneration = generation
}

function currentBranchStillLive(state, branchClass) {
  const current = state.branches.get(branchClass)
  const now = absoluteNow(state.extensionClock.wallNow)
  return !!(current && current.material.expiresAt > now)
}

function afterRotationFailure(state, branchClass) {
  state.status = currentBranchStillLive(state, branchClass) ? 'READY' : 'UNAVAILABLE'
  state.ready = state.status === 'READY'
}

function abortRotationSeedState(state, branchClass, pending, cancelTimer = true) {
  if (cancelTimer) cancelScheduled(state, pending.timer)
  pending.timer = null
  if (state.rotationSeeds.get(branchClass) === pending) {
    state.rotationSeeds.delete(branchClass)
  }
  safeDestroyDestinationOwner(pending.owner)
  safeDestroyOpenMaterial(pending.material)
  destroyInitialBranchDrafts(pending.draft)
  afterRotationFailure(state, branchClass)
}

function armRotationSeedDeadline(state, branchClass, pending) {
  const now = absoluteNow(state.monotonicNow)
  if (now >= pending.deadline) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  const delay = Number(pending.deadline - now)
  let arming = true
  let firedSynchronously = false
  let handle = null
  const expired = () => {
    if (arming) {
      firedSynchronously = true
      return
    }
    pending.timer = null
    if (state.destroyed || state.rotationSeeds.get(branchClass) !== pending) return
    try {
      if (absoluteNow(state.monotonicNow) < pending.deadline) {
        armRotationSeedDeadline(state, branchClass, pending)
        return
      }
    } catch {}
    abortRotationSeedState(state, branchClass, pending, false)
  }
  try {
    handle = state.terminalClock.schedule(expired, delay)
  } catch {
    arming = false
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  arming = false
  if (firedSynchronously || handle === null || handle === undefined) {
    cancelScheduled(state, handle)
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  pending.timer = handle
}

function rotationDeadline(state, branchClass) {
  const start = absoluteNow(state.monotonicNow)
  const wallStart = absoluteNow(state.extensionClock.wallNow)
  const current = state.branches.get(branchClass)
  if (!current || current.material.expiresAt <= wallStart) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const defaultDeadline = start + REPLACEMENT_BRANCH_DEADLINE_MS
  const expiryDeadline = start + (current.material.expiresAt - wallStart)
  return expiryDeadline < defaultDeadline ? expiryDeadline : defaultDeadline
}

function createRotationDraft(state, branchClass) {
  return createReplacementBranchDraft({
    guardLease: state.guardLease,
    candidateDirectory: state.candidateDirectory,
    branchClass,
    generation: nextGeneration(state, branchClass),
    branchId: randomId(state.randomBytes),
    circuitId: randomId(state.randomBytes),
    absoluteDeadline: rotationDeadline(state, branchClass),
    wallNow: state.extensionClock.wallNow,
    monotonicNow: state.monotonicNow
  })
}

function publishRotation(manager, branchClass, handoff) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  if (state.building) busy()
  const draftRecord = state.rotationDrafts.get(branchClass)
  if (!draftRecord) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  state.building = true
  let material = null
  try {
    material = consumeOpenHandoff(handoff)
    validateOpenMaterial(material, draftRecord.branch)
    state.rotationDrafts.delete(branchClass)
    const pending = {
      draft: draftRecord.draft,
      branch: draftRecord.branch,
      deadline: draftRecord.deadline,
      capability: Object.freeze({}),
      material,
      owner: null,
      timer: null
    }
    state.rotationSeeds.set(branchClass, pending)
    armRotationSeedDeadline(state, branchClass, pending)
    state.ready = true
    state.status = 'ROTATING'
    return true
  } catch (err) {
    const pending = state.rotationSeeds.get(branchClass)
    if (pending) {
      abortRotationSeedState(state, branchClass, pending)
    } else {
      if (material) safeDestroyOpenMaterial(material)
      else revokeOpenHandoff(handoff)
      state.rotationDrafts.delete(branchClass)
      destroyInitialBranchDrafts(draftRecord.draft)
      afterRotationFailure(state, branchClass)
    }
    throw err
  } finally {
    state.building = false
  }
}

function publishRotationSeed(manager, branchClass, readiness) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  if (state.building) busy()
  const pending = state.rotationSeeds.get(branchClass)
  if (!pending) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  state.building = true
  let published = false
  let seedMaterial = null
  try {
    if (absoluteNow(state.monotonicNow) >= pending.deadline) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    seedMaterial = consumeBranchSeedReady(readiness)
    validateSeedReady(seedMaterial, branchClass, pending)
    const paths = Array.from(state.branches, ([currentClass, current]) =>
      currentClass === branchClass ? pending.branch : current.path
    )
    verifyBranchPathDiversity(state.guardLease, paths)
    cancelScheduled(state, pending.timer)
    pending.timer = null
    commitInitialBranchDrafts(pending.draft)
    state.committedDrafts.add(pending.draft)
    const previous = state.branches.get(branchClass)
    releaseBranchDraftIssuer(previous.draft, branchClass)
    if (inspectInitialBranchDrafts(previous.draft).issuerCount === 0) {
      state.committedDrafts.delete(previous.draft)
      destroyInitialBranchDrafts(previous.draft)
    }
    if (LIVE_PAIR_BY_MANAGER.has(manager)) {
      state.retiredBranches.set(branchClass, previous)
    } else {
      safeDestroyDestinationOwner(previous.owner)
      safeDestroyOpenMaterial(previous.material)
    }
    state.rotationSeeds.delete(branchClass)
    state.capabilities.set(branchClass, pending.capability)
    state.branches.set(branchClass, {
      capability: pending.capability,
      material: pending.material,
      path: pending.branch,
      draft: pending.draft,
      owner: pending.owner
    })
    setGeneration(state, branchClass, pending.branch.generation)
    state.ready = true
    state.status = 'READY'
    armBranchExpiry(state, branchClass)
    published = true
  } catch (err) {
    if (seedMaterial === null) revokeBranchSeedReady(readiness)
    abortRotationSeedState(state, branchClass, pending)
    throw err
  } finally {
    clearSeedReadyMaterial(seedMaterial)
    state.building = false
  }
  if (published) issueReadySink(state)
  return published
}

function publishInitialPair(manager, handoffs) {
  const state = readRouteManager(manager)
  exactObject(handoffs, INITIAL_PAIR_HANDOFF_FIELDS)
  if (state.ready || state.seedPending || state.building) busy()
  if (state.initialDrafts === null) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  const draft = inspectInitialBranchDrafts(state.initialDrafts)
  const consumed = []
  const pending = [
    { key: 'lookup', branch: branchForClass(draft, BRANCH_CLASS.LOOKUP) },
    { key: 'announce', branch: branchForClass(draft, BRANCH_CLASS.ANNOUNCE) }
  ]
  state.building = true
  try {
    for (const item of pending) {
      const material = consumeOpenHandoff(handoffs[item.key])
      consumed.push({ branchClass: item.branch.branchClass, branch: item.branch, material })
      validateOpenMaterial(material, item.branch)
    }
    state.initialSeedDraft = state.initialDrafts
    state.initialDrafts = null
    for (const item of consumed) {
      const capability = Object.freeze({})
      state.capabilities.set(item.branchClass, capability)
      state.branches.set(item.branchClass, {
        capability,
        material: item.material,
        path: item.branch,
        draft: state.initialSeedDraft,
        owner: null
      })
    }
    state.seedPending = true
    state.ready = false
    state.status = 'OPEN_PENDING_SEEDS'
    armInitialSeedDeadline(state)
    return true
  } catch (err) {
    for (let i = consumed.length; i < pending.length; i++)
      revokeOpenHandoff(handoffs[pending[i].key])
    for (const item of consumed) destroyOpenMaterial(item.material)
    if (state.initialDrafts !== null) {
      destroyInitialBranchDrafts(state.initialDrafts)
      state.initialDrafts = null
    }
    if (state.initialSeedDraft !== null) {
      destroyInitialBranchDrafts(state.initialSeedDraft)
      state.initialSeedDraft = null
    }
    state.branches.clear()
    state.capabilities.clear()
    state.seedPending = false
    state.initialDeadline = null
    state.ready = false
    state.status = 'UNAVAILABLE'
    throw err
  } finally {
    state.building = false
  }
}

function createBranchSeedAdmission(manager, branchClass, owner) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  if (state.building) busy()
  const record = state.seedPending
    ? state.branches.get(branchClass)
    : state.rotationSeeds.get(branchClass)
  if (!record) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  const endpointOpenAuthority = record.material.endpointOpenAuthority
  if (!endpointOpenAuthority) throw PrivateRouteError.ERR_REPLAY()
  try {
    const admission = createDhtSeedAdmissionAuthority(owner, endpointOpenAuthority)
    record.material.endpointOpenAuthority = null
    record.owner = owner
    return admission
  } catch (err) {
    if (state.seedPending) {
      abortInitialSeedState(state)
    } else {
      abortRotationSeedState(state, branchClass, record)
    }
    throw err
  }
}
async function receiveInitialSeedPair(manager) {
  const state = readRouteManager(manager)
  if (!state.seedPending || state.ready || state.status !== 'OPEN_PENDING_SEEDS') {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const pending = []
  const readiness = {}
  try {
    for (const [branchClass, key] of [
      [BRANCH_CLASS.LOOKUP, 'lookup'],
      [BRANCH_CLASS.ANNOUNCE, 'announce']
    ]) {
      const record = state.branches.get(branchClass)
      if (!record || record.owner !== null) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      const owner = createLiveOpaqueDestinations({
        branch: branchClass,
        circuitId: record.material.circuitId,
        generation: record.material.generation,
        expiresAt: record.material.expiresAt,
        wallNow: state.terminalClock.wallNow,
        monotonicNow: state.monotonicNow
      })
      const admission = createBranchSeedAdmission(manager, branchClass, owner)
      const { receiveOpenRouteSeedPayload } = require('./live-route-authority')
      pending.push({
        key,
        admission,
        receive: receiveOpenRouteSeedPayload(record.material, state.monotonicNow)
      })
    }
    const encodedPair = await Promise.all(pending.map((item) => item.receive))
    for (let index = 0; index < pending.length; index++) {
      const item = pending[index]
      const encoded = encodedPair[index]
      try {
        stageDhtSeedAdmission(item.admission, encoded)
        const committed = commitDhtSeedAdmission(sealDhtSeedAdmission(item.admission))
        readiness[item.key] = committed.branchSeedReady
      } finally {
        encoded.fill(0)
      }
    }
    return publishInitialSeedPair(manager, Object.freeze(readiness))
  } catch (err) {
    revokeBranchSeedReady(readiness.lookup)
    revokeBranchSeedReady(readiness.announce)
    if (state.seedPending) abortInitialSeedState(state)
    throw err
  }
}

async function receiveRotationSeed(manager, branchClass) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  const record = state.rotationSeeds.get(branchClass)
  if (!record || record.owner !== null || state.status !== 'ROTATING') {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  let readiness = null
  try {
    const owner = createLiveOpaqueDestinations({
      branch: branchClass,
      circuitId: record.material.circuitId,
      generation: record.material.generation,
      expiresAt: record.material.expiresAt,
      wallNow: state.terminalClock.wallNow,
      monotonicNow: state.monotonicNow
    })
    const admission = createBranchSeedAdmission(manager, branchClass, owner)
    const { receiveOpenRouteSeedPayload } = require('./live-route-authority')
    const encoded = await receiveOpenRouteSeedPayload(record.material, state.monotonicNow)
    try {
      stageDhtSeedAdmission(admission, encoded)
      readiness = commitDhtSeedAdmission(sealDhtSeedAdmission(admission)).branchSeedReady
    } finally {
      encoded.fill(0)
    }
    return publishRotationSeed(manager, branchClass, readiness)
  } catch (err) {
    revokeBranchSeedReady(readiness)
    const pending = state.rotationSeeds.get(branchClass)
    if (pending) abortRotationSeedState(state, branchClass, pending)
    throw err
  }
}

class RouteManager {
  buildInitialPair() {
    const state = readRouteManager(this)
    if (state.destroyed) destroyed()
    if (
      state.ready ||
      state.seedPending ||
      state.initialDrafts !== null ||
      state.initialSeedDraft !== null ||
      state.building
    ) {
      busy()
    }
    state.building = true
    try {
      const start = absoluteNow(state.monotonicNow)
      const drafts = createInitialBranchDrafts({
        guardLease: state.guardLease,
        candidateDirectory: state.candidateDirectory,
        lookupGeneration: state.lookupGeneration,
        announceGeneration: state.announceGeneration,
        lookupBranchId: randomId(state.randomBytes),
        announceBranchId: randomId(state.randomBytes),
        lookupCircuitId: randomId(state.randomBytes),
        announceCircuitId: randomId(state.randomBytes),
        absoluteDeadline: start + INITIAL_PAIR_DEADLINE_MS
      })
      state.initialDeadline = start + INITIAL_PAIR_DEADLINE_MS
      state.initialDrafts = drafts
      state.status = 'BUILDING'
      return false
    } catch (err) {
      state.status = 'UNAVAILABLE'
      throw err
    } finally {
      state.building = false
    }
  }

  ready() {
    const state = readRouteManager(this)
    return state.ready
  }

  branchCapability(branchClass) {
    const state = readRouteManager(this)
    if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
    if (state.rotationDrafts.has(branchClass) || state.rotationSeeds.has(branchClass)) {
      throw PrivateRouteError.ERR_PRIVATE_BRANCH_ROTATING()
    }
    if (!state.ready) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    const branch = state.branches.get(branchClass)
    if (!branch || branch.lost) throw PrivateRouteError.ERR_PRIVATE_BRANCH_ROTATING()
    return state.capabilities.get(branchClass)
  }

  publishInitialPair(handoffs) {
    return publishInitialPair(this, handoffs)
  }

  publishInitialSeedPair(readiness) {
    return publishInitialSeedPair(this, readiness)
  }

  createDhtSeedAdmission(branchClass, owner) {
    return createBranchSeedAdmission(this, branchClass, owner)
  }

  receiveInitialSeedPair() {
    return receiveInitialSeedPair(this)
  }
  claimInitialBuild() {
    const state = readRouteManager(this)
    if (state.destroyed || state.status !== 'BUILDING' || state.initialDrafts === null) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    return claimInitialBranchBuild(state.initialDrafts)
  }

  rotate(branchClass) {
    const state = readRouteManager(this)
    if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
    if (state.building || state.initialDrafts !== null) busy()

    if (!state.ready) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    if (state.rotationDrafts.size !== 0 || state.rotationSeeds.size !== 0) {
      throw PrivateRouteError.ERR_PRIVATE_BRANCH_ROTATING()
    }
    state.building = true
    try {
      const draft = createRotationDraft(state, branchClass)
      const observed = inspectInitialBranchDrafts(draft)
      state.rotationDrafts.set(branchClass, {
        draft,
        branch: observed.branch,
        deadline: observed.absoluteDeadline
      })
      state.status = 'ROTATING'
      return false
    } catch (err) {
      afterRotationFailure(state, branchClass)
      throw err
    } finally {
      state.building = false
    }
  }

  claimReplacementBuild(branchClass) {
    const state = readRouteManager(this)
    const record = state.rotationDrafts.get(branchClass)
    if (state.destroyed || state.status !== 'ROTATING' || !record) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    return claimReplacementBranchBuild(record.draft)
  }

  publishRotation(branchClass, handoff) {
    return publishRotation(this, branchClass, handoff)
  }

  publishRotationSeed(branchClass, readiness) {
    return publishRotationSeed(this, branchClass, readiness)
  }

  receiveRotationSeed(branchClass) {
    return receiveRotationSeed(this, branchClass)
  }

  suspend() {
    const state = MANAGERS.get(this)
    if (!state || state.destroyed) destroyed()
    state.destroyed = true
    MANAGERS.delete(this)
    DESTROYED_MANAGERS.add(this)
    cancelScheduled(state, state.initialSeedTimer)
    state.initialSeedTimer = null
    clearBranchExpiryTimers(state)
    if (state.initialDrafts !== null) destroyInitialBranchDrafts(state.initialDrafts)
    if (state.initialSeedDraft !== null) destroyInitialBranchDrafts(state.initialSeedDraft)
    for (const draft of state.rotationDrafts.values()) destroyInitialBranchDrafts(draft.draft)
    for (const draft of state.committedDrafts) destroyInitialBranchDrafts(draft)
    for (const branch of state.branches.values()) {
      safeDestroyDestinationOwner(branch.owner)
      destroyOpenMaterial(branch.material)
    }
    for (const pending of state.rotationSeeds.values()) {
      cancelScheduled(state, pending.timer)
      safeDestroyDestinationOwner(pending.owner)
      destroyOpenMaterial(pending.material)
      destroyInitialBranchDrafts(pending.draft)
    }
    for (const retired of state.retiredBranches.values()) {
      safeDestroyDestinationOwner(retired.owner)
      destroyOpenMaterial(retired.material)
    }
    state.initialDrafts = null
    state.initialSeedDraft = null
    state.rotationDrafts.clear()
    state.rotationSeeds.clear()
    state.committedDrafts.clear()
    state.branches.clear()
    state.capabilities.clear()
    state.retiredBranches.clear()
    state.ready = false
    try {
      state.candidateDirectory.retainForSuspend()
      const reconnect = suspendGuardLease(state.guardLease)
      SUSPENDED_DIRECTORIES.set(reconnect, {
        directory: state.candidateDirectory,
        lookupGeneration: state.lookupGeneration + 1n,
        announceGeneration: state.announceGeneration + 1n
      })
      return reconnect
    } catch (err) {
      try {
        state.candidateDirectory.destroy()
      } catch {}
      destroyGuardLease(state.guardLease)
      throw err
    }
  }

  destroy() {
    const state = MANAGERS.get(this)
    if (!state || state.destroyed) return false
    state.destroyed = true
    MANAGERS.delete(this)
    DESTROYED_MANAGERS.add(this)
    cancelScheduled(state, state.initialSeedTimer)
    state.initialSeedTimer = null
    clearBranchExpiryTimers(state)
    if (state.initialDrafts !== null) destroyInitialBranchDrafts(state.initialDrafts)
    if (state.initialSeedDraft !== null) destroyInitialBranchDrafts(state.initialSeedDraft)
    for (const draft of state.rotationDrafts.values()) destroyInitialBranchDrafts(draft.draft)
    for (const draft of state.committedDrafts) destroyInitialBranchDrafts(draft)
    for (const branch of state.branches.values()) {
      safeDestroyDestinationOwner(branch.owner)
      destroyOpenMaterial(branch.material)
    }
    for (const pending of state.rotationSeeds.values()) {
      cancelScheduled(state, pending.timer)
      safeDestroyDestinationOwner(pending.owner)
      destroyOpenMaterial(pending.material)
      destroyInitialBranchDrafts(pending.draft)
    }
    state.initialDrafts = null
    state.initialSeedDraft = null
    state.rotationDrafts.clear()
    state.rotationSeeds.clear()
    state.committedDrafts.clear()
    state.branches.clear()
    state.capabilities.clear()
    for (const retired of state.retiredBranches.values()) {
      safeDestroyDestinationOwner(retired.owner)
      destroyOpenMaterial(retired.material)
    }
    state.retiredBranches.clear()
    state.ready = false
    try {
      state.candidateDirectory.destroy()
    } finally {
      destroyGuardLease(state.guardLease)
    }
    return true
  }

  [TEST_ONLY_ROUTE_MANAGER_OBSERVER]() {
    const state = readRouteManager(this)
    const draft =
      state.initialDrafts === null ? null : inspectInitialBranchDrafts(state.initialDrafts)
    const rotations = {}
    for (const [branchClass, record] of state.rotationDrafts) {
      const key = branchClass === BRANCH_CLASS.LOOKUP ? 'lookup' : 'announce'
      rotations[key] = inspectInitialBranchDrafts(record.draft)
    }
    return Object.freeze({
      status: state.status,
      ready: state.ready,
      building: state.building,
      lookupGeneration: state.lookupGeneration,
      announceGeneration: state.announceGeneration,
      draft,
      rotations: Object.freeze(rotations)
    })
  }
}

function readRouteManager(manager) {
  const state = isObject(manager) ? MANAGERS.get(manager) : null
  if (!state) {
    if (isObject(manager) && DESTROYED_MANAGERS.has(manager)) destroyed()
    throw PrivateRouteError.UNAUTHORIZED()
  }
  if (state.destroyed) destroyed()
  return state
}

function claimLiveRoutePair(manager) {
  const state = readRouteManager(manager)
  if (
    !state.ready ||
    state.rotationDrafts.size !== 0 ||
    state.rotationSeeds.size !== 0 ||
    LIVE_PAIR_BY_MANAGER.has(manager)
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const lookup = state.branches.get(BRANCH_CLASS.LOOKUP)
  const announce = state.branches.get(BRANCH_CLASS.ANNOUNCE)
  if (!lookup || !announce || !lookup.owner || !announce.owner) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const lease = Object.freeze({})
  LIVE_PAIR_LEASES.set(lease, {
    state,
    lookup,
    announce,
    spent: false
  })
  LIVE_PAIR_BY_MANAGER.set(manager, lease)
  return lease
}

function readLiveRoutePair(lease) {
  const record = isObject(lease) ? LIVE_PAIR_LEASES.get(lease) : null
  if (!record || record.spent) {
    if (isObject(lease) && SPENT_LIVE_PAIR_LEASES.has(lease)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const state = record.state
  if (
    state.destroyed ||
    !state.ready ||
    state.rotationDrafts.size !== 0 ||
    state.rotationSeeds.size !== 0 ||
    state.branches.get(BRANCH_CLASS.LOOKUP) !== record.lookup ||
    state.branches.get(BRANCH_CLASS.ANNOUNCE) !== record.announce
  ) {
    record.spent = true
    LIVE_PAIR_LEASES.delete(lease)
    SPENT_LIVE_PAIR_LEASES.add(lease)
    LIVE_PAIR_BY_MANAGER.delete(record.state.manager)
    throw PrivateRouteError.ERR_DESTROYED()
  }
  return {
    lookup: {
      owner: record.lookup.owner,
      material: record.lookup.material
    },
    announce: {
      owner: record.announce.owner,
      material: record.announce.material
    },
    wallNow: state.extensionClock.wallNow,
    monotonicNow: state.monotonicNow,
    randomBytes: state.randomBytes
  }
}

function revokeLiveRoutePair(lease) {
  const record = isObject(lease) ? LIVE_PAIR_LEASES.get(lease) : null
  if (!record || record.spent) return false
  LIVE_PAIR_BY_MANAGER.delete(record.state.manager)
  record.spent = true
  LIVE_PAIR_LEASES.delete(lease)
  SPENT_LIVE_PAIR_LEASES.add(lease)
  return true
}

function claimRotatedLiveRoutePair(manager, branchClass) {
  const state = readRouteManager(manager)
  if (
    (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    !state.ready ||
    state.status !== 'READY' ||
    state.rotationDrafts.size !== 0 ||
    state.rotationSeeds.size !== 0 ||
    !state.retiredBranches.has(branchClass)
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  const oldLease = LIVE_PAIR_BY_MANAGER.get(manager)
  const oldRecord = oldLease ? LIVE_PAIR_LEASES.get(oldLease) : null
  if (!oldRecord || oldRecord.spent) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  LIVE_PAIR_BY_MANAGER.delete(manager)
  oldRecord.spent = true
  LIVE_PAIR_LEASES.delete(oldLease)
  SPENT_LIVE_PAIR_LEASES.add(oldLease)
  const retired = state.retiredBranches.get(branchClass)
  state.retiredBranches.delete(branchClass)
  try {
    const lease = claimLiveRoutePair(manager)
    return Object.freeze({
      lease,
      pair: readLiveRoutePair(lease),
      retired
    })
  } catch (err) {
    state.retiredBranches.set(branchClass, retired)
    throw err
  }
}

function registerRouteManagerReadySink(manager, sink) {
  const state = readRouteManager(manager)
  const initialRegistration =
    !state.ready && state.initialDrafts === null && state.status === 'EMPTY'
  const rotationRegistration =
    state.ready &&
    state.status === 'READY' &&
    state.rotationDrafts.size === 0 &&
    state.rotationSeeds.size === 0
  if (
    state.readySink !== null ||
    (!initialRegistration && !rotationRegistration) ||
    !isObject(sink) ||
    !Object.isFrozen(sink) ||
    Reflect.ownKeys(sink).length !== 0
  )
    throw PrivateRouteError.UNAUTHORIZED()
  state.readySink = sink
  return true
}

function registerRouteManagerLifecycleSinks(manager, sinks) {
  const state = readRouteManager(manager)
  exactObject(sinks, LIFECYCLE_SINK_FIELDS)
  if (
    state.status !== 'EMPTY' ||
    state.ready ||
    state.initialDrafts !== null ||
    state.lifecycleRegistered
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  for (const field of LIFECYCLE_SINK_FIELDS) {
    const sink = sinks[field]
    if (!isObject(sink) || !Object.isFrozen(sink) || Reflect.ownKeys(sink).length !== 0) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    state.lifecycleSinks[field] = sink
  }
  registerRelayCandidateDirectoryRollbackSink(
    state.candidateDirectory,
    state.lifecycleSinks.wallClockRollback
  )
  state.lifecycleRegistered = true
  return true
}

function registerRouteManagerReplacementSinks(manager, branchClass, sinks) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  const fields =
    branchClass === BRANCH_CLASS.LOOKUP
      ? ['lookupBranchLoss', 'lookupBranchExpiry']
      : ['announceBranchLoss', 'announceBranchExpiry']
  exactObject(sinks, fields)
  const beforeRotation =
    state.status === 'READY' && state.rotationDrafts.size === 0 && state.rotationSeeds.size === 0
  const duringRotation =
    state.status === 'ROTATING' &&
    state.rotationDrafts.size === 1 &&
    state.rotationDrafts.has(branchClass) &&
    state.rotationSeeds.size === 0
  if (!state.ready || (!beforeRotation && !duringRotation)) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  for (const field of fields) {
    const sink = sinks[field]
    if (!isObject(sink) || !Object.isFrozen(sink) || Reflect.ownKeys(sink).length !== 0) {
      throw PrivateRouteError.UNAUTHORIZED()
    }
    state.lifecycleSinks[field] = sink
  }
  return true
}

// A branch expiry is a standing condition on the branch, not an event: the
// material stays past its rotation lead until the branch is replaced. The signal
// carrying it is one-shot, so a delivery the controller refuses - it accepts
// branch signals only in READY - consumes the sink and, because `expired` has
// already dropped the timer, retires the branch's only rotation trigger for good.
// This restores the trigger: the controller hands back a fresh sink for the slot
// its refused delivery emptied, and the manager re-arms its own clock so the
// redelivery does not depend on the controller reaching any particular state.
// Only an empty slot can be filled, so this can never displace a live sink.
function renewRouteManagerBranchExpiry(manager, branchClass, sink) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  if (!isObject(sink) || !Object.isFrozen(sink) || Reflect.ownKeys(sink).length !== 0) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const key = branchSinkKey(branchClass, 'BranchExpiry')
  if (!state.lifecycleRegistered || state.lifecycleSinks[key] !== null) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  state.lifecycleSinks[key] = sink
  try {
    return armBranchExpiry(state, branchClass, BRANCH_EXPIRY_RETRY_MS)
  } catch (err) {
    state.lifecycleSinks[key] = null
    throw err
  }
}

function createRouteManagerBranchLossRegistration(manager, branchClass) {
  const state = readRouteManager(manager)
  if (
    (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) ||
    !state.ready ||
    state.status !== 'READY' ||
    !state.branches.has(branchClass)
  ) {
    throw PrivateRouteError.UNAUTHORIZED()
  }
  const registration = Object.freeze({})
  BRANCH_PHYSICAL_LOSS_REGISTRATIONS.set(registration, {
    manager,
    state,
    branchClass
  })
  state.physicalLossRegistrations.add(registration)
  return registration
}

function revokeRouteManagerBranchLossRegistration(registration) {
  const record = isObject(registration)
    ? BRANCH_PHYSICAL_LOSS_REGISTRATIONS.get(registration)
    : null
  if (!record) return false
  BRANCH_PHYSICAL_LOSS_REGISTRATIONS.delete(registration)
  SPENT_BRANCH_PHYSICAL_LOSS_REGISTRATIONS.add(registration)
  record.state.physicalLossRegistrations.delete(registration)
  return true
}

function issueRouteManagerBranchPhysicalLoss(registration) {
  const record = isObject(registration)
    ? BRANCH_PHYSICAL_LOSS_REGISTRATIONS.get(registration)
    : null
  if (!record) {
    if (isObject(registration) && SPENT_BRANCH_PHYSICAL_LOSS_REGISTRATIONS.has(registration)) {
      throw PrivateRouteError.ERR_REPLAY()
    }
    throw PrivateRouteError.UNAUTHORIZED()
  }
  revokeRouteManagerBranchLossRegistration(registration)
  return reportRouteManagerBranchLoss(record.manager, record.branchClass)
}

function reportRouteManagerBranchLoss(manager, branchClass) {
  const state = readRouteManager(manager)
  if (branchClass !== BRANCH_CLASS.LOOKUP && branchClass !== BRANCH_CLASS.ANNOUNCE) invalid()
  if (!state.ready || state.status !== 'READY') return false
  const branch = state.branches.get(branchClass)
  if (!branch || branch.lost) return false
  branch.lost = true
  state.capabilities.delete(branchClass)
  return issueBranchSink(state, branchClass, 'BranchLoss')
}

function readRouteManagerGenerations(manager) {
  const state = readRouteManager(manager)
  if (
    !state.ready ||
    state.status !== 'READY' ||
    state.rotationDrafts.size !== 0 ||
    state.rotationSeeds.size !== 0
  ) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  return Object.freeze({
    lookupGeneration: state.lookupGeneration,
    announceGeneration: state.announceGeneration
  })
}

function createRouteManagerWithGenerations(options, lookupGeneration, announceGeneration) {
  exactObject(options, MANAGER_FIELDS)
  if (
    typeof lookupGeneration !== 'bigint' ||
    lookupGeneration < 1n ||
    typeof announceGeneration !== 'bigint' ||
    announceGeneration < 1n
  )
    invalid()
  if (!isGuardLease(options.guardLease)) throw PrivateRouteError.UNAUTHORIZED()
  if (!isObject(options.candidateDirectory)) invalid()
  const extensionState = readManagerFactory(readRouteExtensionFactory, options.extensionFactory)
  const terminalState = readManagerFactory(readFinalExitActivationFactory, options.terminalFactory)
  if (
    extensionState.wallNow !== terminalState.wallNow ||
    extensionState.monotonicNow !== options.monotonicNow ||
    terminalState.monotonicNow !== options.monotonicNow ||
    extensionState.monotonicNow !== terminalState.monotonicNow ||
    extensionState.randomBytes !== options.randomBytes ||
    terminalState.randomBytes !== options.randomBytes ||
    extensionState.randomBytes !== terminalState.randomBytes ||
    extensionState.schedule !== terminalState.schedule ||
    extensionState.cancelScheduled !== terminalState.cancelScheduled
  ) {
    invalid()
  }
  if (typeof options.monotonicNow !== 'function' || typeof options.randomBytes !== 'function')
    invalid()
  const manager = new RouteManager()
  MANAGERS.set(manager, {
    guardLease: options.guardLease,
    candidateDirectory: options.candidateDirectory,
    extensionFactory: options.extensionFactory,
    terminalFactory: options.terminalFactory,
    extensionClock: extensionState,
    terminalClock: terminalState,
    monotonicNow: options.monotonicNow,
    randomBytes: options.randomBytes,
    lookupGeneration,
    announceGeneration,
    initialDrafts: null,
    initialSeedDraft: null,
    initialDeadline: null,
    initialSeedTimer: null,
    branchExpiryTimers: new Map(),
    lifecycleRegistered: false,
    lifecycleSinks: {
      lookupBranchLoss: null,
      announceBranchLoss: null,
      lookupBranchExpiry: null,
      announceBranchExpiry: null,
      wallClockRollback: null
    },
    rotationDrafts: new Map(),
    rotationSeeds: new Map(),
    committedDrafts: new Set(),
    branches: new Map(),
    capabilities: new Map(),
    status: 'EMPTY',
    ready: false,
    seedPending: false,
    building: false,
    readySink: null,
    manager,
    destroyed: false,
    retiredBranches: new Map(),
    physicalLossRegistrations: new Set()
  })
  for (const observer of ROUTE_MANAGER_CREATION_OBSERVERS) {
    try {
      observer(manager)
    } catch {}
  }
  return Object.freeze(manager)
}
function createRouteManager(options) {
  return createRouteManagerWithGenerations(options, 1n, 1n)
}

function createResumedRouteManager(options) {
  if (
    !isObject(options) ||
    Reflect.ownKeys(options).length !== 3 ||
    !Object.hasOwn(options, 'managerOptions') ||
    !Object.hasOwn(options, 'lookupGeneration') ||
    !Object.hasOwn(options, 'announceGeneration')
  )
    invalid()
  return createRouteManagerWithGenerations(
    options.managerOptions,
    options.lookupGeneration,
    options.announceGeneration
  )
}

function isRouteManager(manager) {
  const state = isObject(manager) ? MANAGERS.get(manager) : null
  return !!(state && !state.destroyed)
}

function consumeSuspendedDirectory(reconnect) {
  const record =
    reconnect !== null && typeof reconnect === 'object'
      ? SUSPENDED_DIRECTORIES.get(reconnect)
      : null
  if (!record) throw PrivateRouteError.ERR_REPLAY()
  SUSPENDED_DIRECTORIES.delete(reconnect)
  return Object.freeze({
    directory: record.directory,
    lookupGeneration: record.lookupGeneration,
    announceGeneration: record.announceGeneration
  })
}

module.exports = {
  INITIAL_PAIR_DEADLINE_MS,
  TEST_ONLY_ROUTE_MANAGER_OBSERVER,
  TEST_ONLY_ROUTE_MANAGER_FACTORY_ISSUER,
  createFinalExitActivationFactory,
  receiveInitialSeedPair,
  createRouteExtensionFactory,
  readFinalExitActivationFactory,
  readRouteExtensionFactory,
  createRouteManager,
  createRouteManagerBranchLossRegistration,
  readRouteManagerGenerations,
  registerRouteManagerLifecycleSinks,
  registerRouteManagerReplacementSinks,
  renewRouteManagerBranchExpiry,
  issueRouteManagerBranchPhysicalLoss,
  revokeRouteManagerBranchLossRegistration,
  reportRouteManagerBranchLoss,
  registerRouteManagerReadySink,
  claimLiveRoutePair,
  claimRotatedLiveRoutePair,
  readLiveRoutePair,
  revokeLiveRoutePair,
  isRouteManager,
  [SUSPENDED_DIRECTORY_CONSUMER]: consumeSuspendedDirectory,
  [RESUMED_ROUTE_MANAGER_FACTORY]: createResumedRouteManager
}
