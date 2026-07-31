const { PrivateRouteError } = require('./errors')

const CLAIMS = new WeakMap()
const HANDOFF_CLAIMS = new WeakMap()
const SPENT_CLAIMS = new WeakSet()
const OWNERS = new WeakMap()
const DESTROYED_OWNERS = new WeakSet()
const RESERVATIONS = new WeakMap()
const SPENT_RESERVATIONS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function object(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}

function createFinalExitActivationClaim(handoff) {
  if (!object(handoff) || HANDOFF_CLAIMS.has(handoff)) invalid()
  const claim = Object.freeze({})
  CLAIMS.set(claim, { handoff })
  HANDOFF_CLAIMS.set(handoff, claim)
  return claim
}

function revokeFinalExitActivationClaim(claim) {
  if (!object(claim)) return false
  const record = CLAIMS.get(claim)
  if (!record) return false
  CLAIMS.delete(claim)
  HANDOFF_CLAIMS.delete(record.handoff)
  SPENT_CLAIMS.add(claim)
  record.handoff = null
  return true
}

function claimFinalExitActivation(handoff, claim) {
  const record = object(claim) ? CLAIMS.get(claim) : null
  if (!record) {
    if (object(claim) && SPENT_CLAIMS.has(claim)) replay()
    authentication()
  }
  if (!object(handoff) || record.handoff !== handoff || HANDOFF_CLAIMS.get(handoff) !== claim) {
    authentication()
  }
  CLAIMS.delete(claim)
  HANDOFF_CLAIMS.delete(handoff)
  SPENT_CLAIMS.add(claim)
  record.handoff = null
  let prepared = null
  let owner = null
  let complete = false
  try {
    owner = Object.freeze({})
    OWNERS.set(owner, {
      material: null,
      reservation: null,
      consumed: false,
      destroyed: false
    })
    const {
      prepareTailControlFinalExitActivation,
      commitTailControlFinalExitActivation
    } = require('./tail-control')
    prepared = prepareTailControlFinalExitActivation(handoff, owner)
    OWNERS.get(owner).material = prepared.material
    commitTailControlFinalExitActivation(prepared.transfer, owner)
    complete = true
    return owner
  } finally {
    if (!complete) {
      if (prepared) {
        const { revokeTailControlFinalExitActivation } = require('./tail-control')
        revokeTailControlFinalExitActivation(prepared.transfer)
      }
      if (owner) destroyFinalExitActivationOwner(owner)
    }
  }
}

function reserveFinalExitActivationOwner(owner) {
  const record = object(owner) ? OWNERS.get(owner) : null
  if (!record || record.destroyed || record.consumed || DESTROYED_OWNERS.has(owner)) invalid()
  if (record.reservation !== null) replay()
  const reservation = Object.freeze({})
  const reservationState = {
    reservation,
    owner,
    record,
    destroyed: false
  }
  record.reservation = reservationState
  RESERVATIONS.set(reservation, reservationState)
  return reservation
}

function consumeFinalExitActivationOwnerReservation(reservation, owner) {
  const reservationState = object(reservation) ? RESERVATIONS.get(reservation) : null
  if (!reservationState) {
    if (object(reservation) && SPENT_RESERVATIONS.has(reservation)) replay()
    authentication()
  }
  const record = object(owner) ? OWNERS.get(owner) : null
  if (
    !record ||
    record.destroyed ||
    record.consumed ||
    DESTROYED_OWNERS.has(owner) ||
    reservationState.destroyed ||
    reservationState.owner !== owner ||
    reservationState.record !== record ||
    record.reservation !== reservationState
  ) {
    authentication()
  }
  RESERVATIONS.delete(reservation)
  SPENT_RESERVATIONS.add(reservation)
  reservationState.reservation = null
  reservationState.destroyed = true
  record.reservation = null
  record.consumed = true
  return record.material
}

function revokeFinalExitActivationOwnerReservation(reservation) {
  const reservationState = object(reservation) ? RESERVATIONS.get(reservation) : null
  if (!reservationState || reservationState.destroyed) return false
  RESERVATIONS.delete(reservation)
  SPENT_RESERVATIONS.add(reservation)
  reservationState.destroyed = true
  if (reservationState.record && reservationState.record.reservation === reservationState) {
    reservationState.record.reservation = null
  }
  reservationState.reservation = null
  reservationState.owner = null
  reservationState.record = null
  return true
}

function destroyFinalExitActivationOwner(owner) {
  const record = object(owner) ? OWNERS.get(owner) : null
  if (!record || record.destroyed || DESTROYED_OWNERS.has(owner)) return false
  OWNERS.delete(owner)
  DESTROYED_OWNERS.add(owner)
  record.destroyed = true
  const material = record.material
  if (material && object(material.tailControl)) {
    try {
      const { destroyTailControlFinalExitActivation } = require('./tail-control')
      destroyTailControlFinalExitActivation(material.tailControl, owner)
    } catch {}
  }
  record.material = null
  if (record.reservation !== null) {
    const reservationState = record.reservation
    RESERVATIONS.delete(reservationState.reservation)
    SPENT_RESERVATIONS.add(reservationState.reservation)
    reservationState.destroyed = true
    reservationState.reservation = null
    reservationState.owner = null
    reservationState.record = null
    record.reservation = null
  }
  const { destroyFinalExitHandoffMaterial } = require('./final-exit-handoff')
  destroyFinalExitHandoffMaterial(material)
  return true
}

module.exports = {
  claimFinalExitActivation,
  consumeFinalExitActivationOwnerReservation,
  createFinalExitActivationClaim,
  destroyFinalExitActivationOwner,
  reserveFinalExitActivationOwner,
  revokeFinalExitActivationClaim,
  revokeFinalExitActivationOwnerReservation
}
