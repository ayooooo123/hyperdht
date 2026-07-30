const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')

const LINK_OFFER_SIZE = 374
const LINK_ACCEPT_SIZE = 285
const REDACTED_RESPONDER_PROOF_SIZE = 378
const CANONICAL_ENDPOINT_SIZE = 19
const OFFER_RECEIVERS = new WeakMap()
const RESPONSE_RECEIVERS = new WeakMap()
const RESPONSE_WRITERS = new WeakMap()
const SPENT_OFFER_RECEIVERS = new WeakSet()
const SPENT_RESPONSE_RECEIVERS = new WeakSet()
const SPENT_RESPONSE_WRITERS = new WeakSet()
const EMPTY_ARGUMENTS = []
const applyIntrinsic = Reflect.apply
const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const setIntrinsic = Uint8Array.prototype.set
const fillIntrinsic = Uint8Array.prototype.fill

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

function option(value, key) {
  try {
    return value[key]
  } catch {
    invalid()
  }
}

function length(value) {
  try {
    return b4a.isBuffer(value) ? byteLengthGetter.call(value) : -1
  } catch {
    return -1
  }
}

function copy(value, size) {
  if (length(value) !== size) invalid()
  const result = b4a.allocUnsafeSlow(size)
  try {
    setIntrinsic.call(result, value)
    return result
  } catch {
    clear(result)
    invalid()
  }
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) fillIntrinsic.call(value, 0)
  } catch {}
}

function channelDestructor(value) {
  if (!object(value)) return null
  const callback = option(value, 'destroy')
  return typeof callback === 'function' ? callback : null
}

function destroyChannel(callback, channel) {
  try {
    applyIntrinsic(callback, channel, EMPTY_ARGUMENTS)
  } catch {}
}

function destroy(callback) {
  try {
    callback()
  } catch {}
}

function destroyedOrReplay(value, spent) {
  if (object(value) && spent.has(value)) replay()
  authentication()
}

function createExtensionOfferReceiver(options = {}) {
  if (!object(options)) invalid()
  let observedPredecessorEndpoint = null
  try {
    const receiveObject = option(options, 'receiveObject')
    const takePhysicalChannel = option(options, 'takePhysicalChannel')
    const sendObject = option(options, 'sendObject')
    const finish = option(options, 'finish')
    const destroy = option(options, 'destroy')
    if (
      typeof receiveObject !== 'function' ||
      typeof takePhysicalChannel !== 'function' ||
      typeof sendObject !== 'function' ||
      typeof finish !== 'function' ||
      typeof destroy !== 'function'
    ) {
      invalid()
    }
    observedPredecessorEndpoint = copy(
      option(options, 'observedPredecessorEndpoint'),
      CANONICAL_ENDPOINT_SIZE
    )
    const receiver = Object.freeze({})
    OFFER_RECEIVERS.set(receiver, {
      receiveObject,
      takePhysicalChannel,
      sendObject,
      finish,
      destroy,
      observedPredecessorEndpoint
    })
    observedPredecessorEndpoint = null
    return receiver
  } finally {
    clear(observedPredecessorEndpoint)
  }
}

function isExtensionOfferReceiver(value) {
  return object(value) && OFFER_RECEIVERS.has(value)
}

function destroyExtensionOfferReceiver(receiver) {
  const state = object(receiver) ? OFFER_RECEIVERS.get(receiver) : null
  if (!state) return false
  OFFER_RECEIVERS.delete(receiver)
  SPENT_OFFER_RECEIVERS.add(receiver)
  clear(state.observedPredecessorEndpoint)
  destroy(state.destroy)
  return true
}

function takeExtensionOffer(receiver) {
  const state = object(receiver) ? OFFER_RECEIVERS.get(receiver) : null
  if (!state) destroyedOrReplay(receiver, SPENT_OFFER_RECEIVERS)
  OFFER_RECEIVERS.delete(receiver)
  SPENT_OFFER_RECEIVERS.add(receiver)
  let offer = null
  let extra = null
  let observedPredecessorEndpoint = null
  let physicalChannel = null
  let physicalChannelDestroy = null
  let responseWriter = null
  let transferred = false
  try {
    offer = copy(state.receiveObject(), LINK_OFFER_SIZE)
    extra = state.receiveObject()
    if (extra !== null) invalid()
    observedPredecessorEndpoint = state.observedPredecessorEndpoint
    state.observedPredecessorEndpoint = null
    const physicalChannelCandidate = state.takePhysicalChannel()
    const physicalChannelCandidateDestroy = channelDestructor(physicalChannelCandidate)
    if (!physicalChannelCandidateDestroy) invalid()
    physicalChannel = physicalChannelCandidate
    physicalChannelDestroy = physicalChannelCandidateDestroy
    responseWriter = Object.freeze({})
    RESPONSE_WRITERS.set(responseWriter, {
      sendObject: state.sendObject,
      finish: state.finish,
      phase: 0
    })
    const result = Object.freeze({
      offer,
      observedPredecessorEndpoint,
      physicalChannel,
      responseWriter
    })
    offer = null
    observedPredecessorEndpoint = null
    physicalChannel = null
    physicalChannelDestroy = null
    responseWriter = null
    transferred = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(extra)
    clear(offer)
    clear(observedPredecessorEndpoint)
    clear(state.observedPredecessorEndpoint)
    state.observedPredecessorEndpoint = null
    if (!transferred) {
      if (responseWriter) {
        RESPONSE_WRITERS.delete(responseWriter)
        SPENT_RESPONSE_WRITERS.add(responseWriter)
      }
      if (physicalChannel) {
        destroyChannel(physicalChannelDestroy, physicalChannel)
      } else {
        destroy(state.destroy)
      }
    }
  }
}

function sendExtensionAccept(writer, encodedAccept) {
  const state = object(writer) ? RESPONSE_WRITERS.get(writer) : null
  if (!state) destroyedOrReplay(writer, SPENT_RESPONSE_WRITERS)
  if (state.phase !== 0) replay()
  let accept = null
  try {
    accept = copy(encodedAccept, LINK_ACCEPT_SIZE)
    state.sendObject(accept)
    accept = null
    state.phase = 1
    return true
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(accept)
  }
}

function sendExtensionProof(writer, encodedProof) {
  const state = object(writer) ? RESPONSE_WRITERS.get(writer) : null
  if (!state) destroyedOrReplay(writer, SPENT_RESPONSE_WRITERS)
  if (state.phase !== 1) replay()
  let proof = null
  try {
    proof = copy(encodedProof, REDACTED_RESPONDER_PROOF_SIZE)
    state.sendObject(proof)
    proof = null
    state.phase = 2
    return true
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(proof)
  }
}

function finishExtensionResponse(writer) {
  const state = object(writer) ? RESPONSE_WRITERS.get(writer) : null
  if (!state) destroyedOrReplay(writer, SPENT_RESPONSE_WRITERS)
  if (state.phase !== 2) replay()
  RESPONSE_WRITERS.delete(writer)
  SPENT_RESPONSE_WRITERS.add(writer)
  try {
    state.finish()
    return true
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function destroyExtensionResponseWriter(writer) {
  if (!object(writer) || !RESPONSE_WRITERS.has(writer)) return false
  RESPONSE_WRITERS.delete(writer)
  SPENT_RESPONSE_WRITERS.add(writer)
  return true
}

function createExtensionResponseReceiver(options = {}) {
  if (!object(options)) invalid()
  const receiveObject = option(options, 'receiveObject')
  const takePhysicalChannel = option(options, 'takePhysicalChannel')
  const destroy = option(options, 'destroy')
  if (
    typeof receiveObject !== 'function' ||
    typeof takePhysicalChannel !== 'function' ||
    typeof destroy !== 'function'
  ) {
    invalid()
  }
  const receiver = Object.freeze({})
  RESPONSE_RECEIVERS.set(receiver, { receiveObject, takePhysicalChannel, destroy })
  return receiver
}

function isExtensionResponseReceiver(value) {
  return object(value) && RESPONSE_RECEIVERS.has(value)
}

function destroyExtensionResponseReceiver(receiver) {
  const state = object(receiver) ? RESPONSE_RECEIVERS.get(receiver) : null
  if (!state) return false
  RESPONSE_RECEIVERS.delete(receiver)
  SPENT_RESPONSE_RECEIVERS.add(receiver)
  destroy(state.destroy)
  return true
}

function takeExtensionResponse(receiver) {
  const state = object(receiver) ? RESPONSE_RECEIVERS.get(receiver) : null
  if (!state) destroyedOrReplay(receiver, SPENT_RESPONSE_RECEIVERS)
  RESPONSE_RECEIVERS.delete(receiver)
  SPENT_RESPONSE_RECEIVERS.add(receiver)
  let accept = null
  let proof = null
  let extra = null
  let physicalChannel = null
  let physicalChannelDestroy = null
  let transferred = false
  try {
    accept = copy(state.receiveObject(), LINK_ACCEPT_SIZE)
    proof = copy(state.receiveObject(), REDACTED_RESPONDER_PROOF_SIZE)
    extra = state.receiveObject()
    if (extra !== null) invalid()
    const physicalChannelCandidate = state.takePhysicalChannel()
    const physicalChannelCandidateDestroy = channelDestructor(physicalChannelCandidate)
    if (!physicalChannelCandidateDestroy) invalid()
    physicalChannel = physicalChannelCandidate
    physicalChannelDestroy = physicalChannelCandidateDestroy
    const result = Object.freeze({ accept, proof, physicalChannel })
    accept = null
    proof = null
    physicalChannel = null
    physicalChannelDestroy = null
    transferred = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(accept)
    clear(proof)
    clear(extra)
    if (!transferred) {
      if (physicalChannel) {
        destroyChannel(physicalChannelDestroy, physicalChannel)
      } else {
        destroy(state.destroy)
      }
    }
  }
}

module.exports = {
  createExtensionOfferReceiver,
  isExtensionOfferReceiver,
  destroyExtensionOfferReceiver,
  takeExtensionOffer,
  sendExtensionAccept,
  sendExtensionProof,
  finishExtensionResponse,
  destroyExtensionResponseWriter,
  createExtensionResponseReceiver,
  isExtensionResponseReceiver,
  destroyExtensionResponseReceiver,
  takeExtensionResponse
}
