const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const { consumeSelectedRelayEvidence } = require('./relay-candidate-directory')
const { decodeRelayCapabilityAdvertisement } = require('./relay-capability')
const { decodeM3ContextEnvelope, encodeM3ContextEnvelope } = require('./m3-context')
const { CONTEXT_CLASS } = require('./protocol')

const REQUESTS = new WeakMap()
const FACTORIES = new WeakMap()
const TRANSFERS = new WeakMap()
const SPENT_REQUESTS = new WeakSet()
const TAIL_CONTROL_FRAME_SIZE = 1100
const SPENT_TRANSFERS = new WeakSet()
const MAX_EXTENSION_MS = 5_000n
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn
const DEFAULT_LIMITS = Object.freeze({
  maxCells: 64,
  maxBytes: 65_536,
  maxCommands: 10,
  idleTimeoutMs: 5_000
})
const LIMIT_KEYS = new Set(Object.keys(DEFAULT_LIMITS))
const EXPECTED_REQUEST_KEYS = Object.freeze([
  'absoluteDeadline',
  'branchClass',
  'cancel',
  'cancelScheduled',
  'extensionIndex',
  'generation',
  'limits',
  'monotonicNow',
  'position',
  'randomBytes',
  'schedule',
  'selection',
  'signedExpiry',
  'tailControl',
  'transaction',
  'wallNow'
])
const FACTORY_KEYS = Object.freeze([
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'schedule',
  'cancelScheduled'
])
const OPEN_KEYS = Object.freeze([
  'absoluteDeadline',
  'branchClass',
  'cancel',
  'extensionIndex',
  'generation',
  'limits',
  'position',
  'selection',
  'signedExpiry',
  'tailControl',
  'transaction'
])
const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
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

function length(value) {
  try {
    return b4a.isBuffer(value) ? byteLengthGetter.call(value) : -1
  } catch {
    return -1
  }
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) fillIntrinsic.call(value, 0)
  } catch {}
}

function encodeTailControlEnvelope(encoded) {
  let frame = null
  try {
    frame = b4a.alloc(TAIL_CONTROL_FRAME_SIZE)
    frame.set(encoded)
    return encodeM3ContextEnvelope({
      contextClass: CONTEXT_CLASS.TAIL_CONTROL_ORDERED,
      frame
    })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(frame)
  }
}

function decodeTailControlEnvelope(envelope, byteLength) {
  let decoded = null
  let output = null
  let complete = false
  try {
    decoded = decodeM3ContextEnvelope(envelope)
    if (
      decoded.contextClass !== CONTEXT_CLASS.TAIL_CONTROL_ORDERED ||
      length(decoded.frame) !== TAIL_CONTROL_FRAME_SIZE
    ) {
      invalid()
    }
    for (let index = byteLength; index < TAIL_CONTROL_FRAME_SIZE; index++) {
      if (decoded.frame[index] !== 0) invalid()
    }
    output = b4a.from(decoded.frame.subarray(0, byteLength))
    complete = true
    return output
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(decoded && decoded.frame)
    if (!complete) clear(output)
  }
}

function releaseTailControlEnvelope(transport, envelope) {
  try {
    transport.release(envelope)
  } catch {}
}

function nowValue(now) {
  let value
  try {
    value = now()
  } catch {
    invalid()
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) invalid()
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT64) invalid()
  return value
}

function min(...values) {
  let selected = values[0]
  for (let index = 1; index < values.length; index++) {
    if (values[index] < selected) selected = values[index]
  }
  return selected
}

function exactObject(value, expected) {
  let names
  try {
    if (!object(value)) invalid()
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) invalid()
    if (Object.getOwnPropertySymbols(value).length !== 0) invalid()
    names = Object.getOwnPropertyNames(value)
    if (names.length !== expected.length) invalid()
    for (const key of expected) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function validTailControl(value) {
  if (!object(value)) return false
  const { isTailControlSession } = require('./tail-control')
  return isTailControlSession(value)
}

function validTransport(value) {
  return (
    object(value) &&
    typeof value.send === 'function' &&
    typeof value.receive === 'function' &&
    typeof value.release === 'function'
  )
}
function createRouteExtensionFactory(options) {
  exactObject(options, FACTORY_KEYS)
  const { wallNow, monotonicNow, randomBytes, schedule, cancelScheduled } = options
  if (
    typeof wallNow !== 'function' ||
    typeof monotonicNow !== 'function' ||
    typeof randomBytes !== 'function' ||
    typeof schedule !== 'function' ||
    typeof cancelScheduled !== 'function'
  ) {
    invalid()
  }
  const factory = Object.freeze({})
  FACTORIES.set(factory, { wallNow, monotonicNow, randomBytes, schedule, cancelScheduled })
  return factory
}

function readRouteExtensionFactory(factory) {
  const state = object(factory) ? FACTORIES.get(factory) : null
  if (!state) authentication()
  return state
}

async function openRouteExtension(factory, options) {
  const clock = readRouteExtensionFactory(factory)
  exactObject(options, OPEN_KEYS)
  const request = createRouteExtensionSessionRequest({
    ...options,
    wallNow: clock.wallNow,
    monotonicNow: clock.monotonicNow,
    randomBytes: clock.randomBytes,
    schedule: clock.schedule,
    cancelScheduled: clock.cancelScheduled
  })
  const session = new RouteExtensionSession(request)
  return session.open()
}

function createRouteExtensionLimits(limits, now, deadline) {
  if (!object(limits) || !Object.isFrozen(limits)) invalid()
  if (typeof deadline !== 'bigint' || deadline < 1n || deadline > MAX_UINT64) invalid()
  const keys = Reflect.ownKeys(limits)
  const selected = { ...DEFAULT_LIMITS }
  for (const key of keys) {
    if (typeof key !== 'string' || !LIMIT_KEYS.has(key)) invalid()
    const value = limits[key]
    if (!Number.isInteger(value) || value < 1 || value > DEFAULT_LIMITS[key]) invalid()
    selected[key] = value
  }
  const current = nowValue(now)
  if (deadline <= current || current > MAX_UINT64 - MAX_EXTENSION_MS) {
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  return Object.freeze({
    cellSize: 1200,
    maxCells: selected.maxCells,
    maxBytes: selected.maxBytes,
    maxCommands: selected.maxCommands,
    idleTimeoutMs: selected.idleTimeoutMs,
    expiresAtMs: min(current + MAX_EXTENSION_MS, deadline)
  })
}

function normalizeRequest(options) {
  exactObject(options, EXPECTED_REQUEST_KEYS)
  const values = {}
  for (const key of EXPECTED_REQUEST_KEYS) values[key] = options[key]
  if (
    (values.position !== 'middle' && values.position !== 'exit') ||
    values.extensionIndex !== (values.position === 'middle' ? 1 : 2) ||
    typeof values.generation !== 'bigint' ||
    values.generation < 1n ||
    typeof values.absoluteDeadline !== 'bigint' ||
    typeof values.signedExpiry !== 'bigint' ||
    !object(values.limits) ||
    !Object.isFrozen(values.limits) ||
    typeof values.wallNow !== 'function' ||
    typeof values.monotonicNow !== 'function' ||
    typeof values.randomBytes !== 'function' ||
    typeof values.schedule !== 'function' ||
    typeof values.cancelScheduled !== 'function' ||
    typeof values.cancel !== 'function' ||
    !validTailControl(values.tailControl)
  ) {
    invalid()
  }
  return values
}

function createRouteExtensionSessionRequest(options) {
  const request = Object.freeze({})
  REQUESTS.set(request, normalizeRequest(options))
  return request
}

function takeRequest(request) {
  const material = object(request) ? REQUESTS.get(request) : null
  if (!material) {
    if (object(request) && SPENT_REQUESTS.has(request)) replay()
    authentication()
  }
  REQUESTS.delete(request)
  SPENT_REQUESTS.add(request)
  return material
}

function takeRouteExtensionTransfer(transfer) {
  const material = object(transfer) ? TRANSFERS.get(transfer) : null
  if (!material) {
    if (object(transfer) && SPENT_TRANSFERS.has(transfer)) replay()
    authentication()
  }
  TRANSFERS.delete(transfer)
  SPENT_TRANSFERS.add(transfer)
  material.session._transfer = null
  material.session._destroyed = true
  material.session._material = null
  return Object.freeze({ tailControl: material.tailControl, transport: material.transport })
}

class RouteExtensionSession {
  constructor(request) {
    const material = takeRequest(request)
    let evidence = null
    let decoded = null
    try {
      evidence = consumeSelectedRelayEvidence(material.selection, {
        transaction: material.transaction,
        branchClass: material.branchClass,
        position: material.position,
        generation: material.generation
      })
      decoded = decodeRelayCapabilityAdvertisement(evidence.canonicalAdvertisement)
      const wallStart = nowValue(material.wallNow)
      const localStart = nowValue(material.monotonicNow)
      const delta = min(
        MAX_EXTENSION_MS,
        material.absoluteDeadline - localStart,
        material.signedExpiry - wallStart,
        decoded.expiresAtMs - wallStart
      )
      if (delta <= 0n) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      this._localExpiresAt = localStart + delta
      this._wireExpiresAt = wallStart + delta
      this._material = material
      this._evidence = evidence
      this._timer = null
      this._transport = null
      this._completion = null
      this._transfer = null
      this._opening = false
      this._destroyed = false
      this._expired = false
      Object.seal(this)
      evidence = null
    } finally {
      if (evidence) {
        clear(evidence.canonicalAdvertisement)
        clear(evidence.advertisementDigest)
      }
    }
  }

  async open(...args) {
    if (args.length !== 0) invalid()
    if (this._destroyed) throw PrivateRouteError.ERR_DESTROYED()
    if (this._opening || this._transfer) replay()
    this._opening = true
    let abandonReceives = null
    try {
      this._arm()
      const {
        EXTENDED_SIZE,
        TAIL_READY_SIZE,
        borrowTailControlTransport
      } = require('./tail-control')
      const transport = borrowTailControlTransport(this._material.tailControl)
      if (!validTransport(transport)) invalid()
      this._transport = transport
      const limits = createRouteExtensionLimits(
        this._material.limits,
        this._material.wallNow,
        this._wireExpiresAt
      )
      let extend = null
      let receiveAbandoned = false
      abandonReceives = () => {
        receiveAbandoned = true
        for (const promise of [extendedReceive, readyReceive]) {
          if (!promise) continue
          void promise.then((result) => {
            if (
              result &&
              result.envelope &&
              result.envelope !== extendedEnvelope &&
              result.envelope !== readyEnvelope
            ) {
              releaseTailControlEnvelope(transport, result.envelope)
            }
          })
        }
      }
      let extendedReceive = null
      let readyReceive = null
      let extendedEnvelope = null
      let readyEnvelope = null
      try {
        extend = this._material.tailControl.sealExtend({
          advertisement: this._evidence.canonicalAdvertisement,
          advertisementDigest: this._evidence.advertisementDigest,
          extensionIndex: this._material.extensionIndex,
          requestedLimits: limits,
          absoluteDeadline: this._localExpiresAt,
          randomBytes: this._material.randomBytes
        })
        const captureReceive = (promise) =>
          promise.then(
            (envelope) => {
              if (receiveAbandoned) {
                releaseTailControlEnvelope(transport, envelope)
                return Object.freeze({ abandoned: true })
              }
              return Object.freeze({ envelope })
            },
            (err) => Object.freeze({ err })
          )
        extendedReceive = captureReceive(transport.receive())
        readyReceive = captureReceive(transport.receive())
        await transport.send(encodeTailControlEnvelope(extend))
        this._assertLive()
        const extendedResult = await extendedReceive
        if (extendedResult.err) throw extendedResult.err
        if (extendedResult.abandoned) throw PrivateRouteError.ERR_DESTROYED()
        extendedReceive = null
        extendedEnvelope = extendedResult.envelope
      } finally {
        clear(extend)
      }
      let extended = null
      try {
        extended = decodeTailControlEnvelope(extendedEnvelope, EXTENDED_SIZE)
        this._completion = this._material.tailControl.openExtended(extended)
        this._assertLive()
      } finally {
        releaseTailControlEnvelope(transport, extendedEnvelope)
        extendedEnvelope = null
        clear(extended)
        extended = null
      }
      const readyResult = await readyReceive
      if (readyResult.err) throw readyResult.err
      readyReceive = null
      if (readyResult.abandoned) throw PrivateRouteError.ERR_DESTROYED()
      readyEnvelope = readyResult.envelope
      let ready = null
      let nextTail = null
      try {
        ready = decodeTailControlEnvelope(readyEnvelope, TAIL_READY_SIZE)
        nextTail = this._material.tailControl.completeClientExtension(this._completion, ready)
        this._completion = null
        this._assertLive()
      } finally {
        releaseTailControlEnvelope(transport, readyEnvelope)
        readyEnvelope = null
        clear(ready)
        ready = null
      }
      receiveAbandoned = true
      if (!validTailControl(nextTail)) invalid()
      this._disarm()
      const transfer = Object.freeze({})
      TRANSFERS.set(transfer, { session: this, tailControl: nextTail, transport })
      this._transfer = transfer
      this._transport = null
      this._clearEvidence()
      return transfer
    } catch (err) {
      if (abandonReceives) abandonReceives()
      let expired = this._expired
      const material = this._material
      if (!expired && material) {
        try {
          expired = nowValue(material.monotonicNow) >= this._localExpiresAt
        } catch {}
      }
      this._terminate()
      if (err instanceof PrivateRouteError && err.code === 'ERR_DESTROYED' && expired) {
        throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      }
      if (err instanceof PrivateRouteError) throw err
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    } finally {
      this._opening = false
    }
  }

  diagnostics() {
    return Object.freeze({
      state: this._destroyed ? 'DESTROYED' : this._transfer ? 'ACTIVE' : 'REQUESTED'
    })
  }

  destroy() {
    if (this._destroyed) return false
    this._terminate()
    return true
  }

  _arm() {
    const current = nowValue(this._material.monotonicNow)
    if (current >= this._localExpiresAt) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    let fired = false
    const callback = () => {
      fired = true
      this._expired = true
      this._terminate()
    }
    this._timer = this._material.schedule(callback, Number(this._localExpiresAt - current))
    if (fired || this._destroyed) throw PrivateRouteError.ERR_DESTROYED()
  }

  _disarm() {
    const timer = this._timer
    this._timer = null
    if (timer !== null) {
      try {
        this._material.cancelScheduled(timer)
      } catch {}
    }
  }

  _assertLive() {
    if (this._destroyed || nowValue(this._material.monotonicNow) >= this._localExpiresAt) {
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
  }

  _clearEvidence() {
    if (!this._evidence) return
    clear(this._evidence.canonicalAdvertisement)
    clear(this._evidence.advertisementDigest)
    this._evidence = null
  }

  _terminate() {
    if (this._destroyed) return false
    const material = this._material
    this._destroyed = true
    if (material) {
      try {
        material.cancel()
      } catch {}
    }
    this._disarm()
    if (this._completion && material) {
      try {
        material.tailControl.abortClientExtension(this._completion)
      } catch {}
    }
    this._completion = null
    if (this._transfer) {
      const moved = TRANSFERS.get(this._transfer)
      TRANSFERS.delete(this._transfer)
      SPENT_TRANSFERS.add(this._transfer)
      if (moved) {
        try {
          const { destroyTailControlSession } = require('./tail-control')
          destroyTailControlSession(moved.tailControl)
        } catch {}
      }
      this._transfer = null
    }
    if (material) {
      try {
        const { destroyTailControlSession } = require('./tail-control')
        destroyTailControlSession(material.tailControl)
      } catch {}
    }
    this._clearEvidence()
    this._material = null
    return true
  }
}

module.exports = {
  RouteExtensionSession,
  createRouteExtensionFactory,
  createRouteExtensionLimits,
  createRouteExtensionSessionRequest,
  openRouteExtension,
  readRouteExtensionFactory,
  takeRouteExtensionTransfer
}
