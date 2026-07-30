const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const {
  consumeSelectedRelayEvidence
} = require('./relay-candidate-directory')
const { decodeRelayCapabilityAdvertisement } = require('./relay-capability')

const REQUESTS = new WeakMap()
const TRANSFERS = new WeakMap()
const SPENT_REQUESTS = new WeakSet()
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
  'now',
  'position',
  'randomBytes',
  'schedule',
  'selection',
  'signedExpiry',
  'tailControl',
  'tailControlTransportFactory',
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
  let keys
  try {
    if (!object(value)) invalid()
    keys = Reflect.ownKeys(value)
  } catch {
    invalid()
  }
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== 'string' || !expected.includes(key))
  ) {
    invalid()
  }
}

function validTailControl(value) {
  return (
    object(value) &&
    typeof value.sealExtend === 'function' &&
    typeof value.openExtended === 'function' &&
    typeof value.completeClientExtension === 'function' &&
    typeof value.abortClientExtension === 'function' &&
    typeof value.destroy === 'function'
  )
}

function validTransport(value) {
  return (
    object(value) &&
    typeof value.send === 'function' &&
    typeof value.receive === 'function' &&
    typeof value.destroy === 'function'
  )
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
    typeof values.now !== 'function' ||
    typeof values.randomBytes !== 'function' ||
    typeof values.schedule !== 'function' ||
    typeof values.cancelScheduled !== 'function' ||
    typeof values.cancel !== 'function' ||
    !validTailControl(values.tailControl) ||
    typeof values.tailControlTransportFactory !== 'function'
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
      const start = nowValue(material.now)
      const expiresAt = min(
        start + MAX_EXTENSION_MS,
        material.absoluteDeadline,
        material.signedExpiry,
        decoded.expiresAtMs
      )
      if (expiresAt <= start) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
      this._material = material
      this._evidence = evidence
      this._expiresAt = expiresAt
      this._timer = null
      this._transport = null
      this._completion = null
      this._transfer = null
      this._opening = false
      this._destroyed = false
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
    try {
      this._arm()
      const transport = this._material.tailControlTransportFactory(Object.freeze({}))
      if (!validTransport(transport)) invalid()
      this._transport = transport
      const limits = createRouteExtensionLimits(
        this._material.limits,
        this._material.now,
        this._expiresAt
      )
      let extend = null
      try {
        extend = this._material.tailControl.sealExtend({
          advertisement: this._evidence.canonicalAdvertisement,
          advertisementDigest: this._evidence.advertisementDigest,
          extensionIndex: this._material.extensionIndex,
          requestedLimits: limits,
          absoluteDeadline: this._material.absoluteDeadline,
          randomBytes: this._material.randomBytes
        })
        await transport.send(extend)
        this._assertLive()
      } finally {
        clear(extend)
      }
      let extended = await transport.receive()
      if (length(extended) < 1) invalid()
      try {
        this._completion = this._material.tailControl.openExtended(extended)
        this._assertLive()
      } finally {
        clear(extended)
        extended = null
      }
      let ready = await transport.receive()
      if (length(ready) < 1) invalid()
      let nextTail = null
      try {
        nextTail = this._material.tailControl.completeClientExtension(this._completion, ready)
        this._completion = null
        this._assertLive()
      } finally {
        clear(ready)
        ready = null
      }
      if (!object(nextTail) || typeof nextTail.destroy !== 'function') invalid()
      this._disarm()
      const transfer = Object.freeze({})
      TRANSFERS.set(transfer, { session: this, tailControl: nextTail, transport })
      this._transfer = transfer
      this._transport = null
      this._clearEvidence()
      return transfer
    } catch (err) {
      this._terminate()
      if (err instanceof PrivateRouteError) throw err
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    } finally {
      this._opening = false
    }
  }

  diagnostics() {
    return Object.freeze({ state: this._destroyed ? 'DESTROYED' : this._transfer ? 'ACTIVE' : 'REQUESTED' })
  }

  destroy() {
    if (this._destroyed) return false
    this._terminate()
    return true
  }

  _arm() {
    const current = nowValue(this._material.now)
    if (current >= this._expiresAt) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    let fired = false
    const callback = () => {
      fired = true
      this._terminate()
    }
    this._timer = this._material.schedule(callback, Number(this._expiresAt - current))
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
    if (this._destroyed || nowValue(this._material.now) >= this._expiresAt) {
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
        try { moved.tailControl.destroy() } catch {}
        try { moved.transport.destroy() } catch {}
      }
      this._transfer = null
    }
    if (this._transport) {
      try { this._transport.destroy() } catch {}
      this._transport = null
    }
    if (material) {
      try { material.tailControl.destroy() } catch {}
    }
    this._clearEvidence()
    this._material = null
    return true
  }
}

module.exports = {
  RouteExtensionSession,
  createRouteExtensionLimits,
  createRouteExtensionSessionRequest,
  takeRouteExtensionTransfer
}
