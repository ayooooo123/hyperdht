'use strict'

// Reflected-address discovery state and codecs. UdxCellEndpoint owns the live
// socket and performs every send/receive; this module never receives a socket.
//
// Two identity-pinned public reflectors must agree on the observed tuple before
// a claim is issued. Observations bind to the exact endpoint instance, socket
// generation, local identity, epoch, run, observation time, and short expiry.

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const {
  createDhtExitWireReservation,
  decodeDhtReplyEnvelope,
  encodeDhtExitRequest
} = require('./dht-exit-wire')
const { PrivateRouteError } = require('./errors')
const { parseAddress } = require('./topology-grant')

const PING = 0
const DEFAULT_CLAIM_TTL_MS = 5_000n
const MAX_CLAIM_TTL_MS = 15_000n
const MIN_AGREEING_REFLECTORS = 2
const MAX_REFLECTORS = 3
const PROBE_TIMEOUT_MS = 4_000
const SEND_DELAYS_MS = Object.freeze([0, 300, 900])
const CLAIMS = new WeakMap()
const DESTROYED_CLAIMS = new WeakSet()
const REFLECTION_DOMAIN = b4a.from('hyperdht-private-routes/nat-reflection-claim/v0')

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function validU64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= 0xffff_ffff_ffff_ffffn
}

function clear(buffer) {
  if (b4a.isBuffer(buffer)) b4a.fill(buffer, 0)
}

function copy(value, size) {
  if (!fixed(value, size)) invalid()
  return b4a.from(value)
}

function exactTuple(value) {
  if (!isObject(value)) invalid()
  const host = value.host
  const port = value.port
  if (typeof host !== 'string' || !Number.isSafeInteger(port) || port < 1 || port > 0xffff) {
    invalid()
  }
  parseAddress(host)
  return Object.freeze({ host, port })
}

function sameTuple(left, right) {
  return left && right && left.host === right.host && left.port === right.port
}

function exactReflector(value) {
  if (!isObject(value)) invalid()
  const host = value.host
  const port = value.port
  if (typeof host !== 'string' || !Number.isSafeInteger(port) || port < 1 || port > 0xffff) {
    invalid()
  }
  parseAddress(host)
  if (!fixed(value.identity32, 32)) invalid()
  return Object.freeze({
    host,
    port,
    identity32: b4a.from(value.identity32)
  })
}

function validateReflectorSet(reflectors) {
  if (!Array.isArray(reflectors) || reflectors.length < MIN_AGREEING_REFLECTORS) invalid()
  if (reflectors.length > MAX_REFLECTORS) invalid()
  const seenIdentity = new Set()
  const seenTuple = new Set()
  const resolved = []
  for (const entry of reflectors) {
    const reflector = exactReflector(entry)
    const identityKey = b4a.toString(reflector.identity32, 'hex')
    const tupleKey = `${reflector.host}:${reflector.port}`
    if (seenIdentity.has(identityKey) || seenTuple.has(tupleKey)) invalid()
    seenIdentity.add(identityKey)
    seenTuple.add(tupleKey)
    resolved.push(reflector)
  }
  return resolved
}

function randomTid(randomBytes) {
  if (typeof randomBytes !== 'function') invalid()
  const bytes = randomBytes(2)
  if (!fixed(bytes, 2)) invalid()
  const value = ((bytes[0] << 8) | bytes[1]) % 0xfffe
  clear(bytes)
  return 1 + value
}

function createReflectionProbe(reflector, options) {
  if (!isObject(options)) invalid()
  const randomBytes = options.randomBytes || cryptoSuite.randomBytes
  const tid = options.tid === undefined ? randomTid(randomBytes) : options.tid
  if (!Number.isSafeInteger(tid) || tid < 0 || tid > 0xffff) invalid()
  // Local tuple is a placeholder for the wire reservation; observation mode
  // does not require it to match the reflected answer.
  const local = exactTuple(options.local || { host: '0.0.0.0', port: 1 })
  const remote = exactTuple({ host: reflector.host, port: reflector.port })
  const reservation = createDhtExitWireReservation({ remote, local, tid })
  const packet = encodeDhtExitRequest(reservation, {
    tid,
    token: null,
    internal: true,
    command: PING,
    target: null,
    value: null
  })
  return Object.freeze({
    reservation,
    packet,
    tid,
    remote,
    identity32: b4a.from(reflector.identity32),
    sendDelaysMs: SEND_DELAYS_MS,
    timeoutMs: Number.isSafeInteger(options.timeoutMs) ? options.timeoutMs : PROBE_TIMEOUT_MS
  })
}

function observeReflectionReply(probe, source, packet) {
  if (!isObject(probe) || !probe.reservation) unauthorized()
  const from = exactTuple(source)
  if (!sameTuple(from, probe.remote)) unauthorized()
  const decoded = decodeDhtReplyEnvelope(probe.reservation, source, packet, {
    observeLocalTuple: true
  })
  return Object.freeze({
    tid: decoded.tid,
    from: decoded.from,
    observed: decoded.to,
    reflectorIdentity32: b4a.from(probe.identity32)
  })
}

function claimDigest(record) {
  const hostBytes = b4a.from(record.observed.host)
  const portBytes = b4a.allocUnsafe(2)
  portBytes[0] = (record.observed.port >>> 8) & 0xff
  portBytes[1] = record.observed.port & 0xff
  const family = parseAddress(record.observed.host).family
  const parts = [
    REFLECTION_DOMAIN,
    record.endpointId32,
    b4a.from([record.socketGeneration & 0xff]),
    record.localIdentity32,
    (() => {
      const out = b4a.allocUnsafe(8)
      let value = record.epoch
      for (let i = 7; i >= 0; i--) {
        out[i] = Number(value & 0xffn)
        value >>= 8n
      }
      return out
    })(),
    record.runId32,
    b4a.from([family]),
    hostBytes,
    portBytes,
    (() => {
      const out = b4a.allocUnsafe(8)
      let value = record.observedAt
      for (let i = 7; i >= 0; i--) {
        out[i] = Number(value & 0xffn)
        value >>= 8n
      }
      return out
    })(),
    (() => {
      const out = b4a.allocUnsafe(8)
      let value = record.expiresAt
      for (let i = 7; i >= 0; i--) {
        out[i] = Number(value & 0xffn)
        value >>= 8n
      }
      return out
    })()
  ]
  try {
    return cryptoSuite.hash(parts)
  } finally {
    clear(hostBytes)
    clear(portBytes)
    for (const part of parts) {
      if (
        part !== REFLECTION_DOMAIN &&
        part !== record.endpointId32 &&
        part !== record.localIdentity32 &&
        part !== record.runId32
      ) {
        clear(part)
      }
    }
  }
}

function issueReflectedEndpointClaim(options) {
  if (!isObject(options)) invalid()
  const reflectors = validateReflectorSet(options.reflectors || [])
  if (!Array.isArray(options.observations) || options.observations.length === 0) invalid()
  if (!fixed(options.endpointId32, 32)) invalid()
  if (!Number.isSafeInteger(options.socketGeneration) || options.socketGeneration < 0) invalid()
  if (!fixed(options.localIdentity32, 32)) invalid()
  if (!validU64(options.epoch) || !fixed(options.runId32, 32)) invalid()
  if (!validU64(options.now)) invalid()
  const ttl =
    options.ttlMs === undefined
      ? DEFAULT_CLAIM_TTL_MS
      : typeof options.ttlMs === 'bigint'
        ? options.ttlMs
        : BigInt(options.ttlMs)
  if (!validU64(ttl) || ttl < 1n || ttl > MAX_CLAIM_TTL_MS) invalid()

  const byIdentity = new Map()
  for (const observation of options.observations) {
    if (!isObject(observation) || !fixed(observation.reflectorIdentity32, 32)) invalid()
    const observed = exactTuple(observation.observed)
    const key = b4a.toString(observation.reflectorIdentity32, 'hex')
    const expected = reflectors.find((entry) =>
      b4a.equals(entry.identity32, observation.reflectorIdentity32)
    )
    if (!expected) unauthorized()
    if (byIdentity.has(key)) invalid()
    byIdentity.set(key, observed)
  }

  if (byIdentity.size < MIN_AGREEING_REFLECTORS) unauthorized()
  const values = Array.from(byIdentity.values())
  const agreed = values[0]
  for (const value of values) {
    if (!sameTuple(value, agreed)) unauthorized()
  }

  const record = {
    endpointId32: b4a.from(options.endpointId32),
    socketGeneration: options.socketGeneration,
    localIdentity32: b4a.from(options.localIdentity32),
    epoch: options.epoch,
    runId32: b4a.from(options.runId32),
    observed: { host: agreed.host, port: agreed.port },
    observedAt: options.now,
    expiresAt: options.now + ttl,
    live: true
  }
  record.digest32 = claimDigest(record)
  const claim = Object.freeze({})
  CLAIMS.set(claim, record)
  return claim
}

function readReflectedEndpointClaim(claim, options) {
  const record = isObject(claim) ? CLAIMS.get(claim) : null
  if (!record || !record.live || DESTROYED_CLAIMS.has(claim)) unauthorized()
  if (!isObject(options)) invalid()
  if (!validU64(options.now)) invalid()
  if (options.now >= record.expiresAt) {
    destroyReflectedEndpointClaim(claim)
    unauthorized()
  }
  if (fixed(options.endpointId32, 32) && !b4a.equals(options.endpointId32, record.endpointId32)) {
    unauthorized()
  }
  if (
    Number.isSafeInteger(options.socketGeneration) &&
    options.socketGeneration !== record.socketGeneration
  ) {
    unauthorized()
  }
  if (
    fixed(options.localIdentity32, 32) &&
    !b4a.equals(options.localIdentity32, record.localIdentity32)
  ) {
    unauthorized()
  }
  if (validU64(options.epoch) && options.epoch !== record.epoch) unauthorized()
  if (fixed(options.runId32, 32) && !b4a.equals(options.runId32, record.runId32)) unauthorized()
  return Object.freeze({
    digest32: b4a.from(record.digest32),
    endpointId32: b4a.from(record.endpointId32),
    socketGeneration: record.socketGeneration,
    localIdentity32: b4a.from(record.localIdentity32),
    epoch: record.epoch,
    runId32: b4a.from(record.runId32),
    observed: { host: record.observed.host, port: record.observed.port },
    observedAt: record.observedAt,
    expiresAt: record.expiresAt
  })
}

function destroyReflectedEndpointClaim(claim) {
  const record = isObject(claim) ? CLAIMS.get(claim) : null
  if (!record) return false
  CLAIMS.delete(claim)
  DESTROYED_CLAIMS.add(claim)
  record.live = false
  clear(record.digest32)
  clear(record.endpointId32)
  clear(record.localIdentity32)
  clear(record.runId32)
  record.digest32 = null
  record.endpointId32 = null
  record.localIdentity32 = null
  record.runId32 = null
  record.observed = null
  return true
}

function isReflectedEndpointClaim(value) {
  return isObject(value) && CLAIMS.has(value) && !DESTROYED_CLAIMS.has(value)
}

module.exports = Object.freeze({
  DEFAULT_CLAIM_TTL_MS,
  MAX_CLAIM_TTL_MS,
  MIN_AGREEING_REFLECTORS,
  MAX_REFLECTORS,
  PROBE_TIMEOUT_MS,
  SEND_DELAYS_MS,
  createReflectionProbe,
  observeReflectionReply,
  issueReflectedEndpointClaim,
  readReflectedEndpointClaim,
  destroyReflectedEndpointClaim,
  isReflectedEndpointClaim,
  validateReflectorSet
})
