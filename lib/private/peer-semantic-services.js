'use strict'

const b4a = require('b4a')
const { PrivateRouteError } = require('./errors')
const { PEER_MESSAGE_ID: ID } = require('./peer-protocol')
const { decodePeerSemantic, encodePeerSemantic } = require('./peer-semantic-wire')
const { decodePeerTransport, encodePeerTransport } = require('./peer-transport-wire')
const { hashPeer } = require('./peer-crypto')

const MAX_U64 = 0xffffffffffffffffn
const HANDSHAKE_BYTES = 981
const NOISE_BYTES = 1002
const DOMAIN = 'hyperdht-private-routes/peer/'

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function check(condition) {
  if (!condition) invalid()
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function eraseDecoded(value) {
  if (!value) return
  for (const field of Object.values(value.fields)) clear(field)
  clear(value.body)
  clear(value.authSuffix)
}

function equal(a, b) {
  return b4a.isBuffer(a) && b4a.isBuffer(b) && b4a.equals(a, b)
}

function minimum(...values) {
  return values.reduce((a, b) => (a < b ? a : b))
}

function own(value, name, fallback) {
  const descriptor = value && Object.getOwnPropertyDescriptor(value, name)
  if (!descriptor) return fallback
  check(Object.prototype.hasOwnProperty.call(descriptor, 'value'))
  return descriptor.value
}

function positive(value, maximum) {
  check(Number.isSafeInteger(value) && value > 0 && value <= maximum)
  return value
}

function bytes(value, length) {
  check(b4a.isBuffer(value) && value.byteLength === length)
  return b4a.from(value)
}

function u64(value) {
  check(typeof value === 'bigint' && value > 0n && value <= MAX_U64)
  return value
}

const sodium = require('sodium-universal')
const PROFILES = Object.freeze({
  legacy: [ID.LEGACY_RESOLVE_V2, 112, 12, 4807, 12, 4813, 9620],
  source: [ID.PRIVATE_ACTIVATE_V2, 757, 4, 1297, 4, 752, 2049],
  destination: [ID.PRIVATE_ACTIVATE_V2, 757, 4, 1393, 3, 528, 1921],
  registration: [ID.ENTRY_REGISTER_V2, 486, 2, 582, 1, 144, 726]
})
const HOOKS = [
  'onHandshake',
  'onAuthenticatedOpen',
  'onCiphertext',
  'onRemoteFin',
  'onReset',
  'onWritable'
]

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function errorFor(code) {
  const names = [
    null,
    'ERR_DESTROYED',
    'ERR_AUTHENTICATION',
    'ERR_QUOTA_EXCEEDED',
    'ERR_PRIVACY_UNAVAILABLE',
    'ERR_PRIVACY_UNAVAILABLE',
    'ERR_DESTROYED',
    'ERR_REPLAY',
    'INVALID_ROUTE'
  ]
  check(Number.isSafeInteger(code) && code > 0 && code < names.length)
  return PrivateRouteError[names[code]]()
}

function random(service, length) {
  const value = service.randomBytes(length)
  check(b4a.isBuffer(value) && value.length === length && value.some((byte) => byte !== 0))
  return b4a.from(value)
}

function sameFields(a, b, names) {
  for (const name of names)
    check(b4a.isBuffer(a[name]) ? equal(a[name], b[name]) : a[name] === b[name])
}

function noiseDigest(raw) {
  return hashPeer(DOMAIN + 'noise-ciphertext/v2', [raw])
}

function common(s, direction = s.service.direction, position = 0n) {
  return {
    routeId: s.service.route.routeId,
    streamId: s.id,
    streamEpoch: 1,
    direction,
    flags: 0,
    reserved: 0,
    position
  }
}

function now(service) {
  const value = service.route.monotonicNow()
  check(typeof value === 'bigint' && value >= service.lastNow && value <= MAX_U64)
  service.lastNow = value
  check(!service.destroyed)
  return value
}

function sessionDeadline(s) {
  return minimum(s.deadline, s.idleDeadline, s.semanticOpen ? s.deadline : s.handshakeDeadline)
}

function liveSession(s) {
  if (s.closed || s.service.destroyed) throw PrivateRouteError.ERR_DESTROYED()
  if (now(s.service) >= sessionDeadline(s)) {
    closeSession(s, 4)
    throw errorFor(4)
  }
}

function project(s, expiry) {
  u64(expiry)
  const service = s.service
  const route = service.route
  const wall = route.wallNow()
  const mono = now(service)
  check(typeof wall === 'bigint' && wall >= service.lastWall)
  service.lastWall = wall
  check(wall < expiry && expiry <= s.expiry && expiry <= route.wireExpiresAt)
  const projected = mono + expiry - wall
  check(projected <= MAX_U64)
  s.deadline = minimum(s.deadline, route.localDeadline, projected)
  check(mono < s.deadline)
  s.expiry = minimum(s.expiry, expiry)
  arm(service)
}

function arm(service) {
  if (service.destroyed || !service.route) return
  if (service.cancelTimer) service.cancelTimer()
  service.cancelTimer = null
  const epoch = ++service.timerEpoch
  let deadline = service.route.localDeadline
  for (const s of service.streams.values()) {
    if (!s.closed) deadline = minimum(deadline, sessionDeadline(s))
  }
  const remaining = deadline - now(service)
  check(remaining > 0n)
  const cancel = service.route.schedule(Number(minimum(remaining, 0x7fffffffn)), () => {
    if (service.destroyed || epoch !== service.timerEpoch) return
    service.cancelTimer = null
    try {
      const time = now(service)
      if (time >= service.route.localDeadline) return destroyService(service, errorFor(5))
      for (const s of service.streams.values()) {
        if (!s.closed && time >= sessionDeadline(s)) closeSession(s, 4)
      }
      arm(service)
    } catch (error) {
      destroyService(service, error)
    }
  })
  check(typeof cancel === 'function')
  if (service.destroyed || epoch !== service.timerEpoch) cancel()
  else service.cancelTimer = cancel
}

function touch(s) {
  if (s.idleMs) s.idleDeadline = minimum(s.deadline, now(s.service) + BigInt(s.idleMs))
}

function profile(service, direction, id, semanticClass) {
  const purpose = service.route.purpose
  if (purpose === 3 && direction === 0) {
    check(id === 1n && semanticClass === 1)
    return 'registration'
  }
  check(semanticClass === 2)
  if (purpose === 3) {
    check(direction === 1 && id % 2n === 0n)
    return 'destination'
  }
  check(direction === 0 && id % 2n === 1n)
  return purpose === 1 ? 'legacy' : 'source'
}

function allocate(service, id, direction, kind, open) {
  const count =
    direction === 0 && service.route.purpose === 3
      ? 1
      : service.route.purpose === 3
        ? service.route.limits.maxStreams - 1
        : service.route.limits.maxStreams
  check(
    id > service.lastId[direction] &&
      service.count[direction] < count &&
      service.streams.size < service.maxStreams
  )
  check(id > 0n && id < MAX_U64 && !service.streams.has(id))
  if (kind !== 'registration') {
    check(
      open.requestedDataFrames > 0 &&
        open.requestedDataFrames <= service.maxFrames &&
        open.requestedDataBytes >= 59n &&
        open.requestedDataBytes <= service.maxBytes &&
        open.requestedDataBytes <= 977n * BigInt(open.requestedDataFrames)
    )
    check(
      service.windowUsed <
        minimum(
          24,
          service.route.limits.receiveFrames,
          Math.floor(service.route.limits.receiveBytes / 977)
        )
    )
  }
  const p = PROFILES[kind]
  const endpoint = kind === 'legacy' && service.direction === 0
  const s = {
    service,
    id,
    kind,
    opener: direction,
    openNonce: bytes(open.openNonce, 16),
    sessionId: null,
    state: kind === 'registration' ? 'CONTROL_ACTIVE' : 'AUTHENTICATING',
    closed: false,
    revoked: false,
    epoch: 1,
    endpoint,
    attached: false,
    hooks: null,
    deadline: service.route.localDeadline,
    expiry: service.route.wireExpiresAt,
    idleDeadline: service.route.localDeadline,
    idleMs: 0,
    handshakeDeadline: minimum(
      service.route.localDeadline,
      now(service) + BigInt(service.handshakeTimeoutMs)
    ),
    cache: new Map(),
    cacheBytes: 0,
    cacheLimit: p[6],
    rxPosition: 0n,
    txPosition: 0n,
    rxFrames: 0,
    rxBytes: 0,
    txFrames: 0,
    txBytes: 0,
    reassembly: null,
    queue: [],
    controls: [],
    openTicket: null,
    openedTicket: null,
    initialCredit: null,
    openAck: direction !== service.direction,
    semanticOpen: false,
    transportOpen: false,
    ready: false,
    openWait: deferred(),
    finishWait: deferred(),
    confirmWait: deferred(),
    flights: [null, null],
    options: null,
    native: null,
    jobs: 0,
    lifecycle: 'RESOLVING',
    sendingData: false,
    blocked: true,
    maxFrames: open.requestedDataFrames,
    maxBytes: open.requestedDataBytes,
    sentFrames: 0n,
    sentBytes: 0n,
    receivedFrames: 0n,
    receivedBytes: 0n,
    sentSequence: MAX_U64,
    receivedSequence: MAX_U64,
    remoteCredit: { epoch: 0, frames: 0n, bytes: 0n, wire: null },
    localCredit: { epoch: 0, frames: 0n, bytes: 0n },
    receiveSlots: 0,
    incoming: [],
    draining: false,
    dataAdmissions: new Map(),
    finishing: false,
    finTicket: null,
    remoteFin: null,
    remoteEnded: false,
    receivedControls: new Map(),
    handshakeSent: false,
    handshakeConfirmed: false
  }
  if (kind !== 'registration') {
    service.windowUsed++
    s.receiveSlots = 1
  }
  service.count[direction]++
  service.lastId[direction] = id
  service.streams.set(id, s)
  s.facade = Object.freeze({ attachEndpoint: (hooks) => attachEndpoint(s, hooks) })
  return s
}

function openFields(service, id, kind, options) {
  const p = PROFILES[kind]
  const registration = kind === 'registration'
  const maxFrames = registration ? 0 : positive(own(options, 'maxFrames'), 0xffffffff)
  const maxBytes = registration ? 0n : u64(own(options, 'maxBytes'))
  return {
    common: {
      routeId: service.route.routeId,
      streamId: id,
      streamEpoch: 1,
      direction: service.direction,
      flags: 0,
      reserved: 0,
      position: 0n
    },
    semanticFirstId: p[0],
    semanticClass: registration ? 1 : 2,
    reservedZero: 0,
    firstSemanticWireBytes: p[1],
    requestedHandshakeFrames: p[2],
    requestedHandshakeBytes: BigInt(p[3]),
    requestedDataFrames: maxFrames,
    requestedDataBytes: maxBytes,
    openNonce: random(service, 16)
  }
}

function control(s, id, fields, onSent = null) {
  if (s.service.destroyed) return
  check(s.controls.length < 4)
  s.controls.push({
    wire: encodePeerTransport(id, fields),
    onSent,
    afterHandshake: id === ID.PEER_OPENED_V2 || id === ID.PEER_CREDIT_V2
  })
  flush(s.service)
}

function acknowledged(s, ticket) {
  return ticket && s.service.transport.isCumulativelyAcknowledged(ticket.lane, ticket.sequence)
}

function flush(service) {
  if (service.destroyed || !service.transport) return
  if (service.flushing) {
    service.flushPending = true
    return
  }
  service.flushing = true
  try {
    for (const s of service.streams.values()) {
      while (s.controls.length && !service.destroyed) {
        const next = s.controls[0]
        if (next.afterHandshake && s.queue.length) break
        const ticket = service.transport.trySend(next.wire)
        if (!ticket) break
        if (s.controls[0] !== next) break
        s.controls.shift()
        clear(next.wire)
        if (next.onSent) next.onSent(ticket)
      }
      if (s.closed) continue
      if (!s.openAck && acknowledged(s, s.openTicket)) s.openAck = true
      if (!s.openAck) continue
      while (s.queue.length && !s.closed && !service.destroyed) {
        const row = s.queue[0]
        const offset = row.offset
        const length = Math.min(HANDSHAKE_BYTES, row.wire.length - offset)
        const wire = encodePeerTransport(ID.PEER_HANDSHAKE_V2, {
          common: common(s, service.direction, row.position),
          semanticObjectOffset: offset,
          fragmentBytes: length,
          fragmentFlags: (offset === 0 ? 1 : 0) | (offset + length === row.wire.length ? 2 : 0),
          bytes: row.wire.subarray(offset, offset + length)
        })
        let ticket
        try {
          ticket = service.transport.trySend(wire)
        } finally {
          clear(wire)
        }
        if (!ticket || s.closed || service.destroyed) break
        row.packets.push(ticket)
        row.offset += length
        if (row.offset === row.wire.length) {
          s.queue.shift()
          if (!s.queue.length && s.controls.length) service.flushPending = true
        }
      }
      startup(s)
      maybeFin(s)
      completeFin(s)
    }
  } catch (error) {
    destroyService(service, error)
  } finally {
    service.flushing = false
    if (service.flushPending && !service.destroyed && !service.flushScheduled) {
      service.flushPending = false
      service.flushScheduled = true
      Promise.resolve().then(() => {
        service.flushScheduled = false
        flush(service)
      })
    }
  }
}

function rowKey(decoded) {
  const f = decoded.fields
  return decoded.messageId === ID.PEER_NOISE_FRAGMENT_V2
    ? `${decoded.messageId}:${f.flight}:${f.fragmentIndex}`
    : String(decoded.messageId)
}

function cache(s, wire, incoming, position, packets) {
  const decoded = decodePeerSemantic(wire)
  try {
    const key = rowKey(decoded)
    check(!s.cache.has(key) && s.cacheBytes + wire.length <= s.cacheLimit)
    if (decoded.fields.sessionId) {
      if (s.sessionId) check(equal(s.sessionId, decoded.fields.sessionId))
      else {
        const sid = b4a.toString(decoded.fields.sessionId, 'hex')
        check(!s.service.sessionIds.has(sid))
        s.service.sessionIds.add(sid)
        s.sessionId = bytes(decoded.fields.sessionId, 16)
      }
    }
    const row = { wire, incoming, position, packets, offset: 0 }
    s.cache.set(key, row)
    s.cacheBytes += wire.length
    return row
  } finally {
    eraseDecoded(decoded)
  }
}

function authored(s, id, fields) {
  const wire = encodePeerSemantic(id, fields)
  try {
    return sendCanonical(s, wire)
  } finally {
    clear(wire)
  }
}

function sendCanonical(s, wire) {
  liveSession(s)
  const p = PROFILES[s.kind]
  const side = s.opener === s.service.direction ? 2 : 4
  const frames = Math.ceil(wire.length / HANDSHAKE_BYTES)
  check(s.txFrames + frames <= p[side] && s.txBytes + wire.length <= p[side + 1])
  const owned = b4a.from(wire)
  let row
  try {
    row = cache(s, owned, false, s.txPosition, [])
  } catch (error) {
    clear(owned)
    throw error
  }
  s.txPosition++
  s.txFrames += frames
  s.txBytes += wire.length
  s.queue.push(row)
  flush(s.service)
  return row
}

function fields(s, id) {
  const row = s.cache.get(String(id))
  check(row)
  return decodePeerSemantic(row.wire)
}

function withFields(s, ids, fn) {
  const decoded = []
  try {
    for (const id of ids) decoded.push(fields(s, id))
    return fn(...decoded.map((value) => value.fields))
  } finally {
    for (const value of decoded) eraseDecoded(value)
  }
}

function invoke(s, name, ...args) {
  if (s.revoked || !s.hooks || !s.hooks[name]) return
  const result = s.hooks[name](...args)
  if (result && typeof result.then === 'function') {
    Promise.resolve(result).catch((error) => {
      if (!s.closed) closeSession(s, 2, error)
    })
  }
  return result
}

function asyncJob(s, operation, accept, discard = null) {
  const epoch = s.epoch
  check(s.jobs < 4)
  s.jobs++
  Promise.resolve()
    .then(() => {
      liveSession(s)
      return operation()
    })
    .then((result) => {
      if (s.closed || s.epoch !== epoch || s.service.destroyed) {
        if (discard) discard(result)
        return
      }
      try {
        liveSession(s)
        accept(result)
      } catch (error) {
        if (discard) discard(result)
        throw error
      }
    })
    .catch((error) => {
      if (!s.closed && s.epoch === epoch) closeSession(s, 2, error)
    })
    .finally(() => {
      s.jobs--
    })
}

function receiveHandshake(s, meta, f) {
  const p = PROFILES[s.kind]
  const side = s.opener !== s.service.direction ? 2 : 4
  const position = f.common.position
  const offset = f.semanticObjectOffset
  if (position < s.rxPosition) {
    let row
    for (const value of s.cache.values()) {
      if (value.incoming && value.position === position) {
        row = value
        break
      }
    }
    check(row)
    const packet = row.packets[offset / HANDSHAKE_BYTES]
    check(
      packet &&
        packet.lane === meta.lane &&
        packet.sequence === meta.sequence &&
        equal(packet.digest, meta.nestedDigest) &&
        offset % HANDSHAKE_BYTES === 0 &&
        f.fragmentFlags ===
          ((offset === 0 ? 1 : 0) | (offset + f.fragmentBytes === row.wire.length ? 2 : 0)) &&
        equal(row.wire.subarray(offset, offset + f.fragmentBytes), f.bytes)
    )
    // The lane retains the original response's retry state. Never issue a new sequence.
    return
  }
  check(position === s.rxPosition && !s.semanticOpen)
  if (s.reassembly && offset < s.reassembly.offset) {
    const packet = s.reassembly.packets[offset / HANDSHAKE_BYTES]
    check(
      packet &&
        packet.lane === meta.lane &&
        packet.sequence === meta.sequence &&
        equal(packet.digest, meta.nestedDigest) &&
        equal(s.reassembly.wire.subarray(offset, offset + f.fragmentBytes), f.bytes)
    )
    return
  }
  if (offset === 0) {
    check(!s.reassembly && (f.fragmentFlags & 1) !== 0 && f.bytes.length >= 8)
    const length = 8 + f.bytes.readUInt16BE(6)
    check(f.bytes.readUInt32BE(0) === 2 && length <= 1073 && length > 8)
    if (position === 0n) {
      const first =
        s.opener !== s.service.direction
          ? [p[0], p[1]]
          : s.kind === 'registration'
            ? [ID.ENTRY_REGISTERED_V2, 144]
            : s.kind === 'legacy'
              ? [ID.LEGACY_RESOLVED_V2, 114]
              : [ID.PEER_NOISE_FRAGMENT_V2, 124]
      check(f.bytes.readUInt16BE(4) === first[0] && length === first[1])
    }
    check(s.cacheBytes + length <= s.cacheLimit)
    s.reassembly = { wire: b4a.alloc(length), offset: 0, packets: [] }
  }
  const assembly = s.reassembly
  check(assembly && offset === assembly.offset && offset % HANDSHAKE_BYTES === 0)
  const length = Math.min(HANDSHAKE_BYTES, assembly.wire.length - offset)
  check(
    f.fragmentBytes === length &&
      f.fragmentFlags ===
        ((offset === 0 ? 1 : 0) | (offset + length === assembly.wire.length ? 2 : 0))
  )
  check(s.rxFrames < p[side] && s.rxBytes + length <= p[side + 1])
  f.bytes.copy(assembly.wire, offset)
  assembly.offset += length
  assembly.packets.push({
    lane: meta.lane,
    sequence: meta.sequence,
    digest: bytes(meta.nestedDigest, 32)
  })
  s.rxFrames++
  s.rxBytes += length
  if (assembly.offset !== assembly.wire.length) return
  s.reassembly = null
  let row
  try {
    row = cache(s, assembly.wire, true, position, assembly.packets)
    s.rxPosition++
    const decoded = decodePeerSemantic(row.wire)
    try {
      dispatch(s, decoded, row.wire)
    } finally {
      eraseDecoded(decoded)
    }
  } catch (error) {
    if (!row) clear(assembly.wire)
    for (const packet of assembly.packets) clear(packet.digest)
    throw error
  }
}

function admit(service, meta, nested) {
  if (service.destroyed || !service.route) return false
  let decoded
  let s
  try {
    check(now(service) < service.route.localDeadline)
    decoded = decodePeerTransport(nested)
    const f = decoded.fields
    const c = f.common
    validateEnvelope(service, meta, decoded)
    s = service.streams.get(c.streamId)
    if (decoded.messageId === ID.PEER_OPEN_V2) {
      if (s) {
        check(
          s.openDigest && equal(s.openDigest, meta.nestedDigest) && s.openSequence === meta.sequence
        )
        return true
      }
      const kind = profile(service, c.direction, c.streamId, f.semanticClass)
      const p = PROFILES[kind]
      check(
        f.semanticFirstId === p[0] &&
          f.firstSemanticWireBytes === p[1] &&
          f.requestedHandshakeFrames === p[2] &&
          f.requestedHandshakeBytes === BigInt(p[3])
      )
      if (kind === 'registration') check(f.requestedDataFrames === 0 && f.requestedDataBytes === 0n)
      s = allocate(service, c.streamId, c.direction, kind, f)
      s.openDigest = bytes(meta.nestedDigest, 32)
      s.openSequence = meta.sequence
      arm(service)
      return true
    }
    check(s)
    if (s.closed) return true
    liveSession(s)
    if (decoded.messageId === ID.PEER_DATA_V2) {
      check(s.ready && s.kind !== 'registration' && !s.remoteEnded)
      const admission = s.dataAdmissions.get(meta.sequence)
      if (admission) {
        check(equal(admission.digest, meta.nestedDigest))
        return true
      }
      check(
        s.dataAdmissions.size + s.incoming.length < s.receiveSlots &&
          s.receivedFrames + BigInt(s.dataAdmissions.size) < s.localCredit.frames &&
          f.common.position === s.receivedBytes &&
          s.receivedBytes + BigInt(f.dataBytes) <= s.localCredit.bytes
      )
      s.dataAdmissions.set(meta.sequence, { digest: bytes(meta.nestedDigest, 32) })
    }
    return true
  } catch (error) {
    if (s) {
      closeSession(s, 7, error)
      return true
    }
    destroyService(service, error)
    return false
  } finally {
    eraseDecoded(decoded)
  }
}

function deliver(service, meta, nested) {
  if (service.destroyed) return false
  let decoded, s
  try {
    decoded = decodePeerTransport(nested)
    validateEnvelope(service, meta, decoded)
    const f = decoded.fields
    s = service.streams.get(f.common.streamId)
    check(s)
    if (s.closed) return true
    liveSession(s)
    if (rememberControl(s, meta, decoded)) return true
    switch (decoded.messageId) {
      case ID.PEER_OPEN_V2:
        check(
          s.openDigest && s.openSequence === meta.sequence && equal(s.openDigest, meta.nestedDigest)
        )
        if (s.kind !== 'legacy') admitActivation(s)
        break
      case ID.PEER_HANDSHAKE_V2:
        receiveHandshake(s, meta, f)
        break
      case ID.PEER_OPENED_V2:
        check(
          s.semanticOpen &&
            !s.transportOpen &&
            s.opener === service.direction &&
            equal(f.openNonce, s.openNonce)
        )
        check(
          f.admittedDataFrames > 0 &&
            f.admittedDataFrames <= s.maxFrames &&
            BigInt(f.admittedDataBytes) >= 59n &&
            BigInt(f.admittedDataBytes) <= s.maxBytes &&
            BigInt(f.admittedDataBytes) <= 977n * BigInt(f.admittedDataFrames)
        )
        s.maxFrames = f.admittedDataFrames
        s.maxBytes = BigInt(f.admittedDataBytes)
        s.transportOpen = true
        grant(s)
        break
      case ID.PEER_CREDIT_V2:
        receiveCredit(s, f, nested)
        break
      case ID.PEER_DATA_V2:
        receiveData(s, meta, f)
        break
      case ID.PEER_FIN_V2:
        check(
          s.ready &&
            !s.remoteFin &&
            f.finalCiphertextOffset >= s.receivedBytes &&
            f.finalCiphertextOffset <= s.localCredit.bytes &&
            ((f.finalCiphertextOffset === 0n && f.finalDataSequence === MAX_U64) ||
              (f.finalCiphertextOffset > 0n && f.finalDataSequence < MAX_U64))
        )
        s.remoteFin = { offset: f.finalCiphertextOffset, sequence: f.finalDataSequence }
        drain(s)
        break
      case ID.PEER_CLOSE_V2:
        check(
          s.remoteEnded &&
            s.finishing &&
            acknowledged(s, s.finTicket) &&
            f.finalCiphertextOffset === s.receivedBytes &&
            f.finalDataSequence === s.receivedSequence
        )
        closeSession(s, 0, null, false, true)
        break
      case ID.PEER_RESET_V2:
        closeSession(s, f.errorCode, errorFor(f.errorCode), false)
        break
      default:
        invalid()
    }
    flush(service)
    return true
  } catch (error) {
    if (s) closeSession(s, 7, error)
    else destroyService(service, error)
    return true
  } finally {
    eraseDecoded(decoded)
  }
}

function endpointContext(s) {
  return Object.freeze({
    sessionId: b4a.from(s.sessionId),
    isInitiator: s.kind !== 'destination',
    maxFrames: s.maxFrames,
    maxBytes: s.maxBytes,
    expiresAtUnixMs: s.expiry,
    localDeadline: s.deadline
  })
}

function semanticSuccess(s, f) {
  check(
    !s.semanticOpen &&
      f.maxFrames > 0 &&
      f.maxFrames <= s.maxFrames &&
      f.maxBytes >= 59n &&
      f.maxBytes <= s.maxBytes
  )
  s.maxFrames = f.maxFrames
  s.maxBytes = f.maxBytes
  s.idleMs = positive(f.idleMs, 0xffffffff)
  project(s, f.expiresAtUnixMs)
  s.semanticOpen = true
  s.state = 'OPEN'
  clearBinding(s)
  for (const flight of s.flights) {
    if (flight) {
      if (s.kind === 'legacy') clear(flight.raw)
      flight.raw = null
    }
  }
  s.confirmWait.resolve()
  invoke(s, 'onAuthenticatedOpen', endpointContext(s))
  if (s.closed) return
  if (s.opener !== s.service.direction) {
    control(
      s,
      ID.PEER_OPENED_V2,
      {
        common: common(s, s.opener),
        openNonce: s.openNonce,
        admittedDataFrames: s.maxFrames,
        admittedDataBytes: Number(s.maxBytes)
      },
      (ticket) => {
        if (s.closed) return
        s.openedTicket = ticket
        s.transportOpen = true
        grant(s)
      }
    )
  }
  touch(s)
  arm(s.service)
}

function grant(s) {
  if (!s.transportOpen || s.closed || s.incoming.length || s.dataAdmissions.size) return
  const next = minimum(BigInt(s.maxFrames), s.receivedFrames + BigInt(s.receiveSlots))
  if (next <= s.localCredit.frames) return
  const previous = s.localCredit
  const epoch = previous.epoch + 1
  check(epoch <= 0xffffffff)
  const value = { epoch, frames: next, bytes: minimum(s.maxBytes, 977n * next) }
  s.localCredit = value
  control(
    s,
    ID.PEER_CREDIT_V2,
    {
      common: common(s, s.service.direction ^ 1),
      cumulativeGrantedFrames: value.frames,
      cumulativeGrantedBytes: value.bytes,
      creditEpoch: epoch
    },
    (ticket) => {
      if (epoch === 1 && !s.closed) s.initialCredit = ticket
    }
  )
}

function receiveCredit(s, f, wire) {
  check(s.semanticOpen && s.kind !== 'registration')
  const old = s.remoteCredit
  check(f.creditEpoch > old.epoch)
  check(
    f.creditEpoch === old.epoch + 1 &&
      f.cumulativeGrantedFrames > old.frames &&
      f.cumulativeGrantedFrames <= BigInt(s.maxFrames) &&
      f.cumulativeGrantedBytes === minimum(s.maxBytes, 977n * f.cumulativeGrantedFrames) &&
      f.cumulativeGrantedBytes >= old.bytes &&
      f.cumulativeGrantedBytes >= 59n
  )
  clear(old.wire)
  s.remoteCredit = {
    epoch: f.creditEpoch,
    frames: f.cumulativeGrantedFrames,
    bytes: f.cumulativeGrantedBytes,
    wire: b4a.from(wire)
  }
  startup(s)
}

function startup(s) {
  if (s.closed || !s.transportOpen || !s.remoteCredit.epoch || !acknowledged(s, s.initialCredit))
    return
  if (!s.ready) {
    s.ready = true
    s.state = 'CREDIT_READY'
    s.openWait.resolve()
  }
  drain(s)
  if (
    !s.closed &&
    s.blocked &&
    !s.finishing &&
    !s.sendingData &&
    s.sentFrames < s.remoteCredit.frames &&
    s.sentBytes < s.remoteCredit.bytes
  ) {
    s.blocked = false
    invoke(s, 'onWritable')
    if (!s.closed && s.native) s.native.drain()
  }
}

function sendData(s, raw) {
  liveSession(s)
  check(b4a.isBuffer(raw) && raw.length >= 1 && raw.length <= 977)
  if (
    !s.ready ||
    s.finishing ||
    s.sendingData ||
    s.sentFrames >= s.remoteCredit.frames ||
    s.sentBytes + BigInt(raw.length) > s.remoteCredit.bytes
  ) {
    s.blocked = true
    return false
  }
  const wire = encodePeerTransport(ID.PEER_DATA_V2, {
    common: common(s, s.service.direction, s.sentBytes),
    dataBytes: raw.length,
    dataFlags: 0,
    bytes: raw
  })
  s.sendingData = true
  try {
    const ticket = s.service.transport.trySend(wire)
    if (!ticket) {
      s.blocked = true
      return false
    }
    if (s.closed || s.service.destroyed) return false
    s.sentFrames++
    s.sentBytes += BigInt(raw.length)
    s.sentSequence = ticket.sequence
    touch(s)
    return true
  } catch (error) {
    closeSession(s, 5, error)
    throw error
  } finally {
    s.sendingData = false
    clear(wire)
  }
}

function receiveData(s, meta, f) {
  const admission = s.dataAdmissions.get(meta.sequence)
  check(s.ready && admission && equal(admission.digest, meta.nestedDigest) && !s.remoteEnded)
  check(
    f.common.position === s.receivedBytes &&
      s.receivedFrames < s.localCredit.frames &&
      s.receivedBytes + BigInt(f.dataBytes) <= s.localCredit.bytes &&
      (!s.remoteFin || s.receivedBytes + BigInt(f.dataBytes) <= s.remoteFin.offset)
  )
  s.dataAdmissions.delete(meta.sequence)
  clear(admission.digest)
  s.receivedFrames++
  s.receivedBytes += BigInt(f.dataBytes)
  s.receivedSequence = meta.sequence
  s.incoming.push({ bytes: b4a.from(f.bytes), offset: 0 })
  touch(s)
  drain(s)
}

function drain(s) {
  if (s.closed || s.draining) return
  s.draining = true
  try {
    while (s.ready && s.incoming.length && !s.closed) {
      const row = s.incoming[0]
      const raw = row.bytes.subarray(row.offset)
      let consumed
      if (s.native) consumed = s.native.trySendCiphertext(raw) === true ? raw.length : 0
      else consumed = invoke(s, 'onCiphertext', raw)
      check(Number.isSafeInteger(consumed) && consumed >= 0 && consumed <= raw.length)
      if (s.closed) break
      row.offset += consumed
      if (row.offset !== row.bytes.length) break
      clear(row.bytes)
      s.incoming.shift()
      grant(s)
    }
    if (
      s.remoteFin &&
      !s.remoteEnded &&
      !s.incoming.length &&
      s.receivedBytes === s.remoteFin.offset
    ) {
      check(s.receivedSequence === s.remoteFin.sequence)
      s.remoteEnded = true
      if (s.native) {
        const result = s.native.finish()
        if (result && typeof result.then === 'function') {
          Promise.resolve(result).catch((error) => {
            if (!s.closed) closeSession(s, 6, error)
          })
        }
      } else invoke(s, 'onRemoteFin')
    }
    completeFin(s)
  } catch (error) {
    closeSession(s, 8, error)
  } finally {
    s.draining = false
  }
}

function finish(s) {
  liveSession(s)
  s.finishing = true
  maybeFin(s)
  return s.finishWait.promise
}

function maybeFin(s) {
  if (!s.finishing || !s.ready || s.finTicket || s.closed || s.finQueued) return
  s.finQueued = true
  control(
    s,
    ID.PEER_FIN_V2,
    { common: common(s), finalCiphertextOffset: s.sentBytes, finalDataSequence: s.sentSequence },
    (ticket) => {
      s.finTicket = ticket
    }
  )
}

function completeFin(s) {
  if (s.closed || !s.remoteEnded || !acknowledged(s, s.finTicket)) return
  s.finishWait.resolve()
  closeSession(s, 0, null, false, true)
}

function clearBinding(s) {
  if (s.binding) {
    for (const value of Object.values(s.binding)) clear(value)
    s.binding = null
  }
  clear(s.arena)
  s.arena = null
  clear(s.handshakeInput)
  s.handshakeInput = null
  if (s.options) {
    for (const value of Object.values(s.options)) clear(value)
    s.options = null
  }
}

function closeSession(s, code = 6, error = null, send = true, graceful = false) {
  if (s.closed) return false
  const hooks = s.revoked ? null : s.hooks
  s.closed = true
  s.revoked = true
  s.hooks = null
  s.epoch++
  s.state = 'TOMBSTONE'
  const failure = error || errorFor(code || 6)
  s.service.windowUsed -= s.receiveSlots
  s.receiveSlots = 0
  s.openWait.reject(failure)
  s.confirmWait.reject(failure)
  if (s.registrationWait) s.registrationWait.reject(failure)
  if (s.registration) revokeRegistration(s.registration, code || 6)
  clear(s.descriptor)
  if (s.dependency) {
    s.dependency.sessions.delete(s)
    s.dependency = null
  }
  if (graceful) s.finishWait.resolve()
  else s.finishWait.reject(failure)
  for (const row of s.queue) row.offset = row.wire.length
  s.queue.length = 0
  for (const row of s.controls) clear(row.wire)
  s.controls.length = 0
  for (const row of s.incoming) clear(row.bytes)
  s.incoming.length = 0
  for (const admission of s.dataAdmissions.values()) clear(admission.digest)
  s.dataAdmissions.clear()
  if (s.reassembly) {
    clear(s.reassembly.wire)
    for (const packet of s.reassembly.packets) clear(packet.digest)
    s.reassembly = null
  }
  for (const flight of s.flights) {
    if (flight) {
      clear(flight.raw)
      clear(flight.digest)
      flight.raw = null
    }
  }
  clearBinding(s)
  clear(s.remoteCredit.wire)
  if (s.native) {
    try {
      s.native.destroy(failure)
    } catch {}
    s.native = null
  }
  if (s.resolution) {
    try {
      s.resolution.destroy()
    } catch {}
    s.resolution = null
  }
  if (send && !s.service.destroyed) {
    const f = {
      common: common(s),
      finalCiphertextOffset: s.sentBytes,
      finalDataSequence: s.sentSequence
    }
    if (code) {
      f.errorCode = code
      f.reserved = 0
    }
    try {
      control(s, code ? ID.PEER_RESET_V2 : ID.PEER_CLOSE_V2, f)
    } catch (error) {
      destroyService(s.service, error)
    }
  }
  if (!graceful && hooks && hooks.onReset) {
    try {
      hooks.onReset(failure)
    } catch {}
  }
  s.pair = null
  return true
}

function destroyService(service, error = errorFor(5)) {
  if (service.destroyed) return false
  service.destroyed = true
  service.timerEpoch++
  if (service.cancelTimer) {
    try {
      service.cancelTimer()
    } catch {}
    service.cancelTimer = null
  }
  for (const s of service.streams.values()) {
    closeSession(s, 5, error, false)
    for (const row of s.cache.values()) {
      clear(row.wire)
      for (const packet of row.packets) clear(packet.digest)
    }
    s.cache.clear()
    for (const replay of s.receivedControls.values()) clear(replay.digest)
    s.receivedControls.clear()
    clear(s.openNonce)
    clear(s.openDigest)
    clear(s.sessionId)
    if (s.options) for (const value of Object.values(s.options)) clear(value)
    for (const row of s.controls) clear(row.wire)
    s.controls.length = 0
  }
  service.streams.clear()
  service.sessionIds.clear()
  if (service.table) {
    for (const [key, s] of service.table.tokens) {
      if (s.service === service) service.table.tokens.delete(key)
    }
  }
  clear(service.egressServiceIdentity)
  if (service.route) {
    for (const value of Object.values(service.route)) clear(value)
  }
  service.transport = null
  const owner = service.owner
  if (owner) {
    try {
      owner.destroy(error)
    } catch {}
  }
  service.owner = null
  service.activeWait.reject(error)
  return true
}

function validateEnvelope(service, meta, decoded) {
  const c = decoded.fields.common
  check(
    c &&
      equal(c.routeId, service.route.routeId) &&
      c.streamEpoch === 1 &&
      c.flags === 0 &&
      c.reserved === 0 &&
      typeof c.streamId === 'bigint' &&
      c.streamId > 0n
  )
  check(
    meta &&
      typeof meta.sequence === 'bigint' &&
      meta.sequence >= 0n &&
      meta.sequence < MAX_U64 &&
      b4a.isBuffer(meta.nestedDigest) &&
      meta.nestedDigest.length === 32
  )
  const data = decoded.messageId === ID.PEER_DATA_V2
  const handshakeData =
    decoded.messageId === ID.PEER_HANDSHAKE_V2 &&
    !(service.route.purpose === 3 && c.streamId === 1n)
  const reverse = decoded.messageId === ID.PEER_CREDIT_V2 || decoded.messageId === ID.PEER_OPENED_V2
  check(
    meta.lane === (data || handshakeData ? 0 : 1) &&
      c.direction === (reverse ? service.direction : service.direction ^ 1)
  )
  if (!data && decoded.messageId !== ID.PEER_HANDSHAKE_V2) check(c.position === 0n)
}

function rememberControl(s, meta, decoded) {
  const id = decoded.messageId
  if (id === ID.PEER_OPEN_V2 || id === ID.PEER_HANDSHAKE_V2 || id === ID.PEER_DATA_V2) return false
  const old = s.receivedControls.get(id)
  if (old && old.sequence === meta.sequence) {
    check(equal(old.digest, meta.nestedDigest))
    return true
  }
  if (old) {
    check(id === ID.PEER_CREDIT_V2 && meta.sequence > old.sequence)
    clear(old.digest)
  }
  s.receivedControls.set(id, { sequence: meta.sequence, digest: bytes(meta.nestedDigest, 32) })
  return false
}

function admitActivation(s) {
  if (s.kind === 'registration') check(s.service.entry && s.service.direction === 1)
  else if (s.kind === 'source') {
    check(s.service.entry && s.service.direction === 1)
    s.hooks = bridgeHooks(s)
  } else check(s.service.direction === 0 && typeof s.service.onSession === 'function')
}

function dispatch(s, decoded, wire) {
  switch (decoded.messageId) {
    case ID.ENTRY_REGISTER_V2:
      return receiveRegister(s, decoded)
    case ID.ENTRY_REGISTERED_V2:
      return receiveRegistered(s, decoded.fields)
    case ID.ENTRY_REVOKE_V2:
      return receiveRevoke(s, decoded.fields)
    case ID.PRIVATE_ACTIVATE_V2:
      return receiveActivate(s, decoded, wire)
    case ID.PRIVATE_READY_V2:
      return receiveReady(s, decoded.fields, wire)
    case ID.PRIVATE_ACK_V2:
      return receiveAck(s, decoded.fields, wire)
    case ID.PRIVATE_ACCEPTED_V2:
      return receiveAccepted(s, decoded.fields, wire)
    case ID.PRIVATE_SOURCE_RECEIPT_V2:
      return receiveReceipt(s, decoded.fields)
    case ID.PRIVATE_OPEN_V2:
      return receivePrivateOpen(s, decoded.fields)
    case ID.LEGACY_RESOLVE_V2:
      return receiveResolve(s, decoded.fields)
    case ID.LEGACY_RESOLVED_V2:
      return receiveResolved(s, decoded.fields)
    case ID.LEGACY_RESERVE_V2:
      return receiveReserve(s, decoded.fields)
    case ID.LEGACY_RESERVED_V2:
      return receiveReserved(s, decoded.fields)
    case ID.PEER_NOISE_FRAGMENT_V2:
      return s.kind === 'legacy'
        ? receiveNoise(s, decoded.fields)
        : receivePrivateNoise(s, decoded.fields, wire)
    case ID.LEGACY_HANDSHAKE_ACCEPT_V2:
      return receiveLegacyAccept(s, decoded.fields)
    case ID.LEGACY_OPEN_V2:
      return receiveLegacyOpen(s, decoded.fields)
    default:
      invalid()
  }
}

function sendNoise(s, raw) {
  liveSession(s)
  if (s.kind !== 'legacy') return sendPrivateNoise(s, raw)
  const number = s.service.direction === 0 ? 1 : 2
  check(
    s.kind === 'legacy' &&
      !s.flights[number - 1] &&
      b4a.isBuffer(raw) &&
      raw.length > 0 &&
      raw.length <= 4096
  )
  const flight = { raw: b4a.from(raw), digest: noiseDigest(raw), complete: true, sent: false }
  s.flights[number - 1] = flight
  if (s.lifecycle === 'RESERVED' || number === 2) publishNoise(s, number)
}

function publishNoise(s, number) {
  const flight = s.flights[number - 1]
  check(flight && flight.complete && !flight.sent)
  flight.sent = true
  s.lifecycle = number === 1 ? 'WAITING_NOISE' : 'WAITING_ACCEPT'
  const raw = flight.raw
  const count = Math.ceil(raw.length / NOISE_BYTES)
  for (let index = 0; index < count; index++) {
    liveSession(s)
    const offset = index * NOISE_BYTES
    const fragment = raw.subarray(offset, Math.min(raw.length, offset + NOISE_BYTES))
    authored(s, ID.PEER_NOISE_FRAGMENT_V2, {
      sessionId: s.sessionId,
      flight: number,
      wholeCiphertextCommitment: flight.digest,
      totalCiphertextBytes: raw.length,
      fragmentIndex: index,
      fragmentCount: count,
      ciphertextOffset: offset,
      fragmentBytes: fragment.length,
      ciphertext: fragment
    })
  }
}

function receiveNoise(s, f) {
  const expected = s.service.direction === 0 ? 2 : 1
  check(
    f.flight === expected &&
      equal(f.sessionId, s.sessionId) &&
      s.lifecycle === (expected === 1 ? 'RESERVED' : 'WAITING_NOISE')
  )
  let flight = s.flights[expected - 1]
  if (!flight) {
    check(f.fragmentIndex === 0)
    flight = s.flights[expected - 1] = {
      raw: b4a.alloc(f.totalCiphertextBytes),
      digest: bytes(f.wholeCiphertextCommitment, 32),
      complete: false,
      count: f.fragmentCount,
      received: 0
    }
  }
  check(
    !flight.complete &&
      flight.received === f.fragmentIndex &&
      flight.raw.length === f.totalCiphertextBytes &&
      flight.count === f.fragmentCount &&
      equal(flight.digest, f.wholeCiphertextCommitment)
  )
  f.ciphertext.copy(flight.raw, f.ciphertextOffset)
  if (++flight.received !== flight.count) return
  const hash = noiseDigest(flight.raw)
  try {
    check(equal(hash, flight.digest))
  } finally {
    clear(hash)
  }
  flight.complete = true
  if (expected === 1) return legacyHandshake(s, flight.raw)
  s.lifecycle = 'AUTHENTICATING_NOISE'
  invoke(s, 'onHandshake', flight.raw)
}

function destroyResource(value, error) {
  if (value && typeof value.destroy === 'function') {
    try {
      value.destroy(error)
    } catch {}
  }
}

// The resolver owns discovery state. Its reservation owns native I/O and is
// destroyed synchronously on revocation, including results arriving after it.
function receiveResolve(s, f) {
  check(s.service.direction === 1 && s.lifecycle === 'RESOLVING' && s.rxPosition === 1n)
  check(
    f.requestedFrames === s.maxFrames &&
      f.requestedBytes === s.maxBytes &&
      f.requestedFrames <= s.service.maxFrames &&
      f.requestedBytes <= s.service.maxBytes
  )
  check(s.service.legacy && typeof s.service.legacy.resolve === 'function')
  project(s, f.deadlineUnixMs)
  s.lifecycle = 'RESOLVE_PENDING'
  asyncJob(
    s,
    () =>
      withFields(s, [ID.LEGACY_RESOLVE_V2], (request) => {
        // Adapter arguments are owned by the adapter, not decoded-frame scratch.
        return s.service.legacy.resolve({
          sessionId: b4a.from(request.sessionId),
          expectedNoiseKey: b4a.from(request.expectedNoiseKey),
          clientNonce: b4a.from(request.clientNonce),
          deadlineUnixMs: request.deadlineUnixMs,
          localDeadline: s.deadline,
          maxCandidates: request.maxCandidates,
          maxNoiseBytes: request.maxNoiseBytes,
          requestedFrames: request.requestedFrames,
          requestedBytes: request.requestedBytes
        })
      }),
    (resolution) => {
      check(
        resolution &&
          typeof resolution.reserve === 'function' &&
          typeof resolution.destroy === 'function'
      )
      s.resolution = resolution
      withFields(s, [ID.LEGACY_RESOLVE_V2], (request) => {
        check(resolution.candidateCount <= request.maxCandidates)
        project(s, resolution.expiresAtUnixMs)
        const nonce = random(s.service, 16)
        try {
          s.lifecycle = 'RESOLVED'
          authored(s, ID.LEGACY_RESOLVED_V2, {
            sessionId: s.sessionId,
            clientNonce: request.clientNonce,
            egressRef: resolution.egressRef,
            candidateCount: resolution.candidateCount,
            expiresAtUnixMs: s.expiry,
            reservationNonce: nonce
          })
        } finally {
          clear(nonce)
        }
      })
    },
    destroyResource
  )
}

function receiveResolved(s, f) {
  check(s.endpoint && s.lifecycle === 'RESOLVING')
  withFields(s, [ID.LEGACY_RESOLVE_V2], (request) => {
    sameFields(f, request, ['sessionId', 'clientNonce'])
    check(f.candidateCount <= request.maxCandidates)
  })
  project(s, f.expiresAtUnixMs)
  s.lifecycle = 'RESERVING'
  authored(s, ID.LEGACY_RESERVE_V2, {
    sessionId: s.sessionId,
    egressRef: f.egressRef,
    reservationNonce: f.reservationNonce,
    egressServiceIdentity: s.options.egressServiceIdentity
  })
}

function nativeHooks(s) {
  return Object.freeze({
    onCiphertext(raw) {
      if (s.closed) return 0
      try {
        return sendData(s, raw) ? raw.length : 0
      } catch (error) {
        closeSession(s, 8, error)
        return 0
      }
    },
    onRemoteFin() {
      if (!s.closed) {
        try {
          finish(s)
        } catch (error) {
          closeSession(s, 8, error)
        }
      }
    },
    onWritable() {
      if (!s.closed) drain(s)
    },
    onReset(error) {
      closeSession(s, 6, error instanceof Error ? error : errorFor(6))
    }
  })
}

function receiveReserve(s, f) {
  check(s.service.direction === 1 && s.lifecycle === 'RESOLVED' && s.resolution)
  withFields(s, [ID.LEGACY_RESOLVED_V2], (resolved) =>
    sameFields(f, resolved, ['sessionId', 'egressRef', 'reservationNonce'])
  )
  check(equal(f.egressServiceIdentity, s.service.egressServiceIdentity))
  s.lifecycle = 'RESERVE_PENDING'
  asyncJob(
    s,
    () =>
      withFields(s, [ID.LEGACY_RESERVE_V2], (request) =>
        s.resolution.reserve(
          {
            sessionId: b4a.from(request.sessionId),
            egressRef: b4a.from(request.egressRef),
            reservationNonce: b4a.from(request.reservationNonce),
            egressServiceIdentity: b4a.from(request.egressServiceIdentity),
            localDeadline: s.deadline
          },
          nativeHooks(s)
        )
      ),
    (native) => {
      check(
        native &&
          [
            'sendHandshake',
            'confirmHandshake',
            'trySendCiphertext',
            'drain',
            'finish',
            'destroy'
          ].every((name) => typeof native[name] === 'function')
      )
      s.native = native
      s.lifecycle = 'RESERVED'
      withFields(s, [ID.LEGACY_RESERVE_V2], (request) => {
        authored(s, ID.LEGACY_RESERVED_V2, {
          sessionId: s.sessionId,
          egressRef: request.egressRef,
          reservationNonce: request.reservationNonce,
          sessionCapability: native.sessionCapability,
          egressRawUdxId: native.egressRawUdxId,
          egressServiceIdentity: s.service.egressServiceIdentity
        })
      })
    },
    destroyResource
  )
}

function receiveReserved(s, f) {
  check(s.endpoint && s.lifecycle === 'RESERVING')
  withFields(s, [ID.LEGACY_RESERVE_V2], (request) =>
    sameFields(f, request, ['sessionId', 'egressRef', 'reservationNonce', 'egressServiceIdentity'])
  )
  s.lifecycle = 'RESERVED'
  if (s.flights[0]) publishNoise(s, 1)
}

function legacyHandshake(s, raw) {
  check(s.native && s.lifecycle === 'RESERVED')
  s.lifecycle = 'NATIVE_HANDSHAKE'
  asyncJob(
    s,
    () => s.native.sendHandshake(raw),
    (response) => {
      check(response && b4a.isBuffer(response.ciphertext))
      s.pendingRemoteUdxId = positive(response.pendingRemoteUdxId, 0xffffffff)
      try {
        sendNoise(s, response.ciphertext)
      } finally {
        clear(response.ciphertext)
      }
    },
    (response) => {
      if (response) clear(response.ciphertext)
    }
  )
}

function confirmHandshake(s, binding) {
  liveSession(s)
  if (s.kind !== 'legacy') return confirmPrivateHandshake(s, binding)
  check(
    s.endpoint &&
      s.lifecycle === 'AUTHENTICATING_NOISE' &&
      !s.handshakeConfirmed &&
      s.flights[0] &&
      s.flights[0].complete &&
      s.flights[1] &&
      s.flights[1].complete
  )
  check(own(binding, 'isInitiator') === true)
  const responder = positive(own(binding, 'validatedResponderUdxId'), 0xffffffff)
  const remote = own(binding, 'remotePublicKey')
  withFields(s, [ID.LEGACY_RESOLVE_V2], (request) => check(equal(remote, request.expectedNoiseKey)))
  for (const name of ['publicKey', 'hash', 'rx', 'tx']) {
    const value = own(binding, name)
    check(b4a.isBuffer(value) && value.length === (name === 'hash' ? 64 : 32))
  }
  // Legacy authenticates the Noise identity at the endpoint, not at the egress.
  // Do not retain direction keys here; only the authenticated native ID crosses.
  s.handshakeConfirmed = true
  s.validatedResponderUdxId = responder
  s.lifecycle = 'WAITING_OPEN'
  withFields(s, [ID.LEGACY_RESERVED_V2], (reserved) => {
    authored(s, ID.LEGACY_HANDSHAKE_ACCEPT_V2, {
      sessionId: s.sessionId,
      egressRef: reserved.egressRef,
      reservationNonce: reserved.reservationNonce,
      ik1Digest: s.flights[0].digest,
      ik2Digest: s.flights[1].digest,
      validatedResponderUdxId: responder
    })
  })
  return s.confirmWait.promise
}

function receiveLegacyAccept(s, f) {
  check(
    s.service.direction === 1 &&
      s.lifecycle === 'WAITING_ACCEPT' &&
      s.native &&
      f.validatedResponderUdxId === s.pendingRemoteUdxId &&
      equal(f.ik1Digest, s.flights[0].digest) &&
      equal(f.ik2Digest, s.flights[1].digest)
  )
  withFields(s, [ID.LEGACY_RESERVED_V2], (reserved) =>
    sameFields(f, reserved, ['sessionId', 'egressRef', 'reservationNonce'])
  )
  s.lifecycle = 'NATIVE_CONFIRM'
  asyncJob(
    s,
    () => s.native.confirmHandshake(s.pendingRemoteUdxId),
    (accepted) => {
      check(accepted === true)
      withFields(s, [ID.LEGACY_RESERVED_V2], (reserved) => {
        s.lifecycle = 'OPEN'
        authored(s, ID.LEGACY_OPEN_V2, {
          sessionId: s.sessionId,
          egressRef: reserved.egressRef,
          reservationNonce: reserved.reservationNonce,
          pendingRemoteUdxId: s.pendingRemoteUdxId,
          ik2Digest: s.flights[1].digest
        })
      })
      liveSession(s)
      semanticSuccess(s, {
        maxFrames: s.maxFrames,
        maxBytes: s.maxBytes,
        idleMs: s.service.idleMs,
        expiresAtUnixMs: s.expiry
      })
    }
  )
}

function receiveLegacyOpen(s, f) {
  check(
    s.endpoint &&
      s.lifecycle === 'WAITING_OPEN' &&
      f.pendingRemoteUdxId === s.validatedResponderUdxId &&
      equal(f.ik2Digest, s.flights[1].digest)
  )
  withFields(s, [ID.LEGACY_RESERVED_V2], (reserved) =>
    sameFields(f, reserved, ['sessionId', 'egressRef', 'reservationNonce'])
  )
  s.lifecycle = 'OPEN'
  semanticSuccess(s, {
    maxFrames: s.maxFrames,
    maxBytes: s.maxBytes,
    idleMs: s.service.idleMs,
    expiresAtUnixMs: s.expiry
  })
}

function resetCode(error) {
  switch (error && error.code) {
    case 'ERR_AUTHENTICATION':
      return 2
    case 'ERR_QUOTA_EXCEEDED':
      return 3
    case 'ERR_PRIVACY_UNAVAILABLE':
      return 5
    case 'ERR_REPLAY':
      return 7
    case 'INVALID_ROUTE':
      return 8
    default:
      return 6
  }
}

function sessionDiagnostics(s) {
  return Object.freeze({
    streamId: s.id,
    purpose: s.service.route.purpose,
    state: s.state,
    lifecycle: s.lifecycle,
    attached: s.attached,
    revoked: s.revoked,
    closed: s.closed,
    ready: s.ready,
    localDeadline: s.deadline,
    expiresAtUnixMs: s.expiry,
    queuedControls: s.controls.length,
    queuedHandshakeObjects: s.queue.length,
    cachedHandshakeBytes: s.cacheBytes,
    pendingCiphertextBytes: s.incoming.reduce(
      (total, row) => total + row.bytes.length - row.offset,
      0
    ),
    admittedDataFrames: s.dataAdmissions.size,
    sentFrames: s.sentFrames,
    sentBytes: s.sentBytes,
    receivedFrames: s.receivedFrames,
    receivedBytes: s.receivedBytes,
    localFin: s.finishing,
    remoteFin: s.remoteEnded
  })
}

function attachEndpoint(s, hooks) {
  liveSession(s)
  check(s.endpoint && !s.attached && hooks && typeof hooks === 'object')
  const snapshot = Object.create(null)
  for (const name of Reflect.ownKeys(hooks)) check(HOOKS.includes(name))
  for (const name of HOOKS) {
    const hook = own(hooks, name)
    check(typeof hook === 'function')
    snapshot[name] = hook
  }
  s.hooks = Object.freeze(snapshot)
  s.attached = true
  const lease = Object.freeze({
    sendHandshake(raw) {
      liveSession(s)
      check(!s.handshakeSent)
      try {
        sendNoise(s, raw)
        s.handshakeSent = true
      } catch (error) {
        closeSession(s, 8, error)
        throw error
      }
    },
    confirmHandshake(binding) {
      try {
        return confirmHandshake(s, binding)
      } catch (error) {
        closeSession(s, 2, error)
        throw error
      }
    },
    trySendCiphertext(raw) {
      return sendData(s, raw)
    },
    drain() {
      liveSession(s)
      drain(s)
      flush(s.service)
    },
    finish() {
      return finish(s)
    },
    reset(error = errorFor(6)) {
      return closeSession(s, resetCode(error), error)
    },
    revoke(error = errorFor(6)) {
      if (s.closed) return false
      s.revoked = true
      s.hooks = null
      return closeSession(s, resetCode(error), error)
    },
    whenOpen() {
      return s.openWait.promise
    },
    finished() {
      return s.finishWait.promise
    },
    diagnostics() {
      return sessionDiagnostics(s)
    }
  })
  if (s.kind !== 'legacy') return lease
  try {
    authored(s, ID.LEGACY_RESOLVE_V2, {
      sessionId: s.sessionId,
      expectedNoiseKey: s.options.expectedNoiseKey,
      clientNonce: s.options.clientNonce,
      deadlineUnixMs: s.expiry,
      maxCandidates: s.options.maxCandidates,
      maxNoiseBytes: 4096,
      requestedFrames: s.maxFrames,
      requestedBytes: s.maxBytes
    })
  } catch (error) {
    closeSession(s, 8, error)
    throw error
  }
  return lease
}

function openSession(service, options) {
  if (service.destroyed) throw errorFor(1)
  check(service.route && service.transport)
  if (service.route.purpose === 2) return originate(service, options).facade
  check(service.route.purpose === 1)
  check(service.direction === 0 && options && typeof options === 'object')
  const id = service.lastId[0] + 2n
  const f = openFields(service, id, 'legacy', options)
  let s
  try {
    check(f.requestedDataFrames <= service.maxFrames && f.requestedDataBytes <= service.maxBytes)
    s = allocate(service, id, service.direction, 'legacy', f)
    s.options = Object.create(null)
    s.options.expectedNoiseKey = bytes(own(options, 'expectedNoiseKey'), 32)
    s.options.egressServiceIdentity = bytes(
      own(options, 'egressServiceIdentity', service.egressServiceIdentity),
      32
    )
    s.options.clientNonce = random(service, 32)
    s.options.maxCandidates = positive(own(options, 'maxCandidates', 8), 8)
    s.sessionId = random(service, 16)
    const key = b4a.toString(s.sessionId, 'hex')
    check(!service.sessionIds.has(key))
    service.sessionIds.add(key)
    project(s, own(options, 'expiresAtUnixMs', service.route.wireExpiresAt))
    control(s, ID.PEER_OPEN_V2, f, (ticket) => {
      if (!s.closed) s.openTicket = ticket
    })
    liveSession(s)
    return s.facade
  } catch (error) {
    if (s) closeSession(s, 8, error)
    throw error
  } finally {
    clear(f.openNonce)
  }
}

function bindOwner(service, owner) {
  if (service.destroyed) throw errorFor(1)
  const route = owner.route()
  try {
    check(
      route &&
        (route.role === 'source' || route.role === 'terminal') &&
        [1, 2, 3].includes(route.purpose) &&
        b4a.isBuffer(route.routeId) &&
        route.routeId.length === 16
    )
    check(
      typeof route.schedule === 'function' &&
        typeof route.monotonicNow === 'function' &&
        typeof route.wallNow === 'function' &&
        route.limits
    )
    positive(route.limits.maxStreams, 0xffffffff)
    positive(route.limits.receiveFrames, 0xffffffff)
    positive(route.limits.receiveBytes, Number.MAX_SAFE_INTEGER)
    u64(route.localDeadline)
    u64(route.wireExpiresAt)
    service.route = route
    service.direction = route.role === 'source' ? 0 : 1
    check(now(service) < route.localDeadline)
    const wall = route.wallNow()
    check(typeof wall === 'bigint' && wall >= 0n && wall < route.wireExpiresAt)
    service.lastWall = wall
    service.transport = owner.transport()
    check(
      service.transport &&
        typeof service.transport.trySend === 'function' &&
        typeof service.transport.isCumulativelyAcknowledged === 'function'
    )
    arm(service)
    service.activeWait.resolve()
  } catch (error) {
    for (const value of Object.values(route || {})) clear(value)
    destroyService(service, error)
    throw error
  }
}

function attachOwner(service, owner) {
  check(
    !service.owner &&
      !service.destroyed &&
      owner &&
      typeof owner.route === 'function' &&
      typeof owner.transport === 'function' &&
      typeof owner.whenActive === 'function' &&
      typeof owner.destroy === 'function'
  )
  service.owner = owner
  let active
  try {
    active = owner.whenActive()
  } catch (error) {
    destroyService(service, error)
    throw error
  }
  Promise.resolve(active)
    .then(() => {
      if (!service.destroyed) bindOwner(service, owner)
    })
    .catch((error) => destroyService(service, error))
  return service.activeWait.promise
}

// Purpose-2 sources openSession({ descriptor, maxFrames, maxBytes, idleMs }).
// Purpose-3 sources register() and attach incoming endpoint leases in onSession.
// Both entry-side services must share one entry authority object.
// Construct before the purpose owner; pass streamCallbacks to that owner and
// attachOwner(owner) once. The owner alone provides transport, clock and timers.
function createPeerSemanticServices(options = {}) {
  check(options && typeof options === 'object')
  const service = {
    owner: null,
    route: null,
    transport: null,
    destroyed: false,
    direction: null,
    streams: new Map(),
    sessionIds: new Set(),
    lastId: [-1n, 0n],
    count: [0, 0],
    windowUsed: 0,
    lastNow: 0n,
    lastWall: 0n,
    timerEpoch: 0,
    cancelTimer: null,
    flushing: false,
    flushPending: false,
    flushScheduled: false,
    activeWait: deferred(),
    maxFrames: positive(own(options, 'maxFrames', 4096), 0xffffffff),
    maxStreams: positive(own(options, 'maxStreams', 64), 0xffffffff),
    idleMs: positive(own(options, 'idleMs', 30000), 0xffffffff),
    handshakeTimeoutMs: positive(own(options, 'handshakeTimeoutMs', 2000), 0x7fffffff),
    randomBytes: own(options, 'randomBytes', (length) => {
      const value = b4a.alloc(length)
      sodium.randombytes_buf(value)
      return value
    }),
    legacy: own(options, 'legacy', null),
    egressServiceIdentity: null,
    entry: own(options, 'entry', null),
    onSession: own(options, 'onSession', null),
    table: null
  }
  check(typeof service.randomBytes === 'function')
  check(service.onSession === null || typeof service.onSession === 'function')
  if (service.entry) {
    check(
      b4a.isBuffer(service.entry.identity) &&
        service.entry.identity.length === 32 &&
        typeof service.entry.verifyAdvertisement === 'function'
    )
    u64(service.entry.epoch)
    service.table = tableFor(service.entry)
  }
  service.maxBytes = u64(own(options, 'maxBytes', BigInt(service.maxFrames) * 977n))
  check(
    service.maxBytes >= 59n &&
      service.maxBytes <= 0xffffffffn &&
      service.maxBytes <= BigInt(service.maxFrames) * 977n
  )
  const identity = own(options, 'egressServiceIdentity', null)
  if (identity !== null) service.egressServiceIdentity = bytes(identity, 32)
  const streamCallbacks = Object.freeze({
    onAdmit: (meta, nested) => admit(service, meta, nested),
    onDeliver: (meta, nested) => deliver(service, meta, nested),
    onAcknowledged: () => flush(service),
    onConflict: () => destroyService(service, errorFor(7)),
    onWritable: () => flush(service),
    onFailure: (error) => destroyService(service, error)
  })
  const facade = Object.freeze({
    streamCallbacks,
    attachOwner: (owner) => attachOwner(service, owner),
    whenActive: () => service.activeWait.promise,
    openSession: (options) => openSession(service, options),
    register: (options) => register(service, options),
    destroy: (error) => destroyService(service, error),
    diagnostics: () =>
      Object.freeze({
        active: !!service.transport && !service.destroyed,
        destroyed: service.destroyed,
        purpose: service.route ? service.route.purpose : null,
        streams: service.streams.size,
        receiveSlots: service.windowUsed,
        sessions: Object.freeze(Array.from(service.streams.values(), sessionDiagnostics))
      })
  })
  return facade
}

const { computePeerConfirmation, verifyPeerConfirmation } = require('./peer-crypto')
const ZERO32 = b4a.alloc(32)
const ENTRY_TABLES = new WeakMap()

function checkCommitment(decoded, label, field) {
  const digest = hashPeer(DOMAIN + label + '/v2', [decoded.body.subarray(0, -32)])
  try {
    check(equal(digest, decoded.fields[field]))
  } finally {
    clear(digest)
  }
}

function committed(s, id, values, label) {
  const field = id === ID.ENTRY_REGISTER_V2 ? 'requestCommitment' : 'activateCommitment'
  const wire = encodePeerSemantic(id, { ...values, [field]: ZERO32 })
  const digest = hashPeer(DOMAIN + label + '/v2', [wire.subarray(8, -32)])
  try {
    digest.copy(wire, wire.length - 32)
    return sendCanonical(s, wire)
  } finally {
    clear(wire)
    clear(digest)
  }
}

function tableFor(entry) {
  let table = ENTRY_TABLES.get(entry)
  if (!table) {
    table = { registrations: new Map(), tokens: new Map() }
    ENTRY_TABLES.set(entry, table)
  }
  return table
}

function descriptorFor(service, f, token) {
  const values = {
    kind: 1,
    expectedDestinationNoiseKey: f.destinationNoiseKey,
    entryIdentity: service.entry.identity,
    advertisementLength: 260,
    advertisement: f.advertisement,
    destinationPurposeDigest: f.purposeDigest,
    destinationFinalTranscriptDigest: f.finalTranscriptDigest,
    destinationCircuitId: f.circuitId,
    destinationGeneration: f.generation,
    entryEpoch: f.entryEpoch,
    maxFrames: f.maxFrames,
    maxBytes: f.maxBytes,
    idleTimeoutMs: f.idleMs,
    expiresAtUnixMs: f.expiresAtUnixMs,
    admissionToken: token,
    registrationCommitment: ZERO32
  }
  const provisional = encodePeerSemantic(ID.PEER_DESCRIPTOR_V2, values)
  const b = provisional.subarray(8)
  const commitment = hashPeer(DOMAIN + 'entry-registration/v2', [
    b.subarray(33, 65),
    b.subarray(1, 33),
    b.subarray(391, 415),
    b.subarray(327, 391),
    b.subarray(415, 479),
    b.subarray(67, 327)
  ])
  try {
    return encodePeerSemantic(ID.PEER_DESCRIPTOR_V2, {
      ...values,
      registrationCommitment: commitment
    })
  } finally {
    clear(provisional)
    clear(commitment)
  }
}

function registerBinding(s, f) {
  const service = s.service
  sameFields(f, service.route, [
    'circuitId',
    'generation',
    'purposeDigest',
    'finalTranscriptDigest'
  ])
  check(
    service.entry &&
      service.entry.epoch === f.entryEpoch &&
      service.entry.verifyAdvertisement(f.advertisement) === true
  )
  check(
    f.maxFrames <= service.maxFrames &&
      f.maxBytes <= service.maxBytes &&
      f.maxBytes >= 59n &&
      f.maxBytes <= BigInt(f.maxFrames) * 977n &&
      f.idleMs <= service.idleMs
  )
}

function receiveRegister(s, decoded) {
  check(s.kind === 'registration' && s.service.direction === 1 && s.cache.size === 1)
  const f = decoded.fields
  checkCommitment(decoded, 'entry-register-request', 'requestCommitment')
  registerBinding(s, f)
  project(s, f.expiresAtUnixMs)
  const table = s.service.table
  let token, key, descriptor
  try {
    for (let attempt = 0; attempt < 9; attempt++) {
      clear(token)
      token = random(s.service, 32)
      key = b4a.toString(token, 'hex')
      if (!table.tokens.has(key)) break
    }
    check(!table.tokens.has(key))
    table.tokens.set(key, s)
    descriptor = descriptorFor(s.service, f, token)
    const d = decodePeerSemantic(descriptor)
    try {
      const row = {
        service: s.service,
        control: s,
        live: true,
        key,
        descriptor,
        sessions: new Set(),
        frames: f.maxFrames,
        bytes: f.maxBytes
      }
      s.registration = row
      table.registrations.set(key, row)
      s.handshakeDeadline = s.deadline
      authored(s, ID.ENTRY_REGISTERED_V2, {
        registerNonce: f.registerNonce,
        token,
        registrationCommitment: d.fields.registrationCommitment,
        circuitId: f.circuitId,
        generation: f.generation,
        expiresAtUnixMs: f.expiresAtUnixMs,
        entryEpoch: f.entryEpoch
      })
      descriptor = null
    } finally {
      eraseDecoded(d)
    }
  } finally {
    clear(token)
    clear(descriptor)
  }
}

function receiveRegistered(s, f) {
  check(s.kind === 'registration' && s.service.direction === 0)
  withFields(s, [ID.ENTRY_REGISTER_V2], (request) => {
    sameFields(f, request, [
      'registerNonce',
      'circuitId',
      'generation',
      'expiresAtUnixMs',
      'entryEpoch'
    ])
    const descriptor = descriptorFor(s.service, request, f.token)
    const decoded = decodePeerSemantic(descriptor)
    try {
      check(equal(decoded.fields.registrationCommitment, f.registrationCommitment))
      s.descriptor = b4a.from(descriptor)
      s.handshakeDeadline = s.deadline
      s.registrationWait.resolve(b4a.from(descriptor))
    } finally {
      clear(descriptor)
      eraseDecoded(decoded)
    }
  })
}

function revokeRegistration(row, code) {
  if (!row.live) return
  row.live = false
  row.service.table.registrations.delete(row.key)
  for (const s of row.sessions) closeSession(s, code)
  row.sessions.clear()
  clear(row.descriptor)
}

function receiveRevoke(s, f) {
  check(s.kind === 'registration' && s.registration && s.registration.live)
  withFields(s, [ID.ENTRY_REGISTERED_V2], (registered) =>
    sameFields(f, registered, ['token', 'registrationCommitment', 'circuitId', 'generation'])
  )
  revokeRegistration(s.registration, 6)
  closeSession(s, 6)
}

function bridgeHooks(s) {
  return Object.freeze({
    onCiphertext: (raw) => (s.pair && !s.pair.closed && sendData(s.pair, raw) ? raw.length : 0),
    onRemoteFin: () => {
      if (s.pair && !s.pair.closed) finish(s.pair)
    },
    onWritable: () => {
      if (s.pair && !s.pair.closed) drain(s.pair)
    },
    onReset: (error) => {
      if (s.pair) closeSession(s.pair, 6, error)
    }
  })
}

function originate(service, options, kind = 'source') {
  check(
    !service.destroyed &&
      service.route &&
      service.transport &&
      options &&
      typeof options === 'object'
  )
  const id = service.lastId[service.direction] + 2n
  check(profile(service, service.direction, id, kind === 'registration' ? 1 : 2) === kind)
  const f = openFields(service, id, kind, options)
  let s
  try {
    s = allocate(service, id, service.direction, kind, f)
    project(s, own(options, 'expiresAtUnixMs', service.route.wireExpiresAt))
    if (kind !== 'registration')
      s.idleMs = positive(own(options, 'idleMs', service.idleMs), service.idleMs)
    if (kind === 'source') {
      s.endpoint = true
      s.options = {}
      s.options.descriptor = bytes(own(options, 'descriptor'), 519)
      const d = decodePeerSemantic(s.options.descriptor)
      try {
        check(
          d.messageId === ID.PEER_DESCRIPTOR_V2 &&
            d.fields.kind === 1 &&
            s.maxFrames <= d.fields.maxFrames &&
            s.maxBytes <= d.fields.maxBytes &&
            s.idleMs <= d.fields.idleTimeoutMs
        )
        project(s, minimum(s.expiry, d.fields.expiresAtUnixMs))
      } finally {
        eraseDecoded(d)
      }
      s.sessionId = random(service, 16)
      const key = b4a.toString(s.sessionId, 'hex')
      check(!service.sessionIds.has(key))
      service.sessionIds.add(key)
      s.options.sourceNonce = random(service, 32)
      s.options.idleMs = s.idleMs
    } else if (kind === 'destination') s.hooks = bridgeHooks(s)
    control(s, ID.PEER_OPEN_V2, f, (ticket) => {
      if (!s.closed) s.openTicket = ticket
    })
    liveSession(s)
    return s
  } catch (error) {
    if (s) closeSession(s, 8, error)
    throw error
  } finally {
    clear(f.openNonce)
  }
}

function register(service, options) {
  check(service.route && service.direction === 0 && service.route.purpose === 3 && service.entry)
  const s = originate(service, options, 'registration')
  service.registration = s
  s.registrationWait = deferred()
  const nonce = random(service, 32)
  try {
    const r = service.route
    const values = {
      destinationNoiseKey: own(options, 'destinationNoiseKey'),
      circuitId: r.circuitId,
      generation: r.generation,
      purposeDigest: r.purposeDigest,
      finalTranscriptDigest: r.finalTranscriptDigest,
      entryEpoch: service.entry.epoch,
      maxFrames: positive(own(options, 'maxFrames', service.maxFrames), service.maxFrames),
      maxBytes: u64(own(options, 'maxBytes', service.maxBytes)),
      idleMs: positive(own(options, 'idleMs', service.idleMs), service.idleMs),
      expiresAtUnixMs: s.expiry,
      advertisementLength: 260,
      advertisement: own(options, 'advertisement'),
      registerNonce: nonce
    }
    registerBinding(s, values)
    committed(s, ID.ENTRY_REGISTER_V2, values, 'entry-register-request')
    return Object.freeze({
      whenRegistered: () => s.registrationWait.promise,
      revoke() {
        liveSession(s)
        check(!s.revokeSent)
        withFields(s, [ID.ENTRY_REGISTERED_V2], (f) =>
          authored(s, ID.ENTRY_REVOKE_V2, {
            token: f.token,
            registrationCommitment: f.registrationCommitment,
            circuitId: f.circuitId,
            generation: f.generation
          })
        )
        s.revokeSent = true
      }
    })
  } catch (error) {
    closeSession(s, 8, error)
    throw error
  } finally {
    clear(nonce)
  }
}

function getDescriptor(s) {
  return withFields(s, [ID.PRIVATE_ACTIVATE_V2], (f) => decodePeerSemantic(f.completeDescriptor))
}

function flightBytes(s, flight) {
  const value = s.flights[flight - 1]
  check(value && value.complete)
  return value.raw
}

function sendPrivateNoise(s, raw) {
  liveSession(s)
  const flight = s.kind === 'destination' ? 2 : 1
  check(!s.flights[flight - 1] && b4a.isBuffer(raw) && raw.length === (flight === 1 ? 101 : 53))
  const digest = noiseDigest(raw)
  try {
    if (s.kind === 'source') {
      const o = s.options
      committed(
        s,
        ID.PRIVATE_ACTIVATE_V2,
        {
          sessionId: s.sessionId,
          sourceCircuitId: s.service.route.circuitId,
          sourceGeneration: s.service.route.generation,
          sourceFinalTranscriptDigest: s.service.route.finalTranscriptDigest,
          sourcePurposeDigest: s.service.route.purposeDigest,
          sourceNonce: o.sourceNonce,
          descriptorLength: 519,
          completeDescriptor: o.descriptor,
          sourceMaxFrames: s.maxFrames,
          sourceMaxBytes: s.maxBytes,
          sourceIdleMs: o.idleMs,
          expiresAtUnixMs: s.expiry,
          ik1Digest: digest,
          ik1Bytes: 101
        },
        'private-activate'
      )
    }
    const row = authored(s, ID.PEER_NOISE_FRAGMENT_V2, {
      sessionId: s.sessionId,
      flight,
      wholeCiphertextCommitment: digest,
      totalCiphertextBytes: raw.length,
      fragmentIndex: 0,
      fragmentCount: 1,
      ciphertextOffset: 0,
      fragmentBytes: raw.length,
      ciphertext: raw
    })
    s.flights[flight - 1] = { raw: row.wire.subarray(71), complete: true, digest: b4a.from(digest) }
    if (s.binding) advanceConfirmation(s)
  } finally {
    clear(digest)
  }
}

function receivePrivateNoise(s, f, wire) {
  const flight =
    s.kind === 'source' ? (s.service.direction === 0 ? 2 : 1) : s.service.direction === 0 ? 1 : 2
  check(
    f.flight === flight &&
      !s.flights[flight - 1] &&
      f.totalCiphertextBytes === (flight === 1 ? 101 : 53)
  )
  const digest = noiseDigest(f.ciphertext)
  try {
    check(equal(digest, f.wholeCiphertextCommitment))
  } finally {
    clear(digest)
  }
  s.flights[flight - 1] = {
    raw: wire.subarray(71),
    complete: true,
    digest: bytes(f.wholeCiphertextCommitment, 32)
  }
  if (flight === 1)
    withFields(s, [ID.PRIVATE_ACTIVATE_V2], (a) =>
      check(equal(a.ik1Digest, f.wholeCiphertextCommitment))
    )
  if (s.pair) {
    check(!s.pair.flights[flight - 1])
    const row = sendCanonical(s.pair, wire)
    s.pair.flights[flight - 1] = {
      raw: row.wire.subarray(71),
      complete: true,
      digest: b4a.from(f.wholeCiphertextCommitment)
    }
    return
  }
  const input = b4a.from(s.flights[flight - 1].raw)
  s.handshakeInput = input
  const release = () => {
    clear(input)
    if (s.handshakeInput === input) s.handshakeInput = null
  }
  try {
    const result = invoke(s, 'onHandshake', input)
    if (result && typeof result.then === 'function') {
      Promise.resolve(result).then(release, (error) => {
        release()
        if (!s.closed) closeSession(s, 2, error)
      })
    } else release()
  } catch (error) {
    release()
    throw error
  }
}

function activateBinding(s, decoded) {
  const f = decoded.fields
  checkCommitment(decoded, 'private-activate', 'activateCommitment')
  const descriptor = decodePeerSemantic(f.completeDescriptor)
  try {
    const d = descriptor.fields
    check(
      f.sourceMaxFrames <= s.maxFrames &&
        f.sourceMaxBytes <= s.maxBytes &&
        f.sourceMaxBytes >= 59n &&
        f.sourceMaxFrames <= d.maxFrames &&
        f.sourceMaxBytes <= d.maxBytes &&
        f.sourceIdleMs <= d.idleTimeoutMs &&
        f.sourceIdleMs <= s.service.idleMs &&
        f.expiresAtUnixMs <= d.expiresAtUnixMs
    )
    const r = s.service.route
    if (s.kind === 'source') {
      check(
        equal(f.sourceCircuitId, r.circuitId) &&
          f.sourceGeneration === r.generation &&
          equal(f.sourcePurposeDigest, r.purposeDigest) &&
          equal(f.sourceFinalTranscriptDigest, r.finalTranscriptDigest)
      )
    } else {
      check(
        equal(d.destinationCircuitId, r.circuitId) &&
          d.destinationGeneration === r.generation &&
          equal(d.destinationPurposeDigest, r.purposeDigest) &&
          equal(d.destinationFinalTranscriptDigest, r.finalTranscriptDigest)
      )
    }
    s.maxFrames = f.sourceMaxFrames
    s.maxBytes = f.sourceMaxBytes
    s.idleMs = f.sourceIdleMs
    project(s, f.expiresAtUnixMs)
  } finally {
    eraseDecoded(descriptor)
  }
}

function receiveActivate(s, decoded, wire) {
  check(s.kind === 'source' || s.kind === 'destination')
  activateBinding(s, decoded)
  if (s.kind === 'destination') {
    const registration = s.service.registration
    check(
      s.service.direction === 0 &&
        registration &&
        !registration.closed &&
        !registration.revokeSent &&
        equal(registration.descriptor, decoded.fields.completeDescriptor)
    )
    s.endpoint = true
    s.service.onSession(s.facade)
    check(s.attached && !s.revoked)
    return
  }
  check(s.service.direction === 1 && s.service.table)
  const d = decodePeerSemantic(decoded.fields.completeDescriptor)
  try {
    const registration = s.service.table.registrations.get(
      b4a.toString(d.fields.admissionToken, 'hex')
    )
    check(
      registration &&
        registration.live &&
        equal(registration.descriptor, decoded.fields.completeDescriptor)
    )
    liveSession(registration.control)
    const destination = registration.service
    check(
      destination !== s.service &&
        destination.route.purpose === 3 &&
        equal(d.fields.entryIdentity, s.service.entry.identity) &&
        registration.frames >= s.maxFrames &&
        registration.bytes >= s.maxBytes
    )
    const other = originate(
      destination,
      {
        maxFrames: s.maxFrames,
        maxBytes: s.maxBytes,
        idleMs: s.idleMs,
        expiresAtUnixMs: minimum(s.expiry, registration.control.expiry)
      },
      'destination'
    )
    s.pair = other
    other.pair = s
    registration.sessions.add(s)
    registration.sessions.add(other)
    s.dependency = other.dependency = registration
    registration.frames -= s.maxFrames
    registration.bytes -= s.maxBytes
    sendCanonical(other, wire)
  } finally {
    eraseDecoded(d)
  }
}

function confirmPrivateHandshake(s, binding) {
  check(
    s.endpoint &&
      !s.handshakeConfirmed &&
      s.handshakeSent &&
      s.flights[0] &&
      s.flights[1] &&
      own(binding, 'isInitiator') === (s.kind === 'source')
  )
  const d = getDescriptor(s)
  try {
    const destinationKey = own(binding, s.kind === 'source' ? 'remotePublicKey' : 'publicKey')
    check(equal(destinationKey, d.fields.expectedDestinationNoiseKey))
    s.binding = {}
    for (const name of ['tx', 'rx', 'hash'])
      s.binding[name] = bytes(own(binding, name), name === 'hash' ? 64 : 32)
    s.arena = b4a.alloc(528)
    s.handshakeConfirmed = true
    advanceConfirmation(s)
    return s.confirmWait.promise
  } finally {
    eraseDecoded(d)
  }
}

function confirmation(s, kind, id, values, verify = false) {
  check(s.binding && s.arena && s.arena.length === 528)
  const tagName = kind === 'receipt' ? 'receiptMac' : kind + 'Mac'
  const wire = encodePeerSemantic(id, verify ? values : { ...values, [tagName]: ZERO32 })
  const parts = [s.cache.get(String(ID.PRIVATE_ACTIVATE_V2)).wire]
  if (kind === 'ready') parts.push(flightBytes(s, 1))
  else {
    parts.push(s.cache.get(String(ID.PRIVATE_READY_V2)).wire)
    if (kind === 'ack') parts.push(flightBytes(s, 1), flightBytes(s, 2))
    else {
      parts.push(s.cache.get(String(ID.PRIVATE_ACK_V2)).wire)
      if (kind === 'receipt') parts.push(s.cache.get(String(ID.PRIVATE_ACCEPTED_V2)).wire)
    }
  }
  parts.push(wire.subarray(8, -32))
  const descriptor = getDescriptor(s)
  try {
    const fromSource = kind === 'ack' || kind === 'receipt'
    const key = fromSource === (s.kind === 'source') ? s.binding.tx : s.binding.rx
    withFields(s, [ID.PRIVATE_ACTIVATE_V2], (a) => {
      const options = {
        directionKey: key,
        label: DOMAIN + `private-${kind}-confirmation-key/v2`,
        noiseHash: s.binding.hash,
        sessionId: s.sessionId,
        sourcePurposeDigest: a.sourcePurposeDigest,
        destinationPurposeDigest: descriptor.fields.destinationPurposeDigest,
        registrationCommitment: descriptor.fields.registrationCommitment,
        transcriptParts: parts
      }
      if (verify)
        check(verifyPeerConfirmation(s.arena, { ...options, receivedTag32: values[tagName] }))
      else {
        computePeerConfirmation(s.arena, { ...options, outputTag32: wire.subarray(-32) })
        sendCanonical(s, wire)
      }
    })
  } finally {
    clear(wire)
    eraseDecoded(descriptor)
  }
}

function readyBinding(s, f) {
  const d = getDescriptor(s)
  try {
    withFields(s, [ID.PRIVATE_ACTIVATE_V2], (a) => {
      sameFields(f, a, ['sessionId', 'activateCommitment', 'ik1Digest'])
      sameFields(f, d.fields, ['destinationCircuitId', 'destinationGeneration'])
      check(
        equal(f.ik1Digest, s.flights[0].digest) &&
          equal(f.ik2Digest, s.flights[1].digest) &&
          f.maxFrames <= minimum(a.sourceMaxFrames, d.fields.maxFrames, s.maxFrames) &&
          f.maxBytes <= minimum(a.sourceMaxBytes, d.fields.maxBytes, s.maxBytes) &&
          f.maxBytes >= 59n &&
          f.expiresAtUnixMs <= minimum(a.expiresAtUnixMs, d.fields.expiresAtUnixMs)
      )
    })
  } finally {
    eraseDecoded(d)
  }
}

function ackBinding(s, f) {
  withFields(s, [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_READY_V2], (a, r) => {
    sameFields(f, a, [
      'sessionId',
      'activateCommitment',
      'sourceCircuitId',
      'sourceGeneration',
      'sourceNonce'
    ])
    sameFields(f, r, ['readyMac', 'destinationNonce', 'ik2Digest'])
  })
}

function acceptedBinding(s, f) {
  withFields(s, [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_READY_V2, ID.PRIVATE_ACK_V2], (a, r, k) => {
    sameFields(f, a, ['sessionId', 'activateCommitment'])
    sameFields(f, r, ['readyMac', 'destinationCircuitId', 'destinationGeneration'])
    sameFields(f, k, ['ackMac'])
  })
}

function advanceConfirmation(s) {
  if (s.closed || !s.binding || !s.flights[0] || !s.flights[1]) return
  if (s.kind === 'destination' && !s.cache.has(String(ID.PRIVATE_READY_V2))) {
    const nonce = random(s.service, 32)
    try {
      withFields(s, [ID.PRIVATE_ACTIVATE_V2], (a) =>
        confirmation(s, 'ready', ID.PRIVATE_READY_V2, {
          sessionId: s.sessionId,
          activateCommitment: a.activateCommitment,
          destinationCircuitId: s.service.route.circuitId,
          destinationGeneration: s.service.route.generation,
          destinationNonce: nonce,
          ik1Digest: s.flights[0].digest,
          ik2Digest: s.flights[1].digest,
          expiresAtUnixMs: s.expiry,
          maxFrames: s.maxFrames,
          maxBytes: s.maxBytes
        })
      )
    } finally {
      clear(nonce)
    }
  }
  if (
    s.kind === 'source' &&
    s.cache.has(String(ID.PRIVATE_READY_V2)) &&
    !s.cache.has(String(ID.PRIVATE_ACK_V2))
  ) {
    withFields(s, [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_READY_V2], (a, r) => {
      readyBinding(s, r)
      confirmation(s, 'ready', ID.PRIVATE_READY_V2, r, true)
      confirmation(s, 'ack', ID.PRIVATE_ACK_V2, {
        sessionId: s.sessionId,
        activateCommitment: a.activateCommitment,
        readyMac: r.readyMac,
        sourceCircuitId: a.sourceCircuitId,
        sourceGeneration: a.sourceGeneration,
        sourceNonce: a.sourceNonce,
        destinationNonce: r.destinationNonce,
        ik2Digest: r.ik2Digest
      })
    })
  }
}

function receiveReady(s, f, wire) {
  readyBinding(s, f)
  project(s, f.expiresAtUnixMs)
  s.maxFrames = f.maxFrames
  s.maxBytes = f.maxBytes
  if (s.pair) {
    check(s.kind === 'destination')
    readyBinding(s.pair, f)
    sendCanonical(s.pair, wire)
  } else advanceConfirmation(s)
}

function receiveAck(s, f, wire) {
  ackBinding(s, f)
  if (s.pair) {
    check(s.kind === 'source')
    ackBinding(s.pair, f)
    sendCanonical(s.pair, wire)
    return
  }
  check(s.kind === 'destination')
  confirmation(s, 'ack', ID.PRIVATE_ACK_V2, f, true)
  withFields(s, [ID.PRIVATE_READY_V2], (r) =>
    confirmation(s, 'accepted', ID.PRIVATE_ACCEPTED_V2, {
      sessionId: s.sessionId,
      activateCommitment: f.activateCommitment,
      readyMac: f.readyMac,
      ackMac: f.ackMac,
      destinationCircuitId: r.destinationCircuitId,
      destinationGeneration: r.destinationGeneration
    })
  )
}

function receiveAccepted(s, f, wire) {
  acceptedBinding(s, f)
  if (s.pair) {
    check(s.kind === 'destination')
    acceptedBinding(s.pair, f)
    sendCanonical(s.pair, wire)
    return
  }
  check(s.kind === 'source')
  confirmation(s, 'accepted', ID.PRIVATE_ACCEPTED_V2, f, true)
  const nonce = random(s.service, 16)
  try {
    withFields(s, [ID.PRIVATE_ACTIVATE_V2], (a) =>
      confirmation(s, 'receipt', ID.PRIVATE_SOURCE_RECEIPT_V2, {
        sessionId: s.sessionId,
        acceptedMac: f.acceptedMac,
        sourceCircuitId: a.sourceCircuitId,
        sourceGeneration: a.sourceGeneration,
        receiptNonce: nonce
      })
    )
  } finally {
    clear(nonce)
  }
}

function receiveReceipt(s, f) {
  check(s.kind === 'source' && s.service.direction === 1 && s.pair)
  withFields(s, [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_ACCEPTED_V2], (a, accepted) => {
    sameFields(f, a, ['sessionId', 'sourceCircuitId', 'sourceGeneration'])
    sameFields(f, accepted, ['acceptedMac'])
  })
  const other = s.pair
  liveSession(other)
  check(s.dependency && s.dependency.live)
  const descriptor = getDescriptor(s)
  try {
    withFields(s, [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_READY_V2, ID.PRIVATE_ACK_V2], (a, r, k) => {
      const maxFrames = minimum(
        a.sourceMaxFrames,
        r.maxFrames,
        descriptor.fields.maxFrames,
        s.maxFrames,
        other.maxFrames,
        s.service.maxFrames,
        other.service.maxFrames
      )
      const maxBytes = minimum(
        a.sourceMaxBytes,
        r.maxBytes,
        descriptor.fields.maxBytes,
        s.maxBytes,
        other.maxBytes,
        s.service.maxBytes,
        other.service.maxBytes,
        BigInt(maxFrames) * 977n
      )
      check(maxFrames >= 1 && maxBytes >= 59n && maxBytes <= 0xffffffffn)
      const bridgeId = random(s.service, 16)
      let wire
      try {
        const values = {
          sessionId: s.sessionId,
          activateCommitment: a.activateCommitment,
          readyMac: r.readyMac,
          ackMac: k.ackMac,
          bridgeId,
          sourceGeneration: a.sourceGeneration,
          destinationGeneration: r.destinationGeneration,
          expiresAtUnixMs: minimum(
            s.expiry,
            other.expiry,
            s.dependency.control.expiry,
            r.expiresAtUnixMs
          ),
          maxFrames,
          maxBytes,
          idleMs: minimum(
            a.sourceIdleMs,
            descriptor.fields.idleTimeoutMs,
            s.service.idleMs,
            other.service.idleMs
          ),
          receiptNonce: f.receiptNonce,
          receiptMac: f.receiptMac
        }
        wire = encodePeerSemantic(ID.PRIVATE_OPEN_V2, values)
        sendCanonical(s, wire)
        sendCanonical(other, wire)
        semanticSuccess(s, values)
        semanticSuccess(other, values)
      } finally {
        clear(wire)
        clear(bridgeId)
      }
    })
  } finally {
    eraseDecoded(descriptor)
  }
}

function receivePrivateOpen(s, f) {
  check(s.endpoint && !s.pair)
  withFields(
    s,
    [ID.PRIVATE_ACTIVATE_V2, ID.PRIVATE_READY_V2, ID.PRIVATE_ACK_V2, ID.PRIVATE_ACCEPTED_V2],
    (a, r, k, accepted) => {
      sameFields(f, a, ['sessionId', 'activateCommitment', 'sourceGeneration'])
      sameFields(f, r, ['readyMac', 'destinationGeneration'])
      sameFields(f, k, ['ackMac'])
      check(
        f.maxFrames <= minimum(s.maxFrames, r.maxFrames) &&
          f.maxBytes <= minimum(s.maxBytes, r.maxBytes, BigInt(f.maxFrames) * 977n) &&
          f.maxBytes >= 59n &&
          f.maxBytes <= 0xffffffffn &&
          f.idleMs <= a.sourceIdleMs &&
          f.expiresAtUnixMs <= minimum(s.expiry, r.expiresAtUnixMs)
      )
      if (s.kind === 'source') {
        withFields(s, [ID.PRIVATE_SOURCE_RECEIPT_V2], (receipt) =>
          sameFields(f, receipt, ['receiptNonce', 'receiptMac'])
        )
      } else {
        confirmation(
          s,
          'receipt',
          ID.PRIVATE_SOURCE_RECEIPT_V2,
          {
            sessionId: s.sessionId,
            acceptedMac: accepted.acceptedMac,
            sourceCircuitId: a.sourceCircuitId,
            sourceGeneration: a.sourceGeneration,
            receiptNonce: f.receiptNonce,
            receiptMac: f.receiptMac
          },
          true
        )
      }
      semanticSuccess(s, f)
    }
  )
}

module.exports = Object.freeze({ createPeerSemanticServices })
