'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const Plugin = require('../plugin')
const { hash } = require('../crypto')
const {
  createBlindedSigner,
  deriveBlindedPublicKey,
  periodOf,
  lookupPeriods
} = require('./blinded-presence')
const { PrivateRouteError } = require('./errors')
const {
  COMMAND_LOOKUP,
  QUERY_TIMEOUT_MS,
  StorageRouting,
  boundedSession
} = require('./overlay-storage-routing')

const PLUGIN_NAME = 'private-route'
const PLUGIN_VERSION = 4
const COMMAND_GET = 0
const COMMAND_PUT = 1
const COMMAND_CAPABILITY = 2
const DESCRIPTOR_VERSION = 3
const DESCRIPTOR_BYTES = 217
const DESCRIPTOR_BODY_BYTES = 153
const MAX_RECORDS = 256
const MAX_REPLIES = 8
const MIN_READ_QUORUM = 2
const MIN_WRITE_QUORUM = 3
const MAX_LIFETIME_MS = 15 * 60 * 1000
const DOMAIN = b4a.from('hyperdht/private-route-descriptor/v3')
const RELAY_TARGETS = Object.freeze(
  Array.from({ length: 8 }, (_, index) =>
    hash(b4a.from('hyperdht/private-route-relays/v7/' + index))
  )
)
const DIRECTORY_SAMPLE_TARGETS = 3
const DIRECTORY_TTL_MS = 5 * 60 * 1000

function unavailable() {
  return PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function invalid() {
  return PrivateRouteError.INVALID_ROUTE()
}

function key(value) {
  return b4a.toString(value, 'hex')
}

function same(a, b) {
  return b4a.isBuffer(a) && b4a.isBuffer(b) && b4a.equals(a, b)
}

function fixed(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}
function clearDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== 'object') return
  for (const value of Object.values(descriptor)) {
    if (b4a.isBuffer(value)) value.fill(0)
  }
}

function u64(buffer, offset) {
  let value = 0n
  for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(buffer[offset + i])
  return value
}

function putU64(buffer, offset, value) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffffffffffn) throw invalid()
  for (let i = 7; i >= 0; i--) {
    buffer[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function signatureInput(body) {
  return b4a.concat([DOMAIN, body])
}

function descriptorTarget(destinationPublicKey, period) {
  const blinded = deriveBlindedPublicKey(destinationPublicKey, period)
  try {
    return hash(blinded)
  } finally {
    blinded.fill(0)
  }
}

function blindedDescriptorTarget(blindedPublicKey) {
  if (!fixed(blindedPublicKey, 32)) throw invalid()
  return hash(blindedPublicKey)
}

function targetsForLookup(destinationPublicKey, now) {
  return lookupPeriods(now).map((period) => ({
    period,
    target: descriptorTarget(destinationPublicKey, period)
  }))
}

function encodeDescriptor({
  destinationKeyPair,
  entryRelayPublicKey,
  destinationGuardPublicKey,
  routeToken,
  seq,
  expiresAt,
  period = periodOf(Date.now())
}) {
  if (
    !destinationKeyPair ||
    !fixed(destinationKeyPair.publicKey, 32) ||
    !fixed(destinationKeyPair.secretKey, 64) ||
    !fixed(entryRelayPublicKey, 32) ||
    !fixed(destinationGuardPublicKey, 32) ||
    !fixed(routeToken, 32) ||
    same(entryRelayPublicKey, destinationGuardPublicKey)
  ) {
    throw invalid()
  }

  const signer = createBlindedSigner(destinationKeyPair, BigInt(period))
  const wire = b4a.alloc(DESCRIPTOR_BYTES)
  let input = null
  let signature = null
  try {
    wire[0] = DESCRIPTOR_VERSION
    putU64(wire, 1, BigInt(period))
    signer.publicKey.copy(wire, 9)
    entryRelayPublicKey.copy(wire, 41)
    destinationGuardPublicKey.copy(wire, 73)
    routeToken.copy(wire, 105)
    putU64(wire, 137, BigInt(seq))
    putU64(wire, 145, BigInt(expiresAt))
    input = signatureInput(wire.subarray(0, DESCRIPTOR_BODY_BYTES))
    signature = signer.sign(input)
    signature.copy(wire, DESCRIPTOR_BODY_BYTES)
    return wire
  } finally {
    signer.destroy()
    if (input) input.fill(0)
    if (signature) signature.fill(0)
  }
}

function decodeDescriptor(wire, options = {}) {
  if (!fixed(wire, DESCRIPTOR_BYTES) || wire[0] !== DESCRIPTOR_VERSION) throw invalid()
  const period = u64(wire, 1)
  const blindedPublicKey = b4a.from(wire.subarray(9, 41))
  const entryRelayPublicKey = b4a.from(wire.subarray(41, 73))
  const destinationGuardPublicKey = b4a.from(wire.subarray(73, 105))
  const routeToken = b4a.from(wire.subarray(105, 137))
  const seq = u64(wire, 137)
  const expiresAt = u64(wire, 145)
  if (same(entryRelayPublicKey, destinationGuardPublicKey)) throw invalid()
  if (options.expectedPeriod !== undefined && period !== BigInt(options.expectedPeriod)) {
    throw invalid()
  }
  if (options.expectedDestinationPublicKey) {
    const expectedBlindedPublicKey = deriveBlindedPublicKey(
      options.expectedDestinationPublicKey,
      period
    )
    try {
      if (!same(blindedPublicKey, expectedBlindedPublicKey)) throw invalid()
    } finally {
      expectedBlindedPublicKey.fill(0)
    }
  }
  const input = signatureInput(wire.subarray(0, DESCRIPTOR_BODY_BYTES))
  let verified = false
  try {
    verified = sodium.crypto_sign_verify_detached(
      wire.subarray(DESCRIPTOR_BODY_BYTES),
      input,
      blindedPublicKey
    )
  } finally {
    input.fill(0)
  }
  if (!verified) throw invalid()
  const now = BigInt(options.now === undefined ? Date.now() : options.now)
  if (expiresAt <= now || expiresAt - now > BigInt(MAX_LIFETIME_MS)) throw unavailable()
  return Object.freeze({
    wire: b4a.from(wire),
    period,
    blindedPublicKey,
    entryRelayPublicKey,
    destinationGuardPublicKey,
    routeToken,
    seq,
    expiresAt
  })
}

class DescriptorPlugin extends Plugin {
  constructor(relayPublicKey, now, onDestroy) {
    super(PLUGIN_NAME, PLUGIN_VERSION)
    this.relayPublicKey = relayPublicKey === null ? null : b4a.from(relayPublicKey)
    this.now = now
    this.records = new Map()
    this.onDestroy = onDestroy
    this.storage = null
  }

  onpersistent() {}

  destroy() {
    this.onDestroy()
    for (const record of this.records.values()) clearDescriptor(record)
    this.records.clear()
    if (this.relayPublicKey) this.relayPublicKey.fill(0)
    this.relayPublicKey = null
  }

  onrequest(request, outer) {
    if (request.command === COMMAND_CAPABILITY) {
      if (
        this.relayPublicKey !== null &&
        RELAY_TARGETS.some((target) => same(outer.target, target))
      ) {
        outer.reply(this.relayPublicKey, { closerNodes: true })
      }
      return
    }
    if (!fixed(outer.target, 32)) return
    this._prune()
    if (request.command === COMMAND_LOOKUP) {
      if (!fixed(request.value, 1) || request.value[0] > 1) return
      const record = this.records.get(key(outer.target))
      const reply = this.storage.reply(outer.target, record ? record.wire : null)
      outer.reply(reply, { closerNodes: false })
      if (reply !== null && request.value[0] === 1) {
        this.storage.learnRequester(outer.from, outer.target)
      }
      return
    }
    const recordKey = key(outer.target)
    if (request.command === COMMAND_GET) {
      const record = this.records.get(recordKey)
      outer.reply(record ? b4a.from(record.wire) : null)
      return
    }
    if (request.command !== COMMAND_PUT || !outer.token || !b4a.isBuffer(request.value)) return
    let descriptor = null
    let retained = false
    try {
      descriptor = decodeDescriptor(request.value, {
        now: this.now(),
        expectedPeriod: periodOf(this.now())
      })
      const target = blindedDescriptorTarget(descriptor.blindedPublicKey)
      try {
        if (!same(target, outer.target)) return
      } finally {
        target.fill(0)
      }
      const current = this.records.get(recordKey)
      if (current && descriptor.seq === current.seq && !same(descriptor.wire, current.wire)) return
      if (!current || descriptor.seq > current.seq) {
        if (!current && this.records.size >= MAX_RECORDS) this._evictOldest()
        if (current) clearDescriptor(current)
        this.records.set(recordKey, descriptor)
        retained = true
      }
      outer.reply(null, { token: false, closerNodes: false })
    } catch {
      return
    } finally {
      if (!retained) clearDescriptor(descriptor)
    }
  }

  _prune() {
    const now = BigInt(this.now())
    for (const [recordKey, record] of this.records) {
      if (record.expiresAt > now) continue
      this.records.delete(recordKey)
      clearDescriptor(record)
    }
  }

  _evictOldest() {
    let oldestKey = null
    let oldestExpiry = null
    for (const [recordKey, record] of this.records) {
      if (oldestExpiry === null || record.expiresAt < oldestExpiry) {
        oldestKey = recordKey
        oldestExpiry = record.expiresAt
      }
    }
    if (oldestKey !== null) {
      const record = this.records.get(oldestKey)
      this.records.delete(oldestKey)
      clearDescriptor(record)
    }
  }
}

class DescriptorOperation {
  constructor(service, cleanup = false) {
    this.service = service
    this.cleanup = cleanup
    this.queries = new Map()
    this.requestSessions = new Set()
    this.requests = new Set()
    this.closed = false
    this.finishing = false
    this.finished = false
    this.failure = null
    this.untrack = null
    this.done = new Promise((resolve) => {
      this.resolveDone = resolve
    })
    service.operations.add(this)
  }

  check() {
    if (
      this.closed ||
      this.finishing ||
      this.finished ||
      (!this.cleanup && (this.service.closed || this.service.suspended))
    ) {
      throw this.failure || unavailable()
    }
  }

  _query(session, create) {
    this.check()
    let query = null
    try {
      query = create(session)
      const timer = setTimeout(() => this.releaseQuery(query, unavailable()), QUERY_TIMEOUT_MS)
      this.queries.set(query, { session, timer })
      this.check()
      return query
    } catch (error) {
      if (query) this.releaseQuery(query, error)
      else session.destroy(error)
      throw error
    }
  }

  query(message) {
    this.check()
    if (
      !this.service.storage.started ||
      Object.prototype.hasOwnProperty.call(this.service.plugin, 'query')
    ) {
      return this._query(boundedSession(this.service.dht), (session) =>
        this.service.plugin.query(message, { session, retries: 0, concurrency: 6 })
      )
    }
    return this._query(this.service.storage.engine.session(), (session) =>
      this.service.storage.engine.query(message, {
        session,
        retries: 0,
        concurrency: 6,
        transportContext: this
      })
    )
  }

  nativeQuery(create) {
    this.check()
    return this._query(boundedSession(this.service.dht), create)
  }

  releaseQuery(query, reason = this.failure) {
    const owned = this.queries.get(query)
    if (!owned) return
    this.queries.delete(query)
    clearTimeout(owned.timer)
    // Stop scheduling before cancelling the requests that could reschedule it.
    query.destroy(reason)
    owned.session.destroy(reason)
  }

  attempt(message, to, native = false) {
    this.check()
    const session = boundedSession(this.service.dht)
    this.requestSessions.add(session)
    let cancelled = false
    let pending
    try {
      const requester = native ? this.service.dht : this.service.plugin
      pending = requester.request(message, to, { session, retry: false }).then((reply) => {
        this.check()
        if (
          cancelled ||
          !reply ||
          (reply.error !== 0 && reply.error !== undefined) ||
          !reply.from ||
          reply.from.host !== to.host ||
          reply.from.port !== to.port
        )
          throw unavailable()
        return reply
      })
    } catch (error) {
      session.destroy(error)
      this.requestSessions.delete(session)
      throw error
    }
    this.requests.add(pending)
    const release = () => {
      session.destroy()
      this.requestSessions.delete(session)
      this.requests.delete(pending)
    }
    pending.then(release, release)
    return {
      promise: pending,
      cancel(reason) {
        cancelled = true
        session.destroy(reason || unavailable())
      }
    }
  }

  request(message, to) {
    return this.attempt(message, to).promise
  }

  nativeRequest(message, to) {
    return this.attempt(message, to, true).promise
  }

  destroy(error) {
    if (this.closed || this.finished) return
    this.closed = true
    this.failure = error || unavailable()
    for (const query of this.queries.keys()) this.releaseQuery(query)
    for (const session of this.requestSessions) session.destroy(this.failure)
  }

  async finish() {
    this.finishing = true
    for (const query of this.queries.keys()) this.releaseQuery(query)
    for (const session of this.requestSessions) session.destroy(this.failure)
    await Promise.allSettled(this.requests)
    this.finished = true
    this.service.operations.delete(this)
    if (this.untrack) this.untrack()
    this.resolveDone()
  }
}

class OverlayDescriptorService {
  constructor(dht, relayPublicKey = null, now = Date.now, clock = { setTimeout, clearTimeout }) {
    this.dht = dht
    this.now = now
    this.clock = clock
    this.directory = []
    this.directoryExpiresAt = 0
    this.directoryGeneration = 0
    this.directoryPending = null
    this.directoryTimer = null
    this.directoryQueries = new Set()
    this.operations = new Set()
    this.closed = false
    this.suspended = false
    this.plugin = new DescriptorPlugin(relayPublicKey, now, () => this._destroyDirectory())
    dht.register(this.plugin.name, this.plugin)
    this.storage = new StorageRouting(this, DESCRIPTOR_BYTES)
    this.plugin.storage = this.storage
  }

  ready() {
    return this.storage.start()
  }

  async discoverRelays(excluded = []) {
    if (this.closed || this.suspended) throw unavailable()
    if (this.now() >= this.directoryExpiresAt) await this._refreshDirectory()
    if (this.closed || this.suspended) throw unavailable()
    const excludedKeys = new Set(excluded.map(key))
    return this.directory
      .filter((publicKey) => !excludedKeys.has(key(publicKey)))
      .map((publicKey) => b4a.from(publicKey))
  }

  _refreshDirectory() {
    if (this.closed || this.suspended) return Promise.reject(unavailable())
    if (this.directoryPending) return this.directoryPending
    const generation = this.directoryGeneration
    this.directoryPending = this._collectDirectory(generation).finally(() => {
      this.directoryPending = null
      this._scheduleDirectoryRefresh()
    })
    return this.directoryPending
  }

  async _collectDirectory(generation) {
    const targets = RELAY_TARGETS.slice()
    for (let i = 0; i < DIRECTORY_SAMPLE_TARGETS; i++) {
      const selected = i + sodium.randombytes_uniform(targets.length - i)
      ;[targets[i], targets[selected]] = [targets[selected], targets[i]]
    }
    const replies = await Promise.allSettled(
      targets
        .slice(0, DIRECTORY_SAMPLE_TARGETS)
        .map((target) => this._sampleDirectoryTarget(target))
    )
    const found = new Map()
    let completed = 0
    for (const reply of replies) {
      if (reply.status !== 'fulfilled') continue
      completed++
      for (const publicKey of reply.value) {
        const id = key(publicKey)
        if (found.has(id)) publicKey.fill(0)
        else found.set(id, publicKey)
      }
    }
    if (
      this.closed ||
      this.suspended ||
      generation !== this.directoryGeneration ||
      completed === 0
    ) {
      for (const publicKey of found.values()) publicKey.fill(0)
      throw unavailable()
    }
    for (const publicKey of this.directory) publicKey.fill(0)
    this.directory = Array.from(found.values())
    this.directoryExpiresAt = this.now() + DIRECTORY_TTL_MS
  }

  async _sampleDirectoryTarget(target) {
    const sampleKey = b4a.allocUnsafe(32)
    const rank = b4a.allocUnsafe(32)
    sodium.randombytes_buf(sampleKey)
    const sample = []
    const selected = new Set()
    let query = null
    let completed = false
    try {
      query = this.dht.lookup(target)
      this.directoryQueries.add(query)
      for await (const reply of query) {
        if (!reply || !Array.isArray(reply.peers)) continue
        for (const peer of reply.peers) {
          if (!peer || !fixed(peer.publicKey, 32)) continue
          const id = key(peer.publicKey)
          if (selected.has(id)) continue
          // Secret priorities remove arrival-order and duplicate-reply weighting
          // while retaining only eight candidates from any one directory target.
          sodium.crypto_generichash(rank, peer.publicKey, sampleKey)
          if (sample.length === MAX_REPLIES && b4a.compare(rank, sample[0].rank) >= 0) continue
          if (sample.length === MAX_REPLIES) {
            const removed = sample.shift()
            selected.delete(removed.id)
            removed.publicKey.fill(0)
            removed.rank.fill(0)
          }
          sample.push({ id, publicKey: b4a.from(peer.publicKey), rank: b4a.from(rank) })
          selected.add(id)
          sample.sort((a, b) => b4a.compare(b.rank, a.rank))
        }
      }
      completed = true
      return sample.map((candidate) => candidate.publicKey)
    } finally {
      if (query) {
        this.directoryQueries.delete(query)
        query.destroy()
      }
      sampleKey.fill(0)
      rank.fill(0)
      for (const candidate of sample) {
        candidate.rank.fill(0)
        if (!completed) candidate.publicKey.fill(0)
      }
    }
  }

  _scheduleDirectoryRefresh() {
    if (this.directoryTimer !== null) this.clock.clearTimeout(this.directoryTimer)
    this.directoryTimer = null
    if (this.closed || this.suspended) return
    const delay = Math.floor(
      DIRECTORY_TTL_MS * (0.75 + (0.15 * sodium.randombytes_uniform(1_000_000)) / 1_000_000)
    )
    this.directoryTimer = this.clock.setTimeout(() => {
      this.directoryTimer = null
      void this._refreshDirectory().catch(() => {})
    }, delay)
    if (this.directoryTimer.unref) this.directoryTimer.unref()
  }

  async suspend() {
    this.suspended = true
    const operationsClosing = this._cancelOperations()
    this.directoryGeneration++
    this.directoryExpiresAt = 0
    if (this.directoryTimer !== null) this.clock.clearTimeout(this.directoryTimer)
    this.directoryTimer = null
    for (const query of this.directoryQueries) query.destroy()
    await Promise.all([
      operationsClosing,
      this.storage.suspend(),
      this.directoryPending && this.directoryPending.catch(() => {})
    ])
  }

  async resume() {
    if (this.closed) return
    this.suspended = false
    await this.storage.resume()
  }

  _destroyDirectory() {
    this.closed = true
    for (const operation of this.operations) operation.destroy()
    this.directoryGeneration++
    if (this.directoryTimer !== null) this.clock.clearTimeout(this.directoryTimer)
    this.directoryTimer = null
    for (const query of this.directoryQueries) query.destroy()
    for (const publicKey of this.directory) publicKey.fill(0)
    this.directory = []
    this.storageClosing = this.storage.destroy()
  }

  async destroy() {
    this.plugin.destroy()
    await Promise.all([
      ...Array.from(this.operations, (operation) => operation.done),
      this.storageClosing,
      this.directoryPending && this.directoryPending.catch(() => {})
    ])
  }

  _cancelOperations() {
    for (const operation of this.operations) operation.destroy()
    return Promise.all(Array.from(this.operations, (operation) => operation.done))
  }

  async _runOperation(owner, run, cleanup = false) {
    if (!cleanup && (this.closed || this.suspended)) throw unavailable()
    const operation = new DescriptorOperation(this, cleanup)
    let result = null
    let failure = null
    try {
      if (owner) operation.untrack = owner.track(operation)
      operation.check()
      result = await run(operation)
      operation.check()
    } catch (error) {
      failure = error
    } finally {
      // Joining real requests precedes owner release and lifecycle completion.
      await operation.finish()
    }
    if (operation.failure || failure) {
      clearDescriptor(result)
      throw operation.failure || failure
    }
    return result
  }

  async get(destinationPublicKey) {
    if (!fixed(destinationPublicKey, 32)) throw invalid()
    return this._runOperation(null, async (operation) => {
      let best = null
      const targets = targetsForLookup(destinationPublicKey, this.now())
      try {
        for (const row of targets) {
          const candidate = await this._readTarget(
            row.target,
            { expectedDestinationPublicKey: destinationPublicKey, expectedPeriod: row.period },
            operation
          )
          if (candidate === null) continue
          if (best === null || candidate.seq > best.seq) {
            clearDescriptor(best)
            best = candidate
          } else {
            clearDescriptor(candidate)
          }
        }
        operation.check()
        if (best === null) throw unavailable()
        const result = best
        best = null
        return result
      } finally {
        clearDescriptor(best)
        for (const row of targets) row.target.fill(0)
      }
    })
  }

  async getByTarget(target, period, options = {}) {
    if (!fixed(target, 32) || !lookupPeriods(this.now()).includes(period)) throw invalid()
    return this._runOperation(options.owner, async (operation) => {
      const descriptor = await this._readTarget(target, { expectedPeriod: period }, operation)
      try {
        operation.check()
        if (descriptor === null) throw unavailable()
        const actualTarget = blindedDescriptorTarget(descriptor.blindedPublicKey)
        const matches = same(target, actualTarget)
        actualTarget.fill(0)
        if (!matches) throw invalid()
        return descriptor
      } catch (error) {
        clearDescriptor(descriptor)
        throw error
      }
    })
  }

  async _readTarget(target, options, operation, nodes = null) {
    const candidates = new Map()
    const respondents = new Set()
    let best = null
    let query = null
    let returned = false
    try {
      const replies =
        nodes === null
          ? (query = operation.query({ command: COMMAND_GET, target }))
          : this._readNodes(target, nodes, operation)
      for await (const reply of replies) {
        operation.check()
        if (!reply || !b4a.isBuffer(reply.value)) continue
        const respondent = reply.from ? reply.from.host + ':' + reply.from.port : null
        if (respondent !== null && respondents.has(respondent)) continue
        let descriptor = null
        try {
          descriptor = decodeDescriptor(reply.value, {
            ...options,
            now: this.now()
          })
          if (options.expectedWire && !same(options.expectedWire, descriptor.wire)) {
            clearDescriptor(descriptor)
            continue
          }
          if (respondent !== null) respondents.add(respondent)
          const id = key(descriptor.wire)
          let candidate = candidates.get(id)
          if (candidate) {
            candidate.count++
            clearDescriptor(descriptor)
          } else {
            candidate = { descriptor, count: 1 }
            candidates.set(id, candidate)
          }
          descriptor = null
          if (candidate.count >= MIN_READ_QUORUM) best = candidate.descriptor
        } catch {
          clearDescriptor(descriptor)
        }
        // A read quorum is complete without waiting for silent unrelated peers.
        // Publication still drains its own query to the natural final closest set.
        if (best !== null) {
          returned = true
          return best
        }
      }
      operation.check()
      returned = true
      return best
    } finally {
      if (query) operation.releaseQuery(query)
      for (const candidate of candidates.values()) {
        if (!returned || candidate.descriptor !== best) clearDescriptor(candidate.descriptor)
      }
    }
  }

  async *_readNodes(target, nodes, operation) {
    const attempts = []
    const requests = []
    const ready = []
    let remaining = 0
    let wake = null
    const settle = (reply) => {
      if (reply) ready.push(reply)
      remaining--
      if (wake) {
        const resolve = wake
        wake = null
        resolve()
      }
    }
    try {
      for (const candidate of nodes) {
        const attempt = operation.attempt({ command: COMMAND_GET, target }, candidate.from)
        attempts.push(attempt)
        remaining++
        requests.push(attempt.promise.then(settle, () => settle(null)))
      }
      while (remaining !== 0 || ready.length !== 0) {
        if (ready.length === 0)
          await new Promise((resolve) => {
            wake = resolve
          })
        operation.check()
        while (ready.length !== 0) yield ready.shift()
      }
    } finally {
      // Cancellation precedes joining: an early quorum must not wait for the
      // remaining native requests to time out before its setup owner can finish.
      for (const attempt of attempts) attempt.cancel()
      await Promise.allSettled(requests)
    }
  }

  async put(wire, options = {}) {
    return this._runOperation(options.owner, async (operation) => {
      const descriptor = decodeDescriptor(wire, {
        now: this.now(),
        expectedPeriod: periodOf(this.now())
      })
      const target = blindedDescriptorTarget(descriptor.blindedPublicKey)
      const candidates = []
      let readback = null
      try {
        const query = operation.query({ command: COMMAND_GET, target })
        try {
          // Arrival order is not a storage quorum: wait for the final closest set.
          for await (const _ of query) {
            operation.check()
          }
          operation.check()
          const selected = new Set()
          for (const reply of query.closestReplies) {
            if (!reply || !reply.from || !fixed(reply.token, 32)) continue
            const id = reply.from.host + ':' + reply.from.port
            if (selected.has(id)) continue
            selected.add(id)
            candidates.push({ from: reply.from, token: b4a.from(reply.token) })
            if (candidates.length >= MAX_REPLIES) break
          }
        } finally {
          operation.releaseQuery(query)
        }
        if (candidates.length < MIN_WRITE_QUORUM) throw unavailable()
        const writes = await Promise.allSettled(
          candidates.map((candidate) =>
            operation.request(
              { token: candidate.token, command: COMMAND_PUT, target, value: descriptor.wire },
              candidate.from
            )
          )
        )
        operation.check()
        const stored = writes.filter((reply) => reply.status === 'fulfilled').length
        if (stored < MIN_WRITE_QUORUM) throw unavailable()
        readback = await this._readTarget(
          target,
          { expectedPeriod: descriptor.period, expectedWire: descriptor.wire },
          operation,
          candidates
        )
        operation.check()
        if (readback === null || !same(readback.wire, descriptor.wire)) throw unavailable()
        return stored
      } finally {
        clearDescriptor(readback)
        clearDescriptor(descriptor)
        target.fill(0)
        for (const candidate of candidates) candidate.token.fill(0)
      }
    })
  }
}

module.exports = {
  DESCRIPTOR_BYTES,
  MAX_LIFETIME_MS,
  OverlayDescriptorService,
  RELAY_TARGETS,
  decodeDescriptor,
  descriptorTarget,
  encodeDescriptor
}
