'use strict'

const { EventEmitter } = require('events')
const b4a = require('b4a')
const UDX = require('udx-native')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  validatePeerNativeOptions,
  createPeerNativeRuntimeConfig,
  peerNativeProfile,
  peerNativePurposeLimits,
  peerNativeBuildLimits
} = require('./peer-native-config')
const { createPeerNativeRuntime, readNativeConfig } = require('./peer-native-runtime')
const { createPeerPurposeSource, createPeerPurposeTerminal } = require('./peer-purpose-owner')
const { createPeerSemanticServices } = require('./peer-semantic-services')
const {
  createPeerEndpointController,
  createPeerConnectingStream
} = require('./peer-endpoint-controller')
const { verifyPeerAdvertisement, readVerifiedPeerAdvertisement } = require('./peer-capability')
const { hashPeer } = require('./peer-crypto')
const { decodePeerSemantic } = require('./peer-semantic-wire')
const { PEER_MESSAGE_ID } = require('./peer-protocol')
const {
  lookupPresence,
  publishPresence,
  revokePresence,
  derivePublicReaderSecret,
  PRESENCE_PARAMETERS_DIGEST,
  TOMBSTONE_SCOPE
} = require('./peer-presence')
const { publishPeriods, PERIOD_MS, OVERLAP_MS } = require('./blinded-presence')

// This ordinary DHT topic carries untrusted guard locators, never dial authority.
// Native CAPS and the granted native path authenticate every subsequently used hop.
const GUARD_TOPIC = hashPeer('hyperdht-private-routes/native/guard-locators/v1', [])
const ADVERTISEMENT_DOMAIN = 'hyperdht-private-routes/m3/capability-advertisement-digest/v2'
const CACHE_LIMIT = 64
const CACHE_TTL_MS = 30_000
const PENDING_LIMIT = 16
const SERVER_STATES = new WeakMap()
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get

function invalid() {
  return PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  return PrivateRouteError.ROUTE_UNAVAILABLE()
}

function destroyed() {
  return PrivateRouteError.ERR_DESTROYED()
}

function clear(value) {
  if (b4a.isBuffer(value)) value.fill(0)
}

function eraseFields(value) {
  if (value) for (const field of Object.values(value)) clear(field)
}

function eraseDecoded(value) {
  if (!value) return
  eraseFields(value.fields)
  clear(value.body)
  clear(value.authSuffix)
}

function exactObject(value, names) {
  if (!value || typeof value !== 'object') throw invalid()
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw invalid()
  const result = Object.create(null)
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !names.includes(key)) throw invalid()
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) throw invalid()
    result[key] = descriptor.value
  }
  return result
}

function copyBytes(value, length, nonzero = false) {
  if (!b4a.isBuffer(value)) throw invalid()
  try {
    if (Reflect.apply(byteLength, value, []) !== length) throw invalid()
  } catch {
    throw invalid()
  }
  const result = b4a.alloc(length)
  Uint8Array.prototype.set.call(result, value)
  if (nonzero && !result.some((byte) => byte !== 0)) throw invalid()
  return result
}

function copyKeyPair(value) {
  const pair = exactObject(value, ['publicKey', 'secretKey'])
  const publicKey = copyBytes(pair.publicKey, 32, true)
  let secretKey = null
  let derived = null
  try {
    secretKey = copyBytes(pair.secretKey, 64)
    derived = cryptoSuite.keyPair(secretKey.subarray(0, 32))
    if (!b4a.equals(publicKey, derived.publicKey) || !b4a.equals(secretKey, derived.secretKey))
      throw invalid()
    return { publicKey, secretKey }
  } catch (error) {
    clear(publicKey)
    clear(secretKey)
    throw error
  } finally {
    if (derived) eraseFields(derived)
  }
}

function random(length, excluded = null) {
  for (;;) {
    const bytes = cryptoSuite.randomBytes(length)
    if (bytes.some((byte) => byte !== 0) && (excluded === null || !b4a.equals(bytes, excluded)))
      return bytes
    clear(bytes)
  }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((yes, no) => {
    resolve = yes
    reject = no
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function settled(promises) {
  return Promise.all(promises.map((promise) => Promise.resolve(promise).catch(() => {})))
}

function policyKey(publicKey, readerSecret) {
  const digest = hashPeer('hyperdht-private-routes/native/presence-cache/v1', [
    publicKey,
    readerSecret
  ])
  try {
    return b4a.toString(digest, 'hex')
  } finally {
    clear(digest)
  }
}

function presenceState(value) {
  if (!value) return null
  return {
    present: value.present,
    period: value.period,
    revision: value.revision,
    recordDigest: b4a.from(value.recordDigest)
  }
}

function verifyDescriptor(wire, publicKey) {
  let decoded = null
  let advertisement = null
  let commitment = null
  try {
    decoded = decodePeerSemantic(wire)
    const fields = decoded.fields
    if (
      wire.length !== 519 ||
      decoded.messageId !== PEER_MESSAGE_ID.PEER_DESCRIPTOR_V2 ||
      fields.kind !== 1 ||
      !b4a.equals(fields.expectedDestinationNoiseKey, publicKey) ||
      fields.expiresAtUnixMs <= BigInt(Date.now()) ||
      fields.maxBytes < 59n ||
      fields.maxBytes > 0xffffffffn ||
      fields.maxBytes > BigInt(fields.maxFrames) * 977n
    )
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    advertisement = readVerifiedPeerAdvertisement(
      verifyPeerAdvertisement(fields.advertisement, {
        expectedIdentity32: fields.entryIdentity,
        expectedCapabilityMask: 11,
        expectedRole: 2
      })
    )
    if (
      advertisement.epoch !== fields.entryEpoch ||
      advertisement.expiresAt <= BigInt(Date.now()) ||
      fields.expiresAtUnixMs > advertisement.expiresAt
    )
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    const body = decoded.body
    commitment = hashPeer('hyperdht-private-routes/peer/entry-registration/v2', [
      body.subarray(33, 65),
      body.subarray(1, 33),
      body.subarray(391, 415),
      body.subarray(327, 391),
      body.subarray(415, 479),
      body.subarray(67, 327)
    ])
    if (!b4a.equals(commitment, fields.registrationCommitment))
      throw PrivateRouteError.INVALID_DESCRIPTOR()
    return {
      advertisement: b4a.from(fields.advertisement),
      maxFrames: fields.maxFrames,
      maxBytes: fields.maxBytes,
      idleMs: fields.idleTimeoutMs,
      expiresAt: fields.expiresAtUnixMs
    }
  } finally {
    eraseDecoded(decoded)
    eraseFields(advertisement)
    clear(commitment)
  }
}

function requireNativeProfile(owner, profiles, expectedPurpose) {
  const route = owner.route()
  try {
    if (
      (route.purpose !== 2 && route.purpose !== 3) ||
      (expectedPurpose !== null && route.purpose !== expectedPurpose)
    )
      throw unavailable()
    const profile = route.purpose === 2 ? profiles.source : profiles.registration
    const expected = peerNativePurposeLimits(profile, route.wireExpiresAt)
    for (const name of Object.keys(expected)) {
      if (name === 'expiresAt') continue
      const actual = route.limits[name]
      if (actual < expected[name]) throw unavailable()
      // M and the receive window determine the reviewed CREDIT and memory
      // budgets. More lifetime streams are not a compatible profile either.
      if (
        (name === 'maxStreams' || name === 'receiveFrames' || name === 'receiveBytes') &&
        actual !== expected[name]
      )
        throw unavailable()
    }
  } finally {
    eraseFields(route)
  }
}

class Operation {
  constructor(controller, deadline = false) {
    this.controller = controller
    this.generation = controller.generation
    this.error = null
    this.listeners = new Set()
    this.timer = deadline
      ? setTimeout(() => this.cancel(unavailable()), controller.profile.limits.idleTimeoutMs)
      : null
  }

  check() {
    if (this.error) throw this.error
    if (this.generation !== this.controller.generation || this.controller.stopping)
      throw unavailable()
    if (this.controller.destroyed) throw destroyed()
  }

  cancel(error = destroyed()) {
    if (this.error) return
    this.error = error
    for (const listener of this.listeners) listener(error)
    this.listeners.clear()
    this.finish()
  }

  finish() {
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }
}

class NativeServer extends EventEmitter {
  constructor(controller, options, onconnection) {
    super()
    const state = {
      controller,
      server: this,
      readerSecret: options.readerSecret === undefined ? null : copyBytes(options.readerSecret, 32),
      publicReader: options.readerSecret === undefined,
      firewall: options.firewall || null,
      keyPair: null,
      listening: false,
      closed: false,
      suspended: false,
      starting: null,
      closing: null,
      refreshing: null,
      operation: null,
      timer: null,
      generations: new Set(),
      current: null,
      previous: new Map(),
      publications: new Map(),
      publicationAttempted: false,
      revision: 0,
      jobs: new Set()
    }
    SERVER_STATES.set(this, state)
    if (onconnection) this.on('connection', onconnection)
  }

  get listening() {
    const state = SERVER_STATES.get(this)
    return state.listening && !state.closed && !state.suspended
  }

  get closed() {
    return SERVER_STATES.get(this).closed
  }

  get publicKey() {
    const pair = SERVER_STATES.get(this).keyPair
    return pair ? b4a.from(pair.publicKey) : null
  }

  get relayAddresses() {
    return []
  }

  address() {
    const publicKey = this.publicKey
    return publicKey ? { publicKey, host: null, port: 0 } : null
  }

  listen(keyPair) {
    const state = SERVER_STATES.get(this)
    if (state.closed || state.starting || state.keyPair) return Promise.reject(invalid())
    try {
      state.keyPair = copyKeyPair(keyPair)
      if (state.publicReader) {
        clear(state.readerSecret)
        state.readerSecret = derivePublicReaderSecret(state.keyPair.publicKey)
      }
      state.controller.claimServer(state)
    } catch (error) {
      if (state.keyPair) eraseFields(state.keyPair)
      state.keyPair = null
      return Promise.reject(error)
    }
    state.starting = state.controller.listen(state)
    state.starting.catch(() => {})
    return state.starting
  }

  close() {
    return SERVER_STATES.get(this).controller.closeServer(SERVER_STATES.get(this))
  }

  refresh() {
    const state = SERVER_STATES.get(this)
    return state.controller.refresh(state)
  }
}

class NativeController {
  constructor({ dht, config, baseReady }) {
    if (!dht || typeof baseReady !== 'function') throw invalid()
    this.dht = dht
    this.config = validatePeerNativeOptions(config)
    this.baseReady = baseReady
    this.profile = peerNativeProfile()
    this.runtime = null
    this.state = 'idle'
    this.generation = 1
    this.destroyed = false
    this.stopping = false
    this.suspended = false
    this.starting = null
    this.suspending = null
    this.resuming = null
    this.closing = null
    this.unregister = null
    this.announced = false
    this.announceTimer = null
    this.queries = new Set()
    this.jobs = new Set()
    this.operations = new Set()
    this.bundles = new Set()
    this.servers = new Set()
    this.identities = new Set()
    this.accepting = true
    this.entries = new Map()
    this.cache = new Map()
    this.lookups = new Map()
    this.pending = []
    this.usedSlots = 0
    this.connecting = 0
    this.withdrawing = Promise.resolve()
    this.managedServers = 0
  }

  track(promise, set = this.jobs) {
    set.add(promise)
    promise.then(
      () => set.delete(promise),
      () => set.delete(promise)
    )
    return promise
  }

  operation(deadline = false) {
    const operation = new Operation(this, deadline)
    this.operations.add(operation)
    return operation
  }

  finishOperation(operation) {
    operation.finish()
    operation.listeners.clear()
    this.operations.delete(operation)
  }

  ready(internal = false) {
    if (this.destroyed) return Promise.reject(destroyed())
    if (this.stopping || this.suspended) return Promise.reject(unavailable())
    if (!internal && !this.accepting) return this.resuming || Promise.reject(unavailable())
    if (!this.starting) {
      const generation = this.generation
      this.state = 'starting'
      this.starting = this.start(generation).catch(async (error) => {
        if (this.runtime) await this.runtime.destroy()
        this.runtime = null
        if (this.unregister) this.unregister()
        this.unregister = null
        if (!this.stopping && !this.destroyed) {
          this.state = 'unavailable'
          this.starting = null
        }
        throw error
      })
      this.starting.catch(() => {})
    }
    return this.starting
  }

  checkGeneration(generation) {
    if (this.destroyed) throw destroyed()
    if (this.stopping || this.suspended || this.generation !== generation) throw unavailable()
  }

  async start(generation) {
    await this.baseReady()
    this.checkGeneration(generation)
    const guards = this.config.relay ? null : await this.discoverGuards(generation)
    this.checkGeneration(generation)
    const config = createPeerNativeRuntimeConfig(this.config, this.dht, guards)
    let validated = null
    try {
      validated = readNativeConfig(config)
      const runtime = createPeerNativeRuntime({ dht: this.dht, config })
      this.runtime = runtime
      if (validated.relay && validated.relay.capabilityMask === 11) {
        this.unregister = runtime.onIncomingFinal((lease) => {
          if (this.stopping || this.destroyed || this.generation !== generation) {
            this.track(Promise.resolve(lease.revoke())).catch(() => {})
            return
          }
          this.track(this.acceptFinal(lease, generation)).catch(() => {})
        })
      }
      await runtime.ready()
      this.checkGeneration(generation)
      if (validated.relay && validated.relay.capabilityMask === 9) {
        await this.announceGuard(generation)
        this.checkGeneration(generation)
      }
      this.state = 'ready'
    } finally {
      if (config.identity) eraseFields(config.identity)
      if (validated && validated.identity) eraseFields(validated.identity)
    }
  }

  async discoverGuards(generation) {
    const candidates = new Map()
    const query = this.dht.lookup(GUARD_TOPIC)
    this.queries.add(query)
    try {
      for await (const reply of query) {
        this.checkGeneration(generation)
        if (!reply || !Array.isArray(reply.peers)) continue
        for (const peer of reply.peers) {
          if (!Array.isArray(peer.relayAddresses)) continue
          for (const address of peer.relayAddresses) {
            if (
              !address ||
              !UDX.isIPv4(address.host) ||
              address.host === '0.0.0.0' ||
              !Number.isInteger(address.port) ||
              address.port < 1 ||
              address.port > 65535
            )
              continue
            const key = address.host + ':' + address.port
            if (!candidates.has(key))
              candidates.set(key, { host: address.host, port: address.port })
            if (candidates.size >= 64) break
          }
          if (candidates.size >= 64) break
        }
        if (candidates.size >= 64) break
      }
    } finally {
      query.destroy()
      await Promise.resolve(query.finished()).catch(() => {})
      this.queries.delete(query)
    }
    this.checkGeneration(generation)
    const guards = Array.from(candidates.values())
    for (let index = guards.length - 1; index > 0; index--) {
      const draw = cryptoSuite.randomBytes(4)
      const chosen = draw.readUInt32BE(0) % (index + 1)
      clear(draw)
      ;[guards[index], guards[chosen]] = [guards[chosen], guards[index]]
    }
    if (!guards.length) throw unavailable()
    return guards.slice(0, 3)
  }

  async announceGuard(generation) {
    this.checkGeneration(generation)
    const config = createPeerNativeRuntimeConfig(this.config, this.dht)
    const query = this.dht.announce(GUARD_TOPIC, config.identity, [config.relay.reachable])
    this.queries.add(query)
    // A partial announce still requires withdrawal if cancellation wins the await.
    this.announced = true
    try {
      await query.finished()
      this.checkGeneration(generation)
      if (this.state === 'unavailable') this.state = 'ready'
    } finally {
      this.queries.delete(query)
      eraseFields(config.identity)
    }
    this.scheduleGuardAnnouncement(generation)
  }

  scheduleGuardAnnouncement(generation) {
    if (
      this.announceTimer ||
      !this.runtime ||
      this.stopping ||
      this.destroyed ||
      generation !== this.generation
    )
      return
    this.announceTimer = setTimeout(
      () => {
        this.announceTimer = null
        if (!this.runtime || this.stopping || this.destroyed || generation !== this.generation)
          return
        this.track(this.announceGuard(generation)).catch(() => {
          if (!this.stopping && !this.destroyed && generation === this.generation) {
            this.state = 'unavailable'
            this.scheduleGuardAnnouncement(generation)
          }
        })
      },
      Math.min(60_000, Math.floor(this.profile.lifetimeMs / 4))
    )
  }

  acquire(operation, count = 1, management = false) {
    operation.check()
    if (this.pending.length >= PENDING_LIMIT) return Promise.reject(unavailable())
    const wait = deferred()
    const row = { operation, count, management, wait, cancel: null }
    row.cancel = (error) => {
      const index = this.pending.indexOf(row)
      if (index !== -1) this.pending.splice(index, 1)
      operation.listeners.delete(row.cancel)
      wait.reject(error)
      this.drainSlots()
    }
    operation.listeners.add(row.cancel)
    this.pending.push(row)
    this.drainSlots()
    return wait.promise
  }

  drainSlots() {
    for (;;) {
      // Management owns two reserved slots while listeners exist. This prevents a
      // persistent registration from deadlocking its replacement's publication.
      const management = this.pending.findIndex((row) => row.management)
      const index = management === -1 ? 0 : management
      const row = this.pending[index]
      if (!row || this.stopping || this.suspended || this.destroyed) return
      const capacity = this.profile.sourceSlots - (!row.management && this.managedServers ? 2 : 0)
      if (this.usedSlots + row.count > capacity) return
      this.pending.splice(index, 1)
      row.operation.listeners.delete(row.cancel)
      this.usedSlots += row.count
      let remaining = row.count
      row.wait.resolve((count = remaining) => {
        if (!Number.isInteger(count) || count < 0 || count > remaining) throw invalid()
        remaining -= count
        this.usedSlots -= count
        this.drainSlots()
      })
    }
  }

  entryAuthority(material) {
    const digestKey = b4a.toString(material.terminalAdvertisementDigest, 'hex')
    let entry = this.entries.get(digestKey)
    if (!entry) {
      let identity
      let epoch
      if (material.role === 'source') {
        const advertisement = readVerifiedPeerAdvertisement(
          verifyPeerAdvertisement(material.terminalAdvertisement260, {
            expectedCapabilityMask: 11,
            expectedRole: 2
          })
        )
        try {
          if (
            !b4a.equals(advertisement.advertisementDigest32, material.terminalAdvertisementDigest)
          )
            throw PrivateRouteError.ERR_AUTHENTICATION()
          identity = b4a.from(advertisement.relayIdentity32)
          epoch = advertisement.epoch
        } finally {
          eraseFields(advertisement)
        }
      } else {
        identity = b4a.from(this.config.relayConfig.identityKeyPair.publicKey)
        epoch = this.config.relayConfig.epoch
      }
      const digest = b4a.from(material.terminalAdvertisementDigest)
      const authority = Object.freeze({
        identity,
        epoch,
        verifyAdvertisement(wire) {
          let candidate = null
          try {
            candidate = hashPeer(ADVERTISEMENT_DOMAIN, [wire])
            return b4a.equals(candidate, digest)
          } finally {
            clear(candidate)
          }
        }
      })
      entry = { authority, digest, refs: 0 }
      this.entries.set(digestKey, entry)
    }
    entry.refs++
    return {
      authority: entry.authority,
      release: () => {
        if (--entry.refs !== 0) return
        this.entries.delete(digestKey)
        clear(entry.digest)
        clear(entry.authority.identity)
      }
    }
  }

  async bundle(lease, purpose, operation, onSession = null) {
    let material = null
    let entry = null
    let ephemeral = null
    let options = null
    let bundle = null
    try {
      material = lease.consume()
      if (operation) operation.check()
      const terminal = material.role === 'terminal'
      const profile = purpose === 2 ? this.profile.source : this.profile.registration
      entry = this.entryAuthority(material)
      const limits = peerNativePurposeLimits(profile, material.parentWireExpiresAt)
      if (terminal) {
        const source = peerNativePurposeLimits(this.profile.source, material.parentWireExpiresAt)
        for (const name of Object.keys(limits))
          if (source[name] > limits[name]) limits[name] = source[name]
      }
      const maxFrames =
        terminal || purpose === 3
          ? this.profile.registrationDataFrames
          : this.profile.sourceDataFrames
      const services = createPeerSemanticServices({
        entry: entry.authority,
        maxFrames,
        maxBytes: BigInt(maxFrames) * 977n,
        maxApplicationFrames: Math.min(maxFrames, this.profile.sourceDataFrames),
        applicationFrameFloor: this.profile.applicationFrameFloor,
        maxStreams: terminal ? this.profile.registration.maxStreams : profile.maxStreams,
        idleMs: this.profile.limits.idleTimeoutMs,
        onSession: onSession ? (session) => onSession(bundle, session) : null
      })
      bundle = {
        lease,
        services,
        owner: null,
        entry,
        advertisement: material.terminalAdvertisement260
          ? b4a.from(material.terminalAdvertisement260)
          : null,
        endpoints: new Set(),
        closing: null,
        closed: false,
        timer: null,
        releaseSlot: null,
        onClose: null,
        expiry: material.parentWireExpiresAt
      }
      let eligible = false
      const requireEligibility = () => {
        if (eligible) return
        requireNativeProfile(bundle.owner, this.profile, terminal ? null : purpose)
        eligible = true
      }
      const callbacks = {
        ...services.streamCallbacks,
        onAdmit: (...args) => {
          requireEligibility()
          return services.streamCallbacks.onAdmit(...args)
        },
        onDeliver: (...args) => {
          requireEligibility()
          return services.streamCallbacks.onDeliver(...args)
        },
        onFailure: (error) => {
          services.streamCallbacks.onFailure(error)
          if (operation) operation.cancel(error)
          Promise.resolve()
            .then(() => this.closeBundle(bundle, error))
            .catch(() => {})
        }
      }
      options = {
        carrier: material.carrier,
        circuitId: material.circuitId,
        generation: material.generation,
        parentWireExpiresAt: material.parentWireExpiresAt,
        parentLocalDeadline: material.parentLocalDeadline,
        clockIdentity: material.clockIdentity,
        tailControlTranscriptDigest: material.tailControlTranscriptDigest,
        terminalAdvertisementDigest: material.terminalAdvertisementDigest,
        terminalRoutePublicKey: material.purposeTerminalPublicKey,
        finalizeKeys: material.finalizeKeys,
        sendLedger: material.sendLedger,
        receiveLedger: material.receiveLedger,
        memoryPool: material.memoryPool,
        limits,
        randomBytes: random,
        streamCallbacks: callbacks
      }
      if (terminal) options.terminalRouteSecretKey = material.purposeTerminalSecretKey
      else {
        ephemeral = cryptoSuite.encryptionKeyPair()
        options.purpose = purpose
        options.routeId = random(16)
        options.queryNonce = random(32)
        options.clientEphemeralPublicKey = ephemeral.publicKey
        options.clientEphemeralSecret = ephemeral.secretKey
      }
      bundle.owner = terminal
        ? createPeerPurposeTerminal(options)
        : createPeerPurposeSource(options)
      eraseFields(material)
      eraseFields(material.finalizeKeys)
      if (ephemeral) eraseFields(ephemeral)
      clear(options.routeId)
      clear(options.queryNonce)
      this.bundles.add(bundle)
      const active = services.attachOwner(bundle.owner)
      bundle.owner.start()
      const remaining = material.parentLocalDeadline - material.carrier.clock.monotonicNow()
      bundle.timer = setTimeout(
        () => {
          this.closeBundle(bundle, unavailable()).catch(() => {})
        },
        Number(remaining > 0n ? remaining : 0n)
      )
      if (operation) {
        bundle.cancel = (error) => {
          this.closeBundle(bundle, error).catch(() => {})
        }
        operation.listeners.add(bundle.cancel)
      }
      await active
      requireEligibility()
      if (operation) operation.check()
      return bundle
    } catch (error) {
      if (bundle) await this.closeBundle(bundle, error)
      else {
        if (entry) entry.release()
        await lease.revoke()
      }
      throw error
    } finally {
      if (operation && bundle && bundle.cancel) operation.listeners.delete(bundle.cancel)
      if (ephemeral) eraseFields(ephemeral)
      if (options) {
        clear(options.routeId)
        clear(options.queryNonce)
      }
      if (material) {
        eraseFields(material)
        eraseFields(material.finalizeKeys)
      }
    }
  }

  closeBundle(bundle, error = destroyed()) {
    if (bundle.closing) return bundle.closing
    bundle.closed = true
    if (bundle.timer) clearTimeout(bundle.timer)
    bundle.timer = null
    const close = deferred()
    bundle.closing = close.promise
    // Revoke semantic authority synchronously, before endpoint close callbacks.
    bundle.services.destroy(error)
    if (bundle.owner) bundle.owner.destroy(error)
    const endpoints = Array.from(bundle.endpoints)
    for (const endpoint of endpoints) endpoint.destroy(error)
    ;(async () => {
      try {
        const results = await Promise.allSettled([
          ...endpoints.map((endpoint) => endpoint.finished()),
          bundle.lease.revoke(),
          ...(bundle.owner ? [bundle.owner.whenClosed()] : [])
        ])
        const failure = results.find((result) => result.status === 'rejected')
        if (failure) throw failure.reason
      } finally {
        bundle.entry.release()
        clear(bundle.advertisement)
        if (bundle.releaseSlot) bundle.releaseSlot()
        this.bundles.delete(bundle)
        if (bundle.onClose) bundle.onClose()
      }
    })().then(close.resolve, close.reject)
    return bundle.closing
  }

  async acceptFinal(lease, generation) {
    const operation = this.operation()
    try {
      this.checkGeneration(generation)
      await this.bundle(lease, null, operation)
      operation.check()
    } catch (error) {
      await lease.revoke()
      throw error
    } finally {
      this.finishOperation(operation)
    }
  }

  async build(purpose, operation, advertisement = null, onSession = null) {
    operation.check()
    const profile = purpose === 2 ? this.profile.source : this.profile.registration
    const digest = random(32, PRESENCE_PARAMETERS_DIGEST)
    let lease
    try {
      lease = await this.runtime.buildTail({
        ...peerNativeBuildLimits(profile, this.profile.limits.idleTimeoutMs),
        payloadParametersDigest: digest,
        terminal: advertisement ? { advertisement260: advertisement } : null
      })
      operation.check()
      return await this.bundle(lease, purpose, operation, onSession)
    } catch (error) {
      if (lease) await lease.revoke()
      throw error
    } finally {
      clear(digest)
    }
  }

  cacheEntry(key) {
    let row = this.cache.get(key)
    if (row) this.cache.delete(key)
    else row = { previous: null, descriptor: null, validUntil: 0, wall: 0, users: 0 }
    this.cache.set(key, row)
    while (this.cache.size > CACHE_LIMIT) {
      const oldest = Array.from(this.cache.keys()).find(
        (candidate) => this.cache.get(candidate).users === 0
      )
      if (oldest === undefined) throw unavailable()
      const removed = this.cache.get(oldest)
      clear(removed.descriptor)
      eraseFields(removed.previous)
      this.cache.delete(oldest)
    }
    return row
  }

  async resolve(publicKey, readerSecret, operation) {
    const key = policyKey(publicKey, readerSecret)
    const row = this.cacheEntry(key)
    const now = Date.now()
    if (row.descriptor && now >= row.wall && now < row.validUntil) return b4a.from(row.descriptor)
    clear(row.descriptor)
    row.descriptor = null
    row.users++
    // Serialize by credential as well as identity, so concurrent completions cannot
    // roll back the last authenticated state in the local cache.
    const preceding = this.lookups.get(key)
    const lookup = (async () => {
      if (preceding) await preceding.catch(() => {})
      operation.check()
      const wall = Date.now()
      if (row.descriptor && wall >= row.wall && wall < row.validUntil)
        return b4a.from(row.descriptor)
      const result = await lookupPresence(this.runtime, {
        publicKey,
        readerSecret,
        previous: row.previous
      })
      try {
        operation.check()
        if (result) {
          eraseFields(row.previous)
          row.previous = presenceState(result)
        }
        if (!result || result.present !== true) {
          clear(row.descriptor)
          row.descriptor = null
          throw unavailable()
        }
        const descriptor = verifyDescriptor(result.descriptor, publicKey)
        try {
          row.wall = Date.now()
          row.validUntil = Math.min(
            row.wall + CACHE_TTL_MS,
            Number(descriptor.expiresAt),
            Number((result.period + 1n) * PERIOD_MS + OVERLAP_MS)
          )
          row.descriptor = b4a.from(result.descriptor)
          return b4a.from(result.descriptor)
        } finally {
          clear(descriptor.advertisement)
        }
      } finally {
        if (result) eraseFields(result)
      }
    })()
    this.lookups.set(key, lookup)
    try {
      return await lookup
    } catch (error) {
      clear(row.descriptor)
      row.descriptor = null
      throw error
    } finally {
      row.users--
      if (this.lookups.get(key) === lookup) this.lookups.delete(key)
    }
  }

  connect(publicKey, options = {}) {
    if (this.config.relay) throw unavailable()
    if (this.destroyed) throw destroyed()
    if (this.stopping || this.suspended) throw unavailable()
    if (this.connecting >= PENDING_LIMIT + Math.max(0, this.profile.sourceSlots - this.usedSlots))
      throw unavailable()
    const fields = exactObject(options, ['readerSecret', 'keyPair'])
    const destination = copyBytes(publicKey, 32, true)
    let readerSecret = null
    let keyPair = null
    try {
      readerSecret =
        fields.readerSecret === undefined
          ? derivePublicReaderSecret(destination)
          : copyBytes(fields.readerSecret, 32)
      keyPair = fields.keyPair === undefined ? cryptoSuite.keyPair() : copyKeyPair(fields.keyPair)
    } catch (error) {
      clear(destination)
      clear(readerSecret)
      throw error
    }
    const operation = this.operation(true)
    this.connecting++
    let endpoint = null
    let bundle = null
    let opening = false
    let erased = false
    const erase = () => {
      if (erased) return
      erased = true
      this.connecting--
      clear(destination)
      clear(readerSecret)
      eraseFields(keyPair)
      this.finishOperation(operation)
    }
    const stream = createPeerConnectingStream(
      (stream) => {
        opening = true
        const job = (async () => {
          let release = null
          let descriptor = null
          let verified = null
          try {
            operation.check()
            await this.ready()
            operation.check()
            release = await this.acquire(operation)
            operation.finish()
            operation.check()
            descriptor = await this.resolve(destination, readerSecret, operation)
            operation.check()
            verified = verifyDescriptor(descriptor, destination)
            bundle = await this.build(2, operation, verified.advertisement)
            operation.check()
            bundle.releaseSlot = release
            release = null
            const session = bundle.services.openSession({
              descriptor,
              maxFrames: Math.min(verified.maxFrames, this.profile.sourceDataFrames),
              maxBytes:
                verified.maxBytes < BigInt(this.profile.sourceDataFrames) * 977n
                  ? verified.maxBytes
                  : BigInt(this.profile.sourceDataFrames) * 977n,
              idleMs: Math.min(verified.idleMs, this.profile.limits.idleTimeoutMs)
            })
            endpoint = createPeerEndpointController({
              owner: bundle.owner,
              session,
              keyPair,
              remotePublicKey: destination,
              stream
            })
            bundle.endpoints.add(endpoint)
            endpoint
              .finished()
              .then(() => this.closeBundle(bundle))
              .catch(() => {})
            await endpoint.whenOpen()
            operation.check()
          } catch (error) {
            if (endpoint) endpoint.destroy(error)
            if (bundle) {
              const closing = this.closeBundle(bundle, error)
              // The opening callback must settle before this facade can close.
              if (endpoint) this.track(closing).catch(() => {})
              else await closing
            }
            throw error
          } finally {
            if (release) release()
            clear(descriptor)
            if (verified) clear(verified.advertisement)
            erase()
          }
        })()
        return this.track(job)
      },
      (error) => {
        if (error === null && endpoint) return
        operation.cancel(error instanceof Error ? error : destroyed())
        if (endpoint) endpoint.destroy(operation.error)
        if (bundle) this.closeBundle(bundle, operation.error).catch(() => {})
        if (!opening) erase()
      }
    )
    operation.listeners.add((error) => stream.destroy(error))
    return stream
  }

  createServer(options = {}, onconnection) {
    if (this.config.relay) throw unavailable()
    if (this.destroyed) throw destroyed()
    if (typeof options === 'function') {
      onconnection = options
      options = {}
    }
    const fields = exactObject(options, ['readerSecret', 'firewall'])
    if (fields.firewall !== undefined && typeof fields.firewall !== 'function') throw invalid()
    if (onconnection !== undefined && typeof onconnection !== 'function') throw invalid()
    const server = new NativeServer(this, fields, onconnection)
    this.servers.add(SERVER_STATES.get(server))
    return server
  }

  claimServer(server) {
    if (this.stopping || this.suspended || this.destroyed) throw unavailable()
    const key = b4a.toString(server.keyPair.publicKey, 'hex')
    if (this.identities.has(key)) throw invalid()
    const limit = Math.max(1, Math.floor((this.profile.sourceSlots - 2) / 2))
    if (this.managedServers >= limit) throw unavailable()
    this.identities.add(key)
    this.managedServers++
    server.identity = key
  }

  async listen(server) {
    try {
      await this.ready()
      if (server.closed || server.suspended) throw destroyed()
      await this.refresh(server)
      if (server.closed || server.suspended) throw destroyed()
      server.listening = true
      server.server.emit('listening')
      return server.server
    } catch (error) {
      await this.closeServer(server)
      throw error
    }
  }

  async nextRevision(server, operation) {
    const periods = publishPeriods(Date.now())
    let revision = server.revision
    for (const period of periods) {
      if (operation) operation.check()
      const result = await lookupPresence(this.runtime, {
        publicKey: server.keyPair.publicKey,
        readerSecret: server.readerSecret,
        period,
        previous: server.previous.get(period) || null
      })
      try {
        if (operation) operation.check()
        if (result) {
          revision = Math.max(revision, result.revision)
          eraseFields(server.previous.get(period))
          server.previous.set(period, presenceState(result))
        }
      } finally {
        if (result) eraseFields(result)
      }
    }
    if (revision >= 0xffffffff) throw unavailable()
    server.revision = revision + 1
    return server.revision
  }

  recordPublication(server, records) {
    for (const record of records) {
      const prior = server.publications.get(record.period)
      if (prior) eraseFields(prior)
      server.publications.set(record.period, {
        period: record.period,
        revision: record.revision,
        recordDigest: b4a.from(record.recordDigest)
      })
      eraseFields(server.previous.get(record.period))
      server.previous.set(record.period, presenceState({ ...record, present: true }))
      eraseFields(record)
    }
    const current = BigInt(Math.floor(Date.now() / Number(PERIOD_MS)))
    for (const [period, record] of server.previous) {
      if (period + 1n < current) {
        eraseFields(record)
        server.previous.delete(period)
      }
    }
    for (const [period, record] of server.publications) {
      if (period + 1n < current) {
        eraseFields(record)
        server.publications.delete(period)
      }
    }
  }

  refresh(server) {
    if (server.refreshing) return server.refreshing
    if (server.closed || server.suspended || !server.keyPair || this.stopping || this.suspended)
      return Promise.reject(unavailable())
    if (server.generations.size >= 2) return Promise.reject(unavailable())
    if (server.timer) clearTimeout(server.timer)
    server.timer = null
    const operation = this.operation(true)
    server.operation = operation
    const job = (async () => {
      let release = null
      let bundle = null
      let descriptor = null
      let published = false
      try {
        await this.ready(true)
        operation.check()
        release = await this.acquire(operation, 2, true)
        operation.finish()
        operation.check()
        const revision = await this.nextRevision(server, operation)
        operation.check()
        bundle = await this.build(3, operation, null, (bundle, session) =>
          this.acceptSession(server, bundle, session)
        )
        operation.check()
        const registration = bundle.services.register({
          destinationNoiseKey: server.keyPair.publicKey,
          advertisement: bundle.advertisement,
          maxFrames: this.profile.registrationDataFrames,
          maxBytes: BigInt(this.profile.registrationDataFrames) * 977n,
          idleMs: this.profile.limits.idleTimeoutMs
        })
        bundle.registration = registration
        descriptor = await registration.whenRegistered()
        operation.check()
        const checked = verifyDescriptor(descriptor, server.keyPair.publicKey)
        clear(checked.advertisement)
        bundle.expiry = checked.expiresAt
        // Keep the new registration owned while publication is in flight. A late
        // publication is retained for cleanup even if close/suspend wins the await.
        server.publicationAttempted = true
        const records = await publishPresence(this.runtime, {
          signerKeyPair: server.keyPair,
          readerSecret: server.readerSecret,
          descriptor,
          revision
        })
        this.recordPublication(server, records)
        published = true
        operation.check()
        const previous = server.current
        bundle.releaseSlot = release
        release(1)
        release = null
        server.generations.add(bundle)
        bundle.onClose = () => {
          server.generations.delete(bundle)
          if (server.current === bundle) server.current = null
          if (!server.closed && !server.suspended && !this.stopping) this.armServer(server, 0)
        }
        server.current = bundle
        if (previous) {
          previous.retired = true
          if (!this.hasApplications(previous)) await this.retire(previous)
        }
        this.invalidateCache(server)
        this.armServer(server)
      } catch (error) {
        if (bundle) await this.closeBundle(bundle, error)
        // A failed partial STORE has no readback receipt. Its descriptor loses all
        // registration authority here; close additionally withdraws known records.
        if (published) this.invalidateCache(server)
        throw error
      } finally {
        if (release) release()
        clear(descriptor)
        this.finishOperation(operation)
        if (server.operation === operation) server.operation = null
      }
    })()
    server.refreshing = job
    this.track(job)
    job.then(
      () => {
        if (server.refreshing === job) server.refreshing = null
      },
      () => {
        if (server.refreshing === job) server.refreshing = null
        if (!server.closed && !server.suspended && !this.stopping) this.armServer(server, 1000)
      }
    )
    return job
  }

  hasApplications(bundle) {
    if (bundle.endpoints.size) return true
    return bundle.services
      .diagnostics()
      .sessions.some((session) => session.streamId % 2n === 0n && !session.closed)
  }

  retire(bundle) {
    if (!bundle.closed && bundle.registration) {
      try {
        bundle.registration.revoke()
      } catch {}
    }
    return this.closeBundle(bundle)
  }

  armServer(server, delay = 250) {
    if (server.timer) clearTimeout(server.timer)
    if (server.closed || server.suspended || this.stopping || this.destroyed) return
    server.timer = setTimeout(() => {
      server.timer = null
      if (server.closed || server.suspended || this.stopping) return
      for (const bundle of server.generations) {
        if (bundle.retired && !this.hasApplications(bundle)) this.retire(bundle).catch(() => {})
      }
      const current = server.current
      const registration = current && current.services.diagnostics().registration
      const margin = Math.min(60_000, Math.floor(this.profile.lifetimeMs / 4))
      const needsRefresh =
        !current ||
        current.closed ||
        !registration ||
        !registration.live ||
        current.expiry - BigInt(Date.now()) <= BigInt(margin) ||
        registration.remainingStreams === 0 ||
        registration.remainingFrames < this.profile.applicationFrameFloor ||
        registration.remainingBytes < BigInt(this.profile.applicationFrameFloor) * 977n
      if (needsRefresh && server.generations.size < 2) {
        this.refresh(server).catch(() => {})
      } else this.armServer(server)
    }, delay)
  }

  acceptSession(server, bundle, session) {
    // onSession must attach synchronously before semantic dispatch resumes.
    if (server.closed || server.suspended || this.stopping || bundle.closed) throw unavailable()
    const endpoint = createPeerEndpointController({
      owner: bundle.owner,
      session,
      keyPair: server.keyPair
    })
    bundle.endpoints.add(endpoint)
    const generation = this.generation
    const job = (async () => {
      try {
        const stream = await endpoint.whenOpen()
        if (server.closed || server.suspended || bundle.closed || generation !== this.generation)
          throw destroyed()
        let refused = false
        if (server.firewall) {
          try {
            refused = !!(await Promise.race([
              Promise.resolve(server.firewall(b4a.from(stream.remotePublicKey))),
              endpoint.finished().then(() => {
                throw destroyed()
              })
            ]))
          } catch {
            refused = true
          }
        }
        if (refused) throw PrivateRouteError.UNAUTHORIZED()
        if (
          server.closed ||
          server.suspended ||
          bundle.closed ||
          this.stopping ||
          generation !== this.generation
        )
          throw destroyed()
        server.server.emit('connection', stream)
      } catch (error) {
        await endpoint.destroy(error)
      }
    })()
    this.track(job, server.jobs)
    this.track(job)
    const closing = endpoint.finished().then(async () => {
      bundle.endpoints.delete(endpoint)
      if (bundle.retired && !this.hasApplications(bundle)) await this.retire(bundle)
      if (!server.closed && !server.suspended) this.armServer(server, 0)
    })
    this.track(closing).catch(() => {})
    this.armServer(server, 0)
  }

  invalidateCache(server) {
    const key = policyKey(server.keyPair.publicKey, server.readerSecret)
    const row = this.cache.get(key)
    if (row) {
      clear(row.descriptor)
      row.descriptor = null
      row.validUntil = 0
    }
  }

  withdraw(server) {
    const job = this.withdrawing.then(async () => {
      if (!this.runtime || !server.keyPair || !server.publicationAttempted) return
      const revision = await this.nextRevision(server, null)
      const records = await revokePresence(this.runtime, {
        signerKeyPair: server.keyPair,
        readerSecret: server.readerSecret,
        revision,
        scope: TOMBSTONE_SCOPE.PERIOD
      })
      for (const record of records) {
        eraseFields(server.previous.get(record.period))
        server.previous.set(record.period, presenceState({ ...record, present: false }))
        eraseFields(record)
      }
      server.publicationAttempted = false
      for (const record of server.publications.values()) eraseFields(record)
      server.publications.clear()
    })
    this.withdrawing = job.catch(() => {})
    return job
  }

  closeServer(server) {
    if (server.closing) return server.closing
    server.closed = true
    server.listening = false
    if (server.timer) clearTimeout(server.timer)
    server.timer = null
    if (server.operation) server.operation.cancel(destroyed())
    const job = (async () => {
      const closing = Array.from(server.generations, (bundle) => this.retire(bundle))
      await settled(closing)
      if (server.refreshing) await server.refreshing.catch(() => {})
      await settled(Array.from(server.jobs))
      let release = null
      let operation = null
      try {
        if (this.runtime && server.publicationAttempted) {
          if (!this.stopping && !this.suspended) {
            operation = this.operation(true)
            try {
              release = await this.acquire(operation, 1, true)
              operation.finish()
              operation.check()
            } catch (error) {
              if (!this.stopping && !this.suspended) throw error
            }
          }
          // Shutdown has canceled application admission and released this
          // listener's registration slots. Cleanup STOREs are serialized.
          await this.withdraw(server)
        }
      } finally {
        if (release) release()
        if (operation) this.finishOperation(operation)
        this.eraseServer(server)
        server.server.emit('close')
      }
    })()
    server.closing = job
    this.track(job)
    return job
  }

  eraseServer(server) {
    this.servers.delete(server)
    if (server.identity && this.identities.delete(server.identity)) this.managedServers--
    if (server.keyPair) {
      this.invalidateCache(server)
      eraseFields(server.keyPair)
    }
    server.keyPair = null
    clear(server.readerSecret)
    server.readerSecret = null
    for (const record of server.previous.values()) eraseFields(record)
    for (const record of server.publications.values()) eraseFields(record)
    server.previous.clear()
    server.publications.clear()
    this.drainSlots()
  }

  snapshot() {
    return Object.freeze({
      state: this.state,
      profile: 'native-v2',
      relay: this.config.relay,
      circuits: this.bundles.size,
      pendingConnections: this.pending.filter((row) => !row.management).length,
      sourceSlots: this.profile.sourceSlots,
      occupiedSlots: this.usedSlots,
      servers: this.managedServers
    })
  }

  exposureReport() {
    return Object.freeze({
      overlayParticipation: 'direct-compatible',
      privacyProfile: 'native-v2',
      relayService: this.config.relay ? 'explicit' : 'disabled',
      relayDiscovery: 'ordinary-dht-native-guard-locators',
      relayLocators: 'untrusted-until-native-caps',
      descriptorAddressing: 'period-blinded',
      descriptorOperations: 'native-three-hop-presence',
      descriptorState: 'destination-signed-quorum-readback',
      readerPolicy: 'public-key-derived-unless-explicit-reader-secret',
      descriptorCache: 'bounded-credential-separated-lru-local-hit-timing-observable',
      peerPayload: 'native-onion-noise-secretstream',
      directDestinationSends: 0,
      entryLinkage: 'registration-and-source-circuits-timing-and-volume',
      positionHiding: false,
      connectionMigration: false,
      cancellation: 'late-results-revoked-inflight-native-operations-joined',
      relayRenewal: 'ends-old-generation-circuits',
      legacyFallback: false
    })
  }

  suspend() {
    if (this.destroyed) return this.closing || Promise.resolve()
    if (this.suspending) return this.suspending
    if (this.suspended) return Promise.resolve()
    this.stopping = true
    this.suspended = true
    this.state = 'suspending'
    this.generation++
    for (const operation of this.operations) operation.cancel(unavailable())
    this.suspending = this.stop(false).then(() => {
      if (!this.destroyed) this.state = 'suspended'
    })
    return this.suspending
  }

  async stop(final) {
    if (this.announceTimer) clearTimeout(this.announceTimer)
    this.announceTimer = null
    for (const server of this.servers) {
      server.suspended = true
      if (server.timer) clearTimeout(server.timer)
      server.timer = null
    }
    for (const query of this.queries) query.destroy()
    await settled(Array.from(this.bundles, (bundle) => this.closeBundle(bundle, unavailable())))
    if (this.starting) await this.starting.catch(() => {})
    // A2/A3 have bounded operations but no per-operation abort API. Join all of
    // them before releasing the shared socket; late material is revoked above.
    while (this.jobs.size) await settled(Array.from(this.jobs))
    for (const server of this.servers) {
      try {
        await this.withdraw(server)
      } catch {}
      server.current = null
      server.generations.clear()
    }
    if (this.announced) {
      try {
        await this.dht.unannounce(GUARD_TOPIC, this.config.relayConfig.identityKeyPair)
      } catch {}
      this.announced = false
    }
    if (this.unregister) this.unregister()
    this.unregister = null
    const runtime = this.runtime
    this.runtime = null
    if (runtime) {
      await runtime.suspend()
      await runtime.destroy()
    }
    this.starting = null
    for (const row of this.cache.values()) {
      clear(row.descriptor)
      eraseFields(row.previous)
    }
    this.cache.clear()
    this.lookups.clear()
    if (final) {
      for (const server of Array.from(this.servers)) {
        server.closed = true
        server.listening = false
        this.eraseServer(server)
        server.server.emit('close')
      }
      if (this.config.relay) eraseFields(this.config.relayConfig.identityKeyPair)
    }
  }

  resume() {
    if (this.destroyed) return Promise.reject(destroyed())
    if (this.resuming) return this.resuming
    if (!this.suspended) return this.ready()
    const job = (async () => {
      if (this.suspending) await this.suspending
      if (this.destroyed) throw destroyed()
      this.suspending = null
      this.suspended = false
      this.accepting = false
      this.stopping = false
      this.generation++
      const generation = this.generation
      try {
        await this.ready(true)
        this.checkGeneration(generation)
        for (const server of this.servers) {
          if (server.closed || !server.keyPair) continue
          server.suspended = false
          await this.refresh(server)
          this.checkGeneration(generation)
        }
        if (this.destroyed || this.suspended) throw unavailable()
        this.accepting = true
        this.state = 'ready'
        this.drainSlots()
      } catch (error) {
        if (!this.destroyed && !this.suspended) await this.suspend()
        throw error
      }
    })()
    this.resuming = job
    job.then(
      () => {
        this.resuming = null
      },
      () => {
        this.resuming = null
        if (!this.destroyed && !this.suspended) {
          this.accepting = false
          this.state = 'unavailable'
        }
      }
    )
    return job
  }

  destroy() {
    if (this.closing) return this.closing
    this.destroyed = true
    this.stopping = true
    this.state = 'destroying'
    this.generation++
    for (const operation of this.operations) operation.cancel(destroyed())
    this.closing = (async () => {
      if (this.suspending) await this.suspending.catch(() => {})
      await this.stop(true)
      this.state = 'destroyed'
    })()
    return this.closing
  }
}

function createPrivateNativeController(options) {
  const controller = new NativeController(options)
  return Object.freeze({
    ready: () => controller.ready(),
    snapshot: () => controller.snapshot(),
    exposureReport: () => controller.exposureReport(),
    connect: (publicKey, options) => controller.connect(publicKey, options),
    createServer: (options, onconnection) => controller.createServer(options, onconnection),
    suspend: () => controller.suspend(),
    resume: () => controller.resume(),
    destroy: () => controller.destroy()
  })
}

module.exports = { createPrivateNativeController }
