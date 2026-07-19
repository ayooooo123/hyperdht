'use strict'

// Cold-start authority narrowed from the reviewed private-routes prototype at
// commit 0305df915b6a767093f9e75e6c06bc0a35da6169 for Gate 3B1.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const {
  abortIndexZeroGuardLink,
  completeIndexZeroGuardLink,
  createIndexZeroGuardLinkOffer,
  destroyM3EstablishedLink,
  readM3EstablishedLink
} = require('./guard-link')
const { digestPayloadParameters } = require('./link-parameters')
const { BRANCH_CLASS, RELAY_CAPABILITY, ROLE, roleForIdentity } = require('./protocol')
const {
  decodeCanonicalEndpoint,
  decodeRelayCapabilityAdvertisement,
  digestRelayCapabilityAdvertisement,
  encodeCanonicalEndpoint
} = require('./relay-capability')
const {
  consumeSealedRelayCandidateDirectory,
  destroySealedRelayCandidateDirectory,
  revokeRelayCandidateDirectorySink,
  sealRelayCandidateDirectorySink
} = require('./relay-candidate-directory')

const BOOTSTRAP_BUDGET = 10_000n
const MAX_CANDIDATES = 16
const MAX_GUARD_CHALLENGES = 3
const MAX_EXPOSURE_ENTRIES = 6
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const REDACTION_DOMAIN = b4a.from('hyperdht-private-routes/bootstrap-exposure/v1')
const OPTION_FIELDS = Object.freeze([
  'endpoints',
  'localIdentity',
  'localSecretKey',
  'datagrams',
  'wallNow',
  'monotonicNow',
  'randomBytes',
  'candidateDirectorySink'
])
const ENDPOINT_FIELDS = Object.freeze(['host', 'port'])
const RESPONSE_FIELDS = Object.freeze({
  cookie: ['cookie'],
  caps: ['advertisements'],
  challenge: ['advertisementDigest'],
  link: ['accept', 'physicalChannel']
})

const byteLengthGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetOwnPropertyNames = Object.getOwnPropertyNames
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols
const objectGetPrototypeOf = Object.getPrototypeOf
const arrayIsArray = Array.isArray
const arrayPush = Array.prototype.push
const reflectApply = Reflect.apply

const states = new WeakMap()
const transfers = new WeakMap()
const leaseMaterials = new WeakMap()
const TEST_ONLY_BOOTSTRAP_IO_OBSERVER = Symbol('test-only-bootstrap-io-observer')

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function unavailable() {
  throw PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? reflectApply(byteLengthGetter, value, []) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (bufferLength(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {}
}

function copy(value, size = bufferLength(value)) {
  if (!fixed(value, size)) invalid()
  const output = b4a.allocUnsafeSlow(size)
  try {
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch {
    clear(output)
    invalid()
  }
}

function exactObject(value, fields) {
  try {
    if (value === null || typeof value !== 'object' || arrayIsArray(value)) invalid()
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) invalid()
    if (objectGetOwnPropertySymbols(value).length !== 0) invalid()
    const names = objectGetOwnPropertyNames(value)
    if (names.length !== fields.length) invalid()
    for (const field of fields) {
      const descriptor = objectGetOwnPropertyDescriptor(value, field)
      if (!descriptor || !('value' in descriptor)) invalid()
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function own(value, name) {
  let descriptor
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (!descriptor || !('value' in descriptor)) invalid()
  return descriptor.value
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function same(left, right) {
  try {
    return bufferLength(left) === bufferLength(right) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function ipv4(host) {
  if (typeof host !== 'string' || host.length < 7 || host.length > 15) return null
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const bytes = b4a.allocUnsafeSlow(4)
  for (let index = 0; index < 4; index++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[index])) return null
    const value = Number(parts[index])
    if (value > 255) return null
    bytes[index] = value
  }
  if (bytes[0] === 0 || bytes[0] >= 224 || bytes.every((value) => value === 255)) return null
  return bytes
}

function ipv6(host) {
  if (typeof host !== 'string' || host.length < 2 || host.length > 45 || host.includes('%')) {
    return null
  }
  if ((host.match(/::/g) || []).length > 1) return null
  const split = host.split('::')
  const left = split[0] === '' ? [] : split[0].split(':')
  const right = split.length === 1 || split[1] === '' ? [] : split[1].split(':')
  if (left.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return null
  if (right.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return null
  const missing = 8 - left.length - right.length
  if ((split.length === 1 && missing !== 0) || (split.length === 2 && missing < 1)) return null
  const words = [...left, ...Array(missing).fill('0'), ...right]
  if (words.length !== 8) return null
  const bytes = b4a.allocUnsafeSlow(16)
  for (let index = 0; index < 8; index++) {
    const word = Number.parseInt(words[index], 16)
    bytes[index * 2] = word >>> 8
    bytes[index * 2 + 1] = word
  }
  let nonzero = false
  for (const byte of bytes) nonzero ||= byte !== 0
  if (!nonzero || bytes[0] === 0xff) return null
  return bytes
}

function ownEndpoint(value) {
  exactObject(value, ENDPOINT_FIELDS)
  const host = own(value, 'host')
  const port = own(value, 'port')
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) invalid()
  let addressBytes = ipv4(host)
  let addressFamily = 4
  if (addressBytes === null) {
    addressBytes = ipv6(host)
    addressFamily = 6
  }
  if (addressBytes === null) invalid()
  let canonical = null
  try {
    canonical = encodeCanonicalEndpoint({ addressFamily, addressBytes, port })
    return { host, port, canonical }
  } finally {
    clear(addressBytes)
  }
}

function ownEndpoints(values) {
  if (!arrayIsArray(values) || values.length < 1) invalid()
  const endpoints = []
  const seen = new Set()
  try {
    for (const value of values) {
      const endpoint = ownEndpoint(value)
      const key = b4a.toString(endpoint.canonical, 'hex')
      if (seen.has(key)) {
        clear(endpoint.canonical)
        continue
      }
      seen.add(key)
      reflectApply(arrayPush, endpoints, [endpoint])
      if (endpoints.length > 3) invalid()
    }
    if (endpoints.length < 1) invalid()
    return endpoints
  } catch (err) {
    for (const endpoint of endpoints) clear(endpoint.canonical)
    throw err
  }
}

function sample(state, name) {
  if (state.sampling || typeof state[name] !== 'function') {
    stop(state)
    destroyed()
  }
  state.sampling = true
  let value
  try {
    value = state[name]()
  } catch {
    stop(state)
    invalid()
  } finally {
    state.sampling = false
  }
  if (!u64(value)) {
    stop(state)
    invalid()
  }
  return value
}

function checkBudget(state) {
  if (!state.live || state.destroyed) destroyed()
  const now = sample(state, 'monotonicNow')
  if (now < state.startedAt || now - state.startedAt >= BOOTSTRAP_BUDGET) unavailable()
  const wall = sample(state, 'wallNow')
  if (state.lastWall !== null && wall + 30_000n < state.lastWall) unavailable()
  state.lastWall = wall
  return wall
}

function random(state, size) {
  let source = null
  try {
    source = state.randomBytes(size)
    if (!state.live) destroyed()
    return copy(source, size)
  } finally {
    clear(source)
  }
}

function exactResponse(value, kind) {
  exactObject(value, RESPONSE_FIELDS[kind])
  return value
}

function request(kind, bytes = null) {
  return objectFreeze(bytes === null ? { kind } : { kind, bytes })
}

async function send(state, endpoint, message) {
  checkBudget(state)
  const transport = state.datagrams
  if (!transport || typeof transport.send !== 'function') destroyed()
  const response = await transport.send(endpoint.host, endpoint.port, message)
  checkBudget(state)
  return response
}

function clearDecoded(value) {
  if (!value) return
  clear(value.relayIdentity)
  clear(value.currentDhtNodeId)
  clear(value.reachableEndpoint)
  clear(value.routeEncryptionPublicKey)
  clear(value.signature)
}

function recordFor(bytes, now) {
  let canonicalBytes = null
  let decoded = null
  let digest = null
  try {
    canonicalBytes = copy(bytes)
    decoded = decodeRelayCapabilityAdvertisement(canonicalBytes, { now })
    digest = digestRelayCapabilityAdvertisement(canonicalBytes, { now })
    const result = {
      canonicalBytes,
      digest,
      identity: copy(decoded.relayIdentity, 32),
      canonicalEndpointBytes: copy(decoded.reachableEndpoint, 19),
      routePublicKey: copy(decoded.routeEncryptionPublicKey, 32),
      role: roleForIdentity(decoded.relayIdentity),
      capabilityMask: decoded.capabilityMask,
      epoch: decoded.epoch,
      issuedAt: decoded.issuedAtMs,
      expiresAt: decoded.expiresAtMs
    }
    canonicalBytes = null
    digest = null
    return result
  } finally {
    clear(canonicalBytes)
    clear(digest)
    clearDecoded(decoded)
  }
}

function clearRecord(record) {
  if (!record) return
  clear(record.canonicalBytes)
  clear(record.digest)
  clear(record.identity)
  clear(record.canonicalEndpointBytes)
  clear(record.routePublicKey)
}

function copyReport(report) {
  return objectFreeze(report.map((entry) => objectFreeze({ ...entry })))
}

function expose(state, phase, category, endpoint, outcome) {
  let digest = null
  let input = null
  try {
    input = b4a.concat([REDACTION_DOMAIN, state.exposureKey, endpoint.canonical])
    digest = cryptoSuite.hash([input])
    const redactedEndpoint = b4a.toString(digest, 'hex').slice(0, 24)
    const now = sample(state, 'monotonicNow')
    const existing = state.exposure.find(
      (entry) => entry.phase === phase && entry.redactedEndpoint === redactedEndpoint
    )
    if (existing) {
      existing.lastAttemptMs = now
      existing.attemptCount++
      existing.outcome = outcome
    } else if (state.exposure.length < MAX_EXPOSURE_ENTRIES) {
      state.exposure.push({
        phase,
        contactCategory: category,
        redactedEndpoint,
        firstAttemptMs: now,
        lastAttemptMs: now,
        attemptCount: 1,
        outcome
      })
    }
  } finally {
    clear(input)
    clear(digest)
  }
}

function stop(state) {
  if (!state || state.destroyed) return false
  state.live = false
  state.destroyed = true
  state.generation = null
  const datagrams = state.datagrams
  state.datagrams = null
  try {
    if (datagrams && typeof datagrams.destroy === 'function') datagrams.destroy()
  } catch {}
  for (const endpoint of state.endpoints) clear(endpoint.canonical)
  state.endpoints.length = 0
  for (const record of state.records) clearRecord(record)
  state.records.length = 0
  state.recordKeys.clear()
  clear(state.localIdentity)
  clear(state.localSecretKey)
  clear(state.exposureKey)
  state.localIdentity = null
  state.localSecretKey = null
  state.exposureKey = null
  state.wallNow = null
  state.monotonicNow = null
  state.randomBytes = null
  return true
}

function destroyLease(material) {
  const state = leaseMaterials.get(material)
  if (!state) return false
  leaseMaterials.delete(material)
  if (state.established) destroyM3EstablishedLink(state.established)
  state.established = null
  return true
}

function issueLease(established) {
  const material = objectFreeze({})
  leaseMaterials.set(material, { established })
  return material
}

function consumeBootstrapGuardPin(transfer) {
  const state = transfer !== null && typeof transfer === 'object' ? transfers.get(transfer) : null
  if (!state) replay()
  transfers.delete(transfer)
  let candidateDirectory = null
  let lease = null
  try {
    if (!leaseMaterials.has(state.guardLeaseMaterial)) replay()
    lease = state.guardLeaseMaterial
    candidateDirectory = consumeSealedRelayCandidateDirectory(state.sealedDirectory)
    const result = objectFreeze({
      guardLeaseMaterial: lease,
      candidateDirectory,
      pinnedGuard: objectFreeze({
        identity: copy(state.pinnedGuard.identity, 32),
        canonicalEndpoint: copy(state.pinnedGuard.canonicalEndpoint, 19),
        advertisementDigest: copy(state.pinnedGuard.advertisementDigest, 32),
        epoch: state.pinnedGuard.epoch,
        expiresAt: state.pinnedGuard.expiresAt
      }),
      exposureReport: copyReport(state.exposureReport)
    })
    state.guardLeaseMaterial = null
    state.sealedDirectory = null
    lease = null
    candidateDirectory = null
    return result
  } catch (err) {
    if (lease) destroyLease(lease)
    if (candidateDirectory && typeof candidateDirectory.destroy === 'function') {
      try {
        candidateDirectory.destroy()
      } catch {}
    }
    throw err
  } finally {
    clear(state.pinnedGuard.identity)
    clear(state.pinnedGuard.canonicalEndpoint)
    clear(state.pinnedGuard.advertisementDigest)
  }
}

function revokeBootstrapGuardPin(transfer) {
  const state = transfer !== null && typeof transfer === 'object' ? transfers.get(transfer) : null
  if (!state) replay()
  transfers.delete(transfer)
  if (state.guardLeaseMaterial) destroyLease(state.guardLeaseMaterial)
  if (state.sealedDirectory) {
    try {
      destroySealedRelayCandidateDirectory(state.sealedDirectory)
    } catch {}
  }
  clear(state.pinnedGuard.identity)
  clear(state.pinnedGuard.canonicalEndpoint)
  clear(state.pinnedGuard.advertisementDigest)
  state.guardLeaseMaterial = null
  state.sealedDirectory = null
  return true
}

async function run(io, state, operationGeneration) {
  let chosen = null
  let pending = null
  let established = null
  let physicalChannel = null
  let sealedDirectory = null
  let lease = null
  let transfer = null
  try {
    state.startedAt = sample(state, 'monotonicNow')
    state.exposureKey = random(state, 32)
    for (const endpoint of state.endpoints) {
      checkBudget(state)
      const cookieResponse = exactResponse(await send(state, endpoint, request('cookie')), 'cookie')
      const cookie = copy(own(cookieResponse, 'cookie'), 32)
      let capsResponse
      try {
        capsResponse = exactResponse(await send(state, endpoint, request('caps', cookie)), 'caps')
      } finally {
        clear(cookie)
      }
      expose(state, 'bootstrap', 'configured-bootstrap', endpoint, 'verified')
      const advertisements = own(capsResponse, 'advertisements')
      if (!arrayIsArray(advertisements) || advertisements.length > MAX_CANDIDATES) invalid()
      for (const bytes of advertisements) {
        if (state.records.length >= MAX_CANDIDATES) break
        const record = recordFor(bytes, checkBudget(state))
        const key = b4a.toString(record.identity, 'hex')
        const prior = state.recordKeys.get(key)
        if (prior !== undefined) {
          if (!same(prior.digest, record.digest)) unavailable()
          clearRecord(record)
          continue
        }
        state.recordKeys.set(key, record)
        state.records.push(record)
      }
    }
    const prospective = state.records.filter(
      (record) =>
        record.role === ROLE.SAFETY && record.capabilityMask === RELAY_CAPABILITY.CIRCUIT_RELAY_V1
    )
    for (let index = 0; index < prospective.length && index < MAX_GUARD_CHALLENGES; index++) {
      const record = prospective[index]
      const endpoint = endpointForRecord(record)
      if (!endpoint) continue
      state.challengeInFlight++
      if (state.challengeInFlight !== 1) unavailable()
      let response
      try {
        response = exactResponse(
          await send(state, endpoint, request('challenge', record.canonicalBytes)),
          'challenge'
        )
      } catch {
        expose(state, 'challenge', 'prospective-guard', endpoint, 'rejected')
        continue
      } finally {
        state.challengeInFlight--
      }
      if (!same(own(response, 'advertisementDigest'), record.digest)) {
        expose(state, 'challenge', 'prospective-guard', endpoint, 'rejected')
        continue
      }
      expose(state, 'challenge', 'prospective-guard', endpoint, 'authenticated')
      chosen = { record, endpoint }
      break
    }
    if (!chosen) unavailable()
    const now = checkBudget(state)
    const identitySeed = copy(state.localSecretKey.subarray(0, 32), 32)
    const identity = cryptoSuite.keyPair(identitySeed)
    clear(identitySeed)
    if (!same(identity.publicKey, state.localIdentity)) unavailable()
    const tailSeed = random(state, 32)
    const tail = cryptoSuite.encryptionKeyPair(tailSeed)
    clear(tailSeed)
    const branchId = random(state, 16)
    const circuitId = random(state, 16)
    const decoded = decodeRelayCapabilityAdvertisement(chosen.record.canonicalBytes, { now })
    try {
      const initiated = createIndexZeroGuardLinkOffer({
        advertisement: chosen.record.canonicalBytes,
        now,
        randomBytes: (size) => random(state, size),
        branchClass: BRANCH_CLASS.LOOKUP,
        branchId,
        circuitId,
        generation: 1n,
        clientCircuitIdentity: identity,
        clientTailEphemeral: tail,
        payloadParametersDigest: digestPayloadParameters(decoded),
        requestedLimits: {
          cellSize: 1200,
          maxCells: decoded.maxCellsPerCircuit,
          maxBytes: decoded.maxBytesPerCircuit,
          maxCommands: decoded.maxCommandsPerCircuit,
          idleTimeoutMs: decoded.idleTimeoutMs,
          expiresAtMs: decoded.expiresAtMs
        }
      })
      pending = initiated.pending
      const linkResponse = exactResponse(
        await send(state, chosen.endpoint, request('link', initiated.offer)),
        'link'
      )
      const channel = own(linkResponse, 'physicalChannel')
      if (
        channel === null ||
        typeof channel !== 'object' ||
        typeof channel.destroy !== 'function'
      ) {
        invalid()
      }
      physicalChannel = channel
      const accept = own(linkResponse, 'accept')
      const movedChannel = physicalChannel
      physicalChannel = null
      established = completeIndexZeroGuardLink(pending, accept, {
        advertisement: chosen.record.canonicalBytes,
        physicalChannel: movedChannel,
        now: checkBudget(state)
      })
      pending = null
      const link = readM3EstablishedLink(established)
      if (!same(link.peerIdentity, chosen.record.identity)) unavailable()
      expose(state, 'link', 'pinned-guard', chosen.endpoint, 'established')
    } finally {
      clear(identity.publicKey)
      clear(identity.secretKey)
      clear(tail.publicKey)
      clear(tail.secretKey)
      clear(branchId)
      clear(circuitId)
      clearDecoded(decoded)
    }
    const directoryRecords = state.records
      .filter((record) => record !== chosen.record)
      .map((record) => ({
        canonicalBytes: record.canonicalBytes,
        digest: record.digest,
        identity: record.identity,
        canonicalEndpointBytes: record.canonicalEndpointBytes,
        routePublicKey: record.routePublicKey,
        role: record.role,
        capabilityMask: record.capabilityMask,
        epoch: record.epoch,
        issuedAt: record.issuedAt,
        expiresAt: record.expiresAt
      }))
    sealedDirectory = sealRelayCandidateDirectorySink(
      state.candidateDirectorySink,
      directoryRecords,
      {
        guardIdentity: chosen.record.identity,
        guardEndpoint: chosen.record.canonicalEndpointBytes,
        guardAdvertisementDigest: chosen.record.digest,
        guardEpoch: chosen.record.epoch,
        guardExpiresAt: chosen.record.expiresAt
      }
    )
    state.sinkOwned = false
    const pinnedGuard = {
      identity: copy(chosen.record.identity, 32),
      canonicalEndpoint: copy(chosen.record.canonicalEndpointBytes, 19),
      advertisementDigest: copy(chosen.record.digest, 32),
      epoch: chosen.record.epoch,
      expiresAt: chosen.record.expiresAt
    }
    // Generic direct-send authority is terminally revoked before either opaque
    // post-bootstrap capability is published.
    stop(state)
    if (state.generation !== null || state.datagrams !== null) destroyed()
    lease = issueLease(established)
    established = null
    transfer = objectFreeze({})
    transfers.set(transfer, {
      guardLeaseMaterial: lease,
      sealedDirectory,
      pinnedGuard,
      exposureReport: copyReport(state.exposure)
    })
    lease = null
    sealedDirectory = null
    return transfer
  } catch (err) {
    if (pending) abortIndexZeroGuardLink(pending)
    if (established) destroyM3EstablishedLink(established)
    if (physicalChannel) {
      try {
        physicalChannel.destroy()
      } catch {}
    }
    if (lease) destroyLease(lease)
    if (sealedDirectory) {
      try {
        destroySealedRelayCandidateDirectory(sealedDirectory)
      } catch {}
    }
    if (state.sinkOwned) {
      state.sinkOwned = false
      try {
        revokeRelayCandidateDirectorySink(state.candidateDirectorySink)
      } catch {}
    }
    stop(state)
    if (err instanceof PrivateRouteError && err.code === 'ERR_PRIVATE_GUARD_UNAVAILABLE') throw err
    unavailable()
  }
}

function endpointForRecord(record) {
  const endpoint = record.canonicalEndpointBytes
  if (!fixed(endpoint, 19)) return null
  const port = endpoint[17] * 0x100 + endpoint[18]
  if (endpoint[0] === 4) {
    return {
      host: `${endpoint[13]}.${endpoint[14]}.${endpoint[15]}.${endpoint[16]}`,
      port,
      canonical: endpoint
    }
  }
  if (endpoint[0] !== 6) return null
  const words = []
  for (let offset = 1; offset < 17; offset += 2) {
    words.push(((endpoint[offset] << 8) | endpoint[offset + 1]).toString(16))
  }
  return { host: words.join(':'), port, canonical: endpoint }
}

class BootstrapIO {
  constructor(options) {
    exactObject(options, OPTION_FIELDS)
    const endpoints = ownEndpoints(own(options, 'endpoints'))
    let localIdentity = null
    let localSecretKey = null
    try {
      localIdentity = copy(own(options, 'localIdentity'), 32)
      localSecretKey = copy(own(options, 'localSecretKey'), 64)
      const datagrams = own(options, 'datagrams')
      const wallNow = own(options, 'wallNow')
      const monotonicNow = own(options, 'monotonicNow')
      const randomBytes = own(options, 'randomBytes')
      const candidateDirectorySink = own(options, 'candidateDirectorySink')
      if (
        datagrams === null ||
        typeof datagrams !== 'object' ||
        typeof datagrams.send !== 'function' ||
        typeof datagrams.destroy !== 'function' ||
        typeof wallNow !== 'function' ||
        typeof monotonicNow !== 'function' ||
        typeof randomBytes !== 'function' ||
        candidateDirectorySink === null ||
        typeof candidateDirectorySink !== 'object'
      )
        invalid()
      states.set(this, {
        endpoints,
        localIdentity,
        localSecretKey,
        datagrams,
        wallNow,
        monotonicNow,
        randomBytes,
        candidateDirectorySink,
        sinkOwned: true,
        records: [],
        recordKeys: new Map(),
        exposure: [],
        exposureKey: null,
        startedAt: null,
        lastWall: null,
        sampling: false,
        challengeInFlight: 0,
        generation: objectFreeze({}),
        startPromise: null,
        live: true,
        destroyed: false
      })
      localIdentity = null
      localSecretKey = null
    } catch (err) {
      for (const endpoint of endpoints) clear(endpoint.canonical)
      clear(localIdentity)
      clear(localSecretKey)
      throw err
    }
  }

  start() {
    const state = states.get(this)
    if (!state || state.destroyed || !state.live) destroyed()
    if (state.startPromise !== null) replay()
    const generation = state.generation
    state.startPromise = Promise.resolve().then(() => run(this, state, generation))
    return state.startPromise
  }

  cancel() {
    const state = states.get(this)
    if (!state || state.destroyed) return false
    if (state.sinkOwned) {
      state.sinkOwned = false
      try {
        revokeRelayCandidateDirectorySink(state.candidateDirectorySink)
      } catch {}
    }
    return stop(state)
  }

  destroy() {
    return this.cancel()
  }

  [TEST_ONLY_BOOTSTRAP_IO_OBSERVER]() {
    const state = states.get(this)
    if (!state) invalid()
    return objectFreeze({
      destroyed: state.destroyed,
      endpointCount: state.endpoints.length,
      candidateCount: state.records.length,
      recordKeyCount: state.recordKeys.size,
      challengeInFlight: state.challengeInFlight,
      exposureReport: copyReport(state.exposure)
    })
  }
}

module.exports = {
  TEST_ONLY_BOOTSTRAP_IO_OBSERVER,
  BootstrapIO,
  consumeBootstrapGuardPin,
  revokeBootstrapGuardPin
}
