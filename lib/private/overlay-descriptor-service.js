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

const PLUGIN_NAME = 'private-route'
const PLUGIN_VERSION = 3
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
const RELAY_TARGET = hash(b4a.from('hyperdht/private-route-relays/v3'))

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
  constructor(relayPublicKey, now) {
    super(PLUGIN_NAME, PLUGIN_VERSION)
    this.relayPublicKey = relayPublicKey === null ? null : b4a.from(relayPublicKey)
    this.now = now
    this.records = new Map()
  }

  onpersistent() {}

  destroy() {
    for (const record of this.records.values()) clearDescriptor(record)
    this.records.clear()
    if (this.relayPublicKey) this.relayPublicKey.fill(0)
    this.relayPublicKey = null
  }

  onrequest(request, outer) {
    if (request.command === COMMAND_CAPABILITY) {
      if (this.relayPublicKey !== null && same(outer.target, RELAY_TARGET)) {
        outer.reply(this.relayPublicKey, { closerNodes: true })
      }
      return
    }
    if (!fixed(outer.target, 32)) return
    this._prune()
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

class OverlayDescriptorService {
  constructor(dht, relayPublicKey = null, now = Date.now) {
    this.dht = dht
    this.now = now
    this.plugin = new DescriptorPlugin(relayPublicKey, now)
    dht.register(this.plugin.name, this.plugin)
  }

  async discoverRelays(excluded = []) {
    const excludedKeys = new Set(excluded.map(key))
    const found = new Map()
    const query = this.dht.lookup(RELAY_TARGET)
    for await (const reply of query) {
      if (!reply || !Array.isArray(reply.peers)) continue
      for (const peer of reply.peers) {
        if (!peer || !fixed(peer.publicKey, 32)) continue
        const publicKey = b4a.from(peer.publicKey)
        const id = key(publicKey)
        if (!excludedKeys.has(id)) found.set(id, publicKey)
        if (found.size >= MAX_REPLIES) {
          query.destroy()
          return Array.from(found.values())
        }
      }
    }
    return Array.from(found.values())
  }

  async get(destinationPublicKey) {
    if (!fixed(destinationPublicKey, 32)) throw invalid()
    let best = null
    const targets = targetsForLookup(destinationPublicKey, this.now())
    try {
      for (const row of targets) {
        const candidate = await this._readTarget(row.target, {
          expectedDestinationPublicKey: destinationPublicKey,
          expectedPeriod: row.period
        })
        if (candidate === null) continue
        if (best === null || candidate.seq > best.seq) {
          clearDescriptor(best)
          best = candidate
        } else {
          clearDescriptor(candidate)
        }
      }
    } finally {
      for (const row of targets) row.target.fill(0)
    }
    if (best === null) throw unavailable()
    return best
  }

  async _readTarget(target, options) {
    const candidates = new Map()
    let best = null
    try {
      const query = this.plugin.query({ command: COMMAND_GET, target })
      for await (const reply of query) {
        if (!reply || !b4a.isBuffer(reply.value)) continue
        try {
          const descriptor = decodeDescriptor(reply.value, {
            ...options,
            now: this.now()
          })
          const id = key(descriptor.wire)
          const current = candidates.get(id)
          if (current) {
            current.count++
            clearDescriptor(descriptor)
          } else {
            candidates.set(id, { descriptor, count: 1 })
          }
        } catch {}
      }
      for (const candidate of candidates.values()) {
        if (candidate.count < MIN_READ_QUORUM) continue
        if (best === null || candidate.descriptor.seq > best.seq) best = candidate.descriptor
      }
      return best
    } finally {
      for (const candidate of candidates.values()) {
        if (candidate.descriptor !== best) clearDescriptor(candidate.descriptor)
      }
    }
  }

  async put(wire) {
    const descriptor = decodeDescriptor(wire, {
      now: this.now(),
      expectedPeriod: periodOf(this.now())
    })
    const target = blindedDescriptorTarget(descriptor.blindedPublicKey)
    const candidates = []
    let readback = null
    try {
      const query = this.plugin.query({ command: COMMAND_GET, target })
      for await (const reply of query) {
        if (!reply || !reply.from || !fixed(reply.token, 32)) continue
        candidates.push({ from: reply.from, token: b4a.from(reply.token) })
        if (candidates.length >= MAX_REPLIES) {
          query.destroy()
          break
        }
      }
      if (candidates.length < MIN_WRITE_QUORUM) throw unavailable()
      let stored = 0
      for (const candidate of candidates) {
        try {
          await this.plugin.request(
            { token: candidate.token, command: COMMAND_PUT, target, value: descriptor.wire },
            candidate.from
          )
          stored++
        } catch {}
      }
      if (stored < MIN_WRITE_QUORUM) throw unavailable()
      readback = await this._readTarget(target, {
        expectedPeriod: descriptor.period
      })
      if (readback === null || !same(readback.wire, descriptor.wire)) throw unavailable()
      return stored
    } finally {
      clearDescriptor(readback)
      clearDescriptor(descriptor)
      target.fill(0)
      for (const candidate of candidates) candidate.token.fill(0)
    }
  }
}

module.exports = {
  DESCRIPTOR_BYTES,
  MAX_LIFETIME_MS,
  OverlayDescriptorService,
  RELAY_TARGET,
  decodeDescriptor,
  descriptorTarget,
  encodeDescriptor
}
