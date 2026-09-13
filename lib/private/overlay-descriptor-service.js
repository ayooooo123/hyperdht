'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const Plugin = require('../plugin')
const { hash } = require('../crypto')
const { deriveBlindedPublicKey, periodOf, lookupPeriods } = require('./blinded-presence')
const { PrivateRouteError } = require('./errors')

const PLUGIN_NAME = 'private-route'
const PLUGIN_VERSION = 2
const COMMAND_GET = 0
const COMMAND_PUT = 1
const COMMAND_CAPABILITY = 2
const DESCRIPTOR_VERSION = 2
const DESCRIPTOR_BYTES = 209
const DESCRIPTOR_BODY_BYTES = 145
const MAX_RECORDS = 256
const MAX_REPLIES = 8
const MAX_LIFETIME_MS = 15 * 60 * 1000
const DOMAIN = b4a.from('hyperdht/private-route-descriptor/v2')
const RELAY_TARGET = hash(b4a.from('hyperdht/private-route-relays/v2'))

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

function targetsForLookup(destinationPublicKey, now) {
  return lookupPeriods(now).map((period) => descriptorTarget(destinationPublicKey, period))
}

function encodeDescriptor({
  destinationKeyPair,
  entryRelayPublicKey,
  destinationGuardPublicKey,
  routeToken,
  seq,
  expiresAt
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

  const wire = b4a.alloc(DESCRIPTOR_BYTES)
  wire[0] = DESCRIPTOR_VERSION
  destinationKeyPair.publicKey.copy(wire, 1)
  entryRelayPublicKey.copy(wire, 33)
  destinationGuardPublicKey.copy(wire, 65)
  routeToken.copy(wire, 97)
  putU64(wire, 129, BigInt(seq))
  putU64(wire, 137, BigInt(expiresAt))
  const input = signatureInput(wire.subarray(0, DESCRIPTOR_BODY_BYTES))
  try {
    sodium.crypto_sign_detached(
      wire.subarray(DESCRIPTOR_BODY_BYTES),
      input,
      destinationKeyPair.secretKey
    )
  } finally {
    input.fill(0)
  }
  return wire
}

function decodeDescriptor(wire, options = {}) {
  if (!fixed(wire, DESCRIPTOR_BYTES) || wire[0] !== DESCRIPTOR_VERSION) throw invalid()
  const destinationPublicKey = b4a.from(wire.subarray(1, 33))
  const entryRelayPublicKey = b4a.from(wire.subarray(33, 65))
  const destinationGuardPublicKey = b4a.from(wire.subarray(65, 97))
  const routeToken = b4a.from(wire.subarray(97, 129))
  const seq = u64(wire, 129)
  const expiresAt = u64(wire, 137)
  if (same(entryRelayPublicKey, destinationGuardPublicKey)) throw invalid()
  const input = signatureInput(wire.subarray(0, DESCRIPTOR_BODY_BYTES))
  let verified = false
  try {
    verified = sodium.crypto_sign_verify_detached(
      wire.subarray(DESCRIPTOR_BODY_BYTES),
      input,
      destinationPublicKey
    )
  } finally {
    input.fill(0)
  }
  if (!verified) throw invalid()
  if (
    options.expectedDestinationPublicKey &&
    !same(destinationPublicKey, options.expectedDestinationPublicKey)
  ) {
    throw invalid()
  }
  const now = BigInt(options.now === undefined ? Date.now() : options.now)
  if (expiresAt <= now || expiresAt - now > BigInt(MAX_LIFETIME_MS)) throw unavailable()
  return Object.freeze({
    wire: b4a.from(wire),
    destinationPublicKey,
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
    this.records.clear()
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
      outer.reply(record ? record.wire : null)
      return
    }
    if (request.command !== COMMAND_PUT || !outer.token || !b4a.isBuffer(request.value)) return
    let descriptor
    try {
      descriptor = decodeDescriptor(request.value, { now: this.now() })
      const target = descriptorTarget(descriptor.destinationPublicKey, periodOf(this.now()))
      try {
        if (!same(target, outer.target)) return
      } finally {
        target.fill(0)
      }
    } catch {
      return
    }
    const current = this.records.get(recordKey)
    if (!current || descriptor.seq > current.seq) {
      if (!current && this.records.size >= MAX_RECORDS) this._evictOldest()
      this.records.set(recordKey, descriptor)
    }
    outer.reply(null, { token: false, closerNodes: false })
  }

  _prune() {
    const now = BigInt(this.now())
    for (const [recordKey, record] of this.records) {
      if (record.expiresAt <= now) this.records.delete(recordKey)
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
    if (oldestKey !== null) this.records.delete(oldestKey)
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
      for (const target of targets) {
        const query = this.plugin.query({ command: COMMAND_GET, target })
        for await (const reply of query) {
          if (!reply || !b4a.isBuffer(reply.value)) continue
          try {
            const descriptor = decodeDescriptor(reply.value, {
              expectedDestinationPublicKey: destinationPublicKey,
              now: this.now()
            })
            if (best === null || descriptor.seq > best.seq) best = descriptor
          } catch {}
        }
      }
    } finally {
      for (const target of targets) target.fill(0)
    }
    if (best === null) throw unavailable()
    return best
  }

  async put(wire) {
    const descriptor = decodeDescriptor(wire, { now: this.now() })
    const target = descriptorTarget(descriptor.destinationPublicKey, periodOf(this.now()))
    const candidates = []
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
      if (candidates.length === 0) throw unavailable()
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
      if (stored === 0) throw unavailable()
      return stored
    } finally {
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
