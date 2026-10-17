'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')
const sodium = require('sodium-universal')
const DHT = require('dht-rpc')
const RoutingTable = require('kademlia-routing-table')
const UDX = require('udx-native')

const { createKeyPair, hash } = require('../crypto')
const Persistent = require('../persistent')
const { PrivateRouteError } = require('./errors')

const COMMAND_LOOKUP = 3
const STORAGE_TOPIC = hash(b4a.from('hyperdht/private-route-storage/v1'))
const REQUEST_TIMEOUT_MS = 250
const QUERY_TIMEOUT_MS = 1000
const MAX_CONTACTS = 256
const MAX_REFERRALS = 20
const MAX_LEARNING = 4
const BOOTSTRAP_TTL_MS = 5 * 60 * 1000
const ANNOUNCE_INTERVAL_MS = 5 * 60 * 1000
const PUBLIC_REQUEST = b4a.from([1])
const CLIENT_REQUEST = b4a.from([0])

function unavailable() {
  return PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
}

function fixed(value, length) {
  return b4a.isBuffer(value) && value.byteLength === length
}

function endpointKey(endpoint) {
  return endpoint.host + ':' + endpoint.port
}

// Native RPC has no public per-request timeout option. Configure only this
// operation's owned requests, before their first send; never mutate shared IO.
function boundedSession(dht) {
  const session = dht.session()
  if (typeof session._attach === 'function') {
    const attach = session._attach.bind(session)
    session._attach = (request) => {
      request.timeout = REQUEST_TIMEOUT_MS
      request.retries = 0
      return attach(request)
    }
  }
  return session
}

class StorageRouting {
  constructor(service, recordBytes) {
    this.service = service
    this.dht = service.dht
    this.recordBytes = recordBytes
    this.serving = service.plugin.relayPublicKey !== null
    this.adKeyPair = this.serving ? createKeyPair() : null
    this.tableId = b4a.allocUnsafe(32)
    sodium.randombytes_buf(this.tableId)
    this.table = new RoutingTable(this.tableId)
    this.bootstrapHints = []
    this.bootstrapExpiresAt = 0
    this.learning = new Map()
    this.learnedAt = new Map()
    this.started = false
    this.stopped = false
    this.closed = false
    this.active = false
    this.published = false
    this.timer = null
    this.advertising = null
    this.advertisingOperation = null
    this.closing = null
    this._onAddress = () => {
      this.bootstrapExpiresAt = 0
      if (this.advertisingOperation) this.advertisingOperation.destroy()
      this._schedule(0)
    }
    if (typeof this.dht.on === 'function') {
      for (const event of ['persistent', 'ephemeral', 'nat-update', 'network-change']) {
        this.dht.on(event, this._onAddress)
      }
    }
    this.engine = new DHT({
      outboundPolicy: 'transport-only',
      requestTimeout: REQUEST_TIMEOUT_MS,
      maxTransportCandidates: MAX_CONTACTS,
      concurrency: 6,
      requestTransport: {
        ready: async () => {
          this.active = true
        },
        suspend: async () => {
          this.active = false
        },
        resume: async () => {
          this.active = !this.closed
        },
        destroy: async () => {
          this.active = false
          for (const contact of this.table.toArray()) this.table.remove(contact.id)
          this.bootstrapHints = []
          this.bootstrapExpiresAt = 0
        },
        key: endpointKey,
        id: (contact) => contact.id,
        closest: ({ target, limit }) => this.table.closest(target, limit),
        bootstrap: ({ limit, context }) => this._bootstrap(limit, context),
        request: (message) => this._request(message)
      }
    })
  }

  _contact(address, observed = false) {
    if (
      !address ||
      UDX.isIP(address.host) !== 4 ||
      !Number.isInteger(address.port) ||
      address.port < 1 ||
      address.port > 65535
    )
      throw unavailable()
    const encoded = c.encode(c.ipv4Address, address)
    if (encoded[0] === 0 || encoded[0] >= 224) throw unavailable()
    if (encoded[0] === 127) {
      const local = this.dht.address()
      if (!local || UDX.isIP(local.host) !== 4 || !local.host.startsWith('127.')) {
        throw unavailable()
      }
    }
    const id = hash(encoded)
    if (observed && (!fixed(address.id, 32) || !b4a.equals(id, address.id))) {
      throw unavailable()
    }
    return Object.freeze({ id, host: address.host, port: address.port })
  }

  _serverAddress() {
    if (!this.serving || !this.dht.id) return null
    const address = this.dht.remoteAddress()
    if (!address) return null
    try {
      const contact = this._contact(address)
      return b4a.equals(contact.id, this.dht.id) ? contact : null
    } catch {
      return null
    }
  }

  _retain(contact) {
    if (this.closed || this.stopped) return
    if (this.table.size >= MAX_CONTACTS && !this.table.has(contact.id)) return
    this.table.add(contact)
  }

  reply(target, wire) {
    if (!this.serving || this.closed || this.stopped || !this._serverAddress()) return null
    const contacts = this.table.closest(target, MAX_REFERRALS)
    const size = wire === null ? 0 : wire.byteLength
    if (size !== 0 && size !== this.recordBytes) throw unavailable()
    const value = b4a.allocUnsafe(4 + size + contacts.length * 6)
    value[0] = 1
    value.writeUInt16BE(size, 1)
    value[3] = contacts.length
    if (wire) wire.copy(value, 4)
    const state = { start: 4 + size, end: value.byteLength, buffer: value }
    for (const contact of contacts) c.ipv4Address.encode(state, contact)
    return value
  }

  _decode(reply, requested) {
    if (!reply || reply.error !== 0 || !fixed(reply.token, 32)) throw unavailable()
    const from = this._contact(reply.from, true)
    if (endpointKey(from) !== endpointKey(requested)) throw unavailable()
    const bytes = reply.value
    if (!b4a.isBuffer(bytes) || bytes.byteLength < 4 || bytes[0] !== 1) throw unavailable()
    const size = bytes.readUInt16BE(1)
    const count = bytes[3]
    if (
      (size !== 0 && size !== this.recordBytes) ||
      count > MAX_REFERRALS ||
      bytes.byteLength !== 4 + size + count * 6
    )
      throw unavailable()
    const state = { start: 4 + size, end: bytes.byteLength, buffer: bytes }
    const closerNodes = []
    for (let i = 0; i < count; i++) {
      try {
        closerNodes.push(this._contact(c.ipv4Address.decode(state)))
      } catch {
        throw unavailable()
      }
    }
    this._retain(from)
    return {
      rtt: reply.rtt,
      from,
      to: null,
      token: reply.token,
      closerNodes,
      error: 0,
      value: size === 0 ? null : b4a.from(bytes.subarray(4, 4 + size))
    }
  }

  _request({ to, target, context, internal, command }) {
    if (!this.active || this.closed || this.stopped || internal || command !== 0) {
      throw unavailable()
    }
    context.check()
    const contact = this._contact(to)
    const attempt = context.attempt(
      {
        command: COMMAND_LOOKUP,
        target,
        value: this._serverAddress() ? PUBLIC_REQUEST : CLIENT_REQUEST
      },
      contact
    )
    let cancelled = false
    const promise = attempt.promise.then(
      (reply) => {
        context.check()
        return this._decode(reply, contact)
      },
      (error) => {
        if (!cancelled) {
          this.table.remove(contact.id)
          this.bootstrapExpiresAt = 0
        }
        throw error
      }
    )
    return {
      promise,
      cancel(reason) {
        cancelled = true
        attempt.cancel(reason)
      }
    }
  }

  async _bootstrap(limit, operation) {
    operation.check()
    if (Date.now() >= this.bootstrapExpiresAt) {
      const sampleKey = b4a.allocUnsafe(32)
      sodium.randombytes_buf(sampleKey)
      const sample = []
      const retained = new Set()
      const query = operation.nativeQuery((session) =>
        this.dht.lookup(STORAGE_TOPIC, {
          session,
          retries: 0,
          concurrency: 6
        })
      )
      let complete = false
      try {
        for await (const reply of query) {
          operation.check()
          if (!reply || !Array.isArray(reply.peers) || reply.peers.length > MAX_REFERRALS) continue
          for (const peer of reply.peers) {
            if (!peer || !Array.isArray(peer.relayAddresses) || peer.relayAddresses.length > 3)
              continue
            for (const address of peer.relayAddresses) {
              let contact
              try {
                contact = this._contact(address)
              } catch {
                continue
              }
              const id = endpointKey(contact)
              if (retained.has(id)) continue
              const rank = b4a.allocUnsafe(32)
              sodium.crypto_generichash(rank, contact.id, sampleKey)
              if (sample.length === MAX_REFERRALS && b4a.compare(rank, sample[0].rank) >= 0) {
                rank.fill(0)
                continue
              }
              if (sample.length === MAX_REFERRALS) {
                const removed = sample.shift()
                retained.delete(removed.id)
                removed.rank.fill(0)
              }
              sample.push({ id, contact, rank })
              retained.add(id)
              sample.sort((a, b) => b4a.compare(b.rank, a.rank))
            }
          }
        }
        operation.check()
        this.bootstrapHints = sample.map((entry) => entry.contact)
        this.bootstrapExpiresAt = Date.now() + BOOTSTRAP_TTL_MS
        complete = true
      } finally {
        operation.releaseQuery(query)
        sampleKey.fill(0)
        for (const entry of sample) entry.rank.fill(0)
        if (!complete) this.bootstrapExpiresAt = 0
      }
    }
    operation.check()
    return this.bootstrapHints.slice(0, limit)
  }

  learnRequester(from, target) {
    if (!this.serving || this.closed || this.stopped || this.learning.size >= MAX_LEARNING) return
    let contact
    try {
      contact = this._contact(from, true)
    } catch {
      return
    }
    if (this.table.has(contact.id)) return
    const id = endpointKey(contact)
    const now = Date.now()
    if (this.learning.has(id) || now - (this.learnedAt.get(id) || 0) < 5000) return
    if (this.learnedAt.size >= MAX_CONTACTS)
      this.learnedAt.delete(this.learnedAt.keys().next().value)
    this.learnedAt.set(id, now)
    const ownedTarget = b4a.from(target)
    const pending = this.service
      ._runOperation(null, async (operation) => {
        const reply = await operation.request(
          {
            command: COMMAND_LOOKUP,
            target: ownedTarget,
            value: CLIENT_REQUEST
          },
          contact
        )
        operation.check()
        this._decode(reply, contact)
      })
      .catch(() => {})
      .finally(() => {
        ownedTarget.fill(0)
        this.learning.delete(id)
      })
    this.learning.set(id, pending)
  }

  async start() {
    if (this.closed) throw unavailable()
    this.started = true
    this.stopped = false
    await this.engine.ready()
    if (this.serving) await this._refreshAdvertisement()
  }

  _schedule(delay) {
    clearTimeout(this.timer)
    this.timer = null
    if (!this.started || this.closed || this.stopped || !this.serving) return
    this.timer = setTimeout(() => {
      this.timer = null
      void this._refreshAdvertisement().catch(() => {})
    }, delay)
    if (this.timer.unref) this.timer.unref()
  }

  _refreshAdvertisement() {
    if (this.closed || this.stopped) return Promise.reject(unavailable())
    if (this.advertising) return this.advertising
    this.advertising = this.service
      ._runOperation(null, async (operation) => {
        this.advertisingOperation = operation
        const address = this._serverAddress()
        if (address === null) {
          await this._withdrawOperation(operation)
          return
        }
        const candidates = await this._directoryTargets(operation)
        if (candidates.length === 0) throw unavailable()
        this.published = true
        const replies = await Promise.allSettled(
          candidates.map((candidate) =>
            this.dht._requestAnnounce(
              this.adKeyPair,
              { request: (message, to) => operation.nativeRequest(message, to) },
              STORAGE_TOPIC,
              candidate.token,
              candidate.from,
              [address],
              Persistent.signAnnounce,
              0
            )
          )
        )
        operation.check()
        if (!replies.some((reply) => reply.status === 'fulfilled' && reply.value.error === 0)) {
          throw unavailable()
        }
      })
      .finally(() => {
        this.advertising = null
        this.advertisingOperation = null
        this._schedule(
          Math.floor(ANNOUNCE_INTERVAL_MS * (0.75 + sodium.randombytes_uniform(150000) / 1000000))
        )
      })
    return this.advertising
  }

  async _directoryTargets(operation) {
    const query = operation.nativeQuery((session) =>
      this.dht.lookup(STORAGE_TOPIC, {
        session,
        retries: 0,
        concurrency: 6
      })
    )
    try {
      for await (const _ of query) operation.check()
      operation.check()
      return query.closestReplies
        .filter(
          (reply) =>
            reply &&
            reply.error === 0 &&
            reply.from &&
            fixed(reply.from.id, 32) &&
            fixed(reply.token, 32)
        )
        .map((reply) => ({ from: reply.from, token: b4a.from(reply.token) }))
    } finally {
      operation.releaseQuery(query)
    }
  }

  async _withdrawOperation(operation) {
    if (!this.published || this.adKeyPair === null) return
    this.published = false
    const candidates = await this._directoryTargets(operation)
    await Promise.allSettled(
      candidates.map((candidate) =>
        this.dht._requestUnannounce(
          this.adKeyPair,
          { request: (message, to) => operation.nativeRequest(message, to) },
          STORAGE_TOPIC,
          candidate.token,
          candidate.from,
          Persistent.signUnannounce
        )
      )
    )
    operation.check()
  }

  async suspend() {
    this.stopped = true
    clearTimeout(this.timer)
    this.timer = null
    this.bootstrapExpiresAt = 0
    await Promise.all([
      this.engine.suspend(),
      this.service
        ._runOperation(null, (operation) => this._withdrawOperation(operation), true)
        .catch(() => {})
    ])
  }

  async resume() {
    if (this.closed) return
    this.stopped = false
    await this.engine.resume()
    if (this.serving) await this._refreshAdvertisement()
  }

  destroy() {
    if (this.closing) return this.closing
    this.closed = true
    this.stopped = true
    clearTimeout(this.timer)
    this.timer = null
    if (typeof this.dht.removeListener === 'function') {
      for (const event of ['persistent', 'ephemeral', 'nat-update', 'network-change']) {
        this.dht.removeListener(event, this._onAddress)
      }
    }
    this.closing = Promise.all([
      this.engine.destroy(),
      this.advertising && this.advertising.catch(() => {}),
      ...this.learning.values(),
      this.service
        ._runOperation(null, (operation) => this._withdrawOperation(operation), true)
        .catch(() => {})
    ]).then(() => {
      if (this.adKeyPair) this.adKeyPair.secretKey.fill(0)
      this.adKeyPair = null
      this.tableId.fill(0)
      this.learnedAt.clear()
    })
    return this.closing
  }
}

module.exports = {
  COMMAND_LOOKUP,
  QUERY_TIMEOUT_MS,
  REQUEST_TIMEOUT_MS,
  STORAGE_TOPIC,
  StorageRouting,
  boundedSession
}
