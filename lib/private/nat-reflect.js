'use strict'

// Production reflected-address discovery, run on the endpoint's own socket.
//
// A NAT mapping belongs to a socket, not to a host. hyperdht learns what the
// world sees for the DHT socket it owns (every dht-rpc reply carries a `to`
// field), but the endpoint socket that route cells travel on is a different
// socket with its own mapping, and no part of the stack answered for it. This
// module is that answer: a production endpoint owns its published address.
//
// The probe is a dht-rpc PING in the exit wire format this repository already
// speaks (lib/private/dht-exit-wire.js). A responder's reply carries the `to`
// field with the port and address the request was seen from, read through
// observeDhtExitPingReply, which - unlike decodeDhtExitReply - does not
// require the reply's `to` to equal a known local tuple, because the tuple `to`
// names IS the answer.
//
// Two different reflectors are asked, and only AGREED answers are published.
// Equal answers mean the mapping does not depend on the destination, so one
// tuple is publishable to any peer and into a signed punch plan. Different
// answers mean there is no publishable value at all - the host sits behind a
// NAT that maps per destination, and no simultaneous punch can repair that.
//
// The reflectors are the public hyperdht bootstrap nodes by default. They are
// asked a question about a UDP flow, not trusted with secrets: the reply names
// the address the world already sees.

const b4a = require('b4a')

const { BOOTSTRAP_NODES } = require('../constants')
const {
  createDhtExitPingReservation,
  encodeDhtExitRequest,
  observeDhtExitPingReply
} = require('./dht-exit-wire')
const { PrivateRouteError } = require('./errors')

const PING = 0
const RESPONSE_ID = 0x13
// Three sends per reflector: a first packet out of a NAT can be lost to a
// mapping that does not exist yet, and "one datagram was dropped" must not be
// mistaken for "there is no mapping".
const SEND_DELAYS_MS = Object.freeze([0, 300, 900])
const PROBE_TIMEOUT_MS = 4_000

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOwnData(value, fields) {
  if (!isObject(value)) return false
  const names = Object.getOwnPropertyNames(value)
  const symbols = Object.getOwnPropertySymbols(value)
  if (symbols.length !== 0 || names.length !== fields.length) return false
  for (const name of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return false
  }
  return true
}

function numericHost(host) {
  if (typeof host !== 'string') return false
  const parts = host.split('.')
  if (parts.length !== 4) return false
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) return false
  }
  return true
}

// `nodes` entries are "id@host:port" or "host:port", the bootstrap format in
// lib/constants.js. The id is irrelevant for a PING.
function resolveReflectors(nodes = BOOTSTRAP_NODES) {
  if (!Array.isArray(nodes) || nodes.length === 0) invalid()
  const resolved = []
  for (const entry of nodes) {
    if (typeof entry !== 'string') invalid()
    const address = entry.includes('@') ? entry.split('@')[1] : entry
    const parts = address.split(':')
    if (parts.length !== 2 || !numericHost(parts[0]) || !/^\d{1,5}$/.test(parts[1])) invalid()
    const port = Number(parts[1])
    if (port < 1 || port > 0xffff) invalid()
    resolved.push(Object.freeze({ host: parts[0], port }))
  }
  return resolved
}

// Sends one PING to `remote` from the caller's bound socket and resolves to the
// observed tuple, or null on timeout. The reservation binds the reply to the
// expected responder and transaction id, so an unrelated datagram cannot be
// read as an observation. Every timer this function arms is cancelled on
// settle: a leaked send timer would fire after the caller closed the socket.
function probeOnce(socket, remote, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false
    let sendTimers = []
    let failedSends = 0
    const tid = 1 + Math.floor(Math.random() * 0xfffe)
    let packet = null
    try {
      const reservation = createDhtExitPingReservation(remote, { host: '0.0.0.0', port: 1 }, tid)
      packet = encodeDhtExitRequest(reservation, {
        tid,
        token: null,
        internal: true,
        command: PING,
        target: null,
        value: null
      })
    } catch {
      return resolve(null)
    }

    function finish(listener) {
      clearTimeout(timer)
      for (const handle of sendTimers) clearTimeout(handle)
      sendTimers = null
      socket.removeListener('message', listener)
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      finish(onMessage)
      resolve(null)
    }, timeoutMs)

    function onMessage(message, from) {
      if (settled) return
      if (!from || from.host !== remote.host || from.port !== remote.port) return
      if (!b4a.isBuffer(message) || message.byteLength < 10 || message[0] !== RESPONSE_ID) return
      let observed = null
      try {
        const reservation = createDhtExitPingReservation(remote, { host: '0.0.0.0', port: 1 }, tid)
        observed = observeDhtExitPingReply(reservation, remote, message).observed
      } catch {
        return
      }
      if (observed === null) return
      settled = true
      finish(onMessage)
      resolve(observed)
    }

    socket.on('message', onMessage)
    for (const delay of SEND_DELAYS_MS) {
      sendTimers.push(
        setTimeout(() => {
          if (settled || sendTimers === null) return
          // udx send resolves a Promise<boolean>; a false or a rejection is a
          // refused send. Observed and counted, never discarded: an unobserved
          // rejection is the leak PR46 was reverted for.
          let sending = null
          try {
            sending = socket.send(packet, remote.port, remote.host)
          } catch {
            failedSends++
            return
          }
          Promise.resolve(sending).then(
            (sent) => {
              if (sent !== true) failedSends++
            },
            () => {
              failedSends++
            }
          )
        }, delay)
      )
    }
  })
}

// Reflects the caller's socket off the given reflectors and reports what a
// signed plan may publish:
//
//   - `observed`: the agreed tuple, or null when no agreement exists,
//   - `stable`: true only when at least two reflectors answered and all
//     answers match, which is the evidence a publishable value needs,
//   - `observations`: every per-reflector answer, for diagnostics.
async function reflectEndpointSocket(socket, reflectors, { timeoutMs = PROBE_TIMEOUT_MS } = {}) {
  if (!socket || typeof socket.send !== 'function' || typeof socket.on !== 'function') invalid()
  if (!Array.isArray(reflectors) || reflectors.length === 0) invalid()
  for (const remote of reflectors) {
    if (
      !isObject(remote) ||
      !exactOwnData(remote, ['host', 'port']) ||
      !numericHost(remote.host) ||
      !Number.isInteger(remote.port) ||
      remote.port < 1 ||
      remote.port > 0xffff
    ) {
      invalid()
    }
  }

  const observations = []
  for (const remote of reflectors) {
    const observed = await probeOnce(socket, remote, timeoutMs)
    observations.push({ reflector: remote, observed })
  }
  const usable = observations.filter((entry) => entry.observed !== null)
  const stable =
    usable.length > 1 &&
    usable.every(
      (entry) =>
        entry.observed.host === usable[0].observed.host &&
        entry.observed.port === usable[0].observed.port
    )
  return {
    observed: usable.length > 0 ? usable[0].observed : null,
    stable,
    observations
  }
}

module.exports = Object.freeze({
  PROBE_TIMEOUT_MS,
  reflectEndpointSocket,
  resolveReflectors
})
