'use strict'

const b4a = require('b4a')

const { PrivateRouteError } = require('./errors')
const {
  consumeDhtExitPacketReservationForIO,
  createDhtExitCorrelatedReplyAuthorityForIO,
  encodeDhtExitPacketReservationTransfer,
  readDhtExitPacketReservationTransferForIO
} = require('./dht-exit-reservation')
const { decodeDhtExitReply, encodeImmutableGetResponse } = require('./dht-exit-wire')
const {
  abortExitDhtReservation,
  consumeDhtExitImmutableGetCompletionForIO,
  readDhtExitDestinationTableBinding,
  readDhtExitDestinationRef,
  reserveOrdinaryDhtRequest,
  reserveReferralProbe,
  settleExitDhtReservation,
  revokeDhtExitReferralReplyAuthority,
  verifyDhtExitRoutedDestination
} = require('./dht-exit-destination-table')
const { BRANCH_CLASS, M3_MESSAGE_ID, ROUTED_ERROR } = require('./protocol')
const {
  clearRoutedRequest,
  encodeRoutedReply,
  validateRoutedRequestForExit
} = require('./routed-dht')
const { UdxAdapter } = require('./udx-adapter')

const IOS = new WeakMap()
const TEST_SOCKET_AUTHORITIES = new WeakMap()
const SPENT_TEST_SOCKET_AUTHORITIES = new WeakSet()
const TEST_ONLY_DHT_EXIT_SOCKET_ISSUER = Symbol.for(
  'hyperdht-private-routes/test-only-dht-exit-socket-issuer'
)
const OPTION_KEYS = Object.freeze([
  'host',
  'port',
  'monotonicNow',
  'schedule',
  'cancelScheduled',
  'onReply'
])
const MAX_PENDING = 0x10000

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactOwnData(value, fields) {
  if (!isObject(value) || Reflect.ownKeys(value).length !== fields.length) invalid()
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || !('value' in descriptor)) invalid()
  }
}

function numericIpv4(host) {
  if (typeof host !== 'string') return false
  if (!/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(host)) return false
  return host.split('.').every((part) => Number(part) <= 255)
}

function readOptions(options) {
  exactOwnData(options, OPTION_KEYS)
  if (!numericIpv4(options.host)) invalid()
  if (!Number.isSafeInteger(options.port) || options.port < 0 || options.port > 0xffff) invalid()
  if (
    typeof options.monotonicNow !== 'function' ||
    typeof options.schedule !== 'function' ||
    typeof options.cancelScheduled !== 'function' ||
    typeof options.onReply !== 'function'
  ) {
    invalid()
  }
  return Object.freeze({
    host: options.host,
    port: options.port,
    monotonicNow: options.monotonicNow,
    schedule: options.schedule,
    cancelScheduled: options.cancelScheduled,
    onReply: options.onReply
  })
}

function createTestDhtExitSocketAuthority(factory) {
  if (typeof factory !== 'function') invalid()
  const authority = Object.freeze({})
  TEST_SOCKET_AUTHORITIES.set(authority, { factory })
  return authority
}

function consumeTestSocketAuthority(authority) {
  const state = isObject(authority) ? TEST_SOCKET_AUTHORITIES.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_TEST_SOCKET_AUTHORITIES.has(authority)) replay()
    authentication()
  }
  TEST_SOCKET_AUTHORITIES.delete(authority)
  SPENT_TEST_SOCKET_AUTHORITIES.add(authority)
  return state.factory
}

function createSocket(factory) {
  let socket = null
  try {
    socket = factory()
  } catch {
    throw PrivateRouteError.ROUTE_UNAVAILABLE()
  }
  if (
    !socket ||
    typeof socket.bind !== 'function' ||
    typeof socket.on !== 'function' ||
    typeof socket.send !== 'function' ||
    typeof socket.close !== 'function'
  ) {
    invalid()
  }
  return socket
}

function createDhtExitIOForTest(options, socketAuthority, ioConsumer) {
  return createDhtExitIOWithSocketFactory(
    options,
    ioConsumer,
    consumeTestSocketAuthority(socketAuthority)
  )
}

function createDhtExitIO(ioConsumer, options) {
  const adapter = new UdxAdapter()
  const udx = adapter.create()
  return createDhtExitIOWithSocketFactory(options, ioConsumer, () => udx.createSocket())
}

function createDhtExitIOWithSocketFactory(options, ioConsumer, factory) {
  const parsed = readOptions(options)
  const io = Object.freeze({})
  const socket = createSocket(factory)
  const state = {
    ioConsumer,
    socket,
    options: parsed,
    live: true,
    pending: new Map(),
    operations: new Set(),
    nextTid: 0
  }
  socket.on('message', (packet, from) => receive(state, packet, from))
  socket.on('error', () => {})
  try {
    const result = socket.bind(parsed.port, parsed.host)
    if (result && typeof result.then === 'function') {
      result.catch(() => closeState(state))
    }
  } catch {
    closeState(state)
    throw PrivateRouteError.ROUTE_UNAVAILABLE()
  }
  IOS.set(io, state)
  return io
}

function readIO(io) {
  const state = isObject(io) ? IOS.get(io) : null
  if (!state || !state.live) destroyed()
  return state
}

function allocateTid(state) {
  for (let count = 0; count < MAX_PENDING; count++) {
    const tid = state.nextTid
    state.nextTid = (state.nextTid + 1) & 0xffff
    if (!state.pending.has(tid)) return tid
  }
  throw PrivateRouteError.COUNTER_EXHAUSTED()
}

function monotonicNow(state) {
  const value = state.options.monotonicNow()
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) invalid()
  return value
}

function cancelPending(state, tid) {
  const pending = state.pending.get(tid)
  if (!pending) return false
  state.pending.delete(tid)
  try {
    if (pending.handle !== null && pending.handle !== undefined) {
      state.options.cancelScheduled(pending.handle)
    }
  } catch {}
  return true
}

function expirePending(state, tid) {
  const pending = state.pending.get(tid)
  if (!pending) return false
  cancelPending(state, tid)
  if (pending.onTimeout !== null) {
    try {
      pending.onTimeout()
    } catch {}
  }
  return true
}

function sendReservedExitDhtPacket(io, reservation) {
  sendReservedExitDhtPacketWithHandler(readIO(io), reservation, null, null)
  return true
}

function sendReservedExitDhtPacketWithHandler(state, reservation, onReply, onTimeout) {
  const tid = allocateTid(state)
  const transfer = consumeDhtExitPacketReservationForIO(state.ioConsumer, reservation, tid)
  const transferState = readDhtExitPacketReservationTransferForIO(transfer)
  const packet = encodeDhtExitPacketReservationTransfer(transfer)
  const now = monotonicNow(state)
  if (now >= transferState.deadline) throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  const delay = Number(transferState.deadline - now)
  const pending = { ...transferState, transfer, handle: null, onReply, onTimeout }
  state.pending.set(tid, pending)
  try {
    const handle = state.options.schedule(() => expirePending(state, tid), delay)
    if (!state.pending.has(tid)) {
      try {
        if (handle !== null && handle !== undefined) state.options.cancelScheduled(handle)
      } catch {}
      if (onTimeout !== null) return null
      throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
    }
    pending.handle = handle
  } catch (err) {
    cancelPending(state, tid)
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  }
  try {
    state.socket.send(packet, transferState.remote.port, transferState.remote.host)
    return tid
  } catch (err) {
    cancelPending(state, tid)
    if (err instanceof PrivateRouteError) throw err
    throw PrivateRouteError.ROUTE_UNAVAILABLE()
  }
}

function requestDhtExitImmutableGet(io, table, encodedRequest, options) {
  exactOwnData(options, ['onRoutedReply'])
  if (typeof options.onRoutedReply !== 'function') invalid()
  const state = readIO(io)
  const binding = readDhtExitDestinationTableBinding(table)
  const request = validateRoutedRequestForExit(encodedRequest, {
    now: state.options.monotonicNow,
    branchClass: binding.branchClass,
    verifyDestination: (value) => verifyDhtExitRoutedDestination(table, value)
  })
  if (
    request.operationClass !== BRANCH_CLASS.LOOKUP ||
    request.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
    request.encodedBody.byteLength !== 32
  ) {
    clearRoutedRequest(request)
    authentication()
  }

  const operationState = {
    live: true,
    tids: new Set(),
    request,
    settlementAuthorities: new Set(),
    referralReplyAuthority: null
  }
  const abortSettlements = () => {
    for (const authority of operationState.settlementAuthorities) {
      try {
        abortExitDhtReservation(authority)
      } catch {}
    }
    operationState.settlementAuthorities.clear()
  }
  const revokeReferralReply = () => {
    if (operationState.referralReplyAuthority === null) return
    revokeDhtExitReferralReplyAuthority(operationState.referralReplyAuthority)
    operationState.referralReplyAuthority = null
  }
  const operation = Object.freeze({
    cancel() {
      if (!operationState.live) return false
      state.operations.delete(operation)
      operationState.live = false
      for (const tid of operationState.tids) cancelPending(state, tid)
      operationState.tids.clear()
      abortSettlements()
      revokeReferralReply()
      clearRoutedRequest(operationState.request)
      operationState.request = null
      return true
    }
  })

  const finish = (errorCode, normalized = null) => {
    if (!operationState.live) return false
    operationState.live = false
    state.operations.delete(operation)
    for (const tid of operationState.tids) cancelPending(state, tid)
    operationState.tids.clear()
    abortSettlements()
    revokeReferralReply()
    let encodedResponse = b4a.alloc(0)
    let encodedReply = null
    const closerNodes = normalized === null ? [] : normalized.closerNodes
    if (normalized !== null) {
      closerNodes.sort((left, right) => {
        for (let index = 0; index < 32; index++) {
          const leftDistance = left.id[index] ^ operationState.request.encodedBody[index]
          const rightDistance = right.id[index] ^ operationState.request.encodedBody[index]
          if (leftDistance !== rightDistance) return leftDistance - rightDistance
        }
        for (let index = 0; index < 32; index++) {
          if (left.id[index] !== right.id[index]) return left.id[index] - right.id[index]
        }
        return 0
      })
    }
    try {
      if (errorCode === 0) {
        encodedResponse = encodeImmutableGetResponse({
          valuePresent: normalized.valuePresent,
          value: normalized.value
        })
      }
      encodedReply = encodeRoutedReply({
        requestId: operationState.request.requestId,
        commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
        commandVersion: 1,
        operationClass: BRANCH_CLASS.LOOKUP,
        from: operationState.request.destination,
        errorCode,
        token: errorCode === 0 && normalized.token !== null ? normalized.token : b4a.alloc(0),
        closerNodes,
        encodedResponse
      })
      options.onRoutedReply(encodedReply)
      encodedReply = null
      return true
    } finally {
      encodedResponse.fill(0)
      if (encodedReply !== null) encodedReply.fill(0)
      if (normalized !== null) {
        if (normalized.token !== null) normalized.token.fill(0)
        if (normalized.value !== null) normalized.value.fill(0)
        for (const closer of closerNodes) {
          closer.id.fill(0)
          closer.handle.fill(0)
        }
      }
      clearRoutedRequest(operationState.request)
      operationState.request = null
    }
  }

  const startReferralProbes = (completed) => {
    operationState.referralReplyAuthority = completed.referralReplyAuthority
    const normalized = {
      token: completed.token,
      valuePresent: completed.valuePresent,
      value: completed.value,
      closerNodes: []
    }
    const probes = {
      next: 0,
      active: 0
    }
    const launch = () => {
      if (!operationState.live) return
      while (
        operationState.live &&
        probes.active < 3 &&
        probes.next < completed.candidates.length
      ) {
        const candidate = completed.candidates[probes.next++]
        const current = monotonicNow(state)
        const probeDeadline =
          current + 1_000n < request.absoluteDeadlineMs
            ? current + 1_000n
            : request.absoluteDeadlineMs
        if (probeDeadline <= current) continue
        let reservation = null
        try {
          reservation = reserveReferralProbe(
            table,
            completed.referralReplyAuthority,
            candidate,
            probeDeadline
          )
        } catch (err) {
          if (err && err.code === 'COUNTER_EXHAUSTED') continue
          operation.cancel()
          return
        }
        if (reservation === null) continue
        probes.active++
        operationState.settlementAuthorities.add(reservation.settlementAuthority)
        let tid = null
        const done = () => {
          if (tid !== null) operationState.tids.delete(tid)
          probes.active--
          if (probes.next >= completed.candidates.length && probes.active === 0) {
            finish(0, normalized)
          } else {
            launch()
          }
        }
        try {
          tid = sendReservedExitDhtPacketWithHandler(
            state,
            reservation.sendAuthority,
            (correlatedReplyAuthority) => {
              operationState.tids.delete(tid)
              operationState.settlementAuthorities.delete(reservation.settlementAuthority)
              try {
                const destinationRef = settleExitDhtReservation(
                  reservation.settlementAuthority,
                  correlatedReplyAuthority
                )
                if (destinationRef !== null) {
                  const admitted = readDhtExitDestinationRef(table, destinationRef)
                  normalized.closerNodes.push({
                    id: admitted.id,
                    handle: admitted.handle
                  })
                }
              } catch {
                operation.cancel()
                return
              }
              done()
            },
            () => {
              operationState.tids.delete(tid)
              operationState.settlementAuthorities.delete(reservation.settlementAuthority)
              try {
                abortExitDhtReservation(reservation.settlementAuthority)
              } catch {}
              done()
            }
          )
          if (tid !== null && operationState.live) operationState.tids.add(tid)
        } catch {
          operationState.settlementAuthorities.delete(reservation.settlementAuthority)
          try {
            abortExitDhtReservation(reservation.settlementAuthority)
          } catch {}
          done()
        }
      }
      if (probes.next >= completed.candidates.length && probes.active === 0) {
        finish(0, normalized)
      }
    }
    launch()
  }

  const reservation = reserveOrdinaryDhtRequest(
    table,
    request.destinationEncoded,
    { command: 9, target: request.encodedBody, token: null },
    request.absoluteDeadlineMs
  )
  state.operations.add(operation)
  operationState.settlementAuthorities.add(reservation.settlementAuthority)
  try {
    let tid = null
    tid = sendReservedExitDhtPacketWithHandler(
      state,
      reservation.sendAuthority,
      (correlatedReplyAuthority) => {
        operationState.tids.delete(tid)
        if (!operationState.live) return
        operationState.settlementAuthorities.delete(reservation.settlementAuthority)
        try {
          const completion = settleExitDhtReservation(
            reservation.settlementAuthority,
            correlatedReplyAuthority
          )
          if (completion === null) {
            finish(ROUTED_ERROR.UPSTREAM_REJECTED)
            return
          }
          const completed = consumeDhtExitImmutableGetCompletionForIO(completion)
          operationState.referralReplyAuthority = completed.referralReplyAuthority
          if (completed.candidates.length === 0) {
            finish(0, {
              token: completed.token,
              valuePresent: completed.valuePresent,
              value: completed.value,
              closerNodes: []
            })
            return
          }
          startReferralProbes(completed)
        } catch {
          operation.cancel()
        }
      },
      () => {
        operationState.tids.delete(tid)
        operationState.settlementAuthorities.delete(reservation.settlementAuthority)
        try {
          abortExitDhtReservation(reservation.settlementAuthority)
        } catch {}
        finish(ROUTED_ERROR.UPSTREAM_TIMEOUT)
      }
    )
    if (tid !== null && operationState.live) operationState.tids.add(tid)
  } catch (err) {
    operationState.live = false
    state.operations.delete(operation)
    abortSettlements()
    clearRoutedRequest(operationState.request)
    operationState.request = null
    throw err
  }
  return operation
}

function receive(state, packet, from) {
  if (!state.live || !b4a.isBuffer(packet)) return
  let tid = -1
  try {
    if (packet.byteLength < 4 || packet[0] !== 0x13) return
    tid = packet[2] | (packet[3] << 8)
    const pending = state.pending.get(tid)
    if (!pending) return
    if (monotonicNow(state) >= pending.deadline) {
      expirePending(state, tid)
      return
    }
    const reply = decodeDhtExitReply(pending.wireReservation, from, packet)
    const authority = createDhtExitCorrelatedReplyAuthorityForIO(pending.transfer, from, reply)
    cancelPending(state, tid)
    if (pending.onReply !== null) pending.onReply(authority)
    else state.options.onReply(authority)
  } catch {}
}

function closeState(state) {
  if (!state || !state.live) return false
  state.live = false
  for (const operation of Array.from(state.operations)) operation.cancel()
  state.operations.clear()
  for (const tid of state.pending.keys()) cancelPending(state, tid)
  try {
    state.socket.close()
  } catch {}
  return true
}

function closeDhtExitIO(io) {
  const state = isObject(io) ? IOS.get(io) : null
  if (!state) return false
  IOS.delete(io)
  return closeState(state)
}

const TEST_ONLY_DHT_EXIT_IO_STATE = Object.freeze({
  address(io) {
    const state = readIO(io)
    if (typeof state.socket.address !== 'function') invalid()
    const address = state.socket.address()
    if (!address || !Number.isSafeInteger(address.port)) invalid()
    return Object.freeze({ host: address.host, port: address.port })
  }
})

module.exports = {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER: Object.freeze({ create: createTestDhtExitSocketAuthority }),
  TEST_ONLY_DHT_EXIT_IO_STATE,
  closeDhtExitIO,
  createDhtExitIO,
  createDhtExitIOForTest,
  requestDhtExitImmutableGet,
  sendReservedExitDhtPacket
}
