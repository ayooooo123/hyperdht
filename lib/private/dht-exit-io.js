'use strict'

const b4a = require('b4a')
const c = require('compact-encoding')

const { ERROR } = require('../constants')
const m = require('../messages')
const { cryptoSuite } = require('./crypto-suite')
const { fragment, Reassembler } = require('./fragments')
const {
  cancelM3RouteFrameReservation,
  destroyM3RouteTransport,
  receiveReservedM3RouteFrame,
  registerM3RouteTeardownHandler,
  reserveM3RouteFrame,
  sendM3RouteFrame
} = require('./m3-adjacency-runtime')
const { PrivateRouteError } = require('./errors')
const {
  consumeDhtExitPacketReservationForIO,
  createDhtExitCorrelatedReplyAuthorityForIO,
  destroyDhtExitRouteTransportForIO,
  encodeDhtExitPacketReservationTransfer,
  readDhtExitPacketReservationTransferForIO,
  releaseDhtExitRouteTransportForTeardown,
  takeDhtExitRouteTransportForIO
} = require('./dht-exit-reservation')
const { decodeDhtExitReply, encodeImmutableGetResponse } = require('./dht-exit-wire')
const {
  abortExitDhtReservation,
  consumeDhtExitImmutableGetCompletionForIO,
  readDhtExitDestinationTableBinding,
  readDhtExitDestinationRef,
  isDhtExitIsolatedCandidate,
  reserveOrdinaryDhtRequest,
  reserveReferralProbe,
  settleExitDhtReservation,
  revokeDhtExitReferralReplyAuthority,
  verifyDhtExitRoutedDestination
} = require('./dht-exit-destination-table')
const { CELL_CLASS, DIRECTION } = require('./protocol')
const {
  ROUTE_ENDPOINT,
  RoutePayloadCodec,
  mintCreatedRoutePayloadContext
} = require('./route-payload')
const { BRANCH_CLASS, M3_MESSAGE_ID, REPLY_MODE, ROUTED_ERROR } = require('./protocol')
const {
  clearRoutedRequest,
  encodeRoutedReply,
  validateRoutedRequestForExit
} = require('./routed-dht')
const {
  createSurbBatchReplyAuthority,
  sendSurbBatchFragments,
  revokeSurbBatchReplyAuthority
} = require('./surb-batch')
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
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

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
  const io = createDhtExitIOWithSocketFactory(options, ioConsumer, () => udx.createSocket())
  const state = IOS.get(io)
  if (state) state.udx = udx
  return io
}
function createDhtExitIOWithSocketFactory(options, ioConsumer, factory) {
  const parsed = readOptions(options)
  const routeOwner = takeDhtExitRouteTransportForIO(ioConsumer)
  const io = Object.freeze({})
  let socket = null
  try {
    socket = createSocket(factory)
  } catch (err) {
    destroyDhtExitRouteTransportForIO(routeOwner)
    throw err
  }
  const state = {
    ioConsumer,
    socket,
    options: parsed,
    live: true,
    bindingPromise: null,
    pending: new Map(),
    operations: new Set(),
    ordinaryRequestCount: 0,
    referralProbeCount: 0,
    routeOwner,
    routeBinding: ioConsumer,
    routeService: null,
    routeClosePromise: null,
    nextTid: Math.floor(Math.random() * 65536),
    seedSent: false
  }
  socket.on('message', (packet, from) => receive(state, packet, from))
  socket.on('error', () => {})
  try {
    const result = socket.bind(parsed.port, parsed.host)
    state.bindingPromise = Promise.resolve(result).then(
      () => true,
      (err) => {
        closeState(state)
        throw err
      }
    )
    void state.bindingPromise.catch(() => {})
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
  if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT64) invalid()
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

function readU64Be(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function readU16Be(buffer, offset) {
  return (buffer[offset] << 8) | buffer[offset + 1]
}

function parseExitCommandBody(commandId, encodedBody) {
  const body = encodedBody
  if (commandId === M3_MESSAGE_ID.IMMUTABLE_GET_V1) {
    if (body.byteLength !== 32) authentication()
    return {
      kind: 'get',
      command: 9,
      target: b4a.from(body),
      token: null,
      value: null,
      referrals: true,
      responseKind: 'immutable'
    }
  }
  if (commandId === M3_MESSAGE_ID.MUTABLE_GET_V1) {
    if (body.byteLength !== 40) authentication()
    const seqBig = readU64Be(body, 32)
    if (seqBig > BigInt(Number.MAX_SAFE_INTEGER)) authentication()
    const seq = Number(seqBig)
    return {
      kind: 'get',
      command: 7,
      target: b4a.from(body.subarray(0, 32)),
      token: null,
      value: c.encode(c.uint, seq),
      referrals: true,
      responseKind: 'mutable'
    }
  }
  if (commandId === M3_MESSAGE_ID.IMMUTABLE_PUT_V1) {
    if (body.byteLength < 67 || body.byteLength > 1090) authentication()
    const token = b4a.from(body.subarray(0, 32))
    const target = b4a.from(body.subarray(32, 64))
    if (body[64] !== 1) authentication()
    const valueLen = readU16Be(body, 65)
    if (67 + valueLen !== body.byteLength || valueLen > 1023) authentication()
    return {
      kind: 'put',
      command: 8,
      target,
      token,
      value: valueLen === 0 ? b4a.alloc(0) : b4a.from(body.subarray(67)),
      referrals: false,
      responseKind: 'ack'
    }
  }
  if (commandId === M3_MESSAGE_ID.MUTABLE_PUT_V1) {
    if (body.byteLength < 171 || body.byteLength > 1066) authentication()
    const token = b4a.from(body.subarray(0, 32))
    const target = b4a.from(body.subarray(32, 64))
    const publicKey = b4a.from(body.subarray(64, 96))
    const seqBig = readU64Be(body, 96)
    if (seqBig > BigInt(Number.MAX_SAFE_INTEGER)) authentication()
    const seq = Number(seqBig)
    if (body[104] !== 1) authentication()
    const valueLen = readU16Be(body, 105)
    if (107 + valueLen + 64 !== body.byteLength || valueLen > 895) authentication()
    const value = valueLen === 0 ? b4a.alloc(0) : b4a.from(body.subarray(107, 107 + valueLen))
    const signature = b4a.from(body.subarray(107 + valueLen))
    const wireValue = c.encode(m.mutablePutRequest, { publicKey, seq, value, signature })
    return {
      kind: 'put',
      command: 6,
      target,
      token,
      value: wireValue,
      referrals: false,
      responseKind: 'ack',
      mapUpstreamError(error) {
        if (error === ERROR.SEQ_REUSED || error === ERROR.SEQ_TOO_LOW) {
          return ROUTED_ERROR.RECORD_CONFLICT
        }
        return ROUTED_ERROR.UPSTREAM_REJECTED
      }
    }
  }
  authentication()
}

function requestDhtExitCommand(io, table, encodedRequest, options) {
  return requestDhtExitImmutableGet(io, table, encodedRequest, options)
}

function requestDhtExitImmutableGet(io, table, encodedRequest, options) {
  const optionFields = ['onRoutedReply']
  if (options && options.reserveReferralCandidate !== undefined) {
    optionFields.push('reserveReferralCandidate')
  }
  if (options && options.onSurbHopMessage !== undefined) {
    optionFields.push('onSurbHopMessage')
  }
  exactOwnData(options, optionFields)
  if (
    typeof options.onRoutedReply !== 'function' ||
    (options.reserveReferralCandidate !== undefined &&
      typeof options.reserveReferralCandidate !== 'function') ||
    (options.onSurbHopMessage !== undefined && typeof options.onSurbHopMessage !== 'function')
  ) {
    invalid()
  }
  const state = readIO(io)
  const binding = readDhtExitDestinationTableBinding(table)
  // KI-15: the request carries a relative budget, not an endpoint timestamp, so the operation's
  // absolute deadline is derived from THIS host's clock. Derived exactly once, inside the
  // destination check, and reused for every reservation below: a second derivation would sample
  // the clock again and admit a destination against an earlier deadline than the one the
  // reservations are capped by, so a request whose entry expires between the two would be
  // dropped rather than answered.
  const admission = { deadline: null }
  const request = validateRoutedRequestForExit(encodedRequest, {
    now: state.options.monotonicNow,
    branchClass: binding.branchClass,
    verifyDestination: (value) => {
      const start = monotonicNow(state)
      admission.deadline =
        start > MAX_UINT64 - value.operationBudgetMs ? MAX_UINT64 : start + value.operationBudgetMs
      return verifyDhtExitRoutedDestination(table, value, admission.deadline)
    }
  })
  if (admission.deadline === null) {
    clearRoutedRequest(request)
    authentication()
  }
  let parsed = null
  try {
    parsed = parseExitCommandBody(request.commandId, request.encodedBody)
  } catch (err) {
    clearRoutedRequest(request)
    throw err
  }
  if (
    (parsed.kind === 'put' && request.operationClass !== BRANCH_CLASS.ANNOUNCE) ||
    (parsed.kind === 'get' &&
      request.operationClass !== BRANCH_CLASS.LOOKUP &&
      request.operationClass !== BRANCH_CLASS.ANNOUNCE)
  ) {
    clearRoutedRequest(request)
    authentication()
  }
  const operationDeadline = admission.deadline

  const operationState = {
    live: true,
    tids: new Set(),
    request,
    parsed,
    target: parsed.target,
    settlementAuthorities: new Set(),
    referralReplyAuthority: null,
    surbBatchAuthority: null
  }

  const replyMode = request.replyMode === undefined ? REPLY_MODE.CORRELATED : request.replyMode
  if (replyMode === REPLY_MODE.SURB_REQUIRED) {
    if (!request.surbDescriptors || request.surbCount < 1) {
      clearRoutedRequest(request)
      authentication()
    }
    if (typeof options.onSurbHopMessage !== 'function') {
      clearRoutedRequest(request)
      authentication()
    }
    try {
      const { deriveSurbId } = require('./surb-path')
      const surbIds = []
      for (let i = 0; i < request.surbDescriptors.length; i++) {
        surbIds.push(deriveSurbId(request.batchId, i))
      }
      operationState.surbBatchAuthority = createSurbBatchReplyAuthority({
        replyMode: REPLY_MODE.SURB_REQUIRED,
        batchId: request.batchId,
        requestId: request.requestId,
        messageId: request.requestId,
        descriptors: request.surbDescriptors,
        surbIds,
        localDeadline: operationDeadline,
        now: () => monotonicNow(state),
        sendHopMessage: options.onSurbHopMessage
      })
    } catch (err) {
      clearRoutedRequest(request)
      throw err
    }
  } else if (replyMode !== REPLY_MODE.CORRELATED) {
    clearRoutedRequest(request)
    authentication()
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
  const revokeSurbBatch = () => {
    if (operationState.surbBatchAuthority === null) return
    try {
      revokeSurbBatchReplyAuthority(operationState.surbBatchAuthority)
    } catch {}
    operationState.surbBatchAuthority = null
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
      revokeSurbBatch()
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
    const closerNodes =
      normalized === null || operationState.parsed.referrals === false ? [] : normalized.closerNodes
    if (normalized !== null && closerNodes.length > 0) {
      closerNodes.sort((left, right) => {
        for (let index = 0; index < 32; index++) {
          const leftDistance = left.id[index] ^ operationState.target[index]
          const rightDistance = right.id[index] ^ operationState.target[index]
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
        if (operationState.parsed.responseKind === 'ack') {
          encodedResponse = b4a.from([0x00])
        } else if (operationState.parsed.responseKind === 'mutable') {
          encodedResponse =
            normalized.value === null || normalized.value === undefined
              ? b4a.alloc(0)
              : b4a.from(normalized.value)
          if (encodedResponse.byteLength > 1023) authentication()
        } else {
          encodedResponse = encodeImmutableGetResponse({
            valuePresent: normalized.valuePresent,
            value: normalized.value
          })
        }
      }
      const token =
        errorCode === 0 &&
        operationState.parsed.kind === 'get' &&
        normalized !== null &&
        normalized.token !== null
          ? normalized.token
          : b4a.alloc(0)
      encodedReply = encodeRoutedReply({
        requestId: operationState.request.requestId,
        commandId: operationState.request.commandId,
        commandVersion: 1,
        operationClass: operationState.request.operationClass,
        from: operationState.request.destination,
        errorCode,
        token,
        closerNodes,
        encodedResponse
      })

      const replyMode =
        operationState.request.replyMode === undefined
          ? REPLY_MODE.CORRELATED
          : operationState.request.replyMode

      if (replyMode === REPLY_MODE.SURB_REQUIRED) {
        // Exit emits hop cells only. No local peel. No correlated fallback.
        try {
          if (!operationState.surbBatchAuthority) {
            encodedReply.fill(0)
            encodedReply = null
            return false
          }
          const batch = operationState.surbBatchAuthority
          operationState.surbBatchAuthority = null
          sendSurbBatchFragments(batch, encodedReply)
        } catch (err) {
          try {
            if (operationState.surbBatchAuthority) {
              revokeSurbBatchReplyAuthority(operationState.surbBatchAuthority)
              operationState.surbBatchAuthority = null
            }
          } catch {}
          // Drop. No correlated fallback. No onRoutedReply.
          return false
        } finally {
          if (encodedReply !== null) {
            encodedReply.fill(0)
            encodedReply = null
          }
        }
        return true
      }

      if (replyMode !== REPLY_MODE.CORRELATED) {
        encodedReply.fill(0)
        encodedReply = null
        return false
      }

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
      if (operationState.surbBatchAuthority) {
        try {
          revokeSurbBatchReplyAuthority(operationState.surbBatchAuthority)
        } catch {}
        operationState.surbBatchAuthority = null
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
    const finishProbe = () => {
      probes.active--
      if (probes.next >= completed.candidates.length && probes.active === 0) {
        finish(0, normalized)
      } else {
        launch()
      }
    }
    const dispatch = (reservation) => {
      if (!operationState.live) {
        if (reservation !== null) {
          try {
            abortExitDhtReservation(reservation.settlementAuthority)
          } catch {}
        }
        return
      }
      if (reservation === null) {
        finishProbe()
        return
      }
      operationState.settlementAuthorities.add(reservation.settlementAuthority)
      state.referralProbeCount++
      let tid = null
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
            finishProbe()
          },
          () => {
            operationState.tids.delete(tid)
            operationState.settlementAuthorities.delete(reservation.settlementAuthority)
            try {
              abortExitDhtReservation(reservation.settlementAuthority)
            } catch {}
            finishProbe()
          }
        )
        if (tid !== null && operationState.live) operationState.tids.add(tid)
      } catch {
        operationState.settlementAuthorities.delete(reservation.settlementAuthority)
        try {
          abortExitDhtReservation(reservation.settlementAuthority)
        } catch {}
        finishProbe()
      }
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
          current + 1_000n < operationDeadline ? current + 1_000n : operationDeadline
        if (probeDeadline <= current) continue
        probes.active++
        const input = Object.freeze({
          candidate: Object.freeze({ host: candidate.host, port: candidate.port }),
          referralReplyAuthority: completed.referralReplyAuthority,
          absoluteDeadline: probeDeadline
        })
        const failProbe = (err) => {
          probes.active--
          if (err && err.code === 'COUNTER_EXHAUSTED') {
            launch()
            return
          }
          operation.cancel()
        }
        // Only an isolated candidate consults the caller's asynchronous reservation
        // hook. An ordinary candidate reserves and dispatches in this turn so a probe
        // never trails the reply that produced it.
        if (
          options.reserveReferralCandidate !== undefined &&
          isDhtExitIsolatedCandidate(input.candidate)
        ) {
          Promise.resolve()
            .then(() => options.reserveReferralCandidate(input))
            .then(dispatch, failProbe)
          continue
        }
        let reservation = null
        try {
          reservation = reserveReferralProbe(
            table,
            completed.referralReplyAuthority,
            candidate,
            probeDeadline
          )
        } catch (err) {
          failProbe(err)
          continue
        }
        dispatch(reservation)
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
    {
      command: parsed.command,
      target: parsed.target,
      token: parsed.token,
      value: parsed.value
    },
    operationDeadline
  )
  state.operations.add(operation)
  state.ordinaryRequestCount++
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
          const completed = consumeDhtExitImmutableGetCompletionForIO(
            completion,
            options.reserveReferralCandidate !== undefined
          )
          if (completed.upstreamError !== 0) {
            const mapper =
              operationState.parsed.mapUpstreamError || (() => ROUTED_ERROR.UPSTREAM_REJECTED)
            try {
              revokeDhtExitReferralReplyAuthority(completed.referralReplyAuthority)
            } catch {}
            finish(mapper(completed.upstreamError))
            return
          }
          if (operationState.parsed.kind === 'put') {
            finish(0, {
              token: null,
              valuePresent: false,
              value: null,
              closerNodes: []
            })
            return
          }
          operationState.referralReplyAuthority = completed.referralReplyAuthority
          if (completed.candidates.length === 0 || operationState.parsed.referrals === false) {
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

function routeBindingMatches(state, binding) {
  const expected = state.routeBinding
  return (
    binding.branchClass === expected.branchClass &&
    binding.generation === expected.generation &&
    binding.expiresAt === expected.expiresAt &&
    binding.absoluteDeadline === expected.absoluteDeadline &&
    b4a.equals(binding.branchId, expected.branchId) &&
    b4a.equals(binding.circuitId, expected.circuitId) &&
    b4a.equals(binding.exitIdentity, expected.exitIdentity)
  )
}

function closeDhtExitRouteService(state) {
  const service = state.routeService
  if (!service || !service.live) return false
  service.live = false
  state.routeService = null
  if (service.receiveReservation !== null) {
    cancelM3RouteFrameReservation(service.receiveReservation)
    service.receiveReservation = null
  }
  if (service.activeOperation !== null) {
    try {
      service.activeOperation.cancel()
    } catch {}
    service.activeOperation = null
  }
  const releaseIncoming = service.releaseIncoming
  service.releaseIncoming = null
  const joins = [...service.replyPumps]
  if (service.requestPump !== null) joins.push(service.requestPump)
  const closing = (async () => {
    await Promise.allSettled(joins)
    service.replyPumps.clear()
    try {
      service.codec.destroy()
    } catch {}
    try {
      service.reassembler.destroy()
    } catch {}
    service.codec = null
    service.reassembler = null
    try {
      if (typeof releaseIncoming === 'function') await releaseIncoming()
    } finally {
      destroyDhtExitRouteTransportForIO(service.routeOwner)
      service.routeOwner = null
      service.transport = null
    }
  })()
  service.closePromise = closing
  state.routeClosePromise = closing
  void closing.catch(() => {})
  return true
}

async function drainDhtExitRouteService(state, service) {
  if (state.routeService !== service || !service.live || service.draining) replay()
  service.draining = true
  service.live = false
  state.routeService = null
  if (service.receiveReservation !== null) {
    cancelM3RouteFrameReservation(service.receiveReservation)
    service.receiveReservation = null
  }
  if (service.activeOperation !== null) {
    try {
      service.activeOperation.cancel()
    } catch {}
    service.activeOperation = null
  }
  const joins = [...service.replyPumps]
  if (service.requestPump !== null) joins.push(service.requestPump)
  await Promise.allSettled(joins)
  try {
    service.codec.destroy()
  } catch {}
  try {
    service.reassembler.destroy()
  } catch {}
  service.codec = null
  service.reassembler = null
  const releaseIncoming = service.releaseIncoming
  service.releaseIncoming = null
  if (typeof releaseIncoming !== 'function') authentication()
  try {
    await releaseIncoming()
  } catch (err) {
    destroyDhtExitRouteTransportForIO(service.routeOwner)
    service.routeOwner = null
    service.transport = null
    throw err
  }
  const transport = releaseDhtExitRouteTransportForTeardown(service.routeOwner)
  if (transport !== service.transport) authentication()
  service.routeOwner = null
  service.transport = null
  return true
}

function installDhtExitRoute(io, table, ...args) {
  if (args.length !== 1 || !isObject(args[0])) invalid()
  const fields = Reflect.ownKeys(args[0])
  const allowed = new Set(['releaseIncoming', 'reserveReferralCandidate', 'onCorrelatedFrame'])
  if (!fields.includes('releaseIncoming')) invalid()
  for (const field of fields) {
    if (!allowed.has(field)) invalid()
    const descriptor = Object.getOwnPropertyDescriptor(args[0], field)
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) invalid()
    if (typeof descriptor.value !== 'function') invalid()
  }
  const reserveReferralCandidate = args[0].reserveReferralCandidate || null
  const releaseIncoming = args[0].releaseIncoming
  const onCorrelatedFrame = args[0].onCorrelatedFrame || null
  const state = readIO(io)
  const binding = readDhtExitDestinationTableBinding(table)
  const routeOwner = state.routeOwner
  if (
    state.routeService !== null ||
    routeOwner === null ||
    !isObject(routeOwner) ||
    !isObject(routeOwner.transport) ||
    !routeBindingMatches(state, binding)
  ) {
    authentication()
  }
  const context = mintCreatedRoutePayloadContext({
    endpointRole: ROUTE_ENDPOINT.DESTINATION,
    descriptorId: routeOwner.payloadDigest,
    circuitId: binding.circuitId,
    forwardKey: routeOwner.payloadForwardKey,
    forwardNoncePrefix: routeOwner.payloadForwardNoncePrefix,
    reverseKey: routeOwner.payloadReverseKey,
    reverseNoncePrefix: routeOwner.payloadReverseNoncePrefix
  })
  const codec = new RoutePayloadCodec({
    crypto: cryptoSuite,
    context,
    window: 64,
    gapTimeout: 5_000,
    now: () => Number(monotonicNow(state))
  })
  const reassembler = new Reassembler({
    now: () => Number(monotonicNow(state)),
    epochExpiresAt: Number(binding.expiresAt)
  })
  const service = {
    live: true,
    draining: false,
    routeOwner,
    transport: routeOwner.transport,
    codec,
    reassembler,
    activeOperation: null,
    receiveReservation: null,
    releaseIncoming,
    reserveReferralCandidate,
    onCorrelatedFrame,
    onSurbHopEmit: null,
    correlatedFrameCount: 0,
    surbHopCellCount: 0,
    replyPumps: new Set(),
    closePromise: null,
    requestPump: null
  }
  state.routeService = service
  state.routeOwner = null
  try {
    registerM3RouteTeardownHandler(service.transport, () =>
      drainDhtExitRouteService(state, service)
    )
  } catch (err) {
    closeDhtExitRouteService(state)
    throw err
  }

  const routeReply = (encodedReply) => {
    const owned = b4a.from(encodedReply)
    encodedReply.fill(0)
    if (!state.live || !service.live) {
      owned.fill(0)
      return
    }
    const pump = (async () => {
      const payloads = fragment(owned, { randomBytes: cryptoSuite.randomBytes })
      owned.fill(0)
      try {
        for (const payload of payloads) {
          if (!state.live || !service.live) return
          service.correlatedFrameCount++
          if (typeof service.onCorrelatedFrame === 'function') {
            try {
              service.onCorrelatedFrame()
            } catch {}
          }
          const frame = codec.seal({
            direction: DIRECTION.REVERSE,
            class: CELL_CLASS.DATAGRAM,
            payload
          })
          try {
            await sendM3RouteFrame(service.transport, frame)
          } finally {
            frame.fill(0)
          }
        }
      } finally {
        for (const payload of payloads) payload.fill(0)
      }
    })()
    service.replyPumps.add(pump)
    pump
      .catch(() => {
        if (state.live && service.live) closeState(state)
      })
      .finally(() => {
        service.replyPumps.delete(pump)
      })
  }

  // Exit SURB output: first-hop cell only. No local peel. No relay secrets.
  const routeSurbHop = (info) => {
    if (!info || !b4a.isBuffer(info.cell)) invalid()
    const owned = b4a.from(info.cell)
    info.cell.fill(0)
    if (!state.live || !service.live) {
      owned.fill(0)
      return
    }
    const pump = (async () => {
      try {
        if (!state.live || !service.live) return
        service.surbHopCellCount++
        // Harness/wire tap: deliver the hop cell to the first reverse hop. Production M3
        // relays receive via packed reverse frames; the live opaque-forwarder harness
        // installs onSurbHopEmit to feed processRelaySurbHop at each hosted relay.
        if (typeof service.onSurbHopEmit === 'function') {
          try {
            service.onSurbHopEmit(owned)
          } finally {
            owned.fill(0)
          }
          return
        }
        const { packSurbRouteFrame } = require('./surb-path')
        let packed = null
        try {
          packed = packSurbRouteFrame(owned)
        } finally {
          owned.fill(0)
        }
        try {
          await sendM3RouteFrame(service.transport, packed)
        } finally {
          if (packed) packed.fill(0)
        }
      } catch {
        // Drop. Never fall back to correlated.
      }
    })()
    service.replyPumps.add(pump)
    pump
      .catch(() => {
        if (state.live && service.live) closeState(state)
      })
      .finally(() => {
        service.replyPumps.delete(pump)
      })
  }

  const requestPump = (async () => {
    while (state.live && service.live) {
      let frame = null
      let reservation = null
      try {
        reservation = reserveM3RouteFrame(service.transport)
        service.receiveReservation = reservation
        frame = await receiveReservedM3RouteFrame(reservation)
      } catch {
        if (state.live && service.live) closeState(state)
        return
      } finally {
        if (service.receiveReservation === reservation) service.receiveReservation = null
      }
      let opened = null
      let encodedRequest = null
      try {
        try {
          opened = codec.open({ direction: DIRECTION.FORWARD }, frame)
        } catch {
          continue
        }
        if (
          !opened ||
          Array.isArray(opened) ||
          opened.class !== CELL_CLASS.DATAGRAM ||
          !b4a.isBuffer(opened.payload)
        ) {
          continue
        }
        try {
          encodedRequest = reassembler.pushAuthenticated(opened.payload)
        } catch {
          continue
        }
        if (encodedRequest === null || service.activeOperation !== null) continue
        const pending = Object.freeze({})
        service.activeOperation = pending
        let operation = null
        try {
          const requestOptions = {
            onRoutedReply(reply) {
              if (service.activeOperation !== pending && service.activeOperation !== operation) {
                reply.fill(0)
                return
              }
              service.activeOperation = null
              routeReply(reply)
            }
          }
          if (service.reserveReferralCandidate !== null) {
            requestOptions.reserveReferralCandidate = service.reserveReferralCandidate
          }
          // SURB_REQUIRED always gets the hop-cell reverse sender. Exit never peels.
          requestOptions.onSurbHopMessage = routeSurbHop
          operation = requestDhtExitCommand(io, table, encodedRequest, requestOptions)
          if (service.activeOperation === pending) service.activeOperation = operation
        } catch {
          if (service.activeOperation === pending) service.activeOperation = null
        }
      } finally {
        if (frame !== null) frame.fill(0)
        if (opened && opened.payload) opened.payload.fill(0)
        if (encodedRequest !== null) encodedRequest.fill(0)
      }
    }
  })()
  service.requestPump = requestPump
  void requestPump.finally(() => {
    if (service.requestPump === requestPump) service.requestPump = null
  })
  return true
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
    const source = { host: from && from.host, port: from && from.port }
    const reply = decodeDhtExitReply(pending.wireReservation, source, packet)
    const authority = createDhtExitCorrelatedReplyAuthorityForIO(pending.transfer, source, reply)
    cancelPending(state, tid)
    if (pending.onReply !== null) pending.onReply(authority)
    else state.options.onReply(authority)
  } catch {}
}

async function sendDhtExitSeeds(io, deliveryAuthority, seedSetNonce, exitSecretKey) {
  const state = readIO(io)
  const service = state.routeService
  if (
    state.seedSent ||
    !service ||
    !service.live ||
    !b4a.isBuffer(seedSetNonce) ||
    seedSetNonce.byteLength !== 32 ||
    !b4a.isBuffer(exitSecretKey) ||
    exitSecretKey.byteLength !== 64
  ) {
    authentication()
  }
  state.seedSent = true
  const { encodeDhtExitSeeds, signDhtExitSeedsFromAuthority } = require('./dht-exit-seeds')
  let encoded = null
  let frame = null
  try {
    encoded = encodeDhtExitSeeds(
      signDhtExitSeedsFromAuthority(deliveryAuthority, { seedSetNonce }, exitSecretKey)
    )
    frame = service.codec.seal({
      direction: DIRECTION.REVERSE,
      class: CELL_CLASS.DATAGRAM,
      payload: encoded
    })
    await sendM3RouteFrame(service.transport, frame)
    return true
  } catch (err) {
    if (state.live) closeState(state)
    throw err instanceof PrivateRouteError ? err : PrivateRouteError.ERR_PRIVACY_UNAVAILABLE()
  } finally {
    if (encoded) encoded.fill(0)
    if (frame) frame.fill(0)
  }
}

function closeState(state) {
  if (!state || !state.live) return false
  state.live = false
  closeDhtExitRouteService(state)
  destroyDhtExitRouteTransportForIO(state.routeOwner)
  state.routeOwner = null
  for (const operation of Array.from(state.operations)) operation.cancel()
  state.operations.clear()
  for (const tid of state.pending.keys()) cancelPending(state, tid)
  try {
    state.socket.close()
  } catch {}
  state.socket = null
  state.ioConsumer = null
  return true
}

function waitDhtExitIOReady(io) {
  const state = readIO(io)
  return state.bindingPromise
}

function closeDhtExitIO(io) {
  const state = isObject(io) ? IOS.get(io) : null
  if (!state) return false
  IOS.delete(io)
  return closeState(state)
}
async function destroyDhtExitIO(io) {
  const state = isObject(io) ? IOS.get(io) : null
  if (!state) return false
  const socket = state.socket
  IOS.delete(io)
  closeState(state)
  const joins = []
  if (state.routeClosePromise !== null) joins.push(state.routeClosePromise)
  if (socket && typeof socket.close === 'function') {
    try {
      joins.push(Promise.resolve(socket.close()))
    } catch {}
  }
  await Promise.allSettled(joins)
  return true
}

const TEST_ONLY_DHT_EXIT_IO_STATE = Object.freeze({
  address(io) {
    const state = readIO(io)
    if (typeof state.socket.address !== 'function') invalid()
    const address = state.socket.address()
    if (!address || !Number.isSafeInteger(address.port)) invalid()
    return Object.freeze({ host: address.host, port: address.port })
  },
  snapshot(io) {
    const state = readIO(io)
    const service = state.routeService
    return Object.freeze({
      activeOperations: state.operations.size,
      ordinaryRequestCount: state.ordinaryRequestCount,
      pendingPackets: state.pending.size,
      referralProbeCount: state.referralProbeCount,
      correlatedFrameCount: service ? service.correlatedFrameCount : 0,
      surbHopCellCount: service ? service.surbHopCellCount : 0
    })
  },
  configureSurb(io, options) {
    const state = readIO(io)
    if (!state.routeService) invalid()
    if (options === null || typeof options !== 'object') invalid()
    // hopAuthorities intentionally not accepted — exit must not hold relay secrets.
    if (options.onCorrelatedFrame !== undefined) {
      if (typeof options.onCorrelatedFrame !== 'function') invalid()
      state.routeService.onCorrelatedFrame = options.onCorrelatedFrame
    }
    if (options.onSurbHopEmit !== undefined) {
      if (typeof options.onSurbHopEmit !== 'function') invalid()
      state.routeService.onSurbHopEmit = options.onSurbHopEmit
    }
    return true
  }
})

module.exports = {
  TEST_ONLY_DHT_EXIT_SOCKET_ISSUER: Object.freeze({ create: createTestDhtExitSocketAuthority }),
  TEST_ONLY_DHT_EXIT_IO_STATE,
  closeDhtExitIO,
  createDhtExitIO,
  createDhtExitIOForTest,
  destroyDhtExitIO,
  installDhtExitRoute,
  requestDhtExitCommand,
  requestDhtExitImmutableGet,
  sendDhtExitSeeds,
  sendReservedExitDhtPacket,
  waitDhtExitIOReady
}
