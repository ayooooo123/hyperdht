'use strict'

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { fragment, Reassembler } = require('./fragments')
const {
  destroyM3RouteTransport,
  receiveM3RouteFrame,
  sendM3RouteFrame
} = require('./m3-adjacency-runtime')
const { PrivateRouteError } = require('./errors')
const {
  consumeDhtExitPacketReservationForIO,
  createDhtExitCorrelatedReplyAuthorityForIO,
  destroyDhtExitRouteTransportForIO,
  encodeDhtExitPacketReservationTransfer,
  readDhtExitPacketReservationTransferForIO,
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

function requestDhtExitImmutableGet(io, table, encodedRequest, options) {
  const optionFields =
    options && options.reserveReferralCandidate !== undefined
      ? ['onRoutedReply', 'reserveReferralCandidate']
      : ['onRoutedReply']
  exactOwnData(options, optionFields)
  if (
    typeof options.onRoutedReply !== 'function' ||
    (options.reserveReferralCandidate !== undefined &&
      typeof options.reserveReferralCandidate !== 'function')
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
  if (
    request.operationClass !== BRANCH_CLASS.LOOKUP ||
    request.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 ||
    request.encodedBody.byteLength !== 32 ||
    admission.deadline === null
  ) {
    clearRoutedRequest(request)
    authentication()
  }
  const operationDeadline = admission.deadline

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
    { command: 9, target: request.encodedBody, token: null },
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
  if (service.activeOperation !== null) {
    try {
      service.activeOperation.cancel()
    } catch {}
    service.activeOperation = null
  }
  try {
    service.codec.destroy()
  } catch {}
  try {
    service.reassembler.destroy()
  } catch {}
  destroyDhtExitRouteTransportForIO(service.routeOwner)
  service.routeOwner = null
  service.transport = null
  service.codec = null
  service.reassembler = null
  return true
}

function installDhtExitRoute(io, table, ...args) {
  let reserveReferralCandidate = null
  if (args.length > 1) invalid()
  if (args.length === 1) {
    exactOwnData(args[0], ['reserveReferralCandidate'])
    if (typeof args[0].reserveReferralCandidate !== 'function') invalid()
    reserveReferralCandidate = args[0].reserveReferralCandidate
  }
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
    routeOwner,
    transport: routeOwner.transport,
    codec,
    reassembler,
    activeOperation: null,
    reserveReferralCandidate,
    replyPump: null
  }
  state.routeService = service
  state.routeOwner = null

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
    service.replyPump = pump
    pump
      .catch(() => {
        if (state.live && service.live) closeState(state)
      })
      .finally(() => {
        if (service.replyPump === pump) service.replyPump = null
      })
  }

  void (async () => {
    while (state.live && service.live) {
      let frame = null
      try {
        frame = await receiveM3RouteFrame(service.transport)
      } catch {
        if (state.live && service.live) closeState(state)
        return
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
          operation = requestDhtExitImmutableGet(io, table, encodedRequest, requestOptions)
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
  try {
    await socket.close()
  } catch {}
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
    return Object.freeze({
      activeOperations: state.operations.size,
      ordinaryRequestCount: state.ordinaryRequestCount,
      pendingPackets: state.pending.size,
      referralProbeCount: state.referralProbeCount
    })
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
  requestDhtExitImmutableGet,
  sendDhtExitSeeds,
  sendReservedExitDhtPacket,
  waitDhtExitIOReady
}
