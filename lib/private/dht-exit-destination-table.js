'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const {
  DESTINATION_REF_SIZE,
  decodeDestinationRef,
  encodeDestinationRef
} = require('./destination-ref')
const { PrivateRouteError } = require('./errors')
const { DESTINATION_VALIDATION_CLASS, M3_MESSAGE_ID } = require('./protocol')
const {
  consumeDhtExitCorrelatedReplyAuthority,
  consumeDhtExitReservationTableIssuer,
  createDhtExitPacketReservation
} = require('./dht-exit-reservation')
const {
  consumeTestDhtExitReferralGrant,
  consumeTestDhtExitTopologyAuthority
} = require('./dht-exit-test-topology-grant')

const DHT_NODE_HANDLE_SIZE = 130
const MAX_U64 = 0xffff_ffff_ffff_ffffn
const TABLES = new WeakMap()
const DESTROYED_TABLES = new WeakSet()
const SETTLEMENTS = new WeakMap()
const SPENT_SETTLEMENTS = new WeakSet()
const COMPLETIONS = new WeakMap()
const SPENT_COMPLETIONS = new WeakSet()
const REFERRAL_REPLIES = new WeakMap()
const SPENT_REFERRAL_REPLIES = new WeakSet()
const MAX_LIVE_ENTRIES = 64
const MAX_GENERATION_PROBES = 32
const MAX_CONCURRENT_PROBES = 3
const MAX_REPLY_PROBES = 8
const PROBE_WINDOW_MS = 60_000n
const PROBE_DEADLINE_MS = 1_000n
const HANDLE_LIFETIME_MS = 300_000n
const HANDLE_DOMAIN = b4a.from('hyperdht-private-routes/dht-exit/destination-handle/v1')
const PEER_ID_DOMAIN = b4a.from('hyperdht-private-routes/dht-exit/peer-id/v1')
const TABLE_FIELDS = Object.freeze(['local', 'configuredBootstrap', 'monotonicNow', 'randomBytes'])
const REQUEST_FIELDS = Object.freeze(['command', 'target', 'token'])
const REQUEST_FIELDS_WITH_VALUE = Object.freeze(['command', 'target', 'token', 'value'])

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

function tuple(value) {
  exactOwnData(value, ['host', 'port'])
  const { host, port } = value
  if (typeof host !== 'string' || !Number.isSafeInteger(port) || port < 0 || port > 0xffff) {
    invalid()
  }
  return Object.freeze({ host, port })
}

function configuredTuple(value) {
  const candidate = tuple(value)
  if (!globallyRoutableIpv4(candidate.host)) invalid()
  return candidate
}

function referralCandidate(value, isolated = false) {
  exactOwnData(value, ['id', 'host', 'port'])
  const candidate = isolated
    ? tuple({ host: value.host, port: value.port })
    : configuredTuple({ host: value.host, port: value.port })
  if (isolated) {
    const bytes = ipv4Bytes(candidate.host)
    bytes.fill(0)
  }
  const id = fixed(value.id, 32)
  const expected = peerId(candidate.host, candidate.port)
  if (!b4a.equals(id, expected)) authentication()
  expected.fill(0)
  return Object.freeze({ id, host: candidate.host, port: candidate.port })
}

function uint64(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) invalid()
  return value
}

function fixed(value, size) {
  if (!b4a.isBuffer(value) || value.byteLength !== size) invalid()
  return b4a.from(value)
}

function copyNullable32(value) {
  return value === null ? null : fixed(value, 32)
}

function copyNullableBuffer(value) {
  return value === null ? null : b4a.from(value)
}

function random32(read) {
  if (typeof read !== 'function') invalid()
  const value = read(32)
  return fixed(value, 32)
}

function now(state) {
  const value = state.monotonicNow()
  if (typeof value === 'bigint' && value >= 0n) return value
  if (Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  invalid()
}

function ipv4Bytes(host) {
  const parts = host.split('.')
  if (parts.length !== 4) invalid()
  const bytes = b4a.allocUnsafeSlow(4)
  for (let i = 0; i < 4; i++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) invalid()
    const value = Number(parts[i])
    if (value > 255) invalid()
    bytes[i] = value
  }
  return bytes
}

function globallyRoutableIpv4(host) {
  let bytes
  try {
    bytes = ipv4Bytes(host)
  } catch {
    return false
  }
  const a = bytes[0]
  const b = bytes[1]
  const c = bytes[2]
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false
  if (a === 192 && b === 88 && c === 99) return false
  if (a === 198 && (b === 18 || b === 19)) return false
  if (a === 198 && b === 51 && c === 100) return false
  if (a === 203 && b === 0 && c === 113) return false
  return true
}
function isDhtExitIsolatedCandidate(value) {
  const candidate = tuple(value)
  return !globallyRoutableIpv4(candidate.host)
}

function peerId(host, port) {
  const out = b4a.allocUnsafeSlow(32)
  const bytes = ipv4Bytes(host)
  out[0] = bytes[0]
  out[1] = bytes[1]
  out[2] = bytes[2]
  out[3] = bytes[3]
  out[4] = port
  out[5] = port >> 8
  sodium.crypto_generichash(out, out.subarray(0, 6))
  bytes.fill(0)
  return out
}
function deriveDhtExitPeerId(value) {
  const candidate = tuple(value)
  return peerId(candidate.host, candidate.port)
}

function hex(value) {
  return b4a.toString(value, 'hex')
}

function writeU64(target, value, offset) {
  for (let i = offset + 7; i >= offset; i--) {
    target[i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(target, offset) {
  let value = 0n
  for (let i = offset; i < offset + 8; i++) value = (value << 8n) | BigInt(target[i])
  return value
}

function tagContext(entry) {
  const tupleBytes = ipv4Bytes(entry.tuple.host)
  const port = b4a.allocUnsafeSlow(2)
  const flags = b4a.allocUnsafeSlow(2)
  port[0] = entry.tuple.port >> 8
  port[1] = entry.tuple.port
  flags[0] = entry.provenance === 'CONFIGURED_BOOTSTRAP' ? 1 : 2
  flags[1] = 1
  const zeroCapabilityDigest = b4a.alloc(32)
  return b4a.concat([entry.id, tupleBytes, port, flags, zeroCapabilityDigest])
}

function tag(state, prefix, entry) {
  const input = b4a.concat([HANDLE_DOMAIN, state.secret, prefix, tagContext(entry)])
  const digest = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(digest, input)
  input.fill(0)
  const out = b4a.from(digest.subarray(0, 16))
  digest.fill(0)
  return out
}

function compareBuffers(left, right) {
  const length = Math.min(left.byteLength, right.byteLength)
  for (let index = 0; index < length; index++) {
    if (left[index] !== right[index]) return left[index] - right[index]
  }
  return left.byteLength - right.byteLength
}

function compareDestinationRefs(left, right) {
  const leftDecoded = decodeDestinationRef(left)
  const rightDecoded = decodeDestinationRef(right)
  try {
    const id = compareBuffers(leftDecoded.id, rightDecoded.id)
    if (id !== 0) return id
    return compareBuffers(leftDecoded.handle, rightDecoded.handle)
  } finally {
    leftDecoded.id.fill(0)
    leftDecoded.handle.fill(0)
    rightDecoded.id.fill(0)
    rightDecoded.handle.fill(0)
  }
}

function encodeHandle(state, entry, expiresAt) {
  const nonce = random32(state.randomBytes)
  const prefix = b4a.allocUnsafeSlow(DHT_NODE_HANDLE_SIZE - 16)
  prefix[0] = 1
  prefix[1] = DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE
  writeU64(prefix, expiresAt, 2)
  prefix.set(entry.exitIdentity, 10)
  prefix.set(state.branchId, 42)
  prefix.set(state.circuitId, 58)
  writeU64(prefix, state.generation, 74)
  prefix.set(nonce, 82)
  const authTag = tag(state, prefix, entry)
  const handle = b4a.concat([prefix, authTag])
  prefix.fill(0)
  authTag.fill(0)
  nonce.fill(0)
  return handle
}

function tableState(table) {
  const state = isObject(table) ? TABLES.get(table) : null
  if (!state) {
    if (isObject(table) && DESTROYED_TABLES.has(table)) destroyed()
    authentication()
  }
  const current = now(state)
  if (!state.live) destroyed()
  if (current >= state.expiresAt || current >= state.absoluteDeadline) destroyed()
  return state
}

function settlementState(authority) {
  const state = isObject(authority) ? SETTLEMENTS.get(authority) : null
  if (!state) {
    if (isObject(authority) && SPENT_SETTLEMENTS.has(authority)) replay()
    authentication()
  }
  if (!state.table.live) destroyed()
  return state
}

function createDhtExitDestinationTable(tableIssuer, options) {
  return createDhtExitDestinationTableInternal(tableIssuer, options, null)
}

function createDhtExitDestinationTableForTest(tableIssuer, options, topologyAuthority) {
  const topology = consumeTestDhtExitTopologyAuthority(topologyAuthority)
  return createDhtExitDestinationTableInternal(tableIssuer, options, topology)
}

function createDhtExitDestinationTableInternal(tableIssuer, options, topology) {
  exactOwnData(options, TABLE_FIELDS)
  const configured = options.configuredBootstrap
  if (!Array.isArray(configured) || configured.length < 1 || configured.length > 3) invalid()
  const entries = configured.map((value) => {
    const candidate = tuple(value)
    if (globallyRoutableIpv4(candidate.host)) return candidate
    if (topology !== null && topology.permits(candidate)) return candidate
    if (topology !== null) authentication()
    invalid()
  })
  const material = consumeDhtExitReservationTableIssuer(tableIssuer)
  const table = Object.freeze({})
  TABLES.set(table, {
    live: true,
    table,
    reservationTable: material,
    branchClass: material.branchClass,
    branchId: b4a.from(material.branchId),
    circuitId: b4a.from(material.circuitId),
    generation: material.generation,
    exitIdentity: b4a.from(material.exitIdentity),
    finalTranscriptDigest: b4a.from(material.finalTranscriptDigest),
    expiresAt: material.expiresAt,
    absoluteDeadline: material.absoluteDeadline,
    local: tuple(options.local),
    configured: Object.freeze(entries),
    topology,
    monotonicNow: options.monotonicNow,
    randomBytes: options.randomBytes,
    secret: random32(options.randomBytes),
    byRef: new Map(),
    byId: new Map(),
    pending: new Set(),
    pendingProbeIds: new Set(),
    completionAuthorities: new Set(),
    referralReplyAuthorities: new Set(),
    concurrentProbes: 0,
    totalProbes: 0
  })
  return table
}

function createSettlement(
  state,
  kind,
  candidate,
  deadline,
  request,
  issuerEntry = null,
  probeKey = null
) {
  const auditClass = Object.freeze({ table: state, kind, candidate })
  const settlementAuthority = Object.freeze({})
  const sendAuthority = createDhtExitPacketReservation(state.reservationTable, {
    remote: candidate,
    local: state.local,
    token: request.token,
    internal: request.internal,
    command: request.command,
    target: request.target,
    value: request.value === undefined ? null : request.value,
    deadline,
    auditClass
  })
  SETTLEMENTS.set(settlementAuthority, {
    table: state,
    kind,
    auditClass,
    candidate,
    deadline,
    request,
    issuerEntry,
    probeKey
  })
  state.pending.add(settlementAuthority)
  return Object.freeze({ sendAuthority, settlementAuthority })
}

function reserveProbeSettlement(state, kind, candidate, deadline, issuerEntry = null) {
  const current = now(state)
  if (!state.live) destroyed()
  if (
    deadline <= current ||
    deadline > current + PROBE_DEADLINE_MS ||
    deadline > state.absoluteDeadline ||
    deadline > state.expiresAt
  ) {
    invalid()
  }
  const candidateId = peerId(candidate.host, candidate.port)
  const probeKey = hex(candidateId)
  candidateId.fill(0)
  if (state.byId.has(probeKey) || state.pendingProbeIds.has(probeKey)) return null
  if (
    state.concurrentProbes >= MAX_CONCURRENT_PROBES ||
    state.totalProbes >= MAX_GENERATION_PROBES
  ) {
    throw PrivateRouteError.COUNTER_EXHAUSTED()
  }
  if (issuerEntry !== null) {
    issuerEntry.probeTimes = issuerEntry.probeTimes.filter(
      (timestamp) => current - timestamp < PROBE_WINDOW_MS
    )
    if (issuerEntry.probeTimes.length >= MAX_REPLY_PROBES) {
      throw PrivateRouteError.COUNTER_EXHAUSTED()
    }
  }
  const result = createSettlement(
    state,
    kind,
    candidate,
    deadline,
    { command: 0, internal: true, target: null, token: null, value: null },
    issuerEntry,
    probeKey
  )
  state.concurrentProbes++
  state.totalProbes++
  if (issuerEntry !== null) issuerEntry.probeTimes.push(current)
  state.pendingProbeIds.add(probeKey)
  return result
}

function releaseProbe(settlement) {
  if (
    settlement.kind !== 'CONFIGURED_BOOTSTRAP' &&
    settlement.kind !== 'VALIDATED_PROTOCOL_REFERRAL'
  ) {
    return
  }
  if (settlement.table.concurrentProbes > 0) settlement.table.concurrentProbes--
  if (settlement.probeKey !== null) settlement.table.pendingProbeIds.delete(settlement.probeKey)
}

function reserveConfiguredBootstrapProbe(table, index, absoluteDeadline) {
  const state = tableState(table)
  const deadline = uint64(absoluteDeadline)
  if (!Number.isSafeInteger(index) || index < 0 || index >= state.configured.length) invalid()
  return reserveProbeSettlement(state, 'CONFIGURED_BOOTSTRAP', state.configured[index], deadline)
}

function admit(state, candidate, provenance) {
  const id = peerId(candidate.host, candidate.port)
  const idKey = hex(id)
  const existing = state.byId.get(idKey)
  if (existing) return b4a.from(existing.destinationRef)
  if (state.byRef.size >= MAX_LIVE_ENTRIES) throw PrivateRouteError.COUNTER_EXHAUSTED()
  const current = now(state)
  if (!state.live) {
    id.fill(0)
    destroyed()
  }
  const expiresAt = [current + HANDLE_LIFETIME_MS, state.expiresAt, state.absoluteDeadline].reduce(
    (minimum, value) => (value < minimum ? value : minimum)
  )
  const entry = {
    tuple: candidate,
    id,
    exitIdentity: state.exitIdentity,
    provenance,
    expiresAt,
    probeTimes: []
  }
  const handle = encodeHandle(state, entry, expiresAt)
  if (!state.live) {
    id.fill(0)
    handle.fill(0)
    destroyed()
  }
  const destinationRef = encodeDestinationRef({ id, handle })
  entry.handle = handle
  entry.destinationRef = destinationRef
  state.byId.set(idKey, entry)
  state.byRef.set(hex(destinationRef), entry)
  return b4a.from(destinationRef)
}

function settleExitDhtReservation(settlementAuthority, correlatedReplyAuthority) {
  const settlement = settlementState(settlementAuthority)
  SETTLEMENTS.delete(settlementAuthority)
  SPENT_SETTLEMENTS.add(settlementAuthority)
  settlement.table.pending.delete(settlementAuthority)
  releaseProbe(settlement)
  const correlated = consumeDhtExitCorrelatedReplyAuthority(correlatedReplyAuthority)
  if (correlated.auditClass !== settlement.auditClass) authentication()
  if (
    settlement.kind === 'CONFIGURED_BOOTSTRAP' ||
    settlement.kind === 'VALIDATED_PROTOCOL_REFERRAL'
  ) {
    if (correlated.message.command !== 0 || correlated.message.internal !== true) authentication()
    if (correlated.reply.error !== 0) return null
    return admit(settlement.table, settlement.candidate, settlement.kind)
  }
  if (settlement.kind === 'ORDINARY_DHT_REQUEST') {
    if (
      (settlement.request.command !== 9 &&
        settlement.request.command !== 8 &&
        settlement.request.command !== 7 &&
        settlement.request.command !== 6) ||
      correlated.message.command !== settlement.request.command ||
      correlated.message.internal !== false
    ) {
      authentication()
    }
    const completion = Object.freeze({})
    COMPLETIONS.set(completion, {
      table: settlement.table,
      issuerEntry: settlement.issuerEntry,
      deadline: settlement.deadline,
      reply: correlated.reply,
      replyDigest: correlated.replyDigest,
      upstreamError: correlated.reply.error,
      command: settlement.request.command
    })
    settlement.table.completionAuthorities.add(completion)
    return completion
  }
  invalid()
}

function abortExitDhtReservation(settlementAuthority) {
  const settlement = settlementState(settlementAuthority)
  SETTLEMENTS.delete(settlementAuthority)
  SPENT_SETTLEMENTS.add(settlementAuthority)
  settlement.table.pending.delete(settlementAuthority)
  releaseProbe(settlement)
  return true
}

function takeCompletion(completion) {
  const state = isObject(completion) ? COMPLETIONS.get(completion) : null
  if (!state) {
    if (isObject(completion) && SPENT_COMPLETIONS.has(completion)) replay()
    authentication()
  }
  const current = now(state.table)
  if (!state.table.live || current >= state.deadline) destroyed()
  COMPLETIONS.delete(completion)
  SPENT_COMPLETIONS.add(completion)
  state.table.completionAuthorities.delete(completion)
  return state
}

function createReferralAuthorityFromState(state) {
  const authority = Object.freeze({})
  REFERRAL_REPLIES.set(authority, {
    ...state,
    candidates: state.reply.closerNodes.slice(0, MAX_REPLY_PROBES),
    used: new Set()
  })
  state.table.referralReplyAuthorities.add(authority)
  return authority
}

function createReferralReplyAuthority(completion) {
  return createReferralAuthorityFromState(takeCompletion(completion))
}

function consumeDhtExitImmutableGetCompletionForIO(completion, includeIsolated = false) {
  if (typeof includeIsolated !== 'boolean') invalid()
  const state = takeCompletion(completion)
  const candidates = []
  for (const candidate of state.reply.closerNodes.slice(0, MAX_REPLY_PROBES)) {
    if (!includeIsolated && !globallyRoutableIpv4(candidate.host)) continue
    candidates.push(
      Object.freeze({
        id: peerId(candidate.host, candidate.port),
        host: candidate.host,
        port: candidate.port
      })
    )
  }
  return Object.freeze({
    token: state.reply.token === null ? null : b4a.from(state.reply.token),
    valuePresent: state.reply.valuePresent,
    value: state.reply.value === null ? null : b4a.from(state.reply.value),
    candidates: Object.freeze(candidates),
    referralReplyAuthority: createReferralAuthorityFromState(state),
    upstreamError: state.upstreamError === undefined ? state.reply.error : state.upstreamError,
    command: state.command === undefined ? 9 : state.command
  })
}

function reserveReferralProbe(table, referralReplyAuthority, candidateValue, absoluteDeadline) {
  return reserveReferralProbeInternal(
    table,
    referralReplyAuthority,
    candidateValue,
    absoluteDeadline,
    null,
    0
  )
}

function reserveTestTopologyReferralProbe(
  table,
  referralReplyAuthority,
  candidateValue,
  absoluteDeadline,
  grantAuthority,
  exitRole
) {
  return reserveReferralProbeInternal(
    table,
    referralReplyAuthority,
    candidateValue,
    absoluteDeadline,
    grantAuthority,
    exitRole
  )
}

function reserveReferralProbeInternal(
  table,
  referralReplyAuthority,
  candidateValue,
  absoluteDeadline,
  grantAuthority,
  exitRole
) {
  const state = tableState(table)
  const referral = isObject(referralReplyAuthority)
    ? REFERRAL_REPLIES.get(referralReplyAuthority)
    : null
  if (!referral) {
    if (isObject(referralReplyAuthority) && SPENT_REFERRAL_REPLIES.has(referralReplyAuthority)) {
      replay()
    }
    authentication()
  }
  const current = now(state)
  if (
    !state.live ||
    TABLES.get(table) !== state ||
    current >= state.expiresAt ||
    current >= state.absoluteDeadline
  ) {
    destroyed()
  }
  if (REFERRAL_REPLIES.get(referralReplyAuthority) !== referral) authentication()
  if (referral.table !== state || current >= referral.deadline) authentication()
  const isolated = grantAuthority !== null
  if (
    isolated &&
    (state.topology === null || !Number.isSafeInteger(exitRole) || exitRole < 1 || exitRole > 0xff)
  ) {
    authentication()
  }
  const candidate = referralCandidate(candidateValue, isolated)
  if (isolated) {
    consumeTestDhtExitReferralGrant(grantAuthority, {
      tuple: { host: candidate.host, port: candidate.port },
      id: candidate.id,
      exitRole,
      generation: state.generation
    })
  }
  const key = `${candidate.host}:${candidate.port}`
  if (
    referral.used.has(key) ||
    !referral.candidates.some(
      (entry) => entry.host === candidate.host && entry.port === candidate.port
    )
  ) {
    authentication()
  }
  const candidateId = peerId(candidate.host, candidate.port)
  const alreadyAdmitted = state.byId.has(hex(candidateId))
  candidateId.fill(0)
  if (alreadyAdmitted) {
    referral.used.add(key)
    if (referral.used.size >= referral.candidates.length) {
      REFERRAL_REPLIES.delete(referralReplyAuthority)
      SPENT_REFERRAL_REPLIES.add(referralReplyAuthority)
      state.referralReplyAuthorities.delete(referralReplyAuthority)
    }
    return null
  }
  const deadline = uint64(absoluteDeadline)
  const result = reserveProbeSettlement(
    state,
    'VALIDATED_PROTOCOL_REFERRAL',
    Object.freeze({ host: candidate.host, port: candidate.port }),
    deadline,
    referral.issuerEntry
  )
  referral.used.add(key)
  if (referral.used.size >= referral.candidates.length) {
    REFERRAL_REPLIES.delete(referralReplyAuthority)
    SPENT_REFERRAL_REPLIES.add(referralReplyAuthority)
    state.referralReplyAuthorities.delete(referralReplyAuthority)
  }
  return result
}

function revokeDhtExitReferralReplyAuthority(authority) {
  const referral = isObject(authority) ? REFERRAL_REPLIES.get(authority) : null
  if (!referral) return false
  REFERRAL_REPLIES.delete(authority)
  SPENT_REFERRAL_REPLIES.add(authority)
  referral.table.referralReplyAuthorities.delete(authority)
  return true
}

function entryForRef(state, destinationRef) {
  const ref = fixed(destinationRef, DESTINATION_REF_SIZE)
  const entry = state.byRef.get(hex(ref))
  if (!entry) authentication()
  const current = now(state)
  if (!state.live || current >= entry.expiresAt) destroyed()
  return entry
}

function verifyDhtExitRoutedDestination(table, value, operationDeadline) {
  const state = tableState(table)
  exactOwnData(value, [
    'destination',
    'destinationEncoded',
    'destinationValidationClass',
    'operationBudgetMs',
    'commandId'
  ])
  if (
    value.destinationValidationClass !== DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE ||
    (value.commandId !== M3_MESSAGE_ID.IMMUTABLE_GET_V1 &&
      value.commandId !== M3_MESSAGE_ID.IMMUTABLE_PUT_V1 &&
      value.commandId !== M3_MESSAGE_ID.MUTABLE_GET_V1 &&
      value.commandId !== M3_MESSAGE_ID.MUTABLE_PUT_V1)
  ) {
    authentication()
  }
  // KI-15: the request carries a relative budget, so the absolute deadline enforced here is in
  // this host's own domain. It is DERIVED BY THE CALLER and passed in rather than derived a
  // second time here: the operation's reservations are capped by the caller's value, and two
  // derivations from two clock samples differ, which would admit a destination against the
  // earlier one and then refuse the reservation against the later one - dropping a request
  // instead of answering it. The budget still has to be a uint64 to be a legal request.
  uint64(value.operationBudgetMs)
  const deadline = uint64(operationDeadline)
  const entry = entryForRef(state, value.destinationEncoded)
  exactOwnData(value.destination, ['id', 'handle'])
  if (
    deadline > state.absoluteDeadline ||
    deadline > entry.expiresAt ||
    !b4a.equals(entry.id, value.destination.id) ||
    !b4a.equals(entry.handle, value.destination.handle)
  ) {
    authentication()
  }
  return true
}

function reserveOrdinaryDhtRequest(table, destinationRef, requestSpec, absoluteDeadline) {
  const state = tableState(table)
  const keys = Reflect.ownKeys(requestSpec)
  if (keys.length === 4 && keys.indexOf('value') !== -1) {
    exactOwnData(requestSpec, REQUEST_FIELDS_WITH_VALUE)
  } else {
    exactOwnData(requestSpec, REQUEST_FIELDS)
  }
  const deadline = uint64(absoluteDeadline)
  const current = now(state)
  if (!state.live) destroyed()
  if (deadline <= current || deadline > state.absoluteDeadline || deadline > state.expiresAt)
    invalid()
  const entry = entryForRef(state, destinationRef)
  if (
    requestSpec.command !== 9 &&
    requestSpec.command !== 8 &&
    requestSpec.command !== 7 &&
    requestSpec.command !== 6
  ) {
    invalid()
  }
  let token = null
  let value = null
  const providedValue = Object.prototype.hasOwnProperty.call(requestSpec, 'value')
    ? requestSpec.value
    : null
  if (requestSpec.command === 9) {
    if (requestSpec.token !== null || providedValue !== null) invalid()
  } else if (requestSpec.command === 7) {
    if (requestSpec.token !== null || !b4a.isBuffer(providedValue)) invalid()
    value = b4a.from(providedValue)
  } else {
    token = fixed(requestSpec.token, 32)
    if (!b4a.isBuffer(providedValue)) invalid()
    value = b4a.from(providedValue)
  }
  return createSettlement(
    state,
    'ORDINARY_DHT_REQUEST',
    entry.tuple,
    deadline,
    {
      command: requestSpec.command,
      internal: false,
      target: fixed(requestSpec.target, 32),
      token,
      value
    },
    entry
  )
}

function readDhtExitDestinationRef(table, destinationRef) {
  const state = tableState(table)
  const entry = entryForRef(state, destinationRef)
  const decoded = decodeDestinationRef(entry.destinationRef)
  if (decoded.handle.byteLength !== DHT_NODE_HANDLE_SIZE) invalid()
  if (decoded.handle[0] !== 1 || decoded.handle[1] !== DESTINATION_VALIDATION_CLASS.DHT_NODE_HANDLE)
    invalid()
  const prefix = decoded.handle.subarray(0, DHT_NODE_HANDLE_SIZE - 16)
  const authTag = decoded.handle.subarray(DHT_NODE_HANDLE_SIZE - 16)
  const expected = tag(state, prefix, entry)
  if (!b4a.equals(authTag, expected)) authentication()
  expected.fill(0)
  return Object.freeze({
    id: b4a.from(decoded.id),
    handle: b4a.from(decoded.handle),
    tuple: entry.tuple,
    expiresAt: readU64(decoded.handle, 2),
    branchClass: state.branchClass,
    branchId: b4a.from(state.branchId),
    circuitId: b4a.from(state.circuitId),
    generation: state.generation
  })
}

function readDhtExitDestinationTableBinding(table) {
  const state = tableState(table)
  return Object.freeze({
    branchClass: state.branchClass,
    branchId: b4a.from(state.branchId),
    circuitId: b4a.from(state.circuitId),
    generation: state.generation,
    exitIdentity: b4a.from(state.exitIdentity),
    expiresAt: state.expiresAt,
    absoluteDeadline: state.absoluteDeadline
  })
}

function snapshotDhtExitDestinationTable(table) {
  const state = tableState(table)
  if (state.byRef.size < 1 || state.byRef.size > 3) invalid()
  return Object.freeze({
    branchClass: state.branchClass,
    branchId: b4a.from(state.branchId),
    circuitId: b4a.from(state.circuitId),
    generation: state.generation,
    exitIdentity: b4a.from(state.exitIdentity),
    expiresAt: state.expiresAt,
    live: () => {
      if (!state.live) return false
      const current = now(state)
      return state.live && current < state.expiresAt && current < state.absoluteDeadline
    },
    absoluteDeadline: state.absoluteDeadline,
    destinationRefs: Object.freeze(
      Array.from(state.byRef.values(), (entry) => b4a.from(entry.destinationRef)).sort(
        compareDestinationRefs
      )
    )
  })
}

function destroyDhtExitDestinationTable(table) {
  const state = isObject(table) ? TABLES.get(table) : null
  if (!state) return false
  TABLES.delete(table)
  DESTROYED_TABLES.add(table)
  state.live = false
  state.secret.fill(0)
  state.branchId.fill(0)
  state.circuitId.fill(0)
  state.exitIdentity.fill(0)
  for (const entry of state.byRef.values()) {
    entry.id.fill(0)
    entry.handle.fill(0)
    entry.destinationRef.fill(0)
  }
  state.byRef.clear()
  state.byId.clear()
  for (const authority of state.pending) {
    SETTLEMENTS.delete(authority)
    SPENT_SETTLEMENTS.add(authority)
  }
  state.pendingProbeIds.clear()
  state.pending.clear()
  for (const authority of state.completionAuthorities) {
    COMPLETIONS.delete(authority)
    SPENT_COMPLETIONS.add(authority)
  }
  state.completionAuthorities.clear()
  for (const authority of state.referralReplyAuthorities) {
    REFERRAL_REPLIES.delete(authority)
    SPENT_REFERRAL_REPLIES.add(authority)
  }
  state.referralReplyAuthorities.clear()
  return true
}

module.exports = Object.freeze({
  DHT_NODE_HANDLE_SIZE,
  abortExitDhtReservation,
  createDhtExitDestinationTable,
  createDhtExitDestinationTableForTest,
  createReferralReplyAuthority,
  consumeDhtExitImmutableGetCompletionForIO,
  destroyDhtExitDestinationTable,
  deriveDhtExitPeerId,
  readDhtExitDestinationRef,
  readDhtExitDestinationTableBinding,
  reserveConfiguredBootstrapProbe,
  isDhtExitIsolatedCandidate,
  reserveReferralProbe,
  reserveTestTopologyReferralProbe,
  reserveOrdinaryDhtRequest,
  revokeDhtExitReferralReplyAuthority,
  snapshotDhtExitDestinationTable,
  settleExitDhtReservation,
  verifyDhtExitRoutedDestination
})
