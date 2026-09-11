'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { encodePeerSemantic } = require('../../lib/private/peer-semantic-wire')
const { encodePeerTransport, decodePeerTransport } = require('../../lib/private/peer-transport-wire')
const {
  PeerReliableLanes,
  LANE_DATA,
  LANE_CONTROL,
  FLAG_CONTROL,
  DATA_SEND_SLOTS,
  CTRL_SEND_SLOTS,
  DATA_REORDER,
  DATA_READY,
  MAX_ATTEMPTS,
  RTO_MS,
  MAX_U64
} = require('../../lib/private/peer-reliable-lanes')

const MAX_ACK_SNAPSHOT = 0xffff_ffff

function expectCode(t, operation, code) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function routeId(fill = 0x11) {
  return b4a.alloc(16, fill)
}

function common(opts = {}) {
  return {
    routeId: opts.routeId || routeId(),
    streamId: opts.streamId === undefined ? 3n : opts.streamId,
    streamEpoch: opts.streamEpoch === undefined ? 1 : opts.streamEpoch,
    direction: opts.direction === undefined ? 0 : opts.direction,
    flags: 0,
    reserved: 0,
    position: opts.position === undefined ? 0n : opts.position
  }
}

/** Peer→us travel direction when this instance sends as localDirection. */
function inboundDirection(localDirection = 0) {
  return localDirection ^ 1
}

function encodeNested(messageId, fields) {
  return encodePeerTransport(messageId, fields)
}

function makeDataNested(opts = {}) {
  const bytes = opts.bytes || b4a.alloc(8, 0xab)
  return encodeNested(PEER_MESSAGE_ID.PEER_DATA_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: opts.streamId,
      direction: opts.direction,
      position: opts.position === undefined ? 0n : opts.position
    }),
    dataBytes: bytes.byteLength,
    dataFlags: 0,
    bytes
  })
}

/** Nested DATA for packets this instance receives (direction = inbound). */
function makeInboundDataNested(opts = {}) {
  const localDirection = opts.localDirection === undefined ? 0 : opts.localDirection
  return makeDataNested({
    ...opts,
    direction:
      opts.direction === undefined ? inboundDirection(localDirection) : opts.direction
  })
}

function makeOpenNested(opts = {}) {
  return encodeNested(PEER_MESSAGE_ID.PEER_OPEN_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: opts.streamId === undefined ? 3n : opts.streamId,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: 0n
    }),
    semanticFirstId: 0x0360,
    semanticClass: 2,
    reservedZero: 0,
    firstSemanticWireBytes: 757,
    requestedHandshakeFrames: 4,
    requestedHandshakeBytes: 1297n,
    requestedDataFrames: 4,
    requestedDataBytes: 3908n,
    openNonce: b4a.alloc(16, 0x5a)
  })
}

function makeRegistrationOpenNested(opts = {}) {
  return encodeNested(PEER_MESSAGE_ID.PEER_OPEN_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: 1n,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: 0n
    }),
    semanticFirstId: 0x0349,
    semanticClass: 1,
    reservedZero: 0,
    firstSemanticWireBytes: 486,
    requestedHandshakeFrames: 2,
    requestedHandshakeBytes: 582n,
    requestedDataFrames: 0,
    requestedDataBytes: 0n,
    openNonce: b4a.alloc(16, 0x5a)
  })
}

function makeRegistrationSemanticPayload() {
  return encodePeerSemantic(PEER_MESSAGE_ID.ENTRY_REVOKE_V2, {
    token: b4a.alloc(32, 0x41),
    registrationCommitment: b4a.alloc(32, 0x42),
    circuitId: b4a.alloc(16, 0x43),
    generation: 1n
  })
}

function makeApplicationSemanticPayload(flight) {
  const ciphertextBytes = flight === 1 ? 101 : 53
  return encodePeerSemantic(PEER_MESSAGE_ID.PEER_NOISE_FRAGMENT_V2, {
    sessionId: b4a.alloc(16, 0x51),
    flight,
    wholeCiphertextCommitment: b4a.alloc(32, 0x52),
    totalCiphertextBytes: ciphertextBytes,
    fragmentIndex: 0,
    fragmentCount: 1,
    ciphertextOffset: 0,
    fragmentBytes: ciphertextBytes,
    ciphertext: b4a.alloc(ciphertextBytes, 0x53)
  })
}

function makeRegHandshakeNested(opts = {}) {
  // purpose3 stream1 HANDSHAKE → CONTROL lane
  const payload = opts.bytes || makeRegistrationSemanticPayload()
  return encodeNested(PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: 1n,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: opts.position === undefined ? 1n : opts.position
    }),
    semanticObjectOffset: 0,
    fragmentBytes: payload.byteLength,
    fragmentFlags: 3,
    bytes: payload
  })
}

function makeAppHandshakeNested(opts = {}) {
  const flight = opts.flight === undefined ? 1 : opts.flight
  const payload = opts.bytes || makeApplicationSemanticPayload(flight)
  return encodeNested(PEER_MESSAGE_ID.PEER_HANDSHAKE_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: opts.streamId === undefined ? 3n : opts.streamId,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: opts.position === undefined ? (flight === 1 ? 1n : 0n) : opts.position
    }),
    semanticObjectOffset: 0,
    fragmentBytes: payload.byteLength,
    fragmentFlags: 3,
    bytes: payload
  })
}

function makeOpenedNested(opts = {}) {
  return encodeNested(PEER_MESSAGE_ID.PEER_OPENED_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: opts.streamId === undefined ? 3n : opts.streamId,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: 0n
    }),
    openNonce: opts.openNonce || b4a.alloc(16, 0x6b),
    admittedDataFrames: opts.admittedDataFrames === undefined ? 4 : opts.admittedDataFrames,
    admittedDataBytes: opts.admittedDataBytes === undefined ? 3908 : opts.admittedDataBytes
  })
}

function makeCreditNested(opts = {}) {
  return encodeNested(PEER_MESSAGE_ID.PEER_CREDIT_V2, {
    common: common({
      routeId: opts.routeId,
      streamId: opts.streamId === undefined ? 3n : opts.streamId,
      direction: opts.direction === undefined ? 0 : opts.direction,
      position: 0n
    }),
    cumulativeGrantedFrames:
      opts.cumulativeGrantedFrames === undefined ? 1n : opts.cumulativeGrantedFrames,
    cumulativeGrantedBytes:
      opts.cumulativeGrantedBytes === undefined ? 59n : opts.cumulativeGrantedBytes,
    creditEpoch: opts.creditEpoch === undefined ? 1 : opts.creditEpoch
  })
}

function clock() {
  let now = 1_000_000n
  const timers = []
  return {
    identity: Object.freeze({ id: 'test-clock' }),
    now: () => now,
    advance(ms) {
      now += BigInt(ms)
      const due = timers.filter((t) => !t.cancelled && !t.fired && t.fireAt <= now)
      for (const t of due) {
        t.fired = true
        t.cb()
      }
    },
    fireCancelled() {
      const cancelled = timers.filter((t) => t.cancelled && !t.fired)
      for (const t of cancelled) {
        t.fired = true
        t.cb()
      }
      return cancelled.length
    },
    schedule(delayMs, cb) {
      const entry = {
        fireAt: now + BigInt(delayMs),
        cb,
        cancelled: false,
        fired: false
      }
      timers.push(entry)
      return () => {
        entry.cancelled = true
      }
    }
  }
}

function createLanes(overrides = {}) {
  const c = overrides.clock || clock()
  const rid = overrides.routeId || routeId()
  const state = {
    transmits: [],
    admits: [],
    delivers: [],
    acked: [],
    conflicts: [],
    failures: [],
    writables: 0,
    autoAdmit: overrides.autoAdmit !== false,
    autoDeliver: overrides.autoDeliver !== false,
    transmitImpl:
      overrides.transmitImpl ||
      ((buf) => {
        // Seal bytes synchronously; native send completion remains asynchronous.
        const copy = b4a.from(buf)
        state.transmits.push(copy)
        return Promise.resolve(true)
      })
  }

  const lanes = new PeerReliableLanes({
    routeId: rid,
    generation: overrides.generation === undefined ? 7n : overrides.generation,
    purpose: overrides.purpose === undefined ? 2 : overrides.purpose,
    localDirection: overrides.localDirection === undefined ? 0 : overrides.localDirection,
    clockIdentity: c.identity,
    monotonicNow: () => c.now(),
    schedule: (ms, cb) => c.schedule(ms, cb),
    localDeadline: overrides.localDeadline === undefined ? 9_000_000n : overrides.localDeadline,
    onTransmit: (buf) => state.transmitImpl(buf),
    onAdmit: (meta, nested) => {
      state.admits.push({
        lane: meta.lane,
        sequence: meta.sequence,
        nested: b4a.from(nested)
      })
      return state.autoAdmit
    },
    onDeliver: (meta, nested) => {
      state.delivers.push({
        lane: meta.lane,
        sequence: meta.sequence,
        nested: b4a.from(nested)
      })
      return state.autoDeliver
    },
    onAcknowledged: (info) => {
      state.acked.push(info)
    },
    onConflict: (info) => {
      state.conflicts.push(info)
    },
    onFailure: (err) => {
      state.failures.push(err)
    },
    onWritable: () => {
      state.writables++
    }
  })

  return { lanes, state, clock: c, routeId: rid }
}

function decodeTx(buf) {
  return decodePeerTransport(buf)
}

function isAck(buf) {
  return decodeTx(buf).messageId === PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2
}

function isPacket(buf) {
  return decodeTx(buf).messageId === PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2
}

function packetsOnly(transmits) {
  return transmits.filter((t) => {
    try {
      return isPacket(t)
    } catch {
      return false
    }
  })
}

function acksOnly(transmits) {
  return transmits.filter((t) => {
    try {
      return isAck(t)
    } catch {
      return false
    }
  })
}

function peerAck(opts) {
  return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2, {
    routeId: opts.routeId,
    generation: opts.generation === undefined ? 7n : opts.generation,
    dataCumulative: opts.dataCumulative === undefined ? MAX_U64 : opts.dataCumulative,
    dataBitmap: opts.dataBitmap === undefined ? 0n : opts.dataBitmap,
    controlCumulative: opts.controlCumulative === undefined ? MAX_U64 : opts.controlCumulative,
    controlBitmap: opts.controlBitmap === undefined ? 0n : opts.controlBitmap,
    ackSnapshot: opts.ackSnapshot === undefined ? 1 : opts.ackSnapshot,
    reservedZero: 0
  })
}

test('trySend DATA assigns sequences and CONTROL is independent', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  const d0 = makeDataNested({ routeId: rid })
  const d1 = makeDataNested({ routeId: rid, position: 8n })
  const c0 = makeOpenNested({ routeId: rid })

  const a = lanes.trySend(d0)
  const b = lanes.trySend(d1)
  const c = lanes.trySend(c0)

  t.alike(a, { lane: LANE_DATA, sequence: 0n })
  t.alike(b, { lane: LANE_DATA, sequence: 1n })
  t.alike(c, { lane: LANE_CONTROL, sequence: 0n })

  const pkts = packetsOnly(state.transmits)
  t.is(pkts.length, 3)
  t.is(decodeTx(pkts[0]).fields.laneSequence, 0n)
  t.is(decodeTx(pkts[0]).fields.flags, 0)
  t.is(decodeTx(pkts[2]).fields.flags, FLAG_CONTROL)
  lanes.destroy()
})

test('trySend validates the complete nested object and route before reservation', (t) => {
  const { lanes, state, routeId: rid } = createLanes()

  const malformed = b4a.from(makeDataNested({ routeId: rid }))
  // PEER_DATA body starts after the 8-byte envelope and 40-byte common prefix.
  // Claim seven payload bytes while retaining the canonical eight-byte body.
  malformed[48] = 0
  malformed[49] = 7
  expectCode(t, () => lanes.trySend(malformed), 'INVALID_ROUTE')
  expectCode(
    t,
    () => lanes.trySend(makeDataNested({ routeId: routeId(0x22) })),
    'INVALID_ROUTE'
  )

  // Neither rejected caller input consumes a sequence, slot, attempt, or route lifetime.
  t.alike(lanes.trySend(makeDataNested({ routeId: rid })), {
    lane: LANE_DATA,
    sequence: 0n
  })
  t.is(state.failures.length, 0)
  lanes.destroy()
})

test('DATA0 lost then out-of-order 1..boundary with selective slot release', async (t) => {
  const localDirection = 0
  const { lanes, state, routeId: rid } = createLanes({ localDirection })

  // Build peer-shaped wrappers: B receives bytes encoded in peer A's outbound direction.
  function peerPacket(seq, nested, flags = 0) {
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: seq,
      nestedLength: nested.byteLength,
      flags,
      completeNestedObject: nested
    })
  }

  const n0 = makeInboundDataNested({ routeId: rid, localDirection, position: 0n })
  const n1 = makeInboundDataNested({ routeId: rid, localDirection, position: 8n })
  const n2 = makeInboundDataNested({ routeId: rid, localDirection, position: 16n })

  // Prove the fixture models peer→local traffic before exercising lane admission.
  t.is(decodeTx(n0).fields.common.direction, localDirection ^ 1)
  t.is(decodeTx(n1).fields.common.direction, localDirection ^ 1)
  t.is(decodeTx(n2).fields.common.direction, localDirection ^ 1)

  // Receive 1 before 0 (gap)
  t.is(lanes.receive(peerPacket(1n, n1)), true)
  t.is(state.delivers.length, 0)
  t.is(state.admits.length, 1)

  // Receive 0 → promotes 0 then 1
  t.is(lanes.receive(peerPacket(0n, n0)), true)
  t.is(state.delivers.length, 2)
  t.is(state.delivers[0].sequence, 0n)
  t.is(state.delivers[1].sequence, 1n)

  // Receive 2
  t.is(lanes.receive(peerPacket(2n, n2)), true)
  t.is(state.delivers[2].sequence, 2n)

  // Sender side: keep DATA0 lost while bitmap ACKs free slots up to the remote horizon.
  state.transmits.length = 0
  for (let sequence = 0; sequence < DATA_SEND_SLOTS; sequence++) {
    const sent = lanes.trySend(
      makeDataNested({ routeId: rid, position: BigInt(sequence) * 8n })
    )
    t.alike(sent, { lane: LANE_DATA, sequence: BigInt(sequence) })
  }
  t.is(packetsOnly(state.transmits).length, DATA_SEND_SLOTS)

  const firstBitmap = ((1n << BigInt(DATA_SEND_SLOTS)) - 1n) & ~1n
  t.is(lanes.receive(peerAck({ routeId: rid, dataBitmap: firstBitmap, ackSnapshot: 1 })), true)
  t.is(state.acked.length, DATA_SEND_SLOTS - 1)
  await Promise.resolve()

  const secondBatchEnd = DATA_SEND_SLOTS * 2 - 2
  for (let sequence = DATA_SEND_SLOTS; sequence <= secondBatchEnd; sequence++) {
    const sent = lanes.trySend(
      makeDataNested({ routeId: rid, position: BigInt(sequence) * 8n })
    )
    t.is(sent.sequence, BigInt(sequence))
  }

  const secondBitmap = ((1n << BigInt(secondBatchEnd + 1)) - 1n) & ~1n
  t.is(lanes.receive(peerAck({ routeId: rid, dataBitmap: secondBitmap, ackSnapshot: 2 })), true)
  t.is(state.acked.length, 2 * (DATA_SEND_SLOTS - 1))
  await Promise.resolve()

  for (let sequence = secondBatchEnd + 1; sequence < DATA_REORDER; sequence++) {
    const sent = lanes.trySend(
      makeDataNested({ routeId: rid, position: BigInt(sequence) * 8n })
    )
    t.is(sent.sequence, BigInt(sequence))
  }

  // Selective releases cannot authorize sequence64 while cumulative remains empty at DATA0.
  t.is(lanes.trySend(makeDataNested({ routeId: rid, position: BigInt(DATA_REORDER) * 8n })), null)
  t.is(lanes.isCumulativelyAcknowledged(LANE_DATA, 0n), false)
  t.is(state.failures.length, 0)

  lanes.destroy()
})

test('changed wrapper at same sequence cannot allocate or reset allowance', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  const n1 = makeInboundDataNested({ routeId: rid, bytes: b4a.alloc(8, 1) })
  const n2 = makeInboundDataNested({ routeId: rid, bytes: b4a.alloc(8, 2) })

  function pkt(nested) {
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: 0n,
      nestedLength: nested.byteLength,
      flags: 0,
      completeNestedObject: nested
    })
  }

  t.is(lanes.receive(pkt(n1)), true)
  t.is(state.admits.length, 1)
  t.is(state.delivers.length, 1)

  // same sequence, different bytes after delivery (history path)
  t.is(lanes.receive(pkt(n2)), false)
  t.is(state.conflicts.length, 1)
  t.is(state.conflicts[0].sequence, 0n)
  t.is(state.admits.length, 1)

  lanes.destroy()
})

test('exact duplicate up to 8 arrivals; ninth drops; history-old silent', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  const nested = makeInboundDataNested({ routeId: rid })
  const pkt = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
    routeId: rid,
    laneSequence: 0n,
    nestedLength: nested.byteLength,
    flags: 0,
    completeNestedObject: nested
  })

  t.is(lanes.receive(pkt), true)
  // arrivals 2..8 exact duplicates after delivery
  for (let i = 2; i <= MAX_ATTEMPTS; i++) {
    t.is(lanes.receive(pkt), true, 'dup ' + i)
  }
  // ninth
  t.is(lanes.receive(pkt), false)
  t.is(acksOnly(state.transmits).length, MAX_ATTEMPTS)

  // Build 64 more contiguous to push history (old identity silent)
  for (let s = 1n; s <= 64n; s++) {
    const n = makeInboundDataNested({ routeId: rid, position: s * 8n })
    const p = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: s,
      nestedLength: n.byteLength,
      flags: 0,
      completeNestedObject: n
    })
    t.is(lanes.receive(p), true, 'hist fill ' + s)
  }
  // sequence 0 is older than history window → silent ignore
  const ackCountBeforeOld = acksOnly(state.transmits).length
  t.is(lanes.receive(pkt), false)
  t.is(acksOnly(state.transmits).length, ackCountBeforeOld)
  t.is(state.conflicts.length, 0)

  lanes.destroy()
})

test('forged future ACK releases nothing atomically', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  const nested = makeDataNested({ routeId: rid })
  lanes.trySend(nested)
  t.is(state.acked.length, 0)

  const forged = peerAck({
    routeId: rid,
    dataCumulative: 5n, // never issued
    ackSnapshot: 1
  })
  t.is(lanes.receive(forged), false)
  t.is(state.acked.length, 0)
  t.ok(state.failures.length >= 1)
})

test('bitmap rebasing drop and cumulative regression rejected', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  // issue seq 0,1
  lanes.trySend(makeDataNested({ routeId: rid }))
  lanes.trySend(makeDataNested({ routeId: rid, position: 8n }))

  // ACK cum=0
  t.is(
    lanes.receive(
      peerAck({ routeId: rid, dataCumulative: 0n, dataBitmap: 0n, ackSnapshot: 1 })
    ),
    true
  )
  t.is(state.acked.length, 1)

  // regression cum
  t.is(
    lanes.receive(
      peerAck({ routeId: rid, dataCumulative: MAX_U64, dataBitmap: 0n, ackSnapshot: 2 })
    ),
    false
  )
  t.ok(state.failures.length >= 1)
})

test('control cumulative OPEN barrier helper and independent CONTROL progress', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  const open = makeOpenNested({ routeId: rid })
  const sent = lanes.trySend(open)
  t.is(sent.lane, LANE_CONTROL)
  t.is(sent.sequence, 0n)

  // bitmap-only does not satisfy cumulative OPEN barrier
  t.is(
    lanes.receive(
      peerAck({
        routeId: rid,
        controlBitmap: 1n,
        ackSnapshot: 1
      })
    ),
    true
  )
  t.is(lanes.isCumulativelyAcknowledged(LANE_CONTROL, 0n), false)
  t.is(state.acked.length, 1)
  t.is(state.acked[0].cumulativeCovered, false)
  t.is(state.writables, 1)

  // cumulative covers OPEN
  t.is(
    lanes.receive(
      peerAck({
        routeId: rid,
        controlCumulative: 0n,
        ackSnapshot: 2
      })
    ),
    true
  )
  t.is(lanes.isCumulativelyAcknowledged(LANE_CONTROL, 0n), true)
  t.is(state.acked.length, 1)
  t.is(state.writables, 2)

  lanes.destroy()
})

test('purpose3 exclusive registration control slot', async (t) => {
  const { lanes, state, routeId: rid } = createLanes({ purpose: 3 })

  // Fill seven non-registration control slots with reciprocal application CREDIT.
  for (let i = 0; i < 7; i++) {
    const credit = makeCreditNested({
      routeId: rid,
      streamId: BigInt(2 + i * 2),
      direction: 1
    })
    const r = lanes.trySend(credit)
    t.ok(r, 'control slot ' + i)
  }
  // 8th non-reg should backpressure (exclusive reserved)
  t.is(
    lanes.trySend(makeCreditNested({ routeId: rid, streamId: 100n, direction: 1 })),
    null
  )

  // Registration stream1 OPEN can still use its exclusive slot.
  const reg = makeRegistrationOpenNested({ routeId: rid })
  const regSend = lanes.trySend(reg)
  t.ok(regSend)
  t.is(regSend.lane, LANE_CONTROL)

  // cannot release while in flight
  expectCode(t, () => lanes.releaseRegistrationControlReservation(), 'INVALID_ROUTE')

  // ACK registration
  lanes.receive(
    peerAck({
      routeId: rid,
      controlCumulative: 7n,
      ackSnapshot: 1
    })
  )
  await Promise.resolve()

  // After free, release reservation
  // Seven non-registration CREDITs are sequences0..6; registration OPEN is sequence7.
  lanes.releaseRegistrationControlReservation()
  t.ok(lanes.trySend(makeCreditNested({ routeId: rid, streamId: 102n, direction: 1 })))

  lanes.destroy()

  // Purpose3 stream1 HANDSHAKE has the same registration-slot identity and CONTROL lane.
  const handshake = createLanes({ purpose: 3 })
  const handshakeSend = handshake.lanes.trySend(
    makeRegHandshakeNested({ routeId: handshake.routeId })
  )
  t.alike(handshakeSend, { lane: LANE_CONTROL, sequence: 0n })
  handshake.lanes.destroy()
})

test('application HANDSHAKE uses DATA lane', (t) => {
  const { lanes, routeId: rid } = createLanes({ purpose: 2 })
  const hs = makeAppHandshakeNested({ routeId: rid, streamId: 3n })
  const r = lanes.trySend(hs)
  t.is(r.lane, LANE_DATA)
  lanes.destroy()
})

test('maximum sequence assignment closes before UINT64_MAX', (t) => {
  // Directly poke internal nextSeq near max via many sends is impractical;
  // validate destroy on counter exhaustion through horizon interaction instead.
  const { lanes, state, routeId: rid } = createLanes()
  // Force nextSeq near max
  lanes._nextSeq[LANE_DATA] = MAX_U64
  t.is(lanes.trySend(makeDataNested({ routeId: rid })), null)
  t.ok(state.failures.length >= 1)
})

test('ACK snapshot closes before UINT32 wrap and stops revoked delivery', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  lanes._ackSnapshotOut = MAX_ACK_SNAPSHOT
  const nested = makeInboundDataNested({ routeId: rid })
  const packet = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
    routeId: rid,
    laneSequence: 0n,
    nestedLength: nested.byteLength,
    flags: 0,
    completeNestedObject: nested
  })

  t.is(lanes.receive(packet), false)
  t.is(state.admits.length, 1)
  t.is(state.delivers.length, 0)
  t.is(acksOnly(state.transmits).length, 0)
  t.is(state.failures.length, 1)
  t.is(state.failures[0].code, 'COUNTER_EXHAUSTED')
})

test('timer callback after destroy does not revive state', (t) => {
  const copies = []
  const { lanes, state, clock: c, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      copies.push(b4a.from(buf))
      return Promise.resolve(true)
    }
  })
  lanes.trySend(makeDataNested({ routeId: rid }))
  const before = copies.length
  lanes.destroy()
  t.is(c.fireCancelled(), 1)
  t.is(copies.length, before)
  t.is(state.failures.length, 1)
})

test('failed native callback remains attempt-spent and retries original bytes', async (t) => {
  let failOnce = true
  const copies = []
  const { lanes, clock: c, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      copies.push(b4a.from(buf))
      if (failOnce) {
        failOnce = false
        return Promise.reject(new Error('native fail'))
      }
      return Promise.resolve(true)
    }
  })
  lanes.trySend(makeDataNested({ routeId: rid }))
  t.is(copies.length, 1)
  await Promise.resolve()
  c.advance(RTO_MS)
  await Promise.resolve()
  t.is(copies.length, 2)
  t.ok(b4a.equals(copies[0], copies[1]))
  lanes.destroy()
})

test('reorder-to-ready backpressure stays inside fixed capacity', (t) => {
  const { lanes, state, routeId: rid } = createLanes({ autoDeliver: false })
  const admitted = DATA_READY + MAX_ATTEMPTS

  function pkt(seq) {
    const n = makeInboundDataNested({ routeId: rid, position: seq * 8n })
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: seq,
      nestedLength: n.byteLength,
      flags: 0,
      completeNestedObject: n
    })
  }

  // Fill every ready row, then retain more admitted wrappers in the reorder arena.
  for (let s = 0n; s < BigInt(admitted); s++) {
    t.is(lanes.receive(pkt(s)), true, 'bp fill ' + s)
  }
  t.is(state.admits.length, admitted)
  t.is(state.delivers.length, DATA_READY)
  const acknowledgementsBeforeDrain = acksOnly(state.transmits).length
  t.ok(acknowledgementsBeforeDrain <= admitted)

  // One owned drain consumes ready rows and promotes every retained reorder row in order.
  state.autoDeliver = true
  lanes.drain()
  const drained = state.delivers.slice(-admitted)
  t.is(drained.length, admitted)
  for (let sequence = 0; sequence < admitted; sequence++) {
    t.is(drained[sequence].sequence, BigInt(sequence), 'drain ' + sequence)
  }
  t.is(state.admits.length, admitted)
  t.is(acksOnly(state.transmits).length, acknowledgementsBeforeDrain)

  lanes.destroy()
})

test('ready plus reorder capacity rejects the first unowned DATA wrapper', (t) => {
  const { lanes, state, routeId: rid } = createLanes({ autoDeliver: false })
  const fixedReceiveRows = DATA_READY + DATA_REORDER

  function pkt(sequence) {
    const nested = makeInboundDataNested({ routeId: rid, position: sequence * 8n })
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: sequence,
      nestedLength: nested.byteLength,
      flags: 0,
      completeNestedObject: nested
    })
  }

  for (let sequence = 0n; sequence < BigInt(fixedReceiveRows); sequence++) {
    t.is(lanes.receive(pkt(sequence)), true, 'fixed row ' + sequence)
  }
  t.is(state.admits.length, fixedReceiveRows)
  t.is(state.delivers.length, DATA_READY)
  const acknowledgementsAtCapacity = acksOnly(state.transmits).length
  t.ok(acknowledgementsAtCapacity <= fixedReceiveRows)

  const outside = BigInt(fixedReceiveRows)
  t.is(lanes.receive(pkt(outside)), false)
  t.is(state.admits.length, fixedReceiveRows)
  t.is(acksOnly(state.transmits).length, acknowledgementsAtCapacity)
  t.is(state.failures.length, 1)
  t.is(state.failures[0].code, 'INVALID_ROUTE')
})

test('constructor rejects missing owned callbacks', (t) => {
  expectCode(
    t,
    () =>
      new PeerReliableLanes({
        routeId: routeId(),
        generation: 1n,
        purpose: 1,
        localDirection: 0,
        clockIdentity: {},
        monotonicNow: () => 0n,
        schedule: () => () => {},
        localDeadline: 1n
        // missing callbacks
      }),
    'INVALID_ROUTE'
  )
})

test('destroy is idempotent and onFailure once', (t) => {
  const { lanes, state } = createLanes()
  lanes.destroy(PrivateRouteError.INVALID_ROUTE())
  t.is(state.failures.length, 1)
  lanes.destroy(PrivateRouteError.INVALID_ROUTE())
  t.is(state.failures.length, 1)
})

test('slot limits enforce DATA 24 and CONTROL 8 backpressure', (t) => {
  const { lanes, routeId: rid } = createLanes()
  for (let i = 0; i < DATA_SEND_SLOTS; i++) {
    t.ok(lanes.trySend(makeDataNested({ routeId: rid, position: BigInt(i) * 8n })))
  }
  t.is(lanes.trySend(makeDataNested({ routeId: rid, position: 9999n })), null)

  for (let i = 0; i < CTRL_SEND_SLOTS; i++) {
    t.ok(
      lanes.trySend(
        makeOpenNested({ routeId: rid, streamId: BigInt(3 + i * 2) })
      )
    )
  }
  t.is(lanes.trySend(makeOpenNested({ routeId: rid, streamId: 201n })), null)
  lanes.destroy()
})

test('ACK snapshot exact repeat is idempotent', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  lanes.trySend(makeDataNested({ routeId: rid }))
  const ack = peerAck({ routeId: rid, dataCumulative: 0n, ackSnapshot: 1 })
  t.is(lanes.receive(ack), true)
  t.is(state.acked.length, 1)
  t.is(lanes.receive(b4a.from(ack)), true)
  t.is(state.acked.length, 1)
  lanes.destroy()
})

test('changed bytes under the same ACK snapshot release no later slot', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  lanes.trySend(makeDataNested({ routeId: rid, position: 0n }))
  lanes.trySend(makeDataNested({ routeId: rid, position: 8n }))

  t.is(lanes.receive(peerAck({ routeId: rid, dataBitmap: 1n, ackSnapshot: 1 })), true)
  t.is(state.acked.length, 1)
  t.is(state.acked[0].sequence, 0n)

  // Both bodies name only issued sequences, isolating changed same-snapshot identity.
  t.is(lanes.receive(peerAck({ routeId: rid, dataBitmap: 3n, ackSnapshot: 1 })), false)
  t.is(state.acked.length, 1)
  t.is(state.failures.length, 1)
  t.is(state.failures[0].code, 'INVALID_ROUTE')
})

test('sentinel ackSnapshot 0 does not enter normal ARQ', (t) => {
  const { lanes, state, routeId: rid } = createLanes()
  lanes.trySend(makeDataNested({ routeId: rid }))
  const sentinel = peerAck({
    routeId: rid,
    dataCumulative: MAX_U64,
    dataBitmap: 0n,
    controlCumulative: MAX_U64,
    controlBitmap: 0n,
    ackSnapshot: 0
  })
  t.is(lanes.receive(sentinel), false)
  t.is(state.acked.length, 0)
  lanes.destroy()
})

function writeU16BE(buf, value, offset) {
  buf[offset] = (value >>> 8) & 0xff
  buf[offset + 1] = value & 0xff
}

function writeU32BE(buf, value, offset) {
  buf[offset] = (value >>> 24) & 0xff
  buf[offset + 1] = (value >>> 16) & 0xff
  buf[offset + 2] = (value >>> 8) & 0xff
  buf[offset + 3] = value & 0xff
}

function writeU64BE(buf, value, offset) {
  let v = value
  for (let i = offset + 7; i >= offset; i--) {
    buf[i] = Number(v & 0xffn)
    v >>= 8n
  }
}

/** Outer reliable packet with arbitrary nested bytes (bypasses nested schema). */
function outerReliablePacket({ routeId, sequence, flags = 0, nested }) {
  const nestedLen = nested.byteLength
  const body = b4a.alloc(28 + nestedLen)
  b4a.copy(routeId, body, 0, 0, 16)
  writeU64BE(body, sequence, 16)
  writeU16BE(body, nestedLen, 24)
  writeU16BE(body, flags, 26)
  b4a.copy(nested, body, 28)
  const wire = b4a.alloc(8 + body.byteLength)
  writeU32BE(wire, 2, 0) // PEER_PROTOCOL_VERSION
  writeU16BE(wire, PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, 4)
  writeU16BE(wire, body.byteLength, 6)
  b4a.copy(body, wire, 8)
  return wire
}

test('malformed nested on older history identity is silent without ACK or failure', (t) => {
  const { lanes, state, routeId: rid } = createLanes()

  // Deliver seq 0..64 so history drops 0 as older
  for (let s = 0n; s <= 64n; s++) {
    const n = makeInboundDataNested({ routeId: rid, position: s * 8n })
    const p = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: s,
      nestedLength: n.byteLength,
      flags: 0,
      completeNestedObject: n
    })
    t.is(lanes.receive(p), true, 'history build seq ' + s)
  }
  const failuresBefore = state.failures.length
  const acksBefore = acksOnly(state.transmits).length

  // Older seq 0 with garbage nested — must not parse nested / fail route
  const garbage = b4a.alloc(32, 0xee)
  const malformedOld = outerReliablePacket({
    routeId: rid,
    sequence: 0n,
    flags: 0,
    nested: garbage
  })
  t.is(lanes.receive(malformedOld), false)
  t.is(state.failures.length, failuresBefore)
  t.is(acksOnly(state.transmits).length, acksBefore)
  lanes.destroy()
})

test('new identity nested routeId or direction mismatch fails the route', (t) => {
  const { lanes, state, routeId: rid } = createLanes({ localDirection: 0 })

  // Wrong nested common.routeId — outer helper bypasses encode-time matchCommonRouteId
  const badRouteNested = makeDataNested({ routeId: routeId(0x22), direction: 1 })
  const pkt1 = outerReliablePacket({
    routeId: rid,
    sequence: 0n,
    flags: 0,
    nested: badRouteNested
  })
  t.is(lanes.receive(pkt1), false)
  t.ok(state.failures.length >= 1)
  t.is(state.admits.length, 0)

  // Fresh lanes for direction mismatch
  const again = createLanes({ localDirection: 0 })
  // Receive outer dir = localDirection^1 = 1; nested DATA with direction 0 mismatches
  const badDirNested = makeDataNested({ routeId: again.routeId, direction: 0 })
  const pkt2 = outerReliablePacket({
    routeId: again.routeId,
    sequence: 0n,
    flags: 0,
    nested: badDirNested
  })
  t.is(again.lanes.receive(pkt2), false)
  t.ok(again.state.failures.length >= 1)
  t.is(again.state.admits.length, 0)
  again.lanes.destroy()
})

test('new identity rejects nested message IDs outside stream set', (t) => {
  const { lanes, state, routeId: rid } = createLanes({ localDirection: 0 })

  // Nest a reliable-ACK object (valid peer object, not a stream nested type).
  const ackNested = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_ACK_V2, {
    routeId: rid,
    generation: 7n,
    dataCumulative: MAX_U64,
    dataBitmap: 0n,
    controlCumulative: MAX_U64,
    controlBitmap: 0n,
    ackSnapshot: 1,
    reservedZero: 0
  })
  const pkt = outerReliablePacket({
    routeId: rid,
    sequence: 0n,
    flags: 0,
    nested: ackNested
  })
  t.is(lanes.receive(pkt), false)
  t.ok(state.failures.length >= 1)
  t.is(state.admits.length, 0)
  t.is(state.delivers.length, 0)
  lanes.destroy()
})

test('RTO reaches eight attempts and two-second deadline while native Promise never resolves', (t) => {
  const copies = []
  const { lanes, state, clock: c, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      copies.push(b4a.from(buf))
      // Never settles — RTO must still fire from attempt start.
      return new Promise(() => {})
    }
  })
  lanes.trySend(makeDataNested({ routeId: rid }))
  t.is(copies.length, 1)
  for (let attempt = 2; attempt <= MAX_ATTEMPTS; attempt++) {
    c.advance(RTO_MS)
    t.is(copies.length, attempt, 'attempt ' + attempt)
    t.ok(b4a.equals(copies[0], copies[attempt - 1]))
  }
  t.is(state.failures.length, 0)
  c.advance(RTO_MS)
  t.is(copies.length, MAX_ATTEMPTS)
  t.is(state.failures.length, 1)
  t.is(state.failures[0].code, 'CIRCUIT_LIMIT')
})

test('slow native settlement after newer attempt is inert', async (t) => {
  const resolvers = []
  const copies = []
  const { lanes, clock: c, routeId: rid, state } = createLanes({
    transmitImpl: (buf) => {
      copies.push(b4a.from(buf))
      return new Promise((resolve) => {
        resolvers.push(resolve)
      })
    }
  })
  lanes.trySend(makeDataNested({ routeId: rid }))
  t.is(copies.length, 1)
  t.is(resolvers.length, 1)
  c.advance(RTO_MS)
  t.is(copies.length, 2)
  t.is(resolvers.length, 2)
  // Late settlement of attempt 1 must not suppress attempt 2's RTO or double-arm.
  resolvers[0](true)
  await Promise.resolve()
  c.advance(RTO_MS)
  t.is(copies.length, 3)
  t.is(state.failures.length, 0)
  lanes.destroy()
})

test('late settlement and cancelled timer after slot reuse are inert', async (t) => {
  const copies = []
  const resolvers = []
  const { lanes, state, clock: c, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      copies.push(b4a.from(buf))
      return new Promise((resolve) => {
        resolvers.push(resolve)
      })
    }
  })

  const first = lanes.trySend(makeDataNested({ routeId: rid, position: 0n }))
  t.alike(first, { lane: LANE_DATA, sequence: 0n })
  t.is(
    lanes.receive(peerAck({ routeId: rid, dataCumulative: 0n, ackSnapshot: 1 })),
    true
  )

  const second = lanes.trySend(makeDataNested({ routeId: rid, position: 8n }))
  t.alike(second, { lane: LANE_DATA, sequence: 1n })
  t.is(copies.length, 2)

  // Invoke the cancelled sequence-0 timer anyway; reused slot/sequence-1 state must survive.
  t.is(c.fireCancelled(), 1)
  t.is(copies.length, 2)
  t.is(state.failures.length, 0)

  // Settle sequence 0 after its slot has been reused, then let sequence 1's own RTO fire.
  resolvers[0](true)
  await Promise.resolve()
  c.advance(RTO_MS)
  t.is(copies.length, 3)
  t.is(decodeTx(copies[0]).fields.laneSequence, 0n)
  t.is(decodeTx(copies[1]).fields.laneSequence, 1n)
  t.is(decodeTx(copies[2]).fields.laneSequence, 1n)
  t.is(state.failures.length, 0)
  lanes.destroy()
})

test('late native settlement after destroy does not revive or pin state', async (t) => {
  let resolveNative = null
  let borrowedBuf = null
  const { lanes, state, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      borrowedBuf = buf
      const copy = b4a.from(buf)
      state.transmits.push(copy)
      return new Promise((resolve) => {
        resolveNative = resolve
      })
    }
  })
  lanes.trySend(makeDataNested({ routeId: rid }))
  t.ok(resolveNative)
  t.ok(borrowedBuf)
  const originalBytes = b4a.from(borrowedBuf)
  const before = state.transmits.length
  lanes.destroy()
  t.is(state.failures.length, 1)
  t.is(state.failures[0].code, 'ERR_DESTROYED')
  // While native send promise is pending, borrowed bytes must not be zeroed by destroy
  t.alike(borrowedBuf, originalBytes)
  resolveNative(true)
  await Promise.resolve()
  // Once native send promise settles, borrowed bytes are safely cleared
  t.alike(borrowedBuf, b4a.alloc(borrowedBuf.byteLength))
  t.is(state.transmits.length, before)
  t.is(state.failures.length, 1)
  // Second destroy remains idempotent after late settlement.
  lanes.destroy()
  t.is(state.failures.length, 1)
})

test('slot quarantine on ACK while send Promise is pending avoids mutating borrowed bytes', async (t) => {
  let resolveFirst = null
  let firstBuf = null
  const { lanes, state, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      const copy = b4a.from(buf)
      state.transmits.push(copy)
      if (!resolveFirst) {
        firstBuf = buf
        return new Promise((resolve) => {
          resolveFirst = resolve
        })
      }
      return Promise.resolve(true)
    }
  })

  const s0 = lanes.trySend(makeDataNested({ routeId: rid, position: 0n }))
  t.alike(s0, { lane: LANE_DATA, sequence: 0n })
  t.ok(firstBuf)
  const originalBytes = b4a.from(firstBuf)

  // ACK sequence 0 while its native send Promise is still pending
  t.is(lanes.receive(peerAck({ routeId: rid, dataCumulative: 0n, ackSnapshot: 1 })), true)
  t.is(state.acked.length, 1)

  // Slot 0 is logically released (ACKed), but its buffer must not be zeroed or reused yet
  t.alike(firstBuf, originalBytes)

  // Sending sequence 1 must not reuse slot 0 while its borrow is pending; it allocates slot 1
  const s1 = lanes.trySend(makeDataNested({ routeId: rid, position: 8n }))
  t.alike(s1, { lane: LANE_DATA, sequence: 1n })
  // firstBuf must remain untouched
  t.alike(firstBuf, originalBytes)

  // Settling the first send clears slot 0 and lifts its quarantine
  resolveFirst(true)
  await Promise.resolve()
  t.alike(firstBuf, b4a.alloc(firstBuf.byteLength))

  lanes.destroy()
})

test('native thenable access cannot escape or strand sender capacity', (t) => {
  for (const throwsOnRead of [true, false]) {
    let reads = 0
    let receiverPreserved = true
    let lastSent = null
    const { lanes, routeId: rid } = createLanes({
      transmitImpl() {
        const result = {
          get then() {
            reads++
            if (throwsOnRead) throw new Error('native then getter failed')
            return function (resolve, reject) {
              receiverPreserved = receiverPreserved && this === result
              resolve(true)
              reject(new Error('duplicate settlement'))
              throw new Error('throw after settlement')
            }
          }
        }
        return result
      }
    })
    try {
      for (let i = 0; i <= DATA_SEND_SLOTS; i++) {
        let sent
        try {
          sent = lanes.trySend(makeDataNested({ routeId: rid, position: BigInt(i * 8) }))
        } catch (error) {
          t.fail('native then getter escaped: ' + error.message)
          break
        }
        lastSent = sent
        if (!sent) break
        lanes.receive(peerAck({ routeId: rid, dataCumulative: BigInt(i), ackSnapshot: i + 1 }))
      }
      t.alike(lastSent, { lane: LANE_DATA, sequence: BigInt(DATA_SEND_SLOTS) },
        'ACKed capacity is reusable beyond the complete sender window')
      if (!throwsOnRead) t.ok(receiverPreserved, 'then receiver is preserved')
      t.is(reads, DATA_SEND_SLOTS + 1, 'each native result is inspected exactly once')
    } finally {
      lanes.destroy()
    }
  }
})

test('ACK newer snapshot while previous native Promise pending', async (t) => {
  const ackResolvers = []
  const ackSnapshots = []
  const { lanes, state, routeId: rid } = createLanes({
    transmitImpl: (buf) => {
      const copy = b4a.from(buf)
      state.transmits.push(copy)
      if (isAck(copy)) {
        const decoded = decodeTx(copy)
        ackSnapshots.push(decoded.fields.ackSnapshot)
        return new Promise((resolve) => {
          ackResolvers.push(resolve)
        })
      }
      return Promise.resolve(true)
    }
  })

  function peerPacket(seq, nested) {
    return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
      routeId: rid,
      laneSequence: seq,
      nestedLength: nested.byteLength,
      flags: 0,
      completeNestedObject: nested
    })
  }

  // Gap admit seq1 → immediate ACK snapshot 1, leave Promise pending.
  const n1 = makeInboundDataNested({ routeId: rid, position: 8n })
  t.is(lanes.receive(peerPacket(1n, n1)), true)
  t.is(ackSnapshots.length, 1)
  t.is(ackSnapshots[0], 1)
  t.is(ackResolvers.length, 1)

  // Contiguous seq0 while ACK1 still pending → must emit newer snapshot 2, not drop.
  const n0 = makeInboundDataNested({ routeId: rid, position: 0n })
  t.is(lanes.receive(peerPacket(0n, n0)), true)
  t.is(ackSnapshots.length, 2)
  t.is(ackSnapshots[1], 2)
  t.is(state.delivers.length, 2)

  // Settling the older ACK Promise must not clear or block newer state.
  ackResolvers[0](true)
  await Promise.resolve()
  t.is(ackSnapshots.length, 2)
  t.is(state.failures.length, 0)
  ackResolvers[1](true)
  await Promise.resolve()
  t.is(ackSnapshots.length, 2)
  lanes.destroy()
})

test('ACK transmission serializes synchronous receive reentrancy without an ACK train', (t) => {
  const rid = routeId()
  const ackSnapshots = []
  const transmitted = []
  let lanesRef = null
  let reentered = false
  let transmitDepth = 0
  let maximumTransmitDepth = 0

  const nested0 = makeInboundDataNested({ routeId: rid, position: 0n })
  const nested1 = makeInboundDataNested({ routeId: rid, position: 8n })
  const packet0 = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
    routeId: rid,
    laneSequence: 0n,
    nestedLength: nested0.byteLength,
    flags: 0,
    completeNestedObject: nested0
  })
  const packet1 = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
    routeId: rid,
    laneSequence: 1n,
    nestedLength: nested1.byteLength,
    flags: 0,
    completeNestedObject: nested1
  })

  const created = createLanes({
    routeId: rid,
    transmitImpl: (buf) => {
      const copy = b4a.from(buf)
      transmitted.push(copy)
      if (!isAck(copy)) return Promise.resolve(true)

      transmitDepth++
      if (transmitDepth > maximumTransmitDepth) maximumTransmitDepth = transmitDepth
      ackSnapshots.push(decodeTx(copy).fields.ackSnapshot)
      if (!reentered) {
        reentered = true
        t.is(lanesRef.receive(packet0), true)
      }
      transmitDepth--
      return new Promise(() => {})
    }
  })
  lanesRef = created.lanes

  t.is(lanesRef.receive(packet1), true)
  t.alike(ackSnapshots, [1, 2])
  t.is(created.state.admits.length, 2)
  t.is(created.state.delivers.length, 2)
  t.is(transmitted.length, 2)
  t.is(maximumTransmitDepth, 1)
  created.clock.advance(RTO_MS)
  t.alike(ackSnapshots, [1, 2])
  lanesRef.destroy()
})

test('OPENED and CREDIT direction rules both localDirections send and receive', (t) => {
  for (const localDirection of [0, 1]) {
    const outboundReplyDir = localDirection ^ 1
    const inboundTravelDir = localDirection ^ 1

    // --- send OPENED/CREDIT: common.direction names saved/granted dir = peer's = local^1
    {
      const { lanes, state, routeId: rid } = createLanes({ localDirection })
      const opened = makeOpenedNested({ routeId: rid, direction: outboundReplyDir })
      const credit = makeCreditNested({ routeId: rid, direction: outboundReplyDir })
      const o = lanes.trySend(opened)
      const c = lanes.trySend(credit)
      t.ok(o, 'opened send ld=' + localDirection)
      t.ok(c, 'credit send ld=' + localDirection)
      t.is(o.lane, LANE_CONTROL)
      t.is(c.lane, LANE_CONTROL)
      const sentPackets = packetsOnly(state.transmits)
      t.is(sentPackets.length, 2)
      t.is(
        decodeTx(decodeTx(sentPackets[0]).fields.completeNestedObject).fields.common.direction,
        outboundReplyDir
      )
      t.is(
        decodeTx(decodeTx(sentPackets[1]).fields.completeNestedObject).fields.common.direction,
        outboundReplyDir
      )

      // Wrong named direction on either reciprocal outbound object must reject.
      expectCode(
        t,
        () => lanes.trySend(makeOpenedNested({ routeId: rid, direction: localDirection })),
        'INVALID_ROUTE'
      )
      expectCode(
        t,
        () => lanes.trySend(makeCreditNested({ routeId: rid, direction: localDirection })),
        'INVALID_ROUTE'
      )
      lanes.destroy()
    }

    // --- receive OPENED/CREDIT: common.direction equals localDirection (named dir)
    {
      const { lanes, state, routeId: rid } = createLanes({ localDirection })
      function ctrlPkt(seq, nested) {
        return encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
          routeId: rid,
          laneSequence: seq,
          nestedLength: nested.byteLength,
          flags: FLAG_CONTROL,
          completeNestedObject: nested
        })
      }
      const openedIn = makeOpenedNested({ routeId: rid, direction: localDirection })
      const creditIn = makeCreditNested({ routeId: rid, direction: localDirection })
      t.is(decodeTx(openedIn).fields.common.direction, localDirection)
      t.is(decodeTx(creditIn).fields.common.direction, localDirection)
      t.is(lanes.receive(ctrlPkt(0n, openedIn)), true, 'opened recv ld=' + localDirection)
      t.is(lanes.receive(ctrlPkt(1n, creditIn)), true, 'credit recv ld=' + localDirection)
      t.is(state.admits.length, 2)
      t.is(state.delivers.length, 2)
      t.is(state.failures.length, 0)

      // Ordinary DATA inbound still uses travel direction = local^1
      const data = createLanes({ localDirection })
      const n = makeInboundDataNested({
        routeId: data.routeId,
        localDirection,
        direction: inboundTravelDir
      })
      const dp = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
        routeId: data.routeId,
        laneSequence: 0n,
        nestedLength: n.byteLength,
        flags: 0,
        completeNestedObject: n
      })
      t.is(data.lanes.receive(dp), true, 'data recv ld=' + localDirection)
      t.is(data.state.failures.length, 0)

      // OPENED with wrong nested direction (travel dir instead of local) fails route
      const bad = createLanes({ localDirection })
      const badOpened = makeOpenedNested({
        routeId: bad.routeId,
        direction: inboundTravelDir
      })
      const badPkt = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
        routeId: bad.routeId,
        laneSequence: 0n,
        nestedLength: badOpened.byteLength,
        flags: FLAG_CONTROL,
        completeNestedObject: badOpened
      })
      t.is(bad.lanes.receive(badPkt), false, 'bad opened dir ld=' + localDirection)
      t.ok(bad.state.failures.length >= 1)
      t.is(bad.state.admits.length, 0)

      lanes.destroy()
      data.lanes.destroy()
      bad.lanes.destroy()
    }
  }
})

test('outbound OPEN DATA HANDSHAKE use localDirection; inbound use localDirection^1', (t) => {
  for (const localDirection of [0, 1]) {
    const { lanes, state, routeId: rid } = createLanes({ localDirection })
    t.ok(lanes.trySend(makeDataNested({ routeId: rid, direction: localDirection })))
    t.ok(lanes.trySend(makeOpenNested({ routeId: rid, direction: localDirection })))
    t.ok(
      lanes.trySend(makeAppHandshakeNested({ routeId: rid, direction: localDirection, streamId: 3n }))
    )
    expectCode(
      t,
      () => lanes.trySend(makeDataNested({ routeId: rid, direction: localDirection ^ 1 })),
      'INVALID_ROUTE'
    )
    t.is(packetsOnly(state.transmits).length, 3)

    const peer = createLanes({ localDirection })
    const inbound = localDirection ^ 1
    const inboundObjects = [
      {
        sequence: 0n,
        flags: 0,
        nested: makeInboundDataNested({ routeId: peer.routeId, localDirection })
      },
      {
        sequence: 0n,
        flags: FLAG_CONTROL,
        nested: makeOpenNested({ routeId: peer.routeId, direction: inbound })
      },
      {
        sequence: 1n,
        flags: 0,
        nested: makeAppHandshakeNested({
          routeId: peer.routeId,
          direction: inbound,
          flight: 2,
          streamId: 3n
        })
      }
    ]
    for (const item of inboundObjects) {
      t.is(decodeTx(item.nested).fields.common.direction, inbound)
      const pkt = encodePeerTransport(PEER_MESSAGE_ID.PEER_RELIABLE_PACKET_V2, {
        routeId: peer.routeId,
        laneSequence: item.sequence,
        nestedLength: item.nested.byteLength,
        flags: item.flags,
        completeNestedObject: item.nested
      })
      t.is(peer.lanes.receive(pkt), true)
    }
    t.is(peer.state.admits.length, inboundObjects.length)

    lanes.destroy()
    peer.lanes.destroy()
  }
})
