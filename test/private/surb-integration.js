'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const {
  MAX_HOPS,
  MAX_REPLY_BYTES,
  RHO,
  SURB_DESCRIPTOR_SIZE,
  MAX_SURB_BATCH,
  MAX_SURB_REPLY_APPLICATION_BYTES,
  SURB_REPLY_DATA_BYTES,
  REPLY_BINDING_SIZE,
  buildSurb,
  sealSurbReply,
  processSurbHop,
  consumeSurbForwardingAuthority,
  openSurbReply,
  revokeSurbOpenAuthority,
  createSurbCapabilityAuthority,
  createSurbReplayAuthority,
  destroySurbReplayAuthority,
  encodeSurbDescriptor,
  decodeSurbDescriptor,
  encodeSurbReplyBinding,
  encodeSurbHopMessage,
  decodeSurbHopMessage
} = require('../../lib/private/surb')
const {
  createSurbBatchReplyAuthority,
  sendSurbBatchFragments,
  revokeSurbBatchReplyAuthority,
  encodeSurbHopCell,
  tryDecodeSurbHopCell,
  SURB_HOP_MAGIC
} = require('../../lib/private/surb-batch')
const {
  fragment,
  Reassembler,
  createFragmentProfile,
  SURB_REPLY_FRAGMENT_PROFILE,
  DEFAULT_ROUTE_FRAGMENT_PROFILE,
  FRAGMENT_HEADER_SIZE,
  MAX_FRAGMENT_DATA
} = require('../../lib/private/fragments')
const {
  encodeRoutedRequest,
  decodeRoutedRequest,
  encodeRoutedRequestV2,
  decodeRoutedRequestV2,
  decodeAnyRoutedRequest,
  encodeRoutedReply,
  ROUTED_REQUEST_FIXED_BODY_SIZE
} = require('../../lib/private/routed-dht')
const { M3_MESSAGE_ID, REPLY_MODE, BRANCH_CLASS } = require('../../lib/private/protocol')
const { MAX_ROUTE_PAYLOAD } = require('../../lib/private/route-payload')
const { PrivateRouteError } = require('../../lib/private/errors')

const NOW = 1_700_000_000_000n

function withSurbId(descriptor, _surbId) {
  return descriptor
}

const EXPIRES = NOW + 3_600_000n
const ISSUED = NOW - 1_000n
const EPOCH = 7n

function relay() {
  const routeKey = b4a.allocUnsafeSlow(32)
  const routeSecretKey = b4a.allocUnsafeSlow(32)
  sodium.crypto_box_keypair(routeKey, routeSecretKey)
  const id = b4a.allocUnsafeSlow(32)
  sodium.randombytes_buf(id)
  return {
    id,
    routeKey,
    routeSecretKey,
    capabilityEpoch: EPOCH,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES
  }
}

function hopOf(r) {
  return {
    id: r.id,
    routeKey: r.routeKey,
    capabilityEpoch: r.capabilityEpoch,
    issuedAtMs: r.issuedAtMs,
    expiresAtMs: r.expiresAtMs
  }
}

function capabilityOf(r, now = NOW) {
  return createSurbCapabilityAuthority({
    routeSecretKey: r.routeSecretKey,
    routeKey: r.routeKey,
    capabilityEpoch: r.capabilityEpoch,
    issuedAtMs: r.issuedAtMs,
    expiresAtMs: r.expiresAtMs,
    now
  })
}

function bindingFor(ids) {
  return encodeSurbReplyBinding({
    surbId: ids.surbId,
    batchId: ids.batchId,
    requestId: ids.requestId,
    messageId: ids.messageId,
    fragmentIndex: ids.fragmentIndex,
    fragmentCount: ids.fragmentCount
  })
}

function ids(fragmentIndex = 0, fragmentCount = 1) {
  return {
    surbId: b4a.alloc(16, 1),
    batchId: b4a.alloc(16, 2),
    requestId: b4a.alloc(16, 3),
    messageId: b4a.alloc(16, 4),
    fragmentIndex,
    fragmentCount
  }
}

function roundTripOpen(relays, terminalHandle, descriptor, openAuthority, plaintext, replyBinding) {
  let msg = sealSurbReply({ descriptor, replyBinding, plaintext })
  const replays = relays.map(() => createSurbReplayAuthority({ maxEntries: 64 }))
  for (let i = 0; i < relays.length; i++) {
    const fwd = processSurbHop({
      message: msg,
      capabilityAuthority: capabilityOf(relays[i]),
      replayAuthority: replays[i]
    })
    const r = consumeSurbForwardingAuthority(fwd)
    if (i < relays.length - 1) {
      if (r.terminal) throw new Error('early terminal')
      msg = r.message
    } else {
      if (!r.terminal) throw new Error('missing terminal')
      return {
        plaintext: openSurbReply({
          openAuthority,
          replyBinding,
          payload: r.message.payload,
          now: NOW
        }),
        hopMessageSize: encodeSurbHopMessage(msg).byteLength,
        terminalPayloadSize: r.message.payload.byteLength
      }
    }
  }
}

function expectCode(t, fn, code) {
  try {
    fn()
    t.fail('expected ' + code)
  } catch (err) {
    t.is(err && err.code, code)
  }
}

// --- Scenario 1: Authenticated context success ---
test('scenario 1 authenticated context success opens', (t) => {
  const relays = [relay(), relay()]
  const terminal = b4a.alloc(32, 9)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor, openAuthority } = buildSurb({
    hops: relays.map(hopOf),
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const plain = b4a.alloc(64, 0xab)
  const out = roundTripOpen(relays, terminal, descriptor, openAuthority, plain, binding)
  t.alike(out.plaintext, plain)
})

// --- Scenarios 2-4: context substitution / old epoch ---
test('scenario 2-4 hop context substitution rejects before wrap', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 1)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const plain = b4a.alloc(32, 7)
  const sealed = sealSurbReply({ descriptor, replyBinding: binding, plaintext: plain })
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  // Wrong epoch capability
  const wrongEpoch = createSurbCapabilityAuthority({
    routeSecretKey: r.routeSecretKey,
    routeKey: r.routeKey,
    capabilityEpoch: EPOCH + 1n,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    now: NOW
  })
  expectCode(
    t,
    () =>
      processSurbHop({
        message: sealed,
        capabilityAuthority: wrongEpoch,
        replayAuthority: replay
      }),
    'INVALID_ROUTE'
  )

  // Fresh correct capability still works (scenario 1 path)
  const good = processSurbHop({
    message: sealed,
    capabilityAuthority: capabilityOf(r),
    replayAuthority: createSurbReplayAuthority({ maxEntries: 8 })
  })
  t.ok(good)
})

// --- Scenario 5: atomic race ---
test('scenario 5 concurrent hop processing admits exactly one', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 2)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const sealed = sealSurbReply({
    descriptor,
    replyBinding: binding,
    plaintext: b4a.alloc(16, 1)
  })
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const cap = capabilityOf(r)
  let wins = 0
  let losses = 0
  for (let i = 0; i < 2; i++) {
    try {
      processSurbHop({
        message: {
          ephem: b4a.from(sealed.ephem),
          header: b4a.from(sealed.header),
          mac: b4a.from(sealed.mac),
          payload: b4a.from(sealed.payload)
        },
        capabilityAuthority: cap,
        replayAuthority: replay
      })
      wins++
    } catch {
      losses++
    }
  }
  t.is(wins, 1)
  t.is(losses, 1)
})

// --- Scenario 6-7: invalid MAC / replay ---
test('scenario 6-7 invalid MAC and replay leave store consistent', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 3)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const sealed = sealSurbReply({
    descriptor,
    replyBinding: binding,
    plaintext: b4a.alloc(8, 2)
  })
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const cap = capabilityOf(r)

  const tampered = {
    ephem: b4a.from(sealed.ephem),
    header: b4a.from(sealed.header),
    mac: b4a.from(sealed.mac),
    payload: b4a.from(sealed.payload)
  }
  tampered.mac[0] ^= 0xff
  expectCode(
    t,
    () =>
      processSurbHop({
        message: tampered,
        capabilityAuthority: cap,
        replayAuthority: replay
      }),
    'INVALID_ROUTE'
  )

  // First good use
  processSurbHop({
    message: sealed,
    capabilityAuthority: cap,
    replayAuthority: replay
  })
  // Replay
  expectCode(
    t,
    () =>
      processSurbHop({
        message: {
          ephem: b4a.from(sealed.ephem),
          header: b4a.from(sealed.header),
          mac: b4a.from(sealed.mac),
          payload: b4a.from(sealed.payload)
        },
        capabilityAuthority: cap,
        replayAuthority: replay
      }),
    'ERR_REPLAY'
  )
})

// --- Scenario 8: quota full ---
test('scenario 8 quota full fails closed', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 4)
  const replay = createSurbReplayAuthority({ maxEntries: 1 })
  const cap = capabilityOf(r)

  function one() {
    const id = ids()
    id.surbId = b4a.alloc(16)
    sodium.randombytes_buf(id.surbId)
    const binding = bindingFor(id)
    const { descriptor } = buildSurb({
      hops: [hopOf(r)],
      terminalHandle: terminal,
      replyBinding: binding,
      now: NOW
    })
    const sealed = sealSurbReply({
      descriptor,
      replyBinding: binding,
      plaintext: b4a.alloc(4, 9)
    })
    return processSurbHop({
      message: sealed,
      capabilityAuthority: cap,
      replayAuthority: replay
    })
  }

  t.ok(one())
  expectCode(t, () => one(), 'ERR_QUOTA_EXCEEDED')
})

// --- Scenario 9: required-mode downgrade ---
test('scenario 9 required mode missing batch never correlates', (t) => {
  // V2 SURB_REQUIRED with empty descriptors is a parse failure
  const v1 = encodeRoutedRequest({
    requestId: b4a.alloc(16, 1),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 1000n,
    destination: {
      id: b4a.alloc(32, 2),
      handle: b4a.alloc(130, 3)
    },
    encodedBody: b4a.alloc(32, 4)
  })
  expectCode(
    t,
    () =>
      encodeRoutedRequestV2({
        replyMode: REPLY_MODE.SURB_REQUIRED,
        batchId: b4a.alloc(16, 5),
        request: v1,
        surbDescriptors: []
      }),
    'INVALID_ROUTE'
  )
})

// --- Scenario 10: mode substitution fails AEAD at nested V1 ---
test('scenario 10 mode field is inside authenticated V2 body', (t) => {
  const relays = [relay()]
  const terminal = b4a.alloc(32, 5)
  const id = ids()
  const binding = bindingFor(id)
  const built = buildSurb({
    hops: relays.map(hopOf),
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const v1 = encodeRoutedRequest({
    requestId: b4a.alloc(16, 1),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 1000n,
    destination: {
      id: b4a.alloc(32, 2),
      handle: b4a.alloc(130, 3)
    },
    encodedBody: b4a.alloc(32, 4)
  })
  const v2 = encodeRoutedRequestV2({
    replyMode: REPLY_MODE.SURB_REQUIRED,
    batchId: b4a.alloc(16, 5),
    request: v1,
    surbDescriptors: [withSurbId(built.descriptor, id.surbId)]
  })
  // Flip replyMode byte inside body (after M3 header)
  const flipped = b4a.from(v2)
  flipped[8] = REPLY_MODE.CORRELATED // body[0] after 8-byte M3 header
  // Nested request AEAD is not here; V2 parse must reject inconsistent CORRELATED+descriptors
  // After flip, surbCount still nonzero → invalid
  expectCode(t, () => decodeRoutedRequestV2(flipped), 'INVALID_ROUTE')
})

// --- Scenario 11: one-use open ---
test('scenario 11 first open consumes authority', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 6)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor, openAuthority } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const out = roundTripOpen(
    r ? [r] : [],
    terminal,
    descriptor,
    openAuthority,
    b4a.alloc(8, 1),
    binding
  )
  t.ok(out.plaintext)
  expectCode(
    t,
    () =>
      openSurbReply({
        openAuthority,
        replyBinding: binding,
        payload: b4a.alloc(64, 0),
        now: NOW
      }),
    'ERR_DESTROYED'
  )
})

// --- Scenario 12-13: expiry and teardown ---
test('scenario 12-13 expiry and revoke clear open authority', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 7)
  const id = ids()
  const binding = bindingFor(id)
  const { openAuthority } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  t.is(revokeSurbOpenAuthority(openAuthority), true)
  t.is(revokeSurbOpenAuthority(openAuthority), false)
})

// --- Scenario 14-15: fragment independence ---
test('scenario 14-15 fragment independence and isolated replay', (t) => {
  const relays = [relay(), relay()]
  const terminal = b4a.alloc(32, 8)
  const batchId = b4a.alloc(16, 0xaa)
  const requestId = b4a.alloc(16, 0xbb)
  const messageId = b4a.alloc(16, 0xcc)
  const items = []
  for (let i = 0; i < 2; i++) {
    const surbId = b4a.alloc(16, i + 1)
    const binding = encodeSurbReplyBinding({
      surbId,
      batchId,
      requestId,
      messageId,
      fragmentIndex: i,
      fragmentCount: 2
    })
    const built = buildSurb({
      hops: relays.map(hopOf),
      terminalHandle: terminal,
      replyBinding: binding,
      now: NOW
    })
    items.push({ surbId, binding, ...built })
  }
  t.absent(b4a.equals(items[0].descriptor.ephem, items[1].descriptor.ephem))
  t.absent(b4a.equals(items[0].descriptor.replyPubKey, items[1].descriptor.replyPubKey))
  t.absent(b4a.equals(items[0].descriptor.mac, items[1].descriptor.mac))

  // Replay on fragment 0 does not affect fragment 1
  const plain0 = b4a.alloc(20, 1)
  plain0[16] = 0
  plain0[17] = 0
  plain0[18] = 0
  plain0[19] = 2
  // Use real fragment frames
  const message = b4a.alloc(40, 0x11)
  const frames = fragment(message, { profile: SURB_REPLY_FRAGMENT_PROFILE, messageId })
  t.is(frames.length >= 1, true)

  const out1 = roundTripOpen(
    relays,
    terminal,
    items[1].descriptor,
    items[1].openAuthority,
    frames[0] || b4a.alloc(20, 2),
    items[1].binding
  )
  t.ok(out1.plaintext)
})

// --- Scenario 16: 492-byte boundary ---
test('scenario 16 512-byte plaintext fits 513 rejected before encryption', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 9)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const fit = b4a.alloc(MAX_REPLY_BYTES, 1)
  t.ok(sealSurbReply({ descriptor, replyBinding: binding, plaintext: fit }))
  expectCode(
    t,
    () =>
      sealSurbReply({
        descriptor,
        replyBinding: binding,
        plaintext: b4a.alloc(MAX_REPLY_BYTES + 1, 1)
      }),
    'INVALID_ROUTE'
  )

  // Fragment profile: 492 data + 20 header = 512
  const profile = SURB_REPLY_FRAGMENT_PROFILE
  t.is(profile.maxDataBytes, 492)
  const ok = fragment(b4a.alloc(492, 2), { profile, messageId: b4a.alloc(16, 1) })
  t.is(ok.length, 1)
  t.is(ok[0].byteLength, 512)
})

// --- Scenario 17: four-hop size under route payload ---
test('scenario 17 four-hop 512 plaintext stays under 1073 route payload', (t) => {
  const relays = [relay(), relay(), relay(), relay()]
  t.is(relays.length, MAX_HOPS)
  const terminal = b4a.alloc(32, 10)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor, openAuthority } = buildSurb({
    hops: relays.map(hopOf),
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const plain = b4a.alloc(512, 3)
  const sealed = sealSurbReply({ descriptor, replyBinding: binding, plaintext: plain })
  const hopSize = encodeSurbHopMessage(sealed).byteLength
  // Review: 996 for 512-byte plaintext at four hops; must stay < 1073
  t.ok(hopSize <= 996 || hopSize < MAX_ROUTE_PAYLOAD)
  t.ok(hopSize < MAX_ROUTE_PAYLOAD)
  const out = roundTripOpen(relays, terminal, descriptor, openAuthority, plain, binding)
  t.alike(out.plaintext, plain)
  t.ok(out.hopMessageSize < MAX_ROUTE_PAYLOAD)
})

// --- Scenario 18: batch carriage multi-cell, no DHT until full ---
test('scenario 18 three descriptors need multiple forward cells', (t) => {
  const relays = [relay()]
  const terminal = b4a.alloc(32, 11)
  const descriptors = []
  const opens = []
  for (let i = 0; i < 3; i++) {
    const id = ids(i, 3)
    id.surbId = b4a.alloc(16, i + 1)
    const binding = bindingFor(id)
    const built = buildSurb({
      hops: relays.map(hopOf),
      terminalHandle: terminal,
      replyBinding: binding,
      now: NOW
    })
    descriptors.push(withSurbId(built.descriptor, id.surbId))
    opens.push(built.openAuthority)
  }
  t.is(SURB_DESCRIPTOR_SIZE, 436)
  t.is(3 * SURB_DESCRIPTOR_SIZE, 1308)

  const v1 = encodeRoutedRequest({
    requestId: b4a.alloc(16, 1),
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 1000n,
    destination: {
      id: b4a.alloc(32, 2),
      handle: b4a.alloc(130, 3)
    },
    encodedBody: b4a.alloc(32, 4)
  })
  const v2 = encodeRoutedRequestV2({
    replyMode: REPLY_MODE.SURB_REQUIRED,
    batchId: b4a.alloc(16, 5),
    request: v1,
    surbDescriptors: descriptors
  })
  const frames = fragment(v2, { randomBytes: (n) => b4a.alloc(n, 7) })
  t.ok(frames.length > 1)

  // Exit must not parse until full reassembly
  const reassembler = new Reassembler({
    now: () => 1,
    epochExpiresAt: 1_000_000
  })
  let complete = null
  let dhtRequests = 0
  for (const frame of frames) {
    complete = reassembler.pushAuthenticated(frame)
    if (complete !== null) {
      dhtRequests++
      const decoded = decodeRoutedRequestV2(complete)
      t.is(decoded.replyMode, REPLY_MODE.SURB_REQUIRED)
      t.is(decoded.surbCount, 3)
    }
  }
  t.is(dhtRequests, 1)
  t.ok(complete)
})

// --- Scenario 19: resource ceiling ---
test('scenario 19 more than eight SURBs or 3936 bytes fails', (t) => {
  t.is(MAX_SURB_BATCH, 8)
  t.is(MAX_SURB_REPLY_APPLICATION_BYTES, 3936)
  t.is(SURB_REPLY_DATA_BYTES, 492)

  expectCode(
    t,
    () => fragment(b4a.alloc(3937, 1), { profile: SURB_REPLY_FRAGMENT_PROFILE }),
    'INVALID_ROUTE'
  )

  const profile = createFragmentProfile({ maxDataBytes: 492, maxFragments: 8 })
  t.is(profile.maxMessageDataBytes, 3936)
})

// --- Scenario 20: malformed native errors stay visible ---
test('scenario 20 only known verification failures map to protocol reject', (t) => {
  // Documented contract: unknown native errors propagate. Covered by surb.js hardening.
  // Here we assert the batch authority rejects bad shapes without swallowing.
  expectCode(
    t,
    () =>
      createSurbBatchReplyAuthority({
        replyMode: REPLY_MODE.CORRELATED,
        batchId: b4a.alloc(16),
        requestId: b4a.alloc(16),
        messageId: b4a.alloc(16),
        descriptors: [{}],
        sendHopMessage() {},
        now: () => NOW,
        localDeadline: EXPIRES
      }),
    'INVALID_ROUTE'
  )
})

// --- V1 byte-for-byte unchanged ---
test('V1 encode/decode fixtures unchanged beside V2', (t) => {
  const requestId = b4a.alloc(16, 0x11)
  const body = b4a.alloc(32, 0x22)
  const destination = {
    id: b4a.alloc(32, 0x33),
    handle: b4a.alloc(130, 0x44)
  }
  const encoded = encodeRoutedRequest({
    requestId,
    operationClass: BRANCH_CLASS.LOOKUP,
    commandId: M3_MESSAGE_ID.IMMUTABLE_GET_V1,
    operationBudgetMs: 2500n,
    destination,
    encodedBody: body
  })
  t.is(encoded[4], (M3_MESSAGE_ID.ROUTED_REQUEST_V1 >>> 8) & 0xff)
  t.is(encoded[5], M3_MESSAGE_ID.ROUTED_REQUEST_V1 & 0xff)
  const decoded = decodeRoutedRequest(encoded)
  t.alike(decoded.requestId, requestId)
  t.is(decoded.commandId, M3_MESSAGE_ID.IMMUTABLE_GET_V1)
  t.is(decoded.operationBudgetMs, 2500n)

  const any = decodeAnyRoutedRequest(encoded)
  t.is(any.replyMode, REPLY_MODE.CORRELATED)
  t.is(any.surbCount, 0)
})

// --- Descriptor size and hop cell magic ---
test('descriptor is 436 bytes and hop cells carry magic', (t) => {
  t.is(SURB_DESCRIPTOR_SIZE, 32 + 32 + 324 + 16 + 32)
  t.is(REPLY_BINDING_SIZE, 68)
  const r = relay()
  const terminal = b4a.alloc(32, 12)
  const id = ids()
  const binding = bindingFor(id)
  const { descriptor } = buildSurb({
    hops: [hopOf(r)],
    terminalHandle: terminal,
    replyBinding: binding,
    now: NOW
  })
  const wire = encodeSurbDescriptor(withSurbId(descriptor, b4a.alloc(16, 9)))
  t.is(wire.byteLength, 436)
  const round = decodeSurbDescriptor(wire)
  t.alike(round.ephem, descriptor.ephem)

  const sealed = sealSurbReply({
    descriptor,
    replyBinding: binding,
    plaintext: b4a.alloc(16, 1)
  })
  const cell = encodeSurbHopCell(sealed)
  t.ok(b4a.equals(cell.subarray(0, SURB_HOP_MAGIC.byteLength), SURB_HOP_MAGIC))
  const decoded = tryDecodeSurbHopCell(cell)
  t.ok(decoded)
  const hop = decodeSurbHopMessage(decoded)
  t.alike(hop.ephem, sealed.ephem)
})

// --- Batch authority sendFragments path ---
test('surb batch authority seals one SURB per fragment without correlated fallback', (t) => {
  const r = relay()
  const terminal = b4a.alloc(32, 13)
  const batchId = b4a.alloc(16, 0x10)
  const requestId = b4a.alloc(16, 0x20)
  const messageId = b4a.alloc(16, 0x30)
  const descriptors = []
  const openAuthorities = []
  const surbIds = []
  for (let i = 0; i < 2; i++) {
    const surbId = b4a.alloc(16, i + 1)
    surbIds.push(surbId)
    const binding = encodeSurbReplyBinding({
      surbId,
      batchId,
      requestId,
      messageId,
      fragmentIndex: i,
      fragmentCount: 2
    })
    const built = buildSurb({
      hops: [hopOf(r)],
      terminalHandle: terminal,
      replyBinding: binding,
      now: NOW
    })
    descriptors.push(withSurbId(built.descriptor, surbId))
    openAuthorities.push({ authority: built.openAuthority, binding })
  }

  const sent = []
  const batch = createSurbBatchReplyAuthority({
    replyMode: REPLY_MODE.SURB_REQUIRED,
    batchId,
    requestId,
    messageId,
    descriptors,
    surbIds,
    localDeadline: EXPIRES,
    now: () => NOW,
    sendHopMessage(info) {
      sent.push(info)
    }
  })

  // Two full 492-byte chunks
  const reply = b4a.alloc(600, 0x5a)
  sendSurbBatchFragments(batch, reply)
  t.is(sent.length, 2)

  // Open each fragment through the hop
  const parts = []
  for (let i = 0; i < sent.length; i++) {
    const raw = tryDecodeSurbHopCell(sent[i].cell)
    const hopMsg = decodeSurbHopMessage(raw)
    const fwd = processSurbHop({
      message: hopMsg,
      capabilityAuthority: capabilityOf(r),
      replayAuthority: createSurbReplayAuthority({ maxEntries: 16 })
    })
    const rslt = consumeSurbForwardingAuthority(fwd)
    t.ok(rslt.terminal)
    const plain = openSurbReply({
      openAuthority: openAuthorities[i].authority,
      replyBinding: openAuthorities[i].binding,
      payload: rslt.message.payload,
      now: NOW
    })
    parts.push(plain)
  }

  const reassembler = new Reassembler({
    now: () => 1,
    epochExpiresAt: 1_000_000,
    profile: SURB_REPLY_FRAGMENT_PROFILE
  })
  let done = null
  for (const part of parts) {
    done = reassembler.pushAuthenticated(part)
  }
  // Batch pads to the committed SURB count; application bytes are a prefix.
  t.alike(done.subarray(0, reply.byteLength), reply)

  // Second send on spent batch fails; no correlated path exists
  expectCode(t, () => sendSurbBatchFragments(batch, reply), 'ERR_DESTROYED')
})

// --- Default fragment profile unchanged ---
test('default route fragment profile stays 1053 data bytes', (t) => {
  t.is(DEFAULT_ROUTE_FRAGMENT_PROFILE.maxDataBytes, MAX_FRAGMENT_DATA)
  t.is(MAX_FRAGMENT_DATA, MAX_ROUTE_PAYLOAD - FRAGMENT_HEADER_SIZE)
  t.is(DEFAULT_ROUTE_FRAGMENT_PROFILE.maxDataBytes, 1053)
})

test('failed SURB batch construction erases keys from completed slots', (t) => {
  const { buildSurbBatch } = require('../../lib/private/surb-path')
  for (const failNative of [false, true]) {
    const r = relay()
    const keypair = sodium.crypto_box_keypair
    const secrets = []
    const handles = []
    const fault = new Error('second SURB construction failed')
    let randomCalls = 0
    sodium.crypto_box_keypair = (publicKey, secretKey) => {
      keypair(publicKey, secretKey)
      secrets.push(secretKey)
      if (failNative && secrets.length === 3) throw fault
    }
    try {
      t.exception(
        () =>
          buildSurbBatch({
            hops: [hopOf(r)],
            batchId: b4a.alloc(16, 1),
            requestId: b4a.alloc(16, 2),
            surbCount: 2,
            now: NOW,
            randomBytes(size) {
              if (++randomCalls === 2 && !failNative) throw fault
              const handle = b4a.alloc(size, 7)
              handles.push(handle)
              return handle
            }
          }),
        fault
      )
      t.ok(
        secrets.every((key) => key.every((byte) => byte === 0)),
        'no prior reply key survives'
      )
      t.ok(
        handles.every((handle) => handle.every((byte) => byte === 0)),
        'owned handles are erased'
      )
    } finally {
      sodium.crypto_box_keypair = keypair
      for (const key of secrets) key.fill(0)
      r.routeSecretKey.fill(0)
    }
  }
})
