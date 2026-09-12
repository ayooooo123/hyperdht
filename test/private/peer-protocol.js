const test = require('brittle')
const b4a = require('b4a')

const { PrivateRouteError } = require('../../lib/private/errors')
const { M3_MESSAGE_ID, decodeM3Object, encodeM3Object } = require('../../lib/private/protocol')
const {
  PEER_MESSAGE_ID,
  decodePeerObject,
  encodePeerObject
} = require('../../lib/private/peer-protocol')

function expectInvalid(t, fn) {
  let error = null

  try {
    fn()
  } catch (err) {
    error = err
  }

  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, 'INVALID_ROUTE')
}

function forgedByteLength(value, byteLength) {
  Object.defineProperty(value, 'byteLength', { value: byteLength })
  return value
}

function overriddenSubarray(value) {
  value.subarray = () => b4a.alloc(0)
  return value
}

function wire(version, messageId, bodyBytes, suffixBytes) {
  const output = b4a.alloc(8 + bodyBytes + suffixBytes)
  output[0] = version >>> 24
  output[1] = version >>> 16
  output[2] = version >>> 8
  output[3] = version
  output[4] = messageId >>> 8
  output[5] = messageId
  output[6] = bodyBytes >>> 8
  output[7] = bodyBytes
  return output
}

const FIXTURES = [
  ['PEER_CAPABILITY_ADVERTISEMENT_V2', 188, 188, 64],
  ['PEER_CAPS_QUERY_V2', 110, 110, 0],
  ['PEER_CAPS_COOKIE_CHALLENGE_V2', 72, 72, 0],
  ['PEER_CAPS_RESPONSE_V2', 335, 335, 64],
  ['PEER_ACTIVE_CHALLENGE_V2', 176, 176, 0],
  ['PEER_ACTIVE_CHALLENGE_RESPONSE_V2', 240, 240, 64],
  ['PEER_DISCOVER_REQUEST_V2', 79, 339, 0],
  ['PEER_DISCOVER_RESPONSE_V2', 436, 436, 0],
  ['PEER_LINK_OFFER_V2', 360, 360, 64],
  ['PEER_LINK_ACCEPT_V2', 213, 213, 64],
  ['PEER_REDACTED_RESPONDER_PROOF_V2', 306, 306, 64],
  ['PEER_EXTENDED_V2', 486, 486, 0],
  ['PEER_TAIL_READY_V2', 210, 210, 64],
  ['PEER_EXTEND_REQUEST_V2', 516, 516, 0],
  ['PEER_BRANCH_DESTROY_V2', 42, 42, 0],
  ['PEER_BRANCH_TEARDOWN_V2', 58, 58, 0],
  ['PEER_BRANCH_TEARDOWN_ACK_V2', 58, 58, 0],
  ['PEER_ROUTE_OFFER_V2', 212, 212, 16],
  ['PEER_ROUTE_ACCEPT_V2', 260, 260, 16],
  ['PEER_ROUTE_REJECT_V2', 64, 64, 16],
  ['PEER_RELIABLE_PACKET_V2', 29, 1065, 0],
  ['PEER_RELIABLE_ACK_V2', 64, 64, 0],
  ['PEER_OPEN_V2', 88, 88, 0],
  ['PEER_OPENED_V2', 64, 64, 0],
  ['PEER_HANDSHAKE_V2', 49, 1029, 0],
  ['PEER_DATA_V2', 45, 1021, 0],
  ['PEER_CREDIT_V2', 60, 60, 0],
  ['PEER_FIN_V2', 56, 56, 0],
  ['PEER_CLOSE_V2', 56, 56, 0],
  ['PEER_RESET_V2', 60, 60, 0],
  ['PEER_ROUTE_CLOSE_V2', 40, 40, 0],
  ['PEER_ROUTE_CLOSE_ACK_V2', 40, 40, 0],
  ['PEER_DESCRIPTOR_V2', 511, 511, 0],
  ['LEGACY_RESOLVE_V2', 104, 104, 0],
  ['LEGACY_RESOLVED_V2', 106, 106, 0],
  ['LEGACY_RESERVE_V2', 96, 96, 0],
  ['LEGACY_RESERVED_V2', 132, 132, 0],
  ['PEER_NOISE_FRAGMENT_V2', 64, 1065, 0],
  ['LEGACY_HANDSHAKE_ACCEPT_V2', 132, 132, 0],
  ['LEGACY_OPEN_V2', 100, 100, 0],
  ['ENTRY_REGISTER_V2', 478, 478, 0],
  ['ENTRY_REGISTERED_V2', 136, 136, 0],
  ['ENTRY_REVOKE_V2', 88, 88, 0],
  ['PRIVATE_ACTIVATE_V2', 749, 749, 0],
  ['PRIVATE_READY_V2', 220, 220, 0],
  ['PRIVATE_ACK_V2', 232, 232, 0],
  ['PRIVATE_ACCEPTED_V2', 168, 168, 0],
  ['PRIVATE_SOURCE_RECEIPT_V2', 120, 120, 0],
  ['PRIVATE_OPEN_V2', 216, 216, 0]
]

test('peer v2 envelopes emit the fixed registry wire identifiers', (t) => {
  const expectedIds = [
    0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305, 0x0306, 0x0307, 0x0308, 0x0309, 0x030a, 0x030b,
    0x030c, 0x030d, 0x030e, 0x030f, 0x0310, 0x0311, 0x0312, 0x0313, 0x0314, 0x0315, 0x0316, 0x0317,
    0x0318, 0x0319, 0x031a, 0x031b, 0x031c, 0x031d, 0x031e, 0x031f, 0x0340, 0x0341, 0x0342, 0x0343,
    0x0344, 0x0345, 0x0346, 0x0347, 0x0349, 0x034a, 0x034b, 0x0360, 0x0361, 0x0362, 0x0363, 0x0364,
    0x0365
  ]
  for (let index = 0; index < FIXTURES.length; index++) {
    const [name, bodyBytes, , suffixBytes] = FIXTURES[index]
    const encoded = encodePeerObject({
      messageId: PEER_MESSAGE_ID[name],
      body: b4a.alloc(bodyBytes),
      authSuffix: b4a.alloc(suffixBytes)
    })
    t.alike(
      encoded.subarray(0, 8),
      wire(2, expectedIds[index], bodyBytes, suffixBytes).subarray(0, 8)
    )
  }
})

test('peer v2 envelope accepts every declared body and suffix boundary', (t) => {
  for (const [name, minimumBodyBytes, maximumBodyBytes, suffixBytes] of FIXTURES) {
    const messageId = PEER_MESSAGE_ID[name]
    const bodyLengths =
      minimumBodyBytes === maximumBodyBytes
        ? [minimumBodyBytes]
        : name === 'PEER_DISCOVER_REQUEST_V2'
          ? [79, 339]
          : [minimumBodyBytes, maximumBodyBytes]

    for (const bodyBytes of bodyLengths) {
      const body = b4a.alloc(bodyBytes, 0x41)
      const authSuffix = b4a.alloc(suffixBytes, 0x52)
      const encoded = encodePeerObject({ messageId, body, authSuffix })
      const decoded = decodePeerObject(encoded)

      t.is(encoded.byteLength, 8 + bodyBytes + suffixBytes)
      t.is(decoded.protocolVersion, 2)
      t.is(decoded.messageId, messageId)
      t.is(decoded.body.byteLength, bodyBytes)
      t.is(decoded.authSuffix.byteLength, suffixBytes)
      t.alike(decoded.body, body)
      t.alike(decoded.authSuffix, authSuffix)
    }

    expectInvalid(t, () => encodePeerObject({ messageId, body: b4a.alloc(minimumBodyBytes - 1) }))
    expectInvalid(t, () => encodePeerObject({ messageId, body: b4a.alloc(maximumBodyBytes + 1) }))
    expectInvalid(t, () => decodePeerObject(wire(2, messageId, minimumBodyBytes - 1, suffixBytes)))
    expectInvalid(t, () => decodePeerObject(wire(2, messageId, maximumBodyBytes + 1, suffixBytes)))

    if (name === 'PEER_DISCOVER_REQUEST_V2') {
      for (const bodyBytes of [80, 338]) {
        expectInvalid(t, () => encodePeerObject({ messageId, body: b4a.alloc(bodyBytes) }))
        expectInvalid(t, () => decodePeerObject(wire(2, messageId, bodyBytes, 0)))
      }
    }

    expectInvalid(t, () =>
      encodePeerObject({
        messageId,
        body: b4a.alloc(minimumBodyBytes),
        authSuffix: b4a.alloc(suffixBytes + 1)
      })
    )
    expectInvalid(t, () => decodePeerObject(wire(2, messageId, minimumBodyBytes, suffixBytes + 1)))
  }
})

test('peer v2 envelope rejects v1, reserved, unknown, and trailing layouts', (t) => {
  const body = b4a.alloc(88)
  const valid = encodePeerObject({ messageId: PEER_MESSAGE_ID.PEER_OPEN_V2, body })

  const wrongVersion = b4a.from(valid)
  wrongVersion[3] = 1
  expectInvalid(t, () => decodePeerObject(wrongVersion))
  expectInvalid(t, () => decodeM3Object(valid))

  const validV1Wire = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
    body: b4a.alloc(105)
  })
  expectInvalid(t, () => decodePeerObject(validV1Wire))

  expectInvalid(t, () => encodePeerObject({ messageId: 0x0008, body: b4a.alloc(48) }))
  expectInvalid(t, () => decodePeerObject(wire(2, 0x0008, 48, 0)))

  for (const messageId of [0x0320, 0x033f, 0x0348, 0x034c, 0x035f, 0x0366, 0x03bf, 0x03c0]) {
    expectInvalid(t, () => encodePeerObject({ messageId, body: b4a.alloc(0) }))
    expectInvalid(t, () => decodePeerObject(wire(2, messageId, 0, 0)))
  }

  const wrongBodyLength = b4a.from(valid)
  wrongBodyLength[7] = 87
  expectInvalid(t, () => decodePeerObject(wrongBodyLength))
  expectInvalid(t, () => decodePeerObject(b4a.concat([valid, b4a.from([0])])))

  expectInvalid(t, () =>
    encodePeerObject({
      messageId: PEER_MESSAGE_ID.PEER_OPEN_V2,
      body: b4a.alloc(88),
      authSuffix: b4a.alloc(1)
    })
  )
})

test('peer v2 decoder retains owned fields and uses intrinsic buffer operations', (t) => {
  const body = b4a.alloc(88, 0x61)
  const signature = b4a.alloc(64, 0x62)
  const encoded = encodePeerObject({
    messageId: PEER_MESSAGE_ID.PEER_CAPABILITY_ADVERTISEMENT_V2,
    body: b4a.alloc(188, 0x63),
    authSuffix: signature
  })
  const decoded = decodePeerObject(encoded)

  encoded.fill(0)
  signature.fill(0)
  t.is(decoded.body[0], 0x63)
  t.is(decoded.authSuffix[0], 0x62)

  const valid = encodePeerObject({ messageId: PEER_MESSAGE_ID.PEER_OPEN_V2, body })
  expectInvalid(t, () =>
    decodePeerObject(forgedByteLength(b4a.concat([valid, b4a.alloc(1)]), valid.byteLength))
  )
  expectInvalid(t, () =>
    decodePeerObject(forgedByteLength(b4a.from(valid.subarray(0, -1)), valid.byteLength))
  )
  t.alike(decodePeerObject(overriddenSubarray(b4a.from(valid))).body, body)

  let reads = 0
  const accessor = {}
  Object.defineProperty(accessor, 'messageId', {
    get() {
      reads++
      return PEER_MESSAGE_ID.PEER_OPEN_V2
    }
  })
  accessor.body = body
  expectInvalid(t, () => encodePeerObject(accessor))
  t.is(reads, 0)

  const hostile = new Proxy(
    { messageId: PEER_MESSAGE_ID.PEER_OPEN_V2, body },
    {
      getOwnPropertyDescriptor() {
        throw new Error('hostile descriptor trap')
      }
    }
  )
  expectInvalid(t, () => encodePeerObject(hostile))
})
