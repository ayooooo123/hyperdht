const test = require('brittle')
const b4a = require('b4a')

const { ERROR_CODES, M3_ERROR_CODES, PrivateRouteError } = require('../../lib/private/errors')
const {
  BOOTSTRAP_REJECT_CODE,
  BOOTSTRAP_TYPE,
  BRANCH_CLASS,
  CAPABILITY,
  CAPACITY_CLASS,
  CELL_CLASS,
  CIRCUIT_STATE,
  CONTEXT_CLASS,
  DESTINATION_VALIDATION_CLASS,
  DIRECTION,
  DOMAIN,
  M3_ID_REGISTRY,
  M3_LINK_ROLE,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  LINK_OPERATION,
  MUTATION_FLAG,
  PROTOCOL_VERSION,
  RELAY_CAPABILITY,
  ROLE,
  ROUTED_ERROR,
  TOPOLOGY_ROLE,
  decodeM3Object,
  encodeM3Object,
  roleForIdentity
} = require('../../lib/private/protocol')

function expectCode(t, fn, code) {
  let error = null

  try {
    fn()
  } catch (err) {
    error = err
  }

  t.ok(error instanceof PrivateRouteError)
  t.is(error && error.code, code)
}

function forgedByteLength(value, byteLength) {
  Object.defineProperty(value, 'byteLength', { value: byteLength })
  return value
}

function overriddenSubarray(value) {
  value.subarray = () => b4a.alloc(0)
  return value
}

function throwingByteLength(value, error) {
  Object.defineProperty(value, 'byteLength', {
    get() {
      throw error
    }
  })
  return value
}

test('private route protocol versions and core enums are exact and frozen', (t) => {
  t.is(PROTOCOL_VERSION, 0)
  t.is(M3_PROTOCOL_VERSION, 1)

  const expected = [
    [BOOTSTRAP_TYPE, { LINK_CREATE: 0, LINK_CREATED: 1, LINK_REJECT: 2, LINK_CANCEL: 3 }],
    [BOOTSTRAP_REJECT_CODE, { UNAUTHORIZED: 0, CIRCUIT_LIMIT: 1, ROUTE_UNAVAILABLE: 2 }],
    [ROLE, { SAFETY: 0, PRIVATE: 1 }],
    [
      TOPOLOGY_ROLE,
      {
        SOURCE: 0,
        SAFETY_GUARD: 1,
        SAFETY_FINAL: 2,
        PRIVATE_ENTRY: 3,
        PRIVATE_MIDDLE: 4,
        PRIVATE_FINAL: 5,
        DESTINATION: 6
      }
    ],
    [LINK_OPERATION, { INITIATE: 1, ACCEPT: 2, KNOWN: 3 }],
    [BRANCH_CLASS, { LOOKUP: 0, ANNOUNCE: 1 }],
    [CELL_CLASS, { CONTROL: 0, STREAM: 1, DATAGRAM: 2 }],
    [DIRECTION, { FORWARD: 0, REVERSE: 1 }],
    [CIRCUIT_STATE, { CREATE: 0, CREATED: 1, OPEN: 2, DRAINING: 3, DESTROYED: 4 }],
    [CAPABILITY, { FORWARD: 1, DATAGRAM: 2, STREAM: 4, KNOWN: 7 }],
    [
      CONTEXT_CLASS,
      {
        TAIL_CONTROL_ORDERED: 0,
        TAIL_FINALIZE_DATAGRAM: 1,
        FINAL_EXIT_FINALIZE_DATAGRAM: 2,
        ROUTE_PAYLOAD: 3,
        TERMINAL_CONTROL_ORDERED: 4
      }
    ],
    [RELAY_CAPABILITY, { CIRCUIT_RELAY_V1: 1, DHT_EXIT_V1: 2, PRIVATE_RECORDS_V1: 4 }],
    [M3_LINK_ROLE, { CLIENT: 0, SAFETY_RELAY: 1, DHT_EXIT: 2 }],
    [CAPACITY_CLASS, { SMALL: 0, MEDIUM: 1, LARGE: 2 }],
    [MUTATION_FLAG, { READ_ONLY: 0, MUTATING: 1 }],
    [
      DESTINATION_VALIDATION_CLASS,
      { EXIT_LOCAL: 0, DHT_NODE_HANDLE: 1, SIGNED_CAPABILITY_HANDLE: 2 }
    ]
  ]

  for (const [actual, value] of expected) {
    t.alike(actual, value)
    t.ok(Object.isFrozen(actual))
  }
})

test('private route message and routed-error IDs form the exact sorted 62-ID registry', (t) => {
  const messages = {
    CAPABILITY_ADVERTISEMENT_V1: 0x0001,
    CAPS_QUERY_V1: 0x0002,
    CAPS_RESPONSE_V1: 0x0003,
    ACTIVE_CHALLENGE_V1: 0x0004,
    ACTIVE_CHALLENGE_RESPONSE_V1: 0x0005,
    RELAY_DISCOVER_V1: 0x0006,
    RELAY_DISCOVER_RESPONSE_V1: 0x0007,
    CORE_FRAGMENT_V1: 0x0008,
    CAPS_COOKIE_CHALLENGE_V1: 0x0009,
    LINK_OFFER_V1: 0x0020,
    LINK_ACCEPT_V1: 0x0021,
    REDACTED_RESPONDER_PROOF_V1: 0x0022,
    EXTENDED_V1: 0x0023,
    TAIL_READY_V1: 0x0024,
    EXTEND_REQUEST_V1: 0x0025,
    BRANCH_DESTROY_V1: 0x0026,
    BRANCH_TEARDOWN_V1: 0x0027,
    BRANCH_TEARDOWN_ACK_V1: 0x0028,
    DHT_EXIT_ACTIVATE_V1: 0x0040,
    DHT_EXIT_READY_V1: 0x0041,
    DHT_EXIT_READY_ACK_V1: 0x0042,
    DHT_EXIT_OPEN_V1: 0x0043,
    DHT_EXIT_SEEDS_V1: 0x0044,
    DHT_EXIT_DHT_SEEDS_V1: 0x0045,
    EXIT_RPC_OPEN_V1: 0x0050,
    EXIT_RPC_ACCEPT_V1: 0x0051,
    EXIT_RPC_FRAGMENT_V1: 0x0052,
    EXIT_RPC_REQUEST_V1: 0x0053,
    EXIT_RPC_RESPONSE_V1: 0x0054,
    DESTINATION_REF_V1: 0x0100,
    ROUTED_REQUEST_V1: 0x0101,
    ROUTED_REPLY_V1: 0x0102,
    IMMUTABLE_GET_V1: 0x0120,
    IMMUTABLE_PUT_V1: 0x0121,
    MUTABLE_GET_V1: 0x0122,
    MUTABLE_PUT_V1: 0x0123,
    PRIVATE_FIND_NODE_V1: 0x0200,
    PRIVATE_FIND_NODE_RESPONSE_V1: 0x0201,
    PRIVATE_PRESENCE_RECORD_V1: 0x0280,
    PRIVATE_TOMBSTONE_V1: 0x0281,
    PRIVATE_LOOKUP_RESPONSE_V1: 0x0282,
    PRIVATE_WRITE_TOKEN_V1: 0x0283,
    PRIVATE_WRITE_RECEIPT_V1: 0x0284,
    PRIVATE_LOOKUP_V1: 0x02a0,
    PRIVATE_PREPARE_V1: 0x02a1,
    PRIVATE_ANNOUNCE_V1: 0x02a2,
    PRIVATE_UNANNOUNCE_V1: 0x02a3
  }
  const errors = {
    MALFORMED: 0x0180,
    UNSUPPORTED_COMMAND: 0x0181,
    POLICY_MISMATCH: 0x0182,
    DESTINATION_INVALID: 0x0183,
    DESTINATION_EXPIRED: 0x0184,
    DEADLINE_EXPIRED: 0x0185,
    BUSY: 0x0186,
    RESPONSE_TOO_LARGE: 0x0187,
    AMPLIFICATION_EXCEEDED: 0x0188,
    UPSTREAM_TIMEOUT: 0x0189,
    UPSTREAM_REJECTED: 0x018a,
    TOKEN_INVALID: 0x018b,
    STORAGE_UNAVAILABLE: 0x018c,
    RECORD_CONFLICT: 0x018d,
    QUOTA_EXCEEDED: 0x018e
  }

  t.alike(M3_MESSAGE_ID, messages)
  t.alike(ROUTED_ERROR, errors)
  t.ok(Object.isFrozen(M3_MESSAGE_ID))
  t.ok(Object.isFrozen(ROUTED_ERROR))

  const assigned = [...Object.values(M3_MESSAGE_ID), ...Object.values(ROUTED_ERROR)]
  t.is(M3_MESSAGE_ID.DHT_EXIT_SEEDS_V1, 0x0044)
  t.is(M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1, 0x0045)
  t.is(M3_ID_REGISTRY.filter((id) => id === 0x0045).length, 1)
  t.is(assigned.length, 62)
  t.is(new Set(assigned).size, 62)
  t.alike(
    M3_ID_REGISTRY,
    assigned.slice().sort((left, right) => left - right)
  )
  t.ok(Object.isFrozen(M3_ID_REGISTRY))
})

test('private route protocol domains are exact defensive buffers in a frozen map', (t) => {
  const expected = {
    ROLE: 'hyperdht-private-routes/role/v0',
    UDX_BOOTSTRAP: 'hyperdht-private-routes/udx-bootstrap/v0',
    TOPOLOGY_GRANT: 'hyperdht-private-routes/topology-grant/v0',
    RELAY_ADVERTISEMENT: 'hyperdht-private-routes/relay-advertisement/v0',
    DESCRIPTOR_DIRECT: 'hyperdht-private-routes/descriptor/direct/v0',
    DELEGATION: 'hyperdht-private-routes/delegation/v0',
    DESCRIPTOR_DELEGATED: 'hyperdht-private-routes/descriptor/delegated/v0',
    KDF_FORWARD_KEY: 'hyperdht-private-routes/kdf/v0/forward-key',
    KDF_REVERSE_KEY: 'hyperdht-private-routes/kdf/v0/reverse-key',
    KDF_FORWARD_NONCE: 'hyperdht-private-routes/kdf/v0/forward-nonce',
    KDF_REVERSE_NONCE: 'hyperdht-private-routes/kdf/v0/reverse-nonce',
    LINK_CREATE: 'hyperdht-private-routes/link/create/v0',
    LINK_CREATED: 'hyperdht-private-routes/link/created/v0',
    TEMPLATE_REGISTER: 'hyperdht-private-routes/template/register/v0',
    TEMPLATE_REGISTERED: 'hyperdht-private-routes/template/registered/v0',
    ACTIVATE_CREATE: 'hyperdht-private-routes/activate/create/v0',
    ACTIVATE_ENTRY_PROOF: 'hyperdht-private-routes/activate/entry-proof/v0',
    ACTIVATE_DESTINATION_PROOF: 'hyperdht-private-routes/activate/destination-proof/v0',
    ACTIVATE_CHALLENGE: 'hyperdht-private-routes/activate/challenge/v0',
    ACTIVATE_PARAMETERS: 'hyperdht-private-routes/activate/parameters/v0',
    CELL_HEADER: 'hyperdht-private-routes/cell/header/v0',
    ROUTE_PAYLOAD: 'hyperdht-private-routes/route-payload/v0',
    DHT_EXIT_DHT_SEEDS: 'hyperdht-private-routes/m3/dht-exit-dht-seeds/v1',
    DHT_EXIT_DHT_SEEDS_SET: 'hyperdht-private-routes/m3/dht-exit-dht-seeds/set/v1'
  }

  t.alike(Object.keys(DOMAIN), Object.keys(expected))
  t.ok(Object.isFrozen(DOMAIN))

  for (const [name, value] of Object.entries(expected)) {
    t.ok(b4a.isBuffer(DOMAIN[name]))
    t.is(b4a.toString(DOMAIN[name]), value)
  }

  const role = DOMAIN.ROLE
  role.fill(0)
  const cellHeader = DOMAIN.CELL_HEADER
  cellHeader.fill(0xff)

  t.is(b4a.toString(DOMAIN.ROLE), expected.ROLE)
  t.is(b4a.toString(DOMAIN.CELL_HEADER), expected.CELL_HEADER)
  t.is(roleForIdentity(b4a.alloc(32, 7)), ROLE.PRIVATE)
})

test('roleForIdentity assigns deterministically and rejects every invalid shape', (t) => {
  const identity = b4a.alloc(32, 7)

  t.is(roleForIdentity(identity), ROLE.PRIVATE)
  t.is(roleForIdentity(identity), roleForIdentity(identity))
  t.ok([ROLE.SAFETY, ROLE.PRIVATE].includes(roleForIdentity(identity)))

  const invalid = [null, 'identity', b4a.alloc(0), b4a.alloc(31), b4a.alloc(33)]

  for (const value of invalid) expectCode(t, () => roleForIdentity(value), 'INVALID_IDENTITY')
})

test('roleForIdentity matches independent hardcoded role vectors', (t) => {
  const vectors = [
    ['0000000000000000000000000000000000000000000000000000000000000000', ROLE.SAFETY],
    ['0101010101010101010101010101010101010101010101010101010101010101', ROLE.SAFETY],
    ['0202020202020202020202020202020202020202020202020202020202020202', ROLE.PRIVATE],
    ['0303030303030303030303030303030303030303030303030303030303030303', ROLE.PRIVATE],
    ['1111111111111111111111111111111111111111111111111111111111111111', ROLE.PRIVATE],
    ['2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a', ROLE.SAFETY],
    ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', ROLE.PRIVATE],
    ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', ROLE.SAFETY]
  ]

  for (const [identity, expectedRole] of vectors) {
    t.is(roleForIdentity(b4a.from(identity, 'hex')), expectedRole)
  }
})

test('roleForIdentity fails closed on forged and hostile buffer shapes', (t) => {
  const sentinel = new Error('hostile identity accessor')
  const hostileProxy = new Proxy(b4a.alloc(32), {
    getPrototypeOf() {
      throw sentinel
    }
  })
  const invalid = [
    forgedByteLength(b4a.alloc(31), 32),
    forgedByteLength(b4a.alloc(33), 32),
    throwingByteLength(b4a.alloc(32), sentinel),
    hostileProxy
  ]

  for (const value of invalid) expectCode(t, () => roleForIdentity(value), 'INVALID_IDENTITY')
})

test('private route errors have exact frozen registries, constructors, and sanitized messages', (t) => {
  const expectedMessages = {
    INVALID_IDENTITY: 'Identity must be a 32-byte buffer',
    INVALID_KEY: 'Key is invalid',
    INVALID_ROLE: 'Role is invalid',
    INVALID_ROUTE: 'Route is invalid',
    INVALID_DESCRIPTOR: 'Descriptor is invalid',
    UNAUTHORIZED: 'Operation is unauthorized',
    REPLAY: 'Replay was detected',
    COUNTER_INVALID: 'Counter is invalid',
    COUNTER_GAP: 'Counter sequence contains a gap',
    COUNTER_EXHAUSTED: 'Counter is exhausted',
    CELL_INVALID: 'Cell is invalid',
    CIRCUIT_LIMIT: 'Circuit limit was reached',
    CIRCUIT_STATE: 'Circuit state is invalid',
    ROUTE_UNAVAILABLE: 'Route is unavailable',
    VIRTUAL_LIMIT: 'Virtual endpoint limit was reached',
    ERR_PRIVACY_UNAVAILABLE: 'Private routing is unavailable',
    ERR_PRIVATE_BRANCH_ROTATING: 'Private branch is rotating',
    ERR_INCOMPATIBLE_RELAY: 'Relay is incompatible',
    ERR_AUTHENTICATION: 'Authentication failed',
    ERR_REPLAY: 'Replay was detected',
    ERR_BUSY: 'Private routing is busy',
    ERR_QUOTA_EXCEEDED: 'Private routing quota was exceeded',
    ERR_PRIVATE_RECORDS_UNAVAILABLE: 'Private records are unavailable',
    ERR_PRIVATE_GUARD_UNAVAILABLE: 'Private guard is unavailable',
    ERR_DESTROYED: 'Private routing state is destroyed'
  }
  const expected = Object.keys(expectedMessages).slice(0, 15)
  const m3Expected = Object.keys(expectedMessages).slice(15)

  t.alike(ERROR_CODES, expected)
  t.alike(M3_ERROR_CODES, m3Expected)
  t.ok(Object.isFrozen(ERROR_CODES))
  t.ok(Object.isFrozen(M3_ERROR_CODES))
  t.is(PrivateRouteError.ERR_PRIVATE_GUARD_UNAVAILABLE().code, 'ERR_PRIVATE_GUARD_UNAVAILABLE')

  const sensitive = 'secret 0123456789abcdef0123456789abcdef at 192.168.100.200'

  for (const code of [...expected, ...m3Expected]) {
    t.is(typeof PrivateRouteError[code], 'function')

    const error = new PrivateRouteError(code, sensitive)
    t.ok(error instanceof PrivateRouteError)
    t.is(error.name, 'PrivateRouteError')
    t.is(error.code, code)
    t.is(error.message, expectedMessages[code])
    t.is(error.message, PrivateRouteError[code]().message)
    t.ok(error.message.length > 0)
    t.absent(error.message.includes(sensitive))
    t.absent(/[a-f0-9]{32,}/i.test(error.message))
    t.absent(/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(error.message))
  }

  let unknownCodeError = null
  try {
    new PrivateRouteError('BOGUS', sensitive)
  } catch (err) {
    unknownCodeError = err
  }

  t.ok(unknownCodeError instanceof TypeError)
})

test('canonical M3 object envelope round trips exact unsigned and signed layouts', (t) => {
  const body = b4a.alloc(105, 0x42)
  const unsigned = encodeM3Object({ messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1, body })
  const expectedHeader = b4a.from('0000000100420069', 'hex')

  t.alike(unsigned.subarray(0, 8), expectedHeader)
  t.is(unsigned.byteLength, 113)

  const decodedUnsigned = decodeM3Object(unsigned)
  t.is(decodedUnsigned.protocolVersion, 1)
  t.is(decodedUnsigned.messageId, M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1)
  t.alike(decodedUnsigned.body, body)
  t.is(decodedUnsigned.authSuffix.byteLength, 0)

  const signedBody = b4a.alloc(233, 0x51)
  const signature = b4a.alloc(64, 0x52)
  const signed = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_READY_V1,
    body: signedBody,
    authSuffix: signature
  })
  const decodedSigned = decodeM3Object(signed)
  t.alike(decodedSigned.body, signedBody)
  t.alike(decodedSigned.authSuffix, signature)

  unsigned.fill(0)
  signed.fill(0)
  body.fill(0)
  signedBody.fill(0)
  signature.fill(0)
  t.alike(decodedUnsigned.body, b4a.alloc(105, 0x42))
  t.alike(decodedSigned.body, b4a.alloc(233, 0x51))
  t.alike(decodedSigned.authSuffix, b4a.alloc(64, 0x52))
})

test('canonical M3 object envelope requires own data properties without invoking accessors', (t) => {
  const messageId = M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1
  const body = b4a.alloc(105)
  const inherited = Object.create({ messageId, body })

  expectCode(t, () => encodeM3Object(inherited), 'INVALID_ROUTE')

  let messageIdReads = 0
  const accessorMessageId = { body }
  Object.defineProperty(accessorMessageId, 'messageId', {
    get() {
      messageIdReads++
      return messageId
    }
  })
  expectCode(t, () => encodeM3Object(accessorMessageId), 'INVALID_ROUTE')
  t.is(messageIdReads, 0)

  let bodyReads = 0
  const accessorBody = { messageId }
  Object.defineProperty(accessorBody, 'body', {
    get() {
      bodyReads++
      return body
    }
  })
  expectCode(t, () => encodeM3Object(accessorBody), 'INVALID_ROUTE')
  t.is(bodyReads, 0)

  let authSuffixReads = 0
  const accessorAuthSuffix = { messageId, body }
  Object.defineProperty(accessorAuthSuffix, 'authSuffix', {
    get() {
      authSuffixReads++
      if (authSuffixReads > 1) throw new Error('time-varying auth suffix')
      return b4a.alloc(0)
    }
  })
  expectCode(t, () => encodeM3Object(accessorAuthSuffix), 'INVALID_ROUTE')
  t.is(authSuffixReads, 0)

  const nullPrototype = Object.assign(Object.create(null), { messageId, body })
  const decoded = decodeM3Object(encodeM3Object(nullPrototype))
  t.is(decoded.messageId, messageId)
  t.alike(decoded.body, body)
})

test('canonical M3 object envelope normalizes proxy descriptor traps', (t) => {
  const sentinel = new Error('hostile descriptor trap')
  let descriptorTraps = 0
  const hostile = new Proxy(
    {
      messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
      body: b4a.alloc(105)
    },
    {
      getOwnPropertyDescriptor() {
        descriptorTraps++
        throw sentinel
      }
    }
  )

  expectCode(t, () => encodeM3Object(hostile), 'INVALID_ROUTE')
  t.is(descriptorTraps, 1)
})

test('canonical M3 object envelope enforces every standalone layout boundary', (t) => {
  const fixtures = [
    [0x0001, 188, 476, 64],
    [0x0002, 110, 110, 0],
    [0x0003, 335, 4473, 64],
    [0x0004, 176, 176, 0],
    [0x0005, 272, 272, 64],
    [0x0006, 69, 69, 0],
    [0x0007, 41, 4441, 0],
    [0x0008, 48, 1192, 0],
    [0x0009, 72, 72, 0],
    [0x0020, 302, 302, 64],
    [0x0021, 213, 213, 64],
    [0x0022, 306, 306, 64],
    [0x0023, 486, 486, 0],
    [0x0024, 210, 210, 64],
    [0x0025, 458, 746, 0],
    [0x0026, 42, 42, 0],
    [0x0040, 96, 96, 0],
    [0x0041, 233, 233, 64],
    [0x0042, 105, 105, 0],
    [0x0043, 169, 169, 0],
    [0x0044, 905, 4265, 64],
    [0x0045, 310, 654, 64],
    [0x0050, 578, 738, 64],
    [0x0051, 124, 124, 16],
    [0x0052, 27, 1176, 16],
    [0x0053, 30, 1191, 0],
    [0x0054, 20, 8082, 0],
    [0x0100, 164, 164, 0],
    [0x0101, 221, 1382, 0],
    [0x0102, 200, 8262, 0],
    [0x0201, 141, 2891, 64],
    [0x0280, 132, 899, 64],
    [0x0281, 131, 131, 64],
    [0x0282, 206, 7990, 64],
    [0x0283, 72, 72, 0],
    [0x0284, 301, 301, 64]
  ]

  t.is(
    encodeM3Object({ messageId: 0x0044, body: b4a.alloc(905), authSuffix: b4a.alloc(64) })
      .byteLength,
    977
  )
  t.is(
    encodeM3Object({ messageId: 0x0044, body: b4a.alloc(4265), authSuffix: b4a.alloc(64) })
      .byteLength,
    4337
  )
  t.is(
    encodeM3Object({ messageId: 0x0045, body: b4a.alloc(310), authSuffix: b4a.alloc(64) })
      .byteLength,
    382
  )
  t.is(
    encodeM3Object({ messageId: 0x0045, body: b4a.alloc(654), authSuffix: b4a.alloc(64) })
      .byteLength,
    726
  )

  for (const [messageId, minimumBodyBytes, maximumBodyBytes, authBytes] of fixtures) {
    for (const bodyBytes of new Set([minimumBodyBytes, maximumBodyBytes])) {
      const encoded = encodeM3Object({
        messageId,
        body: b4a.alloc(bodyBytes),
        authSuffix: b4a.alloc(authBytes)
      })
      const decoded = decodeM3Object(encoded)
      t.is(decoded.messageId, messageId)
      t.is(decoded.body.byteLength, bodyBytes)
      t.is(decoded.authSuffix.byteLength, authBytes)
    }

    expectCode(
      t,
      () =>
        encodeM3Object({
          messageId,
          body: b4a.alloc(minimumBodyBytes - 1),
          authSuffix: b4a.alloc(authBytes)
        }),
      'INVALID_ROUTE'
    )
    expectCode(
      t,
      () =>
        encodeM3Object({
          messageId,
          body: b4a.alloc(maximumBodyBytes + 1),
          authSuffix: b4a.alloc(authBytes)
        }),
      'INVALID_ROUTE'
    )
  }
})

test('canonical M3 object envelope rejects invalid IDs, auth, body, overflow, and trailing bytes', (t) => {
  expectCode(t, () => encodeM3Object({ messageId: 0, body: b4a.alloc(0) }), 'INVALID_ROUTE')
  expectCode(t, () => encodeM3Object({ messageId: 0x0060, body: b4a.alloc(0) }), 'INVALID_ROUTE')
  expectCode(
    t,
    () => encodeM3Object({ messageId: M3_MESSAGE_ID.IMMUTABLE_GET_V1, body: b4a.alloc(32) }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
        body: forgedByteLength(b4a.alloc(104), 105)
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => encodeM3Object({ messageId: ROUTED_ERROR.BUSY, body: b4a.alloc(0) }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_V1,
        body: b4a.alloc(233),
        authSuffix: b4a.alloc(63)
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
        body: b4a.alloc(104)
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => encodeM3Object({ messageId: M3_MESSAGE_ID.CORE_FRAGMENT_V1, body: b4a.alloc(65_536) }),
    'INVALID_ROUTE'
  )

  const valid = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
    body: b4a.alloc(105)
  })
  const wrongVersion = b4a.from(valid)
  wrongVersion[3] = 2
  expectCode(t, () => decodeM3Object(wrongVersion), 'INVALID_ROUTE')

  const wrongBodyLength = b4a.from(valid)
  wrongBodyLength[7] = 104
  expectCode(t, () => decodeM3Object(wrongBodyLength), 'INVALID_ROUTE')
  expectCode(t, () => decodeM3Object(valid.subarray(0, valid.byteLength - 1)), 'INVALID_ROUTE')
  expectCode(t, () => decodeM3Object(b4a.concat([valid, b4a.from([0])])), 'INVALID_ROUTE')
})

test('canonical M3 object envelope rejects hostile objects and non-buffer views', (t) => {
  const sentinel = new Error('hostile getter')
  const hostile = {}
  Object.defineProperty(hostile, 'messageId', {
    get() {
      throw sentinel
    }
  })

  expectCode(t, () => encodeM3Object(hostile), 'INVALID_ROUTE')
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
        body: new Uint16Array(105)
      }),
    'INVALID_ROUTE'
  )
  expectCode(t, () => decodeM3Object(new Uint16Array(113)), 'INVALID_ROUTE')
})

test('canonical M3 object envelope uses intrinsic buffer extents and slicing', (t) => {
  const valid = encodeM3Object({
    messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
    body: b4a.alloc(105)
  })

  expectCode(
    t,
    () => decodeM3Object(forgedByteLength(b4a.concat([valid, b4a.alloc(1)]), valid.byteLength)),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () => decodeM3Object(forgedByteLength(b4a.from(valid.subarray(0, -1)), valid.byteLength)),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_ACK_V1,
        body: forgedByteLength(b4a.alloc(106), 105)
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_V1,
        body: b4a.alloc(233),
        authSuffix: forgedByteLength(b4a.alloc(63), 64)
      }),
    'INVALID_ROUTE'
  )
  expectCode(
    t,
    () =>
      encodeM3Object({
        messageId: M3_MESSAGE_ID.DHT_EXIT_READY_V1,
        body: b4a.alloc(233),
        authSuffix: forgedByteLength(b4a.alloc(65), 64)
      }),
    'INVALID_ROUTE'
  )
  t.alike(decodeM3Object(overriddenSubarray(b4a.from(valid))).body, b4a.alloc(105))
})
