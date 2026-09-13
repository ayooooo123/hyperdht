'use strict'

const test = require('brittle')
const b4a = require('b4a')

const {
  EXIT_ORIGIN_SERVICE_POLICY,
  SERVICE_POLICY_ENTRY_SIZE,
  decodeExitOriginServicePolicy,
  digestExitOriginServicePolicy,
  encodeExitOriginServicePolicy
} = require('../../lib/private/exit-policy')
const { PrivateRouteError } = require('../../lib/private/errors')

const EXPECTED_DIGEST = '61445e852f5e70095e836e2c1128cc1c024a15784406a476990279fe7094610b'
const EXPECTED_POLICY = Object.freeze([
  [0x0120, 1, 32, 4706, 3000, 10, 1, 2, 4445, 0, 1],
  [0x0121, 1, 1090, 209, 3000, 5, 3, 1, 0, 1, 1],
  [0x0122, 1, 40, 4650, 3000, 10, 1, 2, 4381, 0, 1],
  [0x0123, 1, 1066, 209, 3000, 5, 3, 1, 0, 1, 1],
  [0x0200, 1, 69, 4031, 5000, 3, 2, 8, 3733, 0, 2],
  [0x02a0, 1, 134, 8270, 5000, 3, 2, 12, 7907, 0, 2],
  [0x02a1, 1, 189, 288, 3000, 5, 3, 2, 0, 1, 2],
  [0x02a2, 1, 1161, 581, 5000, 5, 5, 3, 0, 1, 2],
  [0x02a3, 1, 393, 581, 5000, 5, 5, 3, 0, 1, 2]
])
const FIELDS = Object.freeze([
  'commandId',
  'commandVersion',
  'maxRequestBytes',
  'maxResponseBytes',
  'timeoutMs',
  'maxOutstanding',
  'requestCost',
  'responseCost',
  'maxAmplificationBytes',
  'mutationFlag',
  'destinationValidationClass'
])

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

function u16(value) {
  return b4a.from([value >>> 8, value])
}

function u32(value) {
  return b4a.from([value >>> 24, value >>> 16, value >>> 8, value])
}

function expectedEntries() {
  return EXPECTED_POLICY.map((values) => {
    const entry = {}
    for (let index = 0; index < FIELDS.length; index++) entry[FIELDS[index]] = values[index]
    return entry
  })
}

function expectedEncoding() {
  const entries = EXPECTED_POLICY.map((value) =>
    b4a.concat([
      u16(value[0]),
      u16(value[1]),
      u32(value[2]),
      u32(value[3]),
      u32(value[4]),
      u16(value[5]),
      u32(value[6]),
      u32(value[7]),
      u32(value[8]),
      b4a.from([value[9], value[10]])
    ])
  )
  return b4a.concat([u16(entries.length), ...entries])
}

test('exit-origin policy is the exact frozen nine-command table', (t) => {
  t.is(SERVICE_POLICY_ENTRY_SIZE, 32)
  t.is(EXIT_ORIGIN_SERVICE_POLICY.length, 9)
  t.ok(Object.isFrozen(EXIT_ORIGIN_SERVICE_POLICY))
  t.alike(EXIT_ORIGIN_SERVICE_POLICY, expectedEntries())

  for (const entry of EXIT_ORIGIN_SERVICE_POLICY) t.ok(Object.isFrozen(entry))
})

test('exit-origin policy has canonical bytes, digest, and frozen decoded values', (t) => {
  const expected = expectedEncoding()
  const encoded = encodeExitOriginServicePolicy()
  const decoded = decodeExitOriginServicePolicy(encoded)

  t.is(encoded.byteLength, 2 + 9 * SERVICE_POLICY_ENTRY_SIZE)
  t.alike(encoded, expected)
  t.alike(decoded, expectedEntries())
  t.ok(Object.isFrozen(decoded))
  for (const entry of decoded) t.ok(Object.isFrozen(entry))
  t.alike(digestExitOriginServicePolicy(), b4a.from(EXPECTED_DIGEST, 'hex'))
  t.alike(digestExitOriginServicePolicy(encoded), b4a.from(EXPECTED_DIGEST, 'hex'))

  encoded.fill(0)
  t.alike(EXIT_ORIGIN_SERVICE_POLICY, expectedEntries())
  t.alike(decoded, expectedEntries())
})

test('exit-origin policy rejects every changed field and noncanonical encoding', (t) => {
  for (let entryIndex = 0; entryIndex < EXPECTED_POLICY.length; entryIndex++) {
    for (const field of FIELDS) {
      const changed = expectedEntries()
      changed[entryIndex][field]++
      expectCode(t, () => encodeExitOriginServicePolicy(changed), 'INVALID_ROUTE')
    }
  }

  const encoded = expectedEncoding()
  const cases = [
    b4a.from(encoded.subarray(0, -1)),
    b4a.concat([encoded, b4a.from([0])]),
    b4a.from(encoded)
  ]
  cases[2][0] = 0
  cases[2][1] = 8
  for (const value of cases) {
    expectCode(t, () => decodeExitOriginServicePolicy(value), 'INVALID_ROUTE')
    expectCode(t, () => digestExitOriginServicePolicy(value), 'INVALID_ROUTE')
  }

  const changed = b4a.from(encoded)
  changed[2 + 8] ^= 1
  expectCode(t, () => decodeExitOriginServicePolicy(changed), 'INVALID_ROUTE')
})

test('exit-origin encoder accepts own data only and never invokes accessors', (t) => {
  const accessorEntries = expectedEntries()
  let reads = 0
  Object.defineProperty(accessorEntries[0], 'commandId', {
    get() {
      reads++
      return 0x0120
    }
  })
  expectCode(t, () => encodeExitOriginServicePolicy(accessorEntries), 'INVALID_ROUTE')
  t.is(reads, 0)

  const inheritedEntries = expectedEntries()
  const inherited = Object.create(inheritedEntries[0])
  inheritedEntries[0] = inherited
  expectCode(t, () => encodeExitOriginServicePolicy(inheritedEntries), 'INVALID_ROUTE')

  const trappedEntries = expectedEntries()
  trappedEntries[0] = new Proxy(trappedEntries[0], {
    getOwnPropertyDescriptor() {
      throw new Error('descriptor trap')
    }
  })
  expectCode(t, () => encodeExitOriginServicePolicy(trappedEntries), 'INVALID_ROUTE')

  const revoked = Proxy.revocable(expectedEntries()[0], {})
  const revokedEntries = expectedEntries()
  revokedEntries[0] = revoked.proxy
  revoked.revoke()
  expectCode(t, () => encodeExitOriginServicePolicy(revokedEntries), 'INVALID_ROUTE')
})

test('policy digest uses one owned snapshot across validation and hashing', (t) => {
  const expected = b4a.from(EXPECTED_DIGEST, 'hex')
  const canonical = expectedEncoding()
  const shared = new Uint8Array(new SharedArrayBuffer(canonical.byteLength))
  Uint8Array.prototype.set.call(shared, canonical)
  const isBuffer = Buffer.isBuffer
  let originalChecks = 0
  let snapshot = null
  let snapshotChecks = 0
  let mutations = 0

  Buffer.isBuffer = function (value) {
    const result = isBuffer.call(Buffer, value)
    if (value === shared) {
      originalChecks++
      if (originalChecks === 3 && mutations === 0) {
        mutations++
        shared[10] ^= 1
      }
    } else if (value && value.byteLength === shared.byteLength) {
      if (snapshot === null) snapshot = value
      if (value === snapshot) {
        snapshotChecks++
        if (snapshotChecks === 2 && mutations === 0) {
          mutations++
          shared[10] ^= 1
        }
      }
    }
    return result
  }

  let actual
  try {
    actual = digestExitOriginServicePolicy(shared)
  } finally {
    Buffer.isBuffer = isBuffer
  }

  t.is(mutations, 1)
  t.alike(actual, expected)
})
