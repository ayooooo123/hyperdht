'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const {
  DOMAIN,
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const {
  LinkDirectory,
  MAX_TOPOLOGY_AUTHORITIES,
  assembleTopologyGrantV1,
  decodeTopologyGrantV1,
  decodeUnsignedTopologyGrantV1,
  encodeUnsignedTopologyGrantV1,
  readLinkHandle,
  readVerifiedTopologyGrant,
  signTopologyGrant,
  signTopologyGrantV1,
  verifyTopologyGrantV1
} = require('../../lib/private/topology-grant')

const seed = (value) => b4a.alloc(32, value)

function expectCode(t, fn, code) {
  let error = null
  try {
    fn()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, `throws PrivateRouteError ${code}`)
  if (error) t.is(error.code, code)
}

function safetyRoleIdentity(start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('Unable to derive deterministic safety-role identity')
}

function fixture() {
  const guard = safetyRoleIdentity(40)
  const safety = safetyRoleIdentity(60)
  const guardAuthority = cryptoSuite.keyPair(seed(91))
  const safetyAuthority = cryptoSuite.keyPair(seed(92))
  const guardStatic = cryptoSuite.encryptionKeyPair(seed(93))
  const safetyStatic = cryptoSuite.encryptionKeyPair(seed(94))
  const grant = {
    version: PROTOCOL_VERSION,
    format: 1,
    grantId32: seed(17),
    endpointA: {
      identity32: guard.publicKey,
      role: TOPOLOGY_ROLE.SAFETY_GUARD,
      host: '192.0.2.1',
      port: 41001,
      operations: LINK_OPERATION.INITIATE,
      authority32: guardAuthority.publicKey,
      linkStaticKey32: guardStatic.publicKey
    },
    endpointB: {
      identity32: safety.publicKey,
      role: TOPOLOGY_ROLE.SAFETY_FINAL,
      host: '2001:db8::2',
      port: 41002,
      operations: LINK_OPERATION.ACCEPT,
      authority32: safetyAuthority.publicKey,
      linkStaticKey32: safetyStatic.publicKey
    },
    epoch: 7n,
    notBefore: 100n,
    expiresAt: 200n,
    runId32: seed(34)
  }
  return { guard, safety, guardAuthority, safetyAuthority, guardStatic, safetyStatic, grant }
}

function signBoth(f, unsigned = encodeUnsignedTopologyGrantV1(f.grant)) {
  const decoded = decodeUnsignedTopologyGrantV1(unsigned)
  const byKey = (authority32) =>
    b4a.equals(authority32, f.guardAuthority.publicKey) ? f.guardAuthority : f.safetyAuthority
  const signatureA = signTopologyGrantV1(unsigned, byKey(decoded.endpointA.authority32))
  const signatureB = signTopologyGrantV1(unsigned, byKey(decoded.endpointB.authority32))
  return assembleTopologyGrantV1(unsigned, signatureA, signatureB)
}

function directory(localIdentity32, localRole, authorityPublicKeys, f, overrides = {}) {
  return new LinkDirectory({
    localIdentity32,
    localRole,
    authorityPublicKeys,
    epoch: f.grant.epoch,
    runId32: f.grant.runId32,
    now: () => 150n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {},
    ...overrides
  })
}

test('format 1 grant has pinned canonical bytes and domain-separated signatures', (t) => {
  const f = fixture()
  const unsigned = encodeUnsignedTopologyGrantV1(f.grant)
  // v0 layout (IPv4 + IPv6 endpoints = 187 bytes) plus two 64-byte extensions.
  t.is(unsigned.byteLength, 187 + 128)
  t.is(unsigned[4], 1, 'format byte')
  t.is(b4a.toString(DOMAIN.TOPOLOGY_GRANT_V1), 'hyperdht-private-routes/topology-grant/v1')

  const swapped = encodeUnsignedTopologyGrantV1({
    ...f.grant,
    endpointA: f.grant.endpointB,
    endpointB: f.grant.endpointA
  })
  t.alike(swapped, unsigned, 'endpoint order is canonical, not caller order')
  t.is(
    b4a.toString(cryptoSuite.hash(unsigned), 'hex'),
    'd1423e2d8031244678163de2e38a64574a2d6d604fa2b765d123ae0256832958',
    'known-answer unsigned bytes'
  )

  const signed = signBoth(f)
  t.is(signed.byteLength, unsigned.byteLength + 128)
  const decoded = decodeTopologyGrantV1(signed)
  const digest = cryptoSuite.hash([DOMAIN.TOPOLOGY_GRANT_V1, unsigned])
  t.is(
    b4a.toString(digest, 'hex'),
    'e8f97d66d10029d84e6acd9b04fbf63ea2fcb2711e4c4271999911fb1cc7e3ed',
    'known-answer signed digest'
  )
  t.ok(cryptoSuite.verify(digest, decoded.signatureA, decoded.endpointA.authority32))
  t.ok(cryptoSuite.verify(digest, decoded.signatureB, decoded.endpointB.authority32))
})

test('both ends admit one identical grant, each under its own configured authority', (t) => {
  const f = fixture()
  const signed = signBoth(f)
  const guardDir = directory(
    f.guard.publicKey,
    TOPOLOGY_ROLE.SAFETY_GUARD,
    [f.guardAuthority.publicKey],
    f
  )
  const safetyDir = directory(
    f.safety.publicKey,
    TOPOLOGY_ROLE.SAFETY_FINAL,
    [f.safetyAuthority.publicKey],
    f
  )
  t.teardown(() => {
    guardDir.destroy()
    safetyDir.destroy()
  })

  const guardDigest = guardDir.add(signed)
  const safetyDigest = safetyDir.add(signed)
  t.alike(guardDigest, safetyDigest, 'NAT punch plans can bind one shared grant digest')

  const guardHandle = guardDir.authorize({
    digest32: guardDigest,
    operation: LINK_OPERATION.INITIATE,
    localIdentity32: f.guard.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: f.safety.publicKey,
    peerRole: TOPOLOGY_ROLE.SAFETY_FINAL,
    epoch: f.grant.epoch,
    runId32: f.grant.runId32
  })
  const link = readLinkHandle(guardHandle)
  t.alike(link.peerIdentity32, f.safety.publicKey)
  t.alike(link.peerAddress, { family: 6, host: '2001:db8::2', port: 41002 })

  const view = readVerifiedTopologyGrant(
    verifyTopologyGrantV1(signed, [f.guardAuthority.publicKey], {
      localIdentity32: f.guard.publicKey,
      now: 150n
    })
  )
  t.is(view.format, 1)
  t.alike(view.peer.linkStaticKey32, f.safetyStatic.publicKey, 'dialer learns the signed key')
  t.alike(view.local.authority32, f.guardAuthority.publicKey)
})

test('a node rejects a fully signed grant unless its own side authority is configured', (t) => {
  const f = fixture()
  const signed = signBoth(f)
  const options = { localIdentity32: f.guard.publicKey, now: 150n }
  expectCode(
    t,
    () => verifyTopologyGrantV1(signed, [f.safetyAuthority.publicKey], options),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () => verifyTopologyGrantV1(signed, [cryptoSuite.keyPair(seed(99)).publicKey], options),
    'UNAUTHORIZED'
  )
  t.ok(
    verifyTopologyGrantV1(
      signed,
      [cryptoSuite.keyPair(seed(99)).publicKey, f.guardAuthority.publicKey],
      options
    ),
    'a larger configured set that includes the local authority admits'
  )
})

test('one-sided or misattributed signatures never assemble or verify', (t) => {
  const f = fixture()
  const unsigned = encodeUnsignedTopologyGrantV1(f.grant)
  const signed = signBoth(f, unsigned)
  const decoded = decodeTopologyGrantV1(signed)
  const outsider = cryptoSuite.keyPair(seed(99))

  expectCode(t, () => signTopologyGrantV1(unsigned, outsider), 'UNAUTHORIZED')
  expectCode(
    t,
    () =>
      signTopologyGrantV1(unsigned, {
        publicKey: f.guardAuthority.publicKey,
        secretKey: outsider.secretKey
      }),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () => assembleTopologyGrantV1(unsigned, decoded.signatureA, decoded.signatureA),
    'UNAUTHORIZED'
  )
  expectCode(
    t,
    () => assembleTopologyGrantV1(unsigned, decoded.signatureB, decoded.signatureA),
    'UNAUTHORIZED'
  )

  // A signature over the v0 domain must not satisfy v1.
  const v0Digest = cryptoSuite.hash([DOMAIN.TOPOLOGY_GRANT, unsigned])
  const crossA = cryptoSuite.sign(v0Digest, f.guardAuthority.secretKey)
  const crossB = cryptoSuite.sign(v0Digest, f.safetyAuthority.secretKey)
  const [first, second] = b4a.equals(decoded.endpointA.authority32, f.guardAuthority.publicKey)
    ? [crossA, crossB]
    : [crossB, crossA]
  expectCode(t, () => assembleTopologyGrantV1(unsigned, first, second), 'UNAUTHORIZED')
})

test('one operator authority may sign both sides of a grant', (t) => {
  const f = fixture()
  f.grant.endpointB = { ...f.grant.endpointB, authority32: f.guardAuthority.publicKey }
  const unsigned = encodeUnsignedTopologyGrantV1(f.grant)
  const signature = signTopologyGrantV1(unsigned, f.guardAuthority)
  const signed = assembleTopologyGrantV1(unsigned, signature, signature)
  t.ok(
    verifyTopologyGrantV1(signed, [f.guardAuthority.publicKey], {
      localIdentity32: f.safety.publicKey,
      now: 150n
    })
  )
})

test('every one-byte mutation of a signed format 1 grant is rejected', (t) => {
  const f = fixture()
  const signed = signBoth(f)
  const authorities = [f.guardAuthority.publicKey, f.safetyAuthority.publicKey]
  let accepted = 0
  for (let index = 0; index < signed.byteLength; index++) {
    const mutated = b4a.from(signed)
    mutated[index] ^= 0x01
    try {
      verifyTopologyGrantV1(mutated, authorities, { localIdentity32: f.guard.publicKey, now: 150n })
      accepted++
    } catch (err) {
      if (!(err instanceof PrivateRouteError)) throw err
    }
  }
  t.is(accepted, 0)
  expectCode(
    t,
    () =>
      verifyTopologyGrantV1(signed.subarray(0, signed.byteLength - 1), authorities, {
        localIdentity32: f.guard.publicKey,
        now: 150n
      }),
    'INVALID_ROUTE'
  )
})

test('format 0 and format 1 directories each refuse the other format', (t) => {
  const f = fixture()
  const signedV1 = signBoth(f)
  const v1Dir = directory(
    f.guard.publicKey,
    TOPOLOGY_ROLE.SAFETY_GUARD,
    [f.guardAuthority.publicKey],
    f
  )
  const v0Dir = new LinkDirectory({
    localIdentity32: f.guard.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    authorityPublicKey: f.guardAuthority.publicKey,
    epoch: f.grant.epoch,
    runId32: f.grant.runId32,
    now: () => 150n,
    schedule: setTimeout,
    cancel: clearTimeout,
    onClose() {}
  })
  t.teardown(() => {
    v1Dir.destroy()
    v0Dir.destroy()
  })

  const v0Grant = { ...f.grant, format: 0 }
  for (const side of ['endpointA', 'endpointB']) {
    const { authority32, linkStaticKey32, ...rest } = v0Grant[side]
    v0Grant[side] = rest
  }
  const signedV0 = signTopologyGrant(v0Grant, f.guardAuthority.secretKey)

  expectCode(t, () => v0Dir.add(signedV1), 'INVALID_ROUTE')
  expectCode(t, () => v1Dir.add(signedV0), 'INVALID_ROUTE')
  t.ok(v0Dir.add(signedV0), 'format 0 path is unchanged')
})

test('directory authority configuration is exact, bounded and duplicate-free', (t) => {
  const f = fixture()
  const key = f.guardAuthority.publicKey
  const make = (overrides) => () =>
    directory(f.guard.publicKey, TOPOLOGY_ROLE.SAFETY_GUARD, [key], f, overrides)

  expectCode(t, make({ authorityPublicKey: key }), 'INVALID_ROUTE')
  expectCode(t, make({ authorityPublicKeys: undefined }), 'INVALID_ROUTE')
  expectCode(t, make({ authorityPublicKeys: [] }), 'INVALID_ROUTE')
  expectCode(t, make({ authorityPublicKeys: [key, b4a.from(key)] }), 'INVALID_ROUTE')
  expectCode(t, make({ authorityPublicKeys: [b4a.alloc(32)] }), 'INVALID_ROUTE')
  const tooMany = Array.from(
    { length: MAX_TOPOLOGY_AUTHORITIES + 1 },
    (_, index) => cryptoSuite.keyPair(seed(150 + index)).publicKey
  )
  expectCode(t, make({ authorityPublicKeys: tooMany }), 'INVALID_ROUTE')
})

test('format 1 endpoints require nonzero authority and link static keys', (t) => {
  const f = fixture()
  for (const field of ['authority32', 'linkStaticKey32']) {
    expectCode(
      t,
      () =>
        encodeUnsignedTopologyGrantV1({
          ...f.grant,
          endpointA: { ...f.grant.endpointA, [field]: b4a.alloc(32) }
        }),
      'INVALID_ROUTE'
    )
  }
  const { linkStaticKey32, ...missing } = f.grant.endpointA
  expectCode(
    t,
    () => encodeUnsignedTopologyGrantV1({ ...f.grant, endpointA: missing }),
    'INVALID_ROUTE'
  )
})
