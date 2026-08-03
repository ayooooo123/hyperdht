'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PrivateRouteError } = require('../../lib/private/errors')
const signer = require('../../lib/private/relay-identity-signer')

const {
  createRelayIdentitySigningAuthority,
  createLinkOfferSigner,
  createDhtExitReadySigner,
  signLinkOffer,
  destroyLinkOfferSigner,
  createExtensionResponderSigner,
  signLinkAccept,
  signRedactedResponderProof,
  destroyExtensionResponderSigner,
  createTailReadySigner,
  signTailReady,
  signDhtExitReady,
  destroyTailReadySigner,
  destroyDhtExitReadySigner,
  destroyRelayIdentitySigningAuthority
} = signer

const REGISTERED = Object.freeze({
  linkOffer: Object.freeze({
    domain: 'hyperdht-private-routes/m3/link-offer/v1',
    messageId: 0x0020,
    bodyLength: 302
  }),
  linkAccept: Object.freeze({
    domain: 'hyperdht-private-routes/m3/link-accept/v1',
    messageId: 0x0021,
    bodyLength: 213
  }),
  redactedResponderProof: Object.freeze({
    domain: 'hyperdht-private-routes/m3/redacted-responder-proof/v1',
    messageId: 0x0022,
    bodyLength: 306
  }),
  tailReady: Object.freeze({
    domain: 'hyperdht-private-routes/m3/tail-ready/v1',
    messageId: 0x0024,
    bodyLength: 210
  }),
  dhtExitReady: Object.freeze({
    domain: 'hyperdht-private-routes/m3/dht-exit-ready/v1',
    messageId: 0x0041,
    bodyLength: 233
  })
})

function bytes(size, value) {
  return b4a.alloc(size, value)
}

function signatureInput(registration, body) {
  const domain = b4a.from(registration.domain)
  const input = b4a.allocUnsafeSlow(10 + domain.byteLength + body.byteLength)
  input[0] = domain.byteLength >>> 8
  input[1] = domain.byteLength
  input.set(domain, 2)
  const versionOffset = 2 + domain.byteLength
  input[versionOffset] = 0
  input[versionOffset + 1] = 0
  input[versionOffset + 2] = 0
  input[versionOffset + 3] = 1
  const messageOffset = versionOffset + 4
  input[messageOffset] = registration.messageId >>> 8
  input[messageOffset + 1] = registration.messageId
  const bodyLengthOffset = messageOffset + 2
  input[bodyLengthOffset] = body.byteLength >>> 8
  input[bodyLengthOffset + 1] = body.byteLength
  input.set(body, bodyLengthOffset + 2)
  return input
}

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, message)
  t.is(error && error.code, code, message)
}

function assertOpaque(t, capability, message) {
  t.ok(Object.isFrozen(capability), `${message} is frozen`)
  t.alike(Object.getOwnPropertyNames(capability), [], `${message} has no named properties`)
  t.alike(Object.getOwnPropertySymbols(capability), [], `${message} has no symbol properties`)
}

function fixture() {
  const identity = cryptoSuite.keyPair()
  const authority = createRelayIdentitySigningAuthority({
    identitySecretKey: identity.secretKey
  })
  return { identity, authority }
}

test('relay identity signer exposes only the approved private surface', (t) => {
  t.alike(Object.keys(signer).sort(), [
    'createDhtExitReadySigner',
    'createExtensionResponderSigner',
    'createLinkOfferSigner',
    'createRelayIdentitySigningAuthority',
    'createTailReadySigner',
    'destroyDhtExitReadySigner',
    'destroyExtensionResponderSigner',
    'destroyLinkOfferSigner',
    'destroyRelayIdentitySigningAuthority',
    'destroyTailReadySigner',
    'signDhtExitReady',
    'signLinkAccept',
    'signLinkOffer',
    'signRedactedResponderProof',
    'signTailReady'
  ])
})

test('relay identity authority accepts one exact own-data 64-byte secret option', (t) => {
  const identity = cryptoSuite.keyPair()
  const snapshot = b4a.from(identity.secretKey)
  const malformed = [
    [null, 'INVALID_ROUTE'],
    [undefined, 'INVALID_ROUTE'],
    [{}, 'INVALID_ROUTE'],
    [[], 'INVALID_ROUTE'],
    [{ identitySecretKey: identity.secretKey, extra: true }, 'INVALID_ROUTE'],
    [Object.create({ identitySecretKey: identity.secretKey }), 'INVALID_ROUTE'],
    [{ identitySecretKey: bytes(32, 0x10) }, 'INVALID_KEY'],
    [{ identitySecretKey: bytes(63, 0x11) }, 'INVALID_KEY'],
    [{ identitySecretKey: bytes(65, 0x12) }, 'INVALID_KEY'],
    [{ identitySecretKey: 'not-a-key' }, 'INVALID_KEY']
  ]

  for (const [options, code] of malformed) {
    expectCode(
      t,
      () => createRelayIdentitySigningAuthority(options),
      code,
      'malformed options fail closed'
    )
  }

  let reads = 0
  const accessor = {}
  Object.defineProperty(accessor, 'identitySecretKey', {
    enumerable: true,
    get() {
      reads++
      return identity.secretKey
    }
  })
  expectCode(
    t,
    () => createRelayIdentitySigningAuthority(accessor),
    'INVALID_ROUTE',
    'accessor option is rejected'
  )
  t.is(reads, 0, 'constructor never invokes an option accessor')

  const symbolOption = { identitySecretKey: identity.secretKey }
  symbolOption[Symbol('extra')] = true
  expectCode(
    t,
    () => createRelayIdentitySigningAuthority(symbolOption),
    'INVALID_ROUTE',
    'symbol option is rejected'
  )

  const nullPrototype = Object.create(null)
  Object.defineProperty(nullPrototype, 'identitySecretKey', {
    configurable: true,
    enumerable: true,
    writable: true,
    value: identity.secretKey
  })
  const authority = createRelayIdentitySigningAuthority(nullPrototype)
  t.alike(identity.secretKey, snapshot, 'successful construction does not modify the caller secret')
  t.is(destroyRelayIdentitySigningAuthority(authority), true)
  t.alike(identity.secretKey, snapshot, 'authority destruction does not modify the caller secret')
})

test('relay identity authority rejects a 64-byte secret with inconsistent seed and public halves', (t) => {
  const identity = cryptoSuite.keyPair()
  const inconsistent = b4a.from(identity.secretKey)
  inconsistent[0] ^= 1
  const snapshot = b4a.from(inconsistent)

  t.alike(
    inconsistent.subarray(32),
    identity.publicKey,
    'fixture preserves the embedded public identity while changing the seed'
  )
  expectCode(
    t,
    () => createRelayIdentitySigningAuthority({ identitySecretKey: inconsistent }),
    'INVALID_KEY',
    'inconsistent Ed25519 secret is rejected before authority publication'
  )
  t.alike(inconsistent, snapshot, 'failed validation leaves the caller secret unchanged')
})

test('relay identity owner and all child signers are empty frozen capabilities', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const extension = createExtensionResponderSigner(f.authority)
  const tail = createTailReadySigner(f.authority)
  const dhtExitReady = createDhtExitReadySigner(f.authority)

  assertOpaque(t, f.authority, 'identity owner')
  assertOpaque(t, link, 'LINK_OFFER signer')
  assertOpaque(t, extension, 'extension responder signer')
  assertOpaque(t, tail, 'TAIL_READY signer')
  assertOpaque(t, dhtExitReady, 'DHT_EXIT_READY signer')
  t.not(link, extension)
  t.not(extension, tail)
  t.not(link, tail)
  t.not(tail, dhtExitReady)

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('relay identity signatures bind the four exact registry domains, ids, and body lengths', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const extension = createExtensionResponderSigner(f.authority)
  const tail = createTailReadySigner(f.authority)
  const dhtExitReady = createDhtExitReadySigner(f.authority)
  const bodies = {
    linkOffer: bytes(REGISTERED.linkOffer.bodyLength, 0x21),
    linkAccept: bytes(REGISTERED.linkAccept.bodyLength, 0x22),
    redactedResponderProof: bytes(REGISTERED.redactedResponderProof.bodyLength, 0x23),
    tailReady: bytes(REGISTERED.tailReady.bodyLength, 0x24),
    dhtExitReady: bytes(REGISTERED.dhtExitReady.bodyLength, 0x25)
  }
  const snapshots = Object.fromEntries(
    Object.entries(bodies).map(([name, body]) => [name, b4a.from(body)])
  )
  const expectedIdentity = b4a.from(f.identity.publicKey)
  const expectedSnapshot = b4a.from(expectedIdentity)
  const signatures = {
    linkOffer: signLinkOffer(link, bodies.linkOffer, expectedIdentity),
    linkAccept: signLinkAccept(extension, bodies.linkAccept, expectedIdentity),
    redactedResponderProof: signRedactedResponderProof(
      extension,
      bodies.redactedResponderProof,
      expectedIdentity
    ),
    tailReady: signTailReady(tail, bodies.tailReady, expectedIdentity),
    dhtExitReady: signDhtExitReady(dhtExitReady, bodies.dhtExitReady, expectedIdentity)
  }

  for (const [name, registration] of Object.entries(REGISTERED)) {
    const input = signatureInput(registration, bodies[name])
    t.is(signatures[name].byteLength, 64, `${name} returns one Ed25519 signature`)
    t.ok(
      cryptoSuite.verify(input, signatures[name], f.identity.publicKey),
      `${name} verifies against the independently framed registry input`
    )
    const wrongId = b4a.from(input)
    wrongId[7 + b4a.byteLength(registration.domain)] ^= 1
    t.is(
      cryptoSuite.verify(wrongId, signatures[name], f.identity.publicKey),
      false,
      `${name} does not verify with a different registered message id`
    )
    t.alike(bodies[name], snapshots[name], `${name} leaves its caller body unchanged`)
  }
  t.alike(
    expectedIdentity,
    expectedSnapshot,
    'all sign operations leave expectedIdentity unchanged'
  )

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('relay identity signing rejects wrong lengths and a 378-byte redacted object without spending signers', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const extension = createExtensionResponderSigner(f.authority)
  const tail = createTailReadySigner(f.authority)
  const dhtExitReady = createDhtExitReadySigner(f.authority)

  expectCode(
    t,
    () => signLinkOffer(link, bytes(301, 0x31), f.identity.publicKey),
    'INVALID_ROUTE',
    'LINK_OFFER requires exactly 302 body bytes'
  )
  expectCode(
    t,
    () => signLinkAccept(extension, bytes(214, 0x32), f.identity.publicKey),
    'INVALID_ROUTE',
    'LINK_ACCEPT requires exactly 213 body bytes'
  )
  expectCode(
    t,
    () => signTailReady(tail, bytes(211, 0x33), f.identity.publicKey),
    'INVALID_ROUTE',
    'TAIL_READY requires exactly 210 body bytes'
  )
  expectCode(
    t,
    () => signDhtExitReady(dhtExitReady, bytes(234, 0x39), f.identity.publicKey),
    'INVALID_ROUTE',
    'DHT_EXIT_READY requires exactly 233 body bytes'
  )

  const accept = bytes(213, 0x34)
  signLinkAccept(extension, accept, f.identity.publicKey)
  expectCode(
    t,
    () => signRedactedResponderProof(extension, bytes(378, 0x35), f.identity.publicKey),
    'INVALID_ROUTE',
    'full encoded redacted object is rejected where the 306-byte body is required'
  )

  t.is(signLinkOffer(link, bytes(302, 0x36), f.identity.publicKey).byteLength, 64)
  t.is(signRedactedResponderProof(extension, bytes(306, 0x37), f.identity.publicKey).byteLength, 64)
  t.is(signTailReady(tail, bytes(210, 0x38), f.identity.publicKey).byteLength, 64)
  t.is(signDhtExitReady(dhtExitReady, bytes(233, 0x3a), f.identity.publicKey).byteLength, 64)

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('expected relay identity must match and mismatch does not consume the signer', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const body = bytes(302, 0x41)
  const otherIdentity = cryptoSuite.keyPair().publicKey

  expectCode(
    t,
    () => signLinkOffer(link, body, otherIdentity),
    'ERR_AUTHENTICATION',
    'different 32-byte identity is rejected'
  )
  expectCode(
    t,
    () => signLinkOffer(link, body, bytes(31, 0x42)),
    'ERR_AUTHENTICATION',
    'malformed expected identity is rejected'
  )
  t.is(signLinkOffer(link, body, f.identity.publicKey).byteLength, 64)

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('expected identity comparison never invokes a caller equals hook or its reentrant destroy', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const body = bytes(302, 0x43)
  const wrongIdentity = b4a.from(cryptoSuite.keyPair().publicKey)
  let hooks = 0
  Object.defineProperty(wrongIdentity, 'equals', {
    value() {
      hooks++
      destroyLinkOfferSigner(link)
      return true
    }
  })

  expectCode(
    t,
    () => signLinkOffer(link, body, wrongIdentity),
    'ERR_AUTHENTICATION',
    'hooked wrong identity cannot authenticate'
  )
  t.is(hooks, 0, 'identity comparison does not dispatch to caller methods')
  t.is(
    signLinkOffer(link, body, f.identity.publicKey).byteLength,
    64,
    'rejected identity does not destroy or spend the signer'
  )

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('expected identity comparison never invokes a caller byteLength getter', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const body = bytes(302, 0x45)
  const wrongIdentity = b4a.from(cryptoSuite.keyPair().publicKey)
  let hooks = 0
  Object.defineProperty(wrongIdentity, 'byteLength', {
    get() {
      hooks++
      destroyLinkOfferSigner(link)
      return 32
    }
  })

  expectCode(
    t,
    () => signLinkOffer(link, body, wrongIdentity),
    'ERR_AUTHENTICATION',
    'wrong identity with a byteLength getter cannot authenticate'
  )
  t.is(hooks, 0, 'identity comparison does not read caller-owned properties')
  t.is(
    signLinkOffer(link, body, f.identity.publicKey).byteLength,
    64,
    'rejected getter-bearing identity does not destroy or spend the signer'
  )

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('semantic retry comparison never invokes a caller equals hook or accepts different bytes', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const body = bytes(302, 0x44)
  const first = signLinkOffer(link, body, f.identity.publicKey)
  const different = b4a.from(body)
  different[0] ^= 1
  let hooks = 0
  Object.defineProperty(different, 'equals', {
    value() {
      hooks++
      return true
    }
  })

  expectCode(
    t,
    () => signLinkOffer(link, different, f.identity.publicKey),
    'ERR_REPLAY',
    'hooked different body cannot reuse the cached signature'
  )
  t.is(hooks, 0, 'semantic comparison does not dispatch to caller methods')
  t.alike(
    signLinkOffer(link, b4a.from(body), f.identity.publicKey),
    first,
    'rejected different body leaves the exact retry cache available'
  )

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('single-phase signers retry only the same owned semantic body and return fresh signature copies', (t) => {
  const f = fixture()
  const cases = [
    {
      name: 'LINK_OFFER',
      registration: REGISTERED.linkOffer,
      capability: createLinkOfferSigner(f.authority),
      sign: signLinkOffer
    },
    {
      name: 'TAIL_READY',
      registration: REGISTERED.tailReady,
      capability: createTailReadySigner(f.authority),
      sign: signTailReady
    },
    {
      name: 'DHT_EXIT_READY',
      registration: REGISTERED.dhtExitReady,
      capability: createDhtExitReadySigner(f.authority),
      sign: signDhtExitReady
    }
  ]

  for (const entry of cases) {
    const body = bytes(entry.registration.bodyLength, 0x51)
    const snapshot = b4a.from(body)
    const first = entry.sign(entry.capability, body, f.identity.publicKey)
    first.fill(0)
    body.fill(0x52)
    const retry = entry.sign(entry.capability, snapshot, f.identity.publicKey)
    t.not(first, retry, `${entry.name} retry returns a fresh allocation`)
    t.ok(
      cryptoSuite.verify(signatureInput(entry.registration, snapshot), retry, f.identity.publicKey),
      `${entry.name} retry is a valid cached signature`
    )
    retry.fill(0)
    const secondRetry = entry.sign(entry.capability, snapshot, f.identity.publicKey)
    t.ok(
      cryptoSuite.verify(
        signatureInput(entry.registration, snapshot),
        secondRetry,
        f.identity.publicKey
      ),
      `${entry.name} cached signature is isolated from caller mutation`
    )
    expectCode(
      t,
      () => entry.sign(entry.capability, body, f.identity.publicKey),
      'ERR_REPLAY',
      `${entry.name} rejects a different semantic body`
    )
    t.alike(
      body,
      bytes(entry.registration.bodyLength, 0x52),
      `${entry.name} leaves retry input unchanged`
    )
  }

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('extension responder signer enforces LINK_ACCEPT then proof and permits exact retries of both phases', (t) => {
  const f = fixture()
  const extension = createExtensionResponderSigner(f.authority)
  const accept = bytes(213, 0x61)
  const differentAccept = bytes(213, 0x62)
  const proof = bytes(306, 0x63)
  const differentProof = bytes(306, 0x64)

  expectCode(
    t,
    () => signRedactedResponderProof(extension, proof, f.identity.publicKey),
    'ERR_REPLAY',
    'proof cannot be signed before LINK_ACCEPT'
  )

  const acceptSignature = signLinkAccept(extension, accept, f.identity.publicKey)
  const acceptRetry = signLinkAccept(extension, b4a.from(accept), f.identity.publicKey)
  t.not(acceptSignature, acceptRetry, 'LINK_ACCEPT retry returns a fresh signature copy')
  t.alike(acceptSignature, acceptRetry, 'LINK_ACCEPT retry uses the cached semantic signature')
  expectCode(
    t,
    () => signLinkAccept(extension, differentAccept, f.identity.publicKey),
    'ERR_REPLAY',
    'different LINK_ACCEPT is rejected'
  )

  const proofSignature = signRedactedResponderProof(extension, proof, f.identity.publicKey)
  const proofRetry = signRedactedResponderProof(extension, b4a.from(proof), f.identity.publicKey)
  t.not(proofSignature, proofRetry, 'proof retry returns a fresh signature copy')
  t.alike(proofSignature, proofRetry, 'proof retry uses the cached semantic signature')
  t.alike(
    signLinkAccept(extension, b4a.from(accept), f.identity.publicKey),
    acceptSignature,
    'exact LINK_ACCEPT retries remain available after proof signing'
  )
  expectCode(
    t,
    () => signLinkAccept(extension, differentAccept, f.identity.publicKey),
    'ERR_REPLAY',
    'completed signer rejects a different LINK_ACCEPT'
  )
  expectCode(
    t,
    () => signRedactedResponderProof(extension, differentProof, f.identity.publicKey),
    'ERR_REPLAY',
    'completed signer rejects a different proof'
  )
  t.alike(accept, bytes(213, 0x61), 'LINK_ACCEPT caller body remains unchanged')
  t.alike(proof, bytes(306, 0x63), 'proof caller body remains unchanged')

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('destroying one signer deeply invalidates it without invalidating siblings', (t) => {
  const f = fixture()
  const link = createLinkOfferSigner(f.authority)
  const extension = createExtensionResponderSigner(f.authority)
  const tail = createTailReadySigner(f.authority)
  const dhtExitReady = createDhtExitReadySigner(f.authority)

  t.is(destroyLinkOfferSigner(link), true)
  t.is(destroyLinkOfferSigner(link), false, 'LINK_OFFER destroy is idempotent')
  expectCode(
    t,
    () => signLinkOffer(link, bytes(302, 0x71), f.identity.publicKey),
    'ERR_DESTROYED',
    'destroyed LINK_OFFER signer cannot sign'
  )
  t.is(signLinkAccept(extension, bytes(213, 0x72), f.identity.publicKey).byteLength, 64)

  t.is(destroyExtensionResponderSigner(extension), true)
  t.is(destroyExtensionResponderSigner(extension), false, 'extension destroy is idempotent')
  expectCode(
    t,
    () => signRedactedResponderProof(extension, bytes(306, 0x73), f.identity.publicKey),
    'ERR_DESTROYED',
    'destroyed extension signer cannot finish'
  )
  t.is(signTailReady(tail, bytes(210, 0x74), f.identity.publicKey).byteLength, 64)
  t.is(signDhtExitReady(dhtExitReady, bytes(233, 0x75), f.identity.publicKey).byteLength, 64)

  t.is(destroyTailReadySigner(tail), true)
  t.is(destroyTailReadySigner(tail), false, 'TAIL_READY destroy is idempotent')
  expectCode(
    t,
    () => signTailReady(tail, bytes(210, 0x74), f.identity.publicKey),
    'ERR_DESTROYED',
    'destroyed TAIL_READY signer cannot retry'
  )

  t.is(destroyDhtExitReadySigner(dhtExitReady), true)
  t.is(destroyDhtExitReadySigner(dhtExitReady), false, 'DHT_EXIT_READY destroy is idempotent')
  expectCode(
    t,
    () => signDhtExitReady(dhtExitReady, bytes(233, 0x75), f.identity.publicKey),
    'ERR_DESTROYED',
    'destroyed DHT_EXIT_READY signer cannot retry'
  )

  destroyRelayIdentitySigningAuthority(f.authority)
})

test('authority destroy clears authority ownership and invalidates every live child', (t) => {
  const identity = cryptoSuite.keyPair()
  const callerSecret = b4a.from(identity.secretKey)
  const callerSnapshot = b4a.from(callerSecret)
  const expectedIdentity = b4a.from(identity.publicKey)
  const expectedSnapshot = b4a.from(expectedIdentity)
  const authority = createRelayIdentitySigningAuthority({ identitySecretKey: callerSecret })
  callerSecret.fill(0xa5)
  const callerMutation = b4a.from(callerSecret)
  const link = createLinkOfferSigner(authority)
  const extension = createExtensionResponderSigner(authority)
  const tail = createTailReadySigner(authority)
  const dhtExitReady = createDhtExitReadySigner(authority)

  t.is(signLinkOffer(link, bytes(302, 0x81), expectedIdentity).byteLength, 64)
  t.is(signLinkAccept(extension, bytes(213, 0x82), expectedIdentity).byteLength, 64)
  t.is(destroyRelayIdentitySigningAuthority(authority), true)
  t.is(destroyRelayIdentitySigningAuthority(authority), false, 'authority destroy is idempotent')
  t.alike(callerSecret, callerMutation, 'destroy does not clear or rewrite the caller-owned secret')
  t.unlike(
    callerSecret,
    callerSnapshot,
    'caller mutation confirms authority signed from its owned key copy'
  )
  t.alike(
    expectedIdentity,
    expectedSnapshot,
    'authority lifecycle leaves caller identity unchanged'
  )

  expectCode(
    t,
    () => createLinkOfferSigner(authority),
    'ERR_DESTROYED',
    'destroyed authority cannot mint children'
  )
  expectCode(
    t,
    () => signLinkOffer(link, bytes(302, 0x81), expectedIdentity),
    'ERR_DESTROYED',
    'authority destroy invalidates a spent LINK_OFFER signer'
  )
  expectCode(
    t,
    () => signRedactedResponderProof(extension, bytes(306, 0x83), expectedIdentity),
    'ERR_DESTROYED',
    'authority destroy invalidates a partially spent extension signer'
  )
  expectCode(
    t,
    () => signTailReady(tail, bytes(210, 0x84), expectedIdentity),
    'ERR_DESTROYED',
    'authority destroy invalidates an unused TAIL_READY signer'
  )
  expectCode(
    t,
    () => signDhtExitReady(dhtExitReady, bytes(233, 0x85), expectedIdentity),
    'ERR_DESTROYED',
    'authority destroy invalidates an unused DHT_EXIT_READY signer'
  )
})
