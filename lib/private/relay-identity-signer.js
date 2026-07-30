'use strict'

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { M3_MESSAGE_ID, M3_PROTOCOL_VERSION } = require('./protocol')

// Signature transcript framing and registered wire bytes follow the reviewed
// private-routes prototype at commit 0305df915b6a767093f9e75e6c06bc0a35da6169.
// Signer capability ownership and lifecycle are specific to the Task 6 amendment;
// the prototype did not contain this module.

const LINK_OFFER = Object.freeze({
  domain: b4a.from('hyperdht-private-routes/m3/link-offer/v1'),
  messageId: M3_MESSAGE_ID.LINK_OFFER_V1,
  bodyLength: 302
})
const LINK_ACCEPT = Object.freeze({
  domain: b4a.from('hyperdht-private-routes/m3/link-accept/v1'),
  messageId: M3_MESSAGE_ID.LINK_ACCEPT_V1,
  bodyLength: 213
})
const REDACTED_RESPONDER_PROOF = Object.freeze({
  domain: b4a.from('hyperdht-private-routes/m3/redacted-responder-proof/v1'),
  messageId: M3_MESSAGE_ID.REDACTED_RESPONDER_PROOF_V1,
  bodyLength: 306
})
const TAIL_READY = Object.freeze({
  domain: b4a.from('hyperdht-private-routes/m3/tail-ready/v1'),
  messageId: M3_MESSAGE_ID.TAIL_READY_V1,
  bodyLength: 210
})

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const arrayIsArray = Array.isArray
const b4aAllocUnsafeSlow = b4a.allocUnsafeSlow
const b4aIsBuffer = b4a.isBuffer
const sodiumMemcmp = sodium.sodium_memcmp
const derivePublicKey = sodium.crypto_sign_ed25519_sk_to_pk
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectGetOwnPropertyNames = Object.getOwnPropertyNames
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols
const objectGetPrototypeOf = Object.getPrototypeOf
const reflectApply = Reflect.apply
const cryptoKeyPair = cryptoSuite.keyPair
const cryptoSign = cryptoSuite.sign
const cryptoVerify = cryptoSuite.verify

const AUTHORITIES = new WeakMap()
const LINK_OFFER_SIGNERS = new WeakMap()
const EXTENSION_RESPONDER_SIGNERS = new WeakMap()
const TAIL_READY_SIGNERS = new WeakMap()
const DESTROYED_AUTHORITIES = new WeakSet()
const DESTROYED_SIGNERS = new WeakSet()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function invalidKey() {
  throw PrivateRouteError.INVALID_KEY()
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

function object(value) {
  return value !== null && typeof value === 'object'
}

function length(value) {
  try {
    return reflectApply(b4aIsBuffer, b4a, [value]) ? reflectApply(bufferByteLength, value, []) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return length(value) === size
}

function clear(value) {
  try {
    if (length(value) >= 0) reflectApply(bufferFill, value, [0])
  } catch {}
}

function allocate(size) {
  let output = null
  try {
    output = reflectApply(b4aAllocUnsafeSlow, b4a, [size])
    if (!fixed(output, size)) invalid()
    return output
  } catch (err) {
    clear(output)
    throw err
  }
}

function copy(value, size) {
  if (!fixed(value, size)) invalid()
  const output = allocate(size)
  try {
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch {
    clear(output)
    invalid()
  }
}

function sameCallerBytes(left, right) {
  const leftLength = length(left)
  const rightLength = length(right)
  if (leftLength < 0 || leftLength !== rightLength) return false
  let difference = 0
  for (let index = 0; index < leftLength; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

function sameInternalBytes(left, right) {
  const leftLength = length(left)
  const rightLength = length(right)
  if (leftLength < 0 || leftLength !== rightLength) return false
  let ownedLeft = null
  let ownedRight = null
  try {
    ownedLeft = copy(left, leftLength)
    ownedRight = copy(right, rightLength)
    return reflectApply(sodiumMemcmp, sodium, [ownedLeft, ownedRight]) === true
  } catch {
    return false
  } finally {
    clear(ownedRight)
    clear(ownedLeft)
  }
}

function exactAuthorityOptions(value) {
  try {
    if (!object(value) || reflectApply(arrayIsArray, Array, [value])) invalid()
    const prototype = reflectApply(objectGetPrototypeOf, Object, [value])
    if (prototype !== Object.prototype && prototype !== null) invalid()
    if (reflectApply(objectGetOwnPropertySymbols, Object, [value]).length !== 0) invalid()
    const names = reflectApply(objectGetOwnPropertyNames, Object, [value])
    if (names.length !== 1 || names[0] !== 'identitySecretKey') invalid()
    const descriptor = reflectApply(objectGetOwnPropertyDescriptor, Object, [
      value,
      'identitySecretKey'
    ])
    if (!descriptor || !('value' in descriptor)) invalid()
    return descriptor.value
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function writeUint16(buffer, value, offset) {
  buffer[offset] = value >>> 8
  buffer[offset + 1] = value
}

function writeUint32(buffer, value, offset) {
  buffer[offset] = value >>> 24
  buffer[offset + 1] = value >>> 16
  buffer[offset + 2] = value >>> 8
  buffer[offset + 3] = value
}

function signatureInput(registration, body) {
  const domainLength = length(registration.domain)
  const input = allocate(10 + domainLength + registration.bodyLength)
  let complete = false
  try {
    writeUint16(input, domainLength, 0)
    reflectApply(bufferSet, input, [registration.domain, 2])
    writeUint32(input, M3_PROTOCOL_VERSION, 2 + domainLength)
    writeUint16(input, registration.messageId, 6 + domainLength)
    writeUint16(input, registration.bodyLength, 8 + domainLength)
    reflectApply(bufferSet, input, [body, 10 + domainLength])
    complete = true
    return input
  } finally {
    if (!complete) clear(input)
  }
}

function authorityState(owner) {
  const state = object(owner) ? AUTHORITIES.get(owner) : null
  if (state && !state.destroyed) return state
  if (object(owner) && DESTROYED_AUTHORITIES.has(owner)) destroyed()
  invalid()
}

function signerState(capability, records) {
  const state = object(capability) ? records.get(capability) : null
  if (state && !state.destroyed) return state
  if (object(capability) && DESTROYED_SIGNERS.has(capability)) destroyed()
  invalid()
}

function createRelayIdentitySigningAuthority(options) {
  const identitySecretKey = exactAuthorityOptions(options)
  if (!fixed(identitySecretKey, 64)) invalidKey()

  let ownedSecretKey = null
  let ownedIdentity = null
  let validationSeed = null
  let validationSecretKey = null
  let validationPublicKey = null
  let owner = null
  let complete = false
  try {
    ownedSecretKey = copy(identitySecretKey, 64)
    ownedIdentity = allocate(32)
    reflectApply(derivePublicKey, sodium, [ownedIdentity, ownedSecretKey])
    if (!fixed(ownedIdentity, 32)) invalidKey()

    validationSeed = allocate(32)
    for (let index = 0; index < 32; index++) validationSeed[index] = ownedSecretKey[index]
    const validationPair = reflectApply(cryptoKeyPair, cryptoSuite, [validationSeed])
    validationSecretKey = validationPair && validationPair.secretKey
    validationPublicKey = validationPair && validationPair.publicKey
    if (
      !fixed(validationSecretKey, 64) ||
      !fixed(validationPublicKey, 32) ||
      !sameInternalBytes(validationSecretKey, ownedSecretKey) ||
      !sameInternalBytes(validationPublicKey, ownedIdentity)
    ) {
      invalidKey()
    }

    owner = objectFreeze({})
    AUTHORITIES.set(owner, {
      owner,
      secretKey: ownedSecretKey,
      identity: ownedIdentity,
      children: new Set(),
      destroyed: false
    })
    ownedSecretKey = null
    ownedIdentity = null
    complete = true
    return owner
  } finally {
    if (!complete && owner !== null) AUTHORITIES.delete(owner)
    clear(validationPublicKey)
    clear(validationSecretKey)
    clear(validationSeed)
    clear(ownedIdentity)
    clear(ownedSecretKey)
  }
}

function createChild(owner, records, slots) {
  const authority = authorityState(owner)
  const capability = objectFreeze({})
  const state = {
    authority,
    capability,
    records,
    slots,
    busy: false,
    destroyed: false
  }
  let added = false
  try {
    authority.children.add(state)
    added = true
    records.set(capability, state)
    return capability
  } catch (err) {
    if (added) authority.children.delete(state)
    records.delete(capability)
    state.authority = null
    state.capability = null
    throw err
  }
}

function createLinkOfferSigner(identityOwner) {
  return createChild(identityOwner, LINK_OFFER_SIGNERS, { linkOffer: null })
}

function createExtensionResponderSigner(identityOwner) {
  return createChild(identityOwner, EXTENSION_RESPONDER_SIGNERS, {
    linkAccept: null,
    redactedResponderProof: null
  })
}

function createTailReadySigner(identityOwner) {
  return createChild(identityOwner, TAIL_READY_SIGNERS, { tailReady: null })
}

function expectedIdentity(authority, expected) {
  if (!fixed(expected, 32) || !sameCallerBytes(expected, authority.identity)) authentication()
}

function verifies(input, signature, identity) {
  try {
    return reflectApply(cryptoVerify, cryptoSuite, [input, signature, identity]) === true
  } catch {
    return false
  }
}

function cachedSignature(authority, phase) {
  if (!verifies(phase.input, phase.signature, authority.identity)) authentication()
  let output = null
  let complete = false
  try {
    output = copy(phase.signature, 64)
    if (!verifies(phase.input, output, authority.identity)) authentication()
    complete = true
    return output
  } finally {
    if (!complete) clear(output)
  }
}

function createSignature(authority, registration, body) {
  let ownedBody = null
  let input = null
  let signatureSource = null
  let ownedSignature = null
  let output = null
  let complete = false
  try {
    ownedBody = copy(body, registration.bodyLength)
    input = signatureInput(registration, ownedBody)
    signatureSource = reflectApply(cryptoSign, cryptoSuite, [input, authority.secretKey])
    if (!fixed(signatureSource, 64)) authentication()
    ownedSignature = copy(signatureSource, 64)
    if (!verifies(input, ownedSignature, authority.identity)) authentication()
    output = copy(ownedSignature, 64)
    if (!verifies(input, output, authority.identity)) authentication()
    complete = true
    return {
      phase: {
        body: ownedBody,
        input,
        signature: ownedSignature
      },
      output
    }
  } finally {
    clear(signatureSource)
    if (!complete) {
      clear(output)
      clear(ownedSignature)
      clear(input)
      clear(ownedBody)
    }
  }
}

function signPhase(state, authority, slot, registration, body, expected) {
  if (!fixed(body, registration.bodyLength)) invalid()
  expectedIdentity(authority, expected)

  const phase = state.slots[slot]
  if (phase !== null) {
    if (!sameCallerBytes(body, phase.body)) replay()
    return cachedSignature(authority, phase)
  }

  const created = createSignature(authority, registration, body)
  state.slots[slot] = created.phase
  return created.output
}

function transact(state, operation) {
  if (state.busy) replay()
  state.busy = true
  try {
    const authority = state.authority
    if (!authority || authority.destroyed) destroyed()
    return operation(authority)
  } finally {
    state.busy = false
  }
}

function signLinkOffer(linkOfferSigner, body, expectedIdentityValue) {
  const state = signerState(linkOfferSigner, LINK_OFFER_SIGNERS)
  return transact(state, (authority) =>
    signPhase(state, authority, 'linkOffer', LINK_OFFER, body, expectedIdentityValue)
  )
}

function signLinkAccept(extensionResponderSigner, body, expectedIdentityValue) {
  const state = signerState(extensionResponderSigner, EXTENSION_RESPONDER_SIGNERS)
  return transact(state, (authority) =>
    signPhase(state, authority, 'linkAccept', LINK_ACCEPT, body, expectedIdentityValue)
  )
}

function signRedactedResponderProof(extensionResponderSigner, body, expectedIdentityValue) {
  const state = signerState(extensionResponderSigner, EXTENSION_RESPONDER_SIGNERS)
  return transact(state, (authority) => {
    if (state.slots.linkAccept === null) replay()
    return signPhase(
      state,
      authority,
      'redactedResponderProof',
      REDACTED_RESPONDER_PROOF,
      body,
      expectedIdentityValue
    )
  })
}

function signTailReady(tailReadySigner, body, expectedIdentityValue) {
  const state = signerState(tailReadySigner, TAIL_READY_SIGNERS)
  return transact(state, (authority) =>
    signPhase(state, authority, 'tailReady', TAIL_READY, body, expectedIdentityValue)
  )
}

function clearPhase(phase) {
  if (phase === null) return
  clear(phase.signature)
  clear(phase.input)
  clear(phase.body)
  phase.signature = null
  phase.input = null
  phase.body = null
}

function invalidateChild(state) {
  if (!state || state.destroyed) return false
  state.destroyed = true
  state.records.delete(state.capability)
  DESTROYED_SIGNERS.add(state.capability)
  if (state.authority) state.authority.children.delete(state)
  for (const phase of Object.values(state.slots)) clearPhase(phase)
  for (const name of Object.keys(state.slots)) state.slots[name] = null
  state.authority = null
  state.capability = null
  state.records = null
  state.busy = false
  return true
}

function destroyChild(capability, records) {
  const state = object(capability) ? records.get(capability) : null
  return state ? invalidateChild(state) : false
}

function destroyLinkOfferSigner(linkOfferSigner) {
  return destroyChild(linkOfferSigner, LINK_OFFER_SIGNERS)
}

function destroyExtensionResponderSigner(extensionResponderSigner) {
  return destroyChild(extensionResponderSigner, EXTENSION_RESPONDER_SIGNERS)
}

function destroyTailReadySigner(tailReadySigner) {
  return destroyChild(tailReadySigner, TAIL_READY_SIGNERS)
}

function destroyRelayIdentitySigningAuthority(identityOwner) {
  const state = object(identityOwner) ? AUTHORITIES.get(identityOwner) : null
  if (!state || state.destroyed) return false

  state.destroyed = true
  AUTHORITIES.delete(identityOwner)
  DESTROYED_AUTHORITIES.add(identityOwner)
  for (const child of state.children) invalidateChild(child)
  state.children.clear()
  clear(state.secretKey)
  clear(state.identity)
  state.secretKey = null
  state.identity = null
  state.owner = null
  return true
}

module.exports = {
  createRelayIdentitySigningAuthority,
  createLinkOfferSigner,
  signLinkOffer,
  destroyLinkOfferSigner,
  createExtensionResponderSigner,
  signLinkAccept,
  signRedactedResponderProof,
  destroyExtensionResponderSigner,
  createTailReadySigner,
  signTailReady,
  destroyTailReadySigner,
  destroyRelayIdentitySigningAuthority
}
