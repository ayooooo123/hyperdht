'use strict'

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const b4a = require('b4a')

const { DatagramReplayWindow, OrderedReceiver, SenderCounter } = require('./counters')
const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')
const { CELL_CLASS, DOMAIN, PROTOCOL_VERSION } = require('./protocol')

const LINK_CREATE_SIZE = 273
const LINK_CREATED_SIZE = 337

// Imported only by this module's tests. Production code receives opaque tickets.
const TEST_ONLY_TICKET_OBSERVER = Symbol('test-only-ticket-observer')
const TEST_ONLY_COUNTER_FACTORY = Symbol.for('hyperdht-private-routes/test-only-counter-factory')

const MAX_U64 = 0xffff_ffff_ffff_ffffn
const MAX_REPLAYS = 4096
const CHECKERS = new WeakSet()
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
const bufferArrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get
const bufferByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get
const bufferByteOffset = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get
const bufferSet = Uint8Array.prototype.set
const bufferFill = Uint8Array.prototype.fill
const bufferSubarray = Uint8Array.prototype.subarray

function unauthorized() {
  throw PrivateRouteError.UNAUTHORIZED()
}

function invalidRoute() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function safeObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  } catch {
    return false
  }
}

function option(value, name) {
  try {
    return value[name]
  } catch {
    invalidRoute()
  }
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? bufferByteLength.call(value) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function u64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_U64
}

function copyBuffer(value) {
  const copy = b4a.allocUnsafeSlow(bufferLength(value))
  bufferSet.call(copy, value)
  return copy
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) bufferFill.call(value, 0)
  } catch {
    // Best-effort zeroization only.
  }
}

function overlaps(left, right) {
  if (!b4a.isBuffer(left) || !b4a.isBuffer(right)) return false
  try {
    if (bufferArrayBuffer.call(left) !== bufferArrayBuffer.call(right)) return false
    const leftStart = bufferByteOffset.call(left)
    const leftEnd = leftStart + bufferLength(left)
    const rightStart = bufferByteOffset.call(right)
    const rightEnd = rightStart + bufferLength(right)
    return leftStart < rightEnd && rightStart < leftEnd
  } catch {
    return false
  }
}

function clearAdapterOutput(value, inputs) {
  if (!inputs.some((input) => overlaps(value, input))) clear(value)
}

function aliasesInput(value, inputs) {
  return inputs.some((input) => overlaps(value, input))
}

function same(left, right) {
  try {
    return fixed(left, bufferLength(right)) && b4a.equals(left, right)
  } catch {
    return false
  }
}

function writeU64(buffer, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64(buffer, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++) {
    value = (value << 8n) | BigInt(buffer[index])
  }
  return value
}

function encodeFields(value, fields, size) {
  if (!safeObject(value)) invalidRoute()
  const output = b4a.allocUnsafeSlow(size)
  let offset = 0

  for (const [name, bytes] of fields) {
    const field = option(value, name)
    if (bytes === 0) {
      if (!u64(field)) invalidRoute()
      writeU64(output, field, offset)
      offset += 8
    } else if (bytes === 1) {
      if (field !== PROTOCOL_VERSION) invalidRoute()
      output[offset++] = field
    } else {
      if (!fixed(field, bytes)) invalidRoute()
      bufferSet.call(output, field, offset)
      offset += bytes
    }
  }

  return output
}

function decodeFields(message, fields, size) {
  if (!fixed(message, size)) invalidRoute()
  const value = {}
  let offset = 0

  for (const [name, bytes] of fields) {
    if (bytes === 0) {
      value[name] = readU64(message, offset)
      offset += 8
    } else if (bytes === 1) {
      value[name] = message[offset++]
    } else {
      value[name] = copyBuffer(bufferSubarray.call(message, offset, offset + bytes))
      offset += bytes
    }
  }

  if (value.version !== PROTOCOL_VERSION) invalidRoute()
  return value
}

const CREATE_FIELDS = Object.freeze([
  ['version', 1],
  ['circuitId', 16],
  ['epoch', 0],
  ['initiatorIdentity', 32],
  ['responderIdentity', 32],
  ['initiatorLocalId', 16],
  ['responderLocalId', 16],
  ['initiatorEphemeralKey', 32],
  ['expiresAt', 0],
  ['staticChallengeCipher', 48],
  ['initiatorIdentitySignature', 64]
])

const CREATED_FIELDS = Object.freeze([
  ['version', 1],
  ['circuitId', 16],
  ['epoch', 0],
  ['initiatorIdentity', 32],
  ['responderIdentity', 32],
  ['initiatorLocalId', 16],
  ['responderLocalId', 16],
  ['initiatorEphemeralKey', 32],
  ['responderEphemeralKey', 32],
  ['createHash', 32],
  ['challengeHash', 32],
  ['expiresAt', 0],
  ['staticPossessionTag', 16],
  ['responderIdentitySignature', 64]
])

function encodeLinkCreate(value) {
  return encodeFields(value, CREATE_FIELDS, LINK_CREATE_SIZE)
}

function decodeLinkCreate(message) {
  return decodeFields(message, CREATE_FIELDS, LINK_CREATE_SIZE)
}

function encodeLinkCreated(value) {
  return encodeFields(value, CREATED_FIELDS, LINK_CREATED_SIZE)
}

function decodeLinkCreated(message) {
  return decodeFields(message, CREATED_FIELDS, LINK_CREATED_SIZE)
}

function createBase(value) {
  return encodeFields(value, CREATE_FIELDS.slice(0, 9), 161)
}

function createUnsigned(value) {
  return encodeFields(value, CREATE_FIELDS.slice(0, 10), 209)
}

function createdUnsigned(value) {
  return encodeFields(value, CREATED_FIELDS.slice(0, 12), 257)
}

function hash(crypto, parts) {
  let value = null
  try {
    value = crypto.hash(parts)
    if (!fixed(value, 32)) invalidRoute()
    if (aliasesInput(value, parts)) invalidRoute()
    return copyBuffer(value)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    clearAdapterOutput(value, parts)
  }
}

function derive(crypto, sharedSecret, transcript) {
  let value = null
  let forwardKey = null
  let reverseKey = null
  let forwardNoncePrefix = null
  let reverseNoncePrefix = null
  let ownedForwardKey = null
  let ownedReverseKey = null
  let ownedForwardNoncePrefix = null
  let ownedReverseNoncePrefix = null
  let transferred = false
  try {
    value = crypto.deriveKeys(sharedSecret, transcript)
    if (!safeObject(value)) invalidRoute()
    forwardKey = option(value, 'forwardKey')
    reverseKey = option(value, 'reverseKey')
    forwardNoncePrefix = option(value, 'forwardNoncePrefix')
    reverseNoncePrefix = option(value, 'reverseNoncePrefix')
    if (
      !fixed(forwardKey, 32) ||
      !fixed(reverseKey, 32) ||
      !fixed(forwardNoncePrefix, 16) ||
      !fixed(reverseNoncePrefix, 16)
    ) {
      invalidRoute()
    }
    ownedForwardKey = copyBuffer(forwardKey)
    ownedReverseKey = copyBuffer(reverseKey)
    ownedForwardNoncePrefix = copyBuffer(forwardNoncePrefix)
    ownedReverseNoncePrefix = copyBuffer(reverseNoncePrefix)
    transferred = true
    return {
      forwardKey: ownedForwardKey,
      reverseKey: ownedReverseKey,
      forwardNoncePrefix: ownedForwardNoncePrefix,
      reverseNoncePrefix: ownedReverseNoncePrefix
    }
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    const inputs = [sharedSecret, transcript]
    clearAdapterOutput(forwardKey, inputs)
    clearAdapterOutput(reverseKey, inputs)
    clearAdapterOutput(forwardNoncePrefix, inputs)
    clearAdapterOutput(reverseNoncePrefix, inputs)
    if (!transferred) {
      clear(ownedForwardKey)
      clear(ownedReverseKey)
      clear(ownedForwardNoncePrefix)
      clear(ownedReverseNoncePrefix)
    }
  }
}

function challengeCipher(crypto, sharedSecret, baseHash, challenge) {
  const transcript = b4a.concat([DOMAIN.LINK_CREATE, baseHash])
  const keys = derive(crypto, sharedSecret, transcript)
  let cipher = null
  try {
    cipher = crypto.seal({
      key: keys.forwardKey,
      noncePrefix: keys.forwardNoncePrefix,
      counter: 0n,
      associatedData: baseHash,
      plaintext: challenge
    })
    if (!fixed(cipher, 48)) invalidRoute()
    return copyBuffer(cipher)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    clear(keys.forwardKey)
    clear(keys.reverseKey)
    clear(keys.forwardNoncePrefix)
    clear(keys.reverseNoncePrefix)
    clear(transcript)
    clear(cipher)
  }
}

function linkChallengeCipher(sharedSecret, baseHash, challenge) {
  if (!fixed(sharedSecret, 32) || !fixed(baseHash, 32) || !fixed(challenge, 32)) invalidRoute()
  return challengeCipher(cryptoSuite, sharedSecret, baseHash, challenge)
}

function possessionTag(crypto, sharedSecret, baseHash, challenge, createHash) {
  const transcript = b4a.concat([DOMAIN.LINK_CREATE, baseHash])
  const challengeHash = hash(crypto, [challenge])
  const associatedData = b4a.concat([challengeHash, createHash])
  const keys = derive(crypto, sharedSecret, transcript)
  let tag = null
  try {
    tag = crypto.seal({
      key: keys.reverseKey,
      noncePrefix: keys.reverseNoncePrefix,
      counter: 1n,
      associatedData,
      plaintext: b4a.alloc(0)
    })
    if (!fixed(tag, 16)) invalidRoute()
    return copyBuffer(tag)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    clear(keys.forwardKey)
    clear(keys.reverseKey)
    clear(keys.forwardNoncePrefix)
    clear(keys.reverseNoncePrefix)
    clear(transcript)
    clear(challengeHash)
    clear(associatedData)
    clear(tag)
  }
}

function linkPossessionTag(sharedSecret, baseHash, challenge, createHash) {
  if (
    !fixed(sharedSecret, 32) ||
    !fixed(baseHash, 32) ||
    !fixed(challenge, 32) ||
    !fixed(createHash, 32)
  ) {
    invalidRoute()
  }
  return possessionTag(cryptoSuite, sharedSecret, baseHash, challenge, createHash)
}

function nowValue(now) {
  let value
  try {
    value = now()
  } catch {
    invalidRoute()
  }
  if (!Number.isSafeInteger(value) || value < 0) invalidRoute()
  return BigInt(value)
}

function validateCommon(value) {
  if (
    !safeObject(value) ||
    !fixed(option(value, 'circuitId'), 16) ||
    !u64(option(value, 'epoch')) ||
    !fixed(option(value, 'initiatorIdentity'), 32) ||
    !fixed(option(value, 'responderIdentity'), 32) ||
    !fixed(option(value, 'initiatorLocalId'), 16) ||
    !fixed(option(value, 'responderLocalId'), 16) ||
    !u64(option(value, 'expiresAt'))
  ) {
    invalidRoute()
  }
}

function matchesCommon(message, expected) {
  return (
    same(message.circuitId, expected.circuitId) &&
    message.epoch === expected.epoch &&
    same(message.initiatorIdentity, expected.initiatorIdentity) &&
    same(message.responderIdentity, expected.responderIdentity) &&
    same(message.initiatorLocalId, expected.initiatorLocalId) &&
    same(message.responderLocalId, expected.responderLocalId) &&
    message.expiresAt === expected.expiresAt
  )
}

function verify(crypto, message, signature, publicKey) {
  try {
    return crypto.verify(message, signature, publicKey) === true
  } catch {
    return false
  }
}

function sign(crypto, message, secretKey) {
  let signature = null
  try {
    signature = crypto.sign(message, secretKey)
    if (!fixed(signature, 64)) invalidRoute()
    if (aliasesInput(signature, [message, secretKey])) invalidRoute()
    return copyBuffer(signature)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    clearAdapterOutput(signature, [message, secretKey])
  }
}

function agreement(crypto, secretKey, publicKey) {
  let shared = null
  try {
    shared = crypto.keyAgreement(secretKey, publicKey)
    if (!fixed(shared, 32)) unauthorized()
    if (aliasesInput(shared, [secretKey, publicKey])) unauthorized()
    return copyBuffer(shared)
  } catch {
    unauthorized()
  } finally {
    clearAdapterOutput(shared, [secretKey, publicKey])
  }
}

function ephemeral(crypto, randomBytes) {
  let seed = null
  let pair = null
  let publicKey = null
  let secretKey = null
  let ownedPublicKey = null
  let ownedSecretKey = null
  let transferred = false
  try {
    seed = randomBytes(32)
    if (!fixed(seed, 32)) invalidRoute()
    pair = crypto.encryptionKeyPair(seed)
    if (!safeObject(pair)) invalidRoute()
    publicKey = option(pair, 'publicKey')
    secretKey = option(pair, 'secretKey')
    if (!fixed(publicKey, 32) || !fixed(secretKey, 32)) invalidRoute()
    ownedPublicKey = copyBuffer(publicKey)
    ownedSecretKey = copyBuffer(secretKey)
    const result = { publicKey: ownedPublicKey, secretKey: ownedSecretKey }
    transferred = true
    return result
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalidRoute()
  } finally {
    clearAdapterOutput(publicKey, [seed])
    clearAdapterOutput(secretKey, [seed])
    clear(seed)
    if (!transferred) {
      clear(ownedPublicKey)
      clear(ownedSecretKey)
    }
  }
}

function createCounter(cellClass, sender, now) {
  return sender
    ? new SenderCounter()
    : cellClass === CELL_CLASS.DATAGRAM
      ? new DatagramReplayWindow({ window: 256 })
      : new OrderedReceiver({ window: 256, gapTimeout: 5000, now })
}

function counterContext(cellClass, key, noncePrefix, sender, now, counterFactory = createCounter) {
  let ownedKey = null
  let ownedNoncePrefix = null
  let counter = null
  let transferred = false
  try {
    ownedKey = copyBuffer(key)
    ownedNoncePrefix = copyBuffer(noncePrefix)
    counter = counterFactory(cellClass, sender, now)
    const result = { key: ownedKey, noncePrefix: ownedNoncePrefix, counter }
    transferred = true
    return result
  } finally {
    if (!transferred) {
      clear(ownedKey)
      clear(ownedNoncePrefix)
      try {
        if (counter) counter.destroy()
      } catch {}
    }
  }
}

function ticketState(
  crypto,
  shared,
  createHash,
  createdHash,
  common,
  initiator,
  now,
  counterFactory
) {
  const contexts = {}
  const result = { epoch: common.epoch, expiresAt: common.expiresAt, contexts }
  let transferred = false
  try {
    for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
      let transcript = null
      let keys = null
      let tx = null
      let rx = null
      try {
        transcript = b4a.concat([
          DOMAIN.LINK_CREATED,
          createHash,
          createdHash,
          b4a.from([cellClass])
        ])
        keys = derive(crypto, shared, transcript)
        tx = counterContext(
          cellClass,
          initiator ? keys.forwardKey : keys.reverseKey,
          initiator ? keys.forwardNoncePrefix : keys.reverseNoncePrefix,
          true,
          now,
          counterFactory
        )
        rx = counterContext(
          cellClass,
          initiator ? keys.reverseKey : keys.forwardKey,
          initiator ? keys.reverseNoncePrefix : keys.forwardNoncePrefix,
          false,
          now,
          counterFactory
        )
        contexts[cellClass] = { tx, rx }
        tx = null
        rx = null
      } finally {
        clear(keys && keys.forwardKey)
        clear(keys && keys.reverseKey)
        clear(keys && keys.forwardNoncePrefix)
        clear(keys && keys.reverseNoncePrefix)
        clear(transcript)
        clearTicketState({ contexts: { partial: { tx, rx } } })
      }
    }
    result.circuitId = copyBuffer(common.circuitId)
    result.localIdentity = copyBuffer(
      initiator ? common.initiatorIdentity : common.responderIdentity
    )
    result.peerIdentity = copyBuffer(
      initiator ? common.responderIdentity : common.initiatorIdentity
    )
    result.localId = copyBuffer(initiator ? common.initiatorLocalId : common.responderLocalId)
    result.peerLocalId = copyBuffer(initiator ? common.responderLocalId : common.initiatorLocalId)
    transferred = true
    return result
  } finally {
    if (!transferred) clearTicketState(result)
  }
}

function observeState(state, now) {
  const snapshot = { contexts: {} }
  try {
    snapshot.circuitId = copyBuffer(state.circuitId)
    snapshot.epoch = state.epoch
    snapshot.localIdentity = copyBuffer(state.localIdentity)
    snapshot.peerIdentity = copyBuffer(state.peerIdentity)
    snapshot.localId = copyBuffer(state.localId)
    snapshot.peerLocalId = copyBuffer(state.peerLocalId)
    snapshot.expiresAt = state.expiresAt
    for (const cellClass of [CELL_CLASS.CONTROL, CELL_CLASS.STREAM, CELL_CLASS.DATAGRAM]) {
      const pair = {}
      snapshot.contexts[cellClass] = pair
      pair.tx = counterContext(
        cellClass,
        state.contexts[cellClass].tx.key,
        state.contexts[cellClass].tx.noncePrefix,
        true,
        now
      )
      pair.rx = counterContext(
        cellClass,
        state.contexts[cellClass].rx.key,
        state.contexts[cellClass].rx.noncePrefix,
        false,
        now
      )
    }
    return snapshot
  } catch (err) {
    clearTicketState(snapshot)
    throw err
  }
}

function clearDecodedFields(value) {
  if (!value) return
  for (const field of Object.values(value)) clear(field)
}

function clearPendingState(state) {
  if (!state) return
  clear(state.common && state.common.initiatorEphemeralKey)
  clear(state.responderStaticKey)
  clear(state.ephemeralSecretKey)
  clear(state.challenge)
  clear(state.createHash)
}

function clearTicketState(state) {
  if (!state) return
  for (const pair of Object.values(state.contexts || {})) {
    for (const context of [pair && pair.tx, pair && pair.rx]) {
      if (!context) continue
      clear(context.key)
      clear(context.noncePrefix)
      try {
        context.counter.destroy()
      } catch {
        // Continue clearing the remaining ticket material.
      }
    }
  }
  clear(state.circuitId)
  clear(state.localIdentity)
  clear(state.peerIdentity)
  clear(state.localId)
  clear(state.peerLocalId)
}

function destroyEstablishedLinkState(state) {
  clearTicketState(state)
}

function createLinkSetupAuthority(options = {}) {
  if (!safeObject(options)) invalidRoute()
  const crypto = option(options, 'crypto') || cryptoSuite
  const now = option(options, 'now')
  let randomBytes = option(options, 'randomBytes')
  if (randomBytes === undefined) {
    try {
      randomBytes = crypto.randomBytes
    } catch {
      invalidRoute()
    }
  }
  const observe = option(options, TEST_ONLY_TICKET_OBSERVER)
  const counterFactory = option(options, TEST_ONLY_COUNTER_FACTORY) || createCounter
  if (typeof now !== 'function' || typeof randomBytes !== 'function') invalidRoute()
  if (observe !== undefined && typeof observe !== 'function') invalidRoute()
  if (typeof counterFactory !== 'function') invalidRoute()

  const pendingStates = new WeakMap()
  const spentPending = new WeakSet()
  const ticketStates = new WeakMap()
  const replay = new Map()

  function issue(state) {
    const ticket = Object.freeze({})
    ticketStates.set(ticket, state)
    if (observe) {
      let snapshot = null
      try {
        snapshot = observeState(state, now)
        observe(ticket, snapshot)
        snapshot = null
      } catch {
        clearTicketState(snapshot)
      }
    }
    return ticket
  }

  const checker = Object.freeze({
    take(ticket) {
      const state = safeObject(ticket) ? ticketStates.get(ticket) : null
      if (!state) unauthorized()
      ticketStates.delete(ticket)
      return state
    }
  })
  CHECKERS.add(checker)

  function pruneReplay(current) {
    for (const [key, expiry] of replay) {
      if (expiry <= current) replay.delete(key)
    }
  }

  return Object.freeze({
    checker,

    abort(pending) {
      const state = safeObject(pending) ? pendingStates.get(pending) : null
      if (!state || spentPending.has(pending)) return false
      pendingStates.delete(pending)
      spentPending.add(pending)
      clearPendingState(state)
      return true
    },

    revoke(ticket) {
      const state = safeObject(ticket) ? ticketStates.get(ticket) : null
      if (!state) return false
      ticketStates.delete(ticket)
      clearTicketState(state)
      return true
    },

    initiate(value) {
      validateCommon(value)
      if (!fixed(option(value, 'responderStaticKey'), 32)) invalidRoute()
      if (!fixed(option(value, 'initiatorIdentitySecretKey'), 64)) invalidRoute()

      const pair = ephemeral(crypto, randomBytes)
      let shared = null
      let baseHash = null
      let challenge = null
      let cipher = null
      let pendingState = null
      let encodedMessage = null
      try {
        const base = {
          version: PROTOCOL_VERSION,
          circuitId: value.circuitId,
          epoch: value.epoch,
          initiatorIdentity: value.initiatorIdentity,
          responderIdentity: value.responderIdentity,
          initiatorLocalId: value.initiatorLocalId,
          responderLocalId: value.responderLocalId,
          initiatorEphemeralKey: pair.publicKey,
          expiresAt: value.expiresAt
        }
        baseHash = hash(crypto, [DOMAIN.LINK_CREATE, createBase(base)])
        shared = agreement(crypto, pair.secretKey, value.responderStaticKey)
        challenge = hash(crypto, [DOMAIN.LINK_CREATE, pair.secretKey, baseHash])
        cipher = challengeCipher(crypto, shared, baseHash, challenge)
        const unsigned = { ...base, staticChallengeCipher: cipher }
        const signed = b4a.concat([DOMAIN.LINK_CREATE, createUnsigned(unsigned)])
        const message = {
          ...unsigned,
          initiatorIdentitySignature: sign(crypto, signed, value.initiatorIdentitySecretKey)
        }
        clear(signed)

        const pending = Object.freeze({})
        const responderStaticKey = copyBuffer(value.responderStaticKey)
        let ephemeralSecretKey = null
        let ownedChallenge = null
        let createHash = null
        try {
          ephemeralSecretKey = copyBuffer(pair.secretKey)
          ownedChallenge = copyBuffer(challenge)
          createHash = hash(crypto, [encodeLinkCreate(message)])
          pendingState = {
            common: base,
            responderStaticKey,
            ephemeralSecretKey,
            challenge: ownedChallenge,
            createHash
          }
          ephemeralSecretKey = null
          ownedChallenge = null
          createHash = null
        } finally {
          if (!pendingState) clear(responderStaticKey)
          clear(ephemeralSecretKey)
          clear(ownedChallenge)
          clear(createHash)
        }
        encodedMessage = encodeLinkCreate(message)
        pendingStates.set(pending, pendingState)
        pendingState = null
        pair.publicKey = null
        return { message: encodedMessage, pending }
      } finally {
        clearPendingState(pendingState)
        clear(pair.publicKey)
        clear(pair.secretKey)
        clear(shared)
        clear(baseHash)
        clear(challenge)
        clear(cipher)
      }
    },

    respond(message, expected) {
      validateCommon(expected)
      if (!fixed(option(expected, 'responderStaticSecretKey'), 32)) invalidRoute()
      if (!fixed(option(expected, 'responderIdentitySecretKey'), 64)) invalidRoute()

      let create = null
      let createHash = null
      let baseHash = null
      let shared = null
      let challenge = null
      let pair = null
      let ephemeralShared = null
      let created = null
      let responderCreatedHash = null
      let challengeHash = null
      let tag = null
      let signed = null
      try {
        create = decodeLinkCreate(message)
        const current = nowValue(now)
        if (!matchesCommon(create, expected) || create.expiresAt <= current) invalidRoute()

        const unsigned = b4a.concat([DOMAIN.LINK_CREATE, createUnsigned(create)])
        if (
          !verify(crypto, unsigned, create.initiatorIdentitySignature, create.initiatorIdentity)
        ) {
          clear(unsigned)
          unauthorized()
        }
        clear(unsigned)

        createHash = hash(crypto, [encodeLinkCreate(create)])
        const replayKey = b4a.toString(createHash, 'hex')
        pruneReplay(current)
        if (replay.has(replayKey)) unauthorizedReplay()
        if (replay.size >= MAX_REPLAYS) throw PrivateRouteError.CIRCUIT_LIMIT()
        // A valid identity signature is enough to consume the create transcript.
        // Otherwise an authenticated initiator can replay a deliberately bad
        // challenge indefinitely and force repeated static-key work.
        replay.set(replayKey, create.expiresAt)

        baseHash = hash(crypto, [DOMAIN.LINK_CREATE, createBase(create)])
        shared = agreement(crypto, expected.responderStaticSecretKey, create.initiatorEphemeralKey)
        const transcript = b4a.concat([DOMAIN.LINK_CREATE, baseHash])
        const keys = derive(crypto, shared, transcript)
        try {
          challenge = crypto.open({
            key: keys.forwardKey,
            noncePrefix: keys.forwardNoncePrefix,
            counter: 0n,
            associatedData: baseHash,
            ciphertext: create.staticChallengeCipher
          })
        } catch {
          challenge = null
        } finally {
          clear(keys.forwardKey)
          clear(keys.reverseKey)
          clear(keys.forwardNoncePrefix)
          clear(keys.reverseNoncePrefix)
          clear(transcript)
        }
        if (!fixed(challenge, 32)) unauthorized()

        pair = ephemeral(crypto, randomBytes)
        challengeHash = hash(crypto, [challenge])
        const createdBase = {
          version: PROTOCOL_VERSION,
          circuitId: create.circuitId,
          epoch: create.epoch,
          initiatorIdentity: create.initiatorIdentity,
          responderIdentity: create.responderIdentity,
          initiatorLocalId: create.initiatorLocalId,
          responderLocalId: create.responderLocalId,
          initiatorEphemeralKey: create.initiatorEphemeralKey,
          responderEphemeralKey: pair.publicKey,
          createHash,
          challengeHash,
          expiresAt: create.expiresAt
        }
        tag = possessionTag(crypto, shared, baseHash, challenge, createHash)
        signed = b4a.concat([DOMAIN.LINK_CREATED, createdUnsigned(createdBase), tag])
        created = {
          ...createdBase,
          staticPossessionTag: tag,
          responderIdentitySignature: sign(crypto, signed, expected.responderIdentitySecretKey)
        }
        clear(signed)
        signed = null

        const encoded = encodeLinkCreated(created)
        responderCreatedHash = hash(crypto, [encoded])
        ephemeralShared = agreement(crypto, pair.secretKey, create.initiatorEphemeralKey)
        const state = ticketState(
          crypto,
          ephemeralShared,
          createHash,
          responderCreatedHash,
          create,
          false,
          now,
          counterFactory
        )
        return { message: encoded, ticket: issue(state) }
      } finally {
        clear(shared)
        clear(challenge)
        clear(baseHash)
        clear(createHash)
        clear(responderCreatedHash)
        clear(challengeHash)
        clear(tag)
        clear(signed)
        clear(pair && pair.publicKey)
        clear(pair && pair.secretKey)
        clear(ephemeralShared)
        clearDecodedFields(created)
        clearDecodedFields(create)
      }
    },

    complete(pending, message) {
      const state = safeObject(pending) ? pendingStates.get(pending) : null
      if (!state || spentPending.has(pending)) unauthorizedReplay()
      pendingStates.delete(pending)
      spentPending.add(pending)

      let shared = null
      let createdHash = null
      let created = null
      let expectedChallengeHash = null
      let baseHash = null
      let expectedTag = null
      try {
        created = decodeLinkCreated(message)
        if (
          !matchesCommon(created, state.common) ||
          !same(created.initiatorEphemeralKey, state.common.initiatorEphemeralKey) ||
          !same(created.createHash, state.createHash) ||
          created.expiresAt <= nowValue(now)
        ) {
          unauthorized()
        }

        const signed = b4a.concat([
          DOMAIN.LINK_CREATED,
          createdUnsigned(created),
          created.staticPossessionTag
        ])
        const validSignature = verify(
          crypto,
          signed,
          created.responderIdentitySignature,
          created.responderIdentity
        )
        clear(signed)
        if (!validSignature) unauthorized()

        expectedChallengeHash = hash(crypto, [state.challenge])
        if (!same(created.challengeHash, expectedChallengeHash)) {
          clear(expectedChallengeHash)
          unauthorized()
        }
        clear(expectedChallengeHash)
        expectedChallengeHash = null

        shared = agreement(crypto, state.ephemeralSecretKey, state.responderStaticKey)
        baseHash = hash(crypto, [DOMAIN.LINK_CREATE, createBase(state.common)])
        expectedTag = possessionTag(crypto, shared, baseHash, state.challenge, state.createHash)
        clear(baseHash)
        baseHash = null
        if (!same(created.staticPossessionTag, expectedTag)) {
          clear(expectedTag)
          unauthorized()
        }
        clear(expectedTag)
        expectedTag = null

        clear(shared)
        shared = agreement(crypto, state.ephemeralSecretKey, created.responderEphemeralKey)
        createdHash = hash(crypto, [encodeLinkCreated(created)])
        return issue(
          ticketState(
            crypto,
            shared,
            state.createHash,
            createdHash,
            state.common,
            true,
            now,
            counterFactory
          )
        )
      } finally {
        clear(shared)
        clear(createdHash)
        clear(expectedChallengeHash)
        clear(baseHash)
        clear(expectedTag)
        clearDecodedFields(created)
        clearPendingState(state)
      }
    }
  })
}

function unauthorizedReplay() {
  throw PrivateRouteError.REPLAY()
}

function isLinkTicketChecker(value) {
  return safeObject(value) && CHECKERS.has(value)
}

module.exports = {
  LINK_CREATE_SIZE,
  LINK_CREATED_SIZE,
  TEST_ONLY_TICKET_OBSERVER,
  encodeLinkCreate,
  decodeLinkCreate,
  encodeLinkCreated,
  decodeLinkCreated,
  linkChallengeCipher,
  linkPossessionTag,
  destroyEstablishedLinkState,
  createLinkSetupAuthority,
  isLinkTicketChecker
}
