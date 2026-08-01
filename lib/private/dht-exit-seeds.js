'use strict'

const b4a = require('b4a')

const { cryptoSuite } = require('./crypto-suite')
const { DESTINATION_REF_SIZE, decodeDestinationRef } = require('./destination-ref')
const { snapshotDhtExitDestinationTable } = require('./dht-exit-destination-table')
const { PrivateRouteError } = require('./errors')
const {
  BRANCH_CLASS,
  DOMAIN,
  M3_MESSAGE_ID,
  M3_PROTOCOL_VERSION,
  decodeM3Object,
  encodeM3Object
} = require('./protocol')

const DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE = 138
const DHT_EXIT_DHT_SEEDS_MIN_COUNT = 1
const DHT_EXIT_DHT_SEEDS_MAX_COUNT = 3
const DHT_EXIT_DHT_SEEDS_REF_OFFSET = 106
const SEED_DELIVERY_AUTHORITIES = new WeakMap()
const SPENT_SEED_DELIVERY_AUTHORITIES = new WeakSet()
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

const bufferByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength'
).get
const bufferFill = Uint8Array.prototype.fill
const bufferSet = Uint8Array.prototype.set
const bufferSubarray = Uint8Array.prototype.subarray
const objectFreeze = Object.freeze
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
const objectHasOwnProperty = Object.prototype.hasOwnProperty
const reflectApply = Reflect.apply

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function authentication() {
  throw PrivateRouteError.ERR_AUTHENTICATION()
}

function object(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
    return value
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function dataProperty(value, name) {
  let descriptor = null
  try {
    descriptor = objectGetOwnPropertyDescriptor(value, name)
  } catch {
    invalid()
  }
  if (!descriptor || !reflectApply(objectHasOwnProperty, descriptor, ['value'])) invalid()
  return descriptor.value
}

function bufferLength(value) {
  try {
    return b4a.isBuffer(value) ? reflectApply(bufferByteLength, value, []) : -1
  } catch {
    return -1
  }
}

function fixed(value, size) {
  return bufferLength(value) === size
}

function clear(value) {
  try {
    if (b4a.isBuffer(value)) reflectApply(bufferFill, value, [0])
  } catch {}
}

function copy(value, size = -1) {
  let output = null
  try {
    const length = bufferLength(value)
    if (length < 0 || (size !== -1 && length !== size)) invalid()
    output = b4a.allocUnsafeSlow(length)
    if (bufferLength(output) !== length) invalid()
    reflectApply(bufferSet, output, [value, 0])
    return output
  } catch (err) {
    clear(output)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function subarray(value, start, end) {
  try {
    return reflectApply(bufferSubarray, value, [start, end])
  } catch {
    invalid()
  }
}

function set(target, source, offset = 0) {
  try {
    reflectApply(bufferSet, target, [source, offset])
  } catch {
    invalid()
  }
}

function uint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function branchClass(value) {
  if (value !== BRANCH_CLASS.LOOKUP && value !== BRANCH_CLASS.ANNOUNCE) invalid()
  return value
}

function writeUint16(target, value, offset) {
  target[offset] = value >>> 8
  target[offset + 1] = value
}

function writeUint32(target, value, offset) {
  target[offset] = value >>> 24
  target[offset + 1] = value >>> 16
  target[offset + 2] = value >>> 8
  target[offset + 3] = value
}

function writeUint64(target, value, offset) {
  for (let index = offset + 7; index >= offset; index--) {
    target[index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readUint64(target, offset) {
  let value = 0n
  for (let index = offset; index < offset + 8; index++)
    value = (value << 8n) | BigInt(target[index])
  return value
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
    clearDestination(leftDecoded)
    clearDestination(rightDecoded)
  }
}

function clearDestination(value) {
  if (!value) return
  clear(value.id)
  clear(value.handle)
}

function normalizeDestinationRefs(value) {
  if (
    !Array.isArray(value) ||
    value.length < DHT_EXIT_DHT_SEEDS_MIN_COUNT ||
    value.length > DHT_EXIT_DHT_SEEDS_MAX_COUNT
  )
    invalid()
  const refs = []
  try {
    for (const item of value) refs.push(copy(item, DESTINATION_REF_SIZE))
    for (let index = 0; index < refs.length; index++) {
      const decoded = decodeDestinationRef(refs[index])
      clearDestination(decoded)
      if (index === 0) continue
      const comparison = compareDestinationRefs(refs[index - 1], refs[index])
      if (comparison >= 0) invalid()
    }
    return refs
  } catch (err) {
    for (const ref of refs) clear(ref)
    if (err instanceof PrivateRouteError) throw err
    invalid()
  }
}

function digestInput(destinationRefs) {
  const domain = DOMAIN.DHT_EXIT_DHT_SEEDS_SET
  const input = b4a.allocUnsafeSlow(
    3 + domain.byteLength + destinationRefs.length * DESTINATION_REF_SIZE
  )
  let offset = 0
  writeUint16(input, domain.byteLength, offset)
  offset += 2
  set(input, domain, offset)
  offset += domain.byteLength
  input[offset++] = destinationRefs.length
  for (const ref of destinationRefs) {
    set(input, ref, offset)
    offset += DESTINATION_REF_SIZE
  }
  return input
}

function seedSetDigest(destinationRefs) {
  let input = null
  try {
    input = digestInput(destinationRefs)
    return cryptoSuite.hash([input])
  } finally {
    clear(input)
  }
}

function signatureInput(body) {
  const domain = DOMAIN.DHT_EXIT_DHT_SEEDS
  const input = b4a.allocUnsafeSlow(10 + domain.byteLength + body.byteLength)
  let offset = 0
  writeUint16(input, domain.byteLength, offset)
  offset += 2
  set(input, domain, offset)
  offset += domain.byteLength
  writeUint32(input, M3_PROTOCOL_VERSION, offset)
  offset += 4
  writeUint16(input, M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1, offset)
  offset += 2
  writeUint16(input, body.byteLength, offset)
  offset += 2
  set(input, body, offset)
  return input
}

function encodeBody(value) {
  const branch = branchClass(dataProperty(value, 'branchClass'))
  const generation = dataProperty(value, 'generation')
  if (!uint64(generation)) invalid()
  const branchId = copy(dataProperty(value, 'branchId'), 16)
  const circuitId = copy(dataProperty(value, 'circuitId'), 16)
  const exitIdentity = copy(dataProperty(value, 'exitIdentity'), 32)
  const seedSetNonce = copy(dataProperty(value, 'seedSetNonce'), 32)
  const destinationRefs = normalizeDestinationRefs(dataProperty(value, 'destinationRefs'))
  const digest = copy(dataProperty(value, 'seedSetDigest'), 32)
  let body = null
  let complete = false
  try {
    const expectedDigest = seedSetDigest(destinationRefs)
    try {
      if (!b4a.equals(digest, expectedDigest)) invalid()
    } finally {
      clear(expectedDigest)
    }
    body = b4a.allocUnsafeSlow(
      DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE + destinationRefs.length * DESTINATION_REF_SIZE
    )
    body[0] = branch
    set(body, branchId, 1)
    set(body, circuitId, 17)
    writeUint64(body, generation, 33)
    set(body, exitIdentity, 41)
    set(body, seedSetNonce, 73)
    body[105] = destinationRefs.length
    let offset = DHT_EXIT_DHT_SEEDS_REF_OFFSET
    for (const ref of destinationRefs) {
      set(body, ref, offset)
      offset += DESTINATION_REF_SIZE
    }
    set(body, digest, offset)
    complete = true
    return body
  } finally {
    clear(branchId)
    clear(circuitId)
    clear(exitIdentity)
    clear(seedSetNonce)
    for (const ref of destinationRefs) clear(ref)
    clear(digest)
    if (!complete) clear(body)
  }
}

function decodeBody(body) {
  const bodyBytes = bufferLength(body)
  if (
    bodyBytes < DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE + DESTINATION_REF_SIZE ||
    bodyBytes >
      DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE + DESTINATION_REF_SIZE * DHT_EXIT_DHT_SEEDS_MAX_COUNT
  ) {
    invalid()
  }
  const count = body[105]
  if (count < DHT_EXIT_DHT_SEEDS_MIN_COUNT || count > DHT_EXIT_DHT_SEEDS_MAX_COUNT) invalid()
  if (bodyBytes !== DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE + count * DESTINATION_REF_SIZE) invalid()
  const branch = branchClass(body[0])
  let offset = DHT_EXIT_DHT_SEEDS_REF_OFFSET
  const destinationRefs = []
  const result = {
    branchClass: branch,
    branchId: copy(subarray(body, 1, 17), 16),
    circuitId: copy(subarray(body, 17, 33), 16),
    generation: readUint64(body, 33),
    exitIdentity: copy(subarray(body, 41, 73), 32),
    seedSetNonce: copy(subarray(body, 73, 105), 32),
    destinationRefs,
    seedSetDigest: null,
    signature: null
  }
  let complete = false
  try {
    for (let index = 0; index < count; index++) {
      destinationRefs.push(
        copy(subarray(body, offset, offset + DESTINATION_REF_SIZE), DESTINATION_REF_SIZE)
      )
      offset += DESTINATION_REF_SIZE
    }
    normalizeDestinationRefs(destinationRefs).forEach(clear)
    result.seedSetDigest = copy(subarray(body, offset, offset + 32), 32)
    const expectedDigest = seedSetDigest(destinationRefs)
    try {
      if (!b4a.equals(result.seedSetDigest, expectedDigest)) invalid()
    } finally {
      clear(expectedDigest)
    }
    complete = true
    return result
  } finally {
    if (!complete) clearDhtExitSeeds(result)
  }
}

function signDhtExitSeeds(value, exitSecretKey) {
  object(value)
  const refs = normalizeDestinationRefs(dataProperty(value, 'destinationRefs'))
  let digest = null
  let body = null
  let input = null
  let signature = null
  const result = {
    branchClass: dataProperty(value, 'branchClass'),
    branchId: copy(dataProperty(value, 'branchId'), 16),
    circuitId: copy(dataProperty(value, 'circuitId'), 16),
    generation: dataProperty(value, 'generation'),
    exitIdentity: copy(dataProperty(value, 'exitIdentity'), 32),
    seedSetNonce: copy(dataProperty(value, 'seedSetNonce'), 32),
    destinationRefs: refs,
    seedSetDigest: null,
    signature: null
  }
  let complete = false
  try {
    if (!fixed(exitSecretKey, 64)) invalid()
    digest = seedSetDigest(refs)
    result.seedSetDigest = copy(digest, 32)
    body = encodeBody(result)
    input = signatureInput(body)
    signature = cryptoSuite.sign(input, exitSecretKey)
    if (!fixed(signature, 64)) invalid()
    result.signature = copy(signature, 64)
    complete = true
    return objectFreeze(result)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(digest)
    clear(body)
    clear(input)
    clear(signature)
    if (!complete) clearDhtExitSeeds(result)
  }
}
function createDhtExitSeedsDeliveryAuthority(table) {
  const snapshot = snapshotDhtExitDestinationTable(table)
  const authority = Object.freeze({})
  SEED_DELIVERY_AUTHORITIES.set(authority, snapshot)
  return authority
}

function signDhtExitSeedsFromAuthority(authority, value, exitSecretKey) {
  object(value)
  const snapshot = SEED_DELIVERY_AUTHORITIES.get(authority)
  if (snapshot === undefined) {
    if (SPENT_SEED_DELIVERY_AUTHORITIES.has(authority)) throw PrivateRouteError.ERR_REPLAY()
    authentication()
  }
  SEED_DELIVERY_AUTHORITIES.delete(authority)
  SPENT_SEED_DELIVERY_AUTHORITIES.add(authority)
  if (typeof snapshot.live !== 'function' || !snapshot.live())
    throw PrivateRouteError.ERR_DESTROYED()
  return signDhtExitSeeds(
    {
      branchClass: snapshot.branchClass,
      branchId: snapshot.branchId,
      circuitId: snapshot.circuitId,
      generation: snapshot.generation,
      exitIdentity: snapshot.exitIdentity,
      expiresAt: snapshot.expiresAt,
      seedSetNonce: dataProperty(value, 'seedSetNonce'),
      destinationRefs: snapshot.destinationRefs
    },
    exitSecretKey
  )
}

function encodeDhtExitSeeds(value) {
  let body = null
  let signature = null
  try {
    object(value)
    signature = copy(dataProperty(value, 'signature'), 64)
    body = encodeBody(value)
    return encodeM3Object({
      messageId: M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1,
      body,
      authSuffix: signature
    })
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    clear(body)
    clear(signature)
  }
}

function decodeDhtExitSeeds(encoded) {
  let decoded = null
  let result = null
  let complete = false
  try {
    decoded = decodeM3Object(encoded)
    if (decoded.messageId !== M3_MESSAGE_ID.DHT_EXIT_DHT_SEEDS_V1 || !fixed(decoded.authSuffix, 64))
      invalid()
    result = decodeBody(decoded.body)
    result.signature = copy(decoded.authSuffix, 64)
    complete = true
    return objectFreeze(result)
  } catch (err) {
    if (err instanceof PrivateRouteError) throw err
    invalid()
  } finally {
    if (decoded) {
      clear(decoded.body)
      clear(decoded.authSuffix)
    }
    if (!complete) clearDhtExitSeeds(result)
  }
}

function same(left, right) {
  return b4a.isBuffer(left) && b4a.isBuffer(right) && b4a.equals(left, right)
}

function verifyDhtExitSeeds(encoded, expected, now) {
  expected = object(expected)
  const decoded = decodeDhtExitSeeds(encoded)
  let body = null
  let input = null
  try {
    if (
      decoded.branchClass !== dataProperty(expected, 'branchClass') ||
      !same(decoded.branchId, dataProperty(expected, 'branchId')) ||
      !same(decoded.circuitId, dataProperty(expected, 'circuitId')) ||
      decoded.generation !== dataProperty(expected, 'generation') ||
      !same(decoded.exitIdentity, dataProperty(expected, 'exitIdentity'))
    ) {
      authentication()
    }
    const expiresAt = dataProperty(expected, 'expiresAt')
    if (!uint64(expiresAt) || !uint64(now) || now >= expiresAt) authentication()
    body = encodeBody(decoded)
    input = signatureInput(body)
    if (!cryptoSuite.verify(input, decoded.signature, decoded.exitIdentity)) authentication()
    return decoded
  } catch (err) {
    clearDhtExitSeeds(decoded)
    if (err instanceof PrivateRouteError) throw err
    authentication()
  } finally {
    clear(body)
    clear(input)
  }
}

function clearDhtExitSeeds(value) {
  if (!value || typeof value !== 'object') return false
  clear(value.branchId)
  clear(value.circuitId)
  clear(value.exitIdentity)
  clear(value.seedSetNonce)
  clear(value.seedSetDigest)
  clear(value.signature)
  if (Array.isArray(value.destinationRefs)) {
    for (const ref of value.destinationRefs) clear(ref)
  }
  return true
}

module.exports = objectFreeze({
  DHT_EXIT_DHT_SEEDS_BODY_FIXED_SIZE,
  createDhtExitSeedsDeliveryAuthority,
  DHT_EXIT_DHT_SEEDS_MAX_COUNT,
  DHT_EXIT_DHT_SEEDS_MIN_COUNT,
  clearDhtExitSeeds,
  decodeDhtExitSeeds,
  encodeDhtExitSeeds,
  signDhtExitSeeds,
  signDhtExitSeedsFromAuthority,
  verifyDhtExitSeeds
})
