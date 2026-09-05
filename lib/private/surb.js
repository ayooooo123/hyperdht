'use strict'

// EXPERIMENTAL — Gate C: Sphinx single-use reply blocks (SURBs) for DATAGRAM
// replies. This module implements the Sphinx construction from the paper
// (Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format",
// IEEE S&P 2009, section 3): header with a blinding chain, per-hop replay
// tags, shift-and-fill routing area, and the LIONESS wide-block body cipher.
//
// Primitive bindings and conformance vectors follow the Goldberg-lineage
// reference implementation (applied-mixnetworks/sphinxmixcrypto, pinned at
// b1603ab; binary-compatible with go-sphinxmixcrypto). No reference code is
// copied: this module implements the published construction on this
// repository's pinned sodium-universal. The reference's published test
// constants are the conformance authority; see test/private/surb.js.
//
// Bindings (both profiles):
//   H(d)          BLAKE2b-256
//   HB(a, s)      clamp32(H(0x11 || a || s))          blinding factor
//   rho(s)        ChaCha20 keystream keyed H(0x22||s), djb 8-byte zero nonce
//   mu(s, beta)   keyed BLAKE2b-lambda, key H(0x33||s) truncated to lambda
//   pi(s, delta)  LIONESS: k1(32)|k2(64)|k3(32)|k4(64) from ChaCha20 keystream
//                 keyed H(0x44||s); stream rounds ChaCha20, hash rounds
//                 keyed BLAKE2b-256
//   tag(s)        H(0x55 || s)                        replay tag
//   group         X25519 (clamped scalars); all-zero agreement rejected
//                 (v1 security contract; the reference accepts any 32-byte
//                 element — published vectors do not exercise zero, so
//                 conformance is unaffected)
//   padding       src || 0* || LE16(len(src) + zeros)
//
// Profiles (paper parameters: lambda = MAC/id security parameter, idBytes =
// node id length, hopEntry = routing-area bytes consumed per hop, maxHops =
// r_max, deltaBytes = body size):
//   VECTORS:    lambda 16, idBytes 16, hopEntry 32, maxHops 5, delta 1024,
//               unkinded ids (the reference grammar: node ids begin 0xff)
//               — reproduces the reference's published vectors exactly.
//   PRODUCTION: lambda 32, idBytes 32 (the relay X25519 route-encryption
//               public key), hopEntry 65 (0xff kind + 32 id + 32 gamma),
//               maxHops 3, delta 906 — a reply datagram is exactly
//               4 magic + 32 alpha + 226 beta + 32 gamma + 906 delta = 1200
//               bytes, the fixed v1 cell size. Reply payload cap: 872 bytes.
//               Routing entries are kinded: a hop entry starts 0xff; a
//               terminal entry starts a client-destination length byte
//               (1..127), which keeps the area prefix-free.
//
// Replay admission is MANDATORY and fail-closed: processSurbHop requires a
// guard; the paper's tag check runs before the MAC check and before any
// transformation; the guard never evicts and throws ERR_QUOTA_EXCEEDED on
// overflow. Not wire-stable: external cryptographic review is still required
// before the format is frozen.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { PrivateRouteError } = require('./errors')

const HASH_BLINDING = b4a.from([0x11])
const HASH_STREAM = b4a.from([0x22])
const HASH_HMAC = b4a.from([0x33])
const HASH_BLOCK = b4a.from([0x44])
const HASH_REPLAY = b4a.from([0x55])

const SHARED_SECRET_BYTES = 32
const SECRET_KEY_BYTES = 32
const GROUP_ELEMENT_BYTES = 32
const STREAM_KEY_BYTES = 32 // LIONESS left half and stream-round key size
const HASH_KEY_BYTES = 64 // LIONESS hash-round key size (blake2b maximum)
const BLOCK_KEY_BYTES = 2 * STREAM_KEY_BYTES + 2 * HASH_KEY_BYTES // 192
const ZERO_32 = b4a.alloc(32)
const NODE_KIND = 0xff // kinded-profile "next mix" entry byte
const DEFAULT_REPLAY_ENTRIES = 1 << 16

const VECTORS = Object.freeze({
  name: 'hyperdht-private-routes/surb/vectors/v1',
  lambda: 16,
  idBytes: 16,
  hopEntry: 32,
  maxHops: 5,
  deltaBytes: 1024,
  kinded: false
})

const PRODUCTION = Object.freeze({
  name: 'hyperdht-private-routes/surb/production/v1',
  lambda: 32,
  idBytes: 32,
  hopEntry: 65,
  maxHops: 3,
  deltaBytes: 906,
  kinded: true,
  magic: b4a.from('SURB'),
  datagramBytes: 1200
})

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function isBuffer(value, size) {
  return b4a.isBuffer(value) && value.byteLength === size
}

function copy(buffer, size) {
  if (!isBuffer(buffer, size)) invalid()
  const out = b4a.allocUnsafeSlow(size)
  out.set(buffer)
  return out
}

function zeroInto(...buffers) {
  for (const buffer of buffers) if (b4a.isBuffer(buffer)) sodium.sodium_memzero(buffer)
}

function xorInto(target, source, sourceOffset = 0) {
  for (let i = 0; i < target.byteLength; i++) target[i] ^= source[sourceOffset + i]
}

function sameBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false
  return sodium.sodium_memcmp(left, right)
}

function hash32(data) {
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, data)
  return out
}

function prefixedHash32(prefix, ...parts) {
  const input = b4a.allocUnsafe(prefix.byteLength + parts.reduce((n, p) => n + p.byteLength, 0))
  let offset = 0
  input.set(prefix, offset)
  offset += prefix.byteLength
  for (const part of parts) {
    input.set(part, offset)
    offset += part.byteLength
  }
  const out = hash32(input)
  zeroInto(input)
  return out
}

function clamp32(scalar) {
  const out = copy(scalar, 32)
  out[0] &= 248
  out[31] &= 127
  out[31] |= 64
  return out
}

function blindingFactor(alpha, shared) {
  return clamp32(prefixedHash32(HASH_BLINDING, alpha, shared))
}

// ChaCha20 (djb) keystream with an 8-byte zero nonce, counter from zero — the
// reference's SphinxStreamCipher. Binding order is (c, m, nonce, ic, k).
function chachaXor(key, data) {
  if (!isBuffer(key, STREAM_KEY_BYTES)) invalid()
  const nonce = b4a.alloc(8)
  const out = b4a.alloc(data.byteLength)
  let offset = 0
  let block = 0
  while (offset < data.byteLength) {
    const chunk = Math.min(64, data.byteLength - offset)
    sodium.crypto_stream_chacha20_xor_ic(
      out.subarray(offset, offset + chunk),
      data.subarray(offset, offset + chunk),
      nonce,
      block,
      key
    )
    offset += chunk
    block++
  }
  return out
}

function streamKey(shared) {
  return prefixedHash32(HASH_STREAM, shared)
}

function hmacKey(shared, lambda) {
  const full = prefixedHash32(HASH_HMAC, shared)
  const out = full.subarray(0, lambda)
  sodium.sodium_memzero(full.subarray(lambda))
  return out
}

function betaMac(shared, beta, lambda) {
  const out = b4a.allocUnsafeSlow(lambda)
  sodium.crypto_generichash(out, beta, hmacKey(shared, lambda))
  return out
}

function blockCipherKey(shared) {
  const k = prefixedHash32(HASH_BLOCK, shared)
  const key = chachaXor(k, b4a.alloc(BLOCK_KEY_BYTES))
  zeroInto(k)
  return key
}

function replayTag(shared) {
  return prefixedHash32(HASH_REPLAY, shared)
}

// LIONESS (Lucks-Anderson 4-round UNP; Sphinx paper section 3.1):
//   E: R ^= S(L^k1); L ^= H(k2,R); R ^= S(L^k3); L ^= H(k4,R)
// k1|k2|k3|k4 = 32|64|32|64 bytes of the block key; L = the left 32 bytes.
// LIONESS is a Feistel construction, so E_k^{-1} = E_k with the rounds
// reversed; decrypt at a hop and encrypt at the opener use the SAME rounds.
function lionessRoundL(l, r, k) {
  const t = b4a.from(l)
  xorInto(t, k)
  const s = chachaXor(t, r)
  r.set(s)
  zeroInto(t, s)
}

function lionessHashL(l, r, key) {
  const h = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(h, r, key)
  xorInto(l, h)
  zeroInto(h)
}

function lionessEncrypt(key, block) {
  const l = b4a.from(block.subarray(0, STREAM_KEY_BYTES))
  const r = b4a.from(block.subarray(STREAM_KEY_BYTES))
  lionessRoundL(l, r, key.subarray(0, STREAM_KEY_BYTES))
  lionessHashL(l, r, key.subarray(STREAM_KEY_BYTES, STREAM_KEY_BYTES + HASH_KEY_BYTES))
  lionessRoundL(l, r, key.subarray(STREAM_KEY_BYTES + HASH_KEY_BYTES, 2 * STREAM_KEY_BYTES + HASH_KEY_BYTES))
  lionessHashL(l, r, key.subarray(2 * STREAM_KEY_BYTES + HASH_KEY_BYTES, BLOCK_KEY_BYTES))
  const out = b4a.concat([l, r])
  zeroInto(l, r)
  return out
}

function lionessDecrypt(key, block) {
  const l = b4a.from(block.subarray(0, STREAM_KEY_BYTES))
  const r = b4a.from(block.subarray(STREAM_KEY_BYTES))
  lionessHashL(l, r, key.subarray(2 * STREAM_KEY_BYTES + HASH_KEY_BYTES, BLOCK_KEY_BYTES))
  lionessRoundL(l, r, key.subarray(STREAM_KEY_BYTES + HASH_KEY_BYTES, 2 * STREAM_KEY_BYTES + HASH_KEY_BYTES))
  lionessHashL(l, r, key.subarray(STREAM_KEY_BYTES, STREAM_KEY_BYTES + HASH_KEY_BYTES))
  lionessRoundL(l, r, key.subarray(0, STREAM_KEY_BYTES))
  const out = b4a.concat([l, r])
  zeroInto(l, r)
  return out
}

// Padding (reference binding): src || 0* || LE16(len(src) + zeros).
function addPadding(src, blockSize) {
  if (blockSize <= 2 || src.byteLength === 0 || src.byteLength >= blockSize - 2) invalid()
  const offset = blockSize - src.byteLength
  const out = b4a.alloc(blockSize)
  out.set(src, 0)
  out[blockSize - 2] = offset & 0xff
  out[blockSize - 1] = (offset >> 8) & 0xff
  return out
}

function removePadding(src) {
  if (src.byteLength < 2) invalid()
  const offset = src[src.byteLength - 2] | (src[src.byteLength - 1] << 8)
  if (offset === 0 || offset > src.byteLength) invalid()
  return src.subarray(0, src.byteLength - offset)
}

// Client destination (prefix-free terminal entry): [len 1..127][bytes].
function encodeClientDestination(id) {
  if (!b4a.isBuffer(id) || id.byteLength < 1 || id.byteLength > 127) invalid()
  const out = b4a.allocUnsafeSlow(id.byteLength + 1)
  out[0] = id.byteLength
  out.set(id, 1)
  return out
}

function decodeClientDestination(encoded) {
  if (!b4a.isBuffer(encoded) || encoded.byteLength < 2) invalid()
  if (encoded[0] < 1 || encoded[0] > 127) invalid()
  if (encoded.byteLength !== encoded[0] + 1) invalid()
  return b4a.from(encoded.subarray(1))
}

function betaSizeFor(profile) {
  return (profile.maxHops - 1) * profile.hopEntry + 3 * profile.lambda
}

function maxPayloadFor(profile) {
  return profile.deltaBytes - profile.lambda - 2
}

// Replay guard: strict single-use up to capacity. Never evicts; a repeat
// returns true from hasSeen (the caller rejects) and an overflow with a fresh
// tag throws ERR_QUOTA_EXCEEDED (fail-closed: rotate the epoch or raise
// capacity). reset() at epoch rollover.
function createReplayGuard(maxEntries = DEFAULT_REPLAY_ENTRIES) {
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) invalid()
  const seen = new Map()
  return {
    hasSeen(tag) {
      if (!isBuffer(tag, SHARED_SECRET_BYTES)) invalid()
      return seen.has(b4a.toString(tag, 'hex'))
    },
    setSeen(tag) {
      if (!isBuffer(tag, SHARED_SECRET_BYTES)) invalid()
      const key = b4a.toString(tag, 'hex')
      if (seen.has(key)) return
      if (seen.size >= maxEntries) replay()
      seen.set(key, true)
    },
    get size() {
      return seen.size
    },
    reset() {
      seen.clear()
    }
  }
}

// Blinding chain per the paper: alpha_0 = g^x; s_i = y_i^(x*prod(b));
// b_i = HB(alpha_i, s_i); alpha_{i+1} = alpha_i^{b_i}. X25519 scalarmult IS
// point exponentiation, so the paper's blinding chain is implemented directly.
// The sodium-native wrapper throws on scalarmult failure; a computed secret
// that is all zeros still succeeds, so the v1 all-zero rule checks the value.
function sharedIsZero(shared) {
  return sameBytes(shared, ZERO_32)
}

function computeRouteChain(route, opts) {
  const x = b4a.allocUnsafeSlow(SECRET_KEY_BYTES)
  if (opts === undefined || opts.xSeed === undefined) {
    sodium.crypto_core_ed25519_scalar_random(x)
  } else {
    x.set(clamp32(opts.xSeed))
  }
  const alphas = new Array(route.length)
  const shareds = new Array(route.length)
  let alpha = b4a.alloc(GROUP_ELEMENT_BYTES)
  sodium.crypto_scalarmult_base(alpha, x)
  // Blinding factors seen so far, applied to each hop's public key as point
  // exponentiations (reference multiexpon): s_i = ((y_i^x)^b_0)^b_1...
  const blinds = [x]
  for (let i = 0; i < route.length; i++) {
    const hop = route[i]
    const key = hop.key === undefined ? hop.id : hop.key
    if (!isBuffer(key, SHARED_SECRET_BYTES)) {
      zeroInto(x, ...shareds)
      invalid()
    }
    // Start from the hop's public key y_i, then apply the accumulated
    // blinding chain as point exponentiations: ((y_i^x)^b_0)^b_1...
    let shared = b4a.alloc(GROUP_ELEMENT_BYTES)
    shared.set(key)
    for (const blind of blinds) {
      const out = b4a.alloc(GROUP_ELEMENT_BYTES)
      sodium.crypto_scalarmult(out, blind, shared)
      zeroInto(shared)
      shared = out
    }
    if (sameBytes(shared, ZERO_32)) {
      zeroInto(shared, ...shareds, x)
      invalid()
    }
    alphas[i] = b4a.from(alpha)
    shareds[i] = shared
    if (i < route.length - 1) {
      const blind = blindingFactor(alpha, shared)
      const next = b4a.alloc(GROUP_ELEMENT_BYTES)
      sodium.crypto_scalarmult(next, blind, alpha)
      zeroInto(alpha)
      alpha = next
      blinds.push(blind)
    }
  }
  zeroInto(x, alpha)
  return { alphas, shareds }
}

// phi: accumulated per the reference. phi_1 = ks_0[betaSize..betaSize+e];
// phi_i = (phi_{i-1} || 0^e) XOR ks_{i-1}[betaSize-(i-1)e .. betaSize-(i-1)e+2e].
// Each wrap stage's zero-tail reconstruction reproduces the next wire beta
// exactly because the accumulated slices cancel per position.
function makeFiller(profile, shareds) {
  const betaSize = betaSizeFor(profile)
  const { hopEntry } = profile
  let phi = b4a.alloc(0)
  for (let i = 1; i <= shareds.length - 1; i++) {
    const min = betaSize - (i - 1) * hopEntry
    const stream = chachaXor(streamKey(shareds[i - 1]), b4a.alloc(betaSize + hopEntry))
    const grown = b4a.alloc(phi.byteLength + hopEntry)
    grown.set(phi, 0)
    xorInto(grown, stream, min)
    zeroInto(stream)
    zeroInto(phi)
    phi = grown
  }
  return phi
}
// Build a SURB. route: [{ id }] in return order (H_1 first); destination is
// the prefix-free terminal entry; messageId is lambda bytes. Seeds in opts
// exist ONLY for deterministic conformance vectors.
function buildSurb(profile, route, destination, messageId, opts) {
  const { lambda, maxHops, hopEntry, kinded } = profile
  const betaSize = betaSizeFor(profile)
  if (!Array.isArray(route) || route.length === 0 || route.length > maxHops) invalid()
  if (!b4a.isBuffer(destination) || destination.byteLength < 2 || destination.byteLength > 128) invalid()
  if (kinded && destination[0] === NODE_KIND) invalid()
  if (!isBuffer(messageId, lambda)) invalid()

  const routeLen = route.length
  const chunkSize = betaSize - (routeLen - 1) * hopEntry
  if (destination.byteLength + messageId.byteLength > chunkSize) {
    invalid()
  }
  const { alphas, shareds } = computeRouteChain(route, opts)
  const phi = makeFiller(profile, shareds)
  // Paper structure, top-down: plaintext routing areas in PLAINTEXT space,
  // then each hop's wire beta = plaintext ⊕ rho(s_i) and gamma = mu(s_i, wire).
  // plaintext_i = [entry_{i+1} (hopEntry)][plaintext_{i+1} head] with the filler
  // restoring constant size; the receiver's zero-tail reconstructs the fresh
  // keystream tail that closes every layer.
  const chunk = b4a.allocUnsafe(chunkSize)
  chunk.set(destination, 0)
  chunk.set(messageId, destination.byteLength)
  if (opts !== undefined && opts.paddingSeed !== undefined) {
    if (!isBuffer(opts.paddingSeed, chunkSize - destination.byteLength - messageId.byteLength)) {
      zeroInto(...shareds)
      invalid()
    }
    chunk.set(opts.paddingSeed, destination.byteLength + messageId.byteLength)
  }
  // wire_r = ([dest||I||pad] XOR ks_r[0..chunkSize]) || phi — only the chunk
  // is masked; phi is appended as already-masked bytes (reference: the
  // keystream slices inside phi are what every later zero-tail restores).
  const terminalStream = chachaXor(streamKey(shareds[routeLen - 1]), b4a.alloc(betaSize + hopEntry))
  const maskedChunk = b4a.alloc(chunkSize)
  maskedChunk.set(chunk, 0)
  xorInto(maskedChunk, terminalStream)
  zeroInto(chunk)
  zeroInto(terminalStream)
  // wire_r = maskedChunk || phi: chunkSize + (r-1)*hopEntry = betaSize.
  let wire = b4a.alloc(betaSize)
  wire.set(maskedChunk, 0)
  if (phi.byteLength > 0) wire.set(phi, chunkSize)
  zeroInto(maskedChunk)
  let gamma = betaMac(shareds[routeLen - 1], wire, lambda)

  for (let i = routeLen - 2; i >= 0; i--) {
    // plaintext_i = [entry_{i+1}][wire_{i+1} head (betaSize - hopEntry)]
    const plain = b4a.alloc(betaSize)
    let offset = 0
    if (kinded) {
      plain[0] = NODE_KIND
      offset = 1
    }
    plain.set(route[i + 1].id.subarray(0, profile.idBytes), offset)
    plain.set(gamma, offset + profile.idBytes)
    plain.set(wire.subarray(0, betaSize - hopEntry), hopEntry)
    const layerStream = chachaXor(streamKey(shareds[i]), b4a.alloc(betaSize + hopEntry))
    wire = b4a.from(plain)
    xorInto(wire, layerStream)
    zeroInto(layerStream, plain)
    gamma = betaMac(shareds[i], wire, lambda)
  }

  const kTilde = b4a.allocUnsafeSlow(SECRET_KEY_BYTES)
  if (opts !== undefined && opts.kTildeSeed !== undefined) {
    if (!isBuffer(opts.kTildeSeed, SECRET_KEY_BYTES)) {
      zeroInto(...shareds)
      invalid()
    }
    kTilde.set(opts.kTildeSeed)
  } else {
    sodium.crypto_core_ed25519_scalar_random(kTilde)
  }

  const keys = shareds.map((s) => blockCipherKey(s))
  zeroInto(...shareds)
  return {
    surb: {
      firstHop: copy(route[0].id, route[0].id.byteLength),
      kTilde,
      header: { alpha: b4a.from(alphas[0]), beta: wire, gamma }
    },
    openToken: { kTilde, keys }
  }
}

// Responder: attach the payload. delta_0 = pi_{k~}(pad(0^lambda || payload)).
function sealReply(profile, surb, payload) {
  const { lambda, deltaBytes } = profile
  if (
    !surb ||
    typeof surb !== 'object' ||
    !isBuffer(surb.kTilde, SECRET_KEY_BYTES) ||
    !surb.header ||
    typeof surb.header !== 'object' ||
    !isBuffer(surb.header.alpha, GROUP_ELEMENT_BYTES) ||
    !isBuffer(surb.header.beta, betaSizeFor(profile)) ||
    !isBuffer(surb.header.gamma, lambda) ||
    !isBuffer(surb.firstHop, surb.firstHop.byteLength) ||
    surb.firstHop.byteLength === 0
  ) {
    invalid()
  }
  if (!b4a.isBuffer(payload) || payload.byteLength === 0 || payload.byteLength > maxPayloadFor(profile)) {
    invalid()
  }
  const key = blockCipherKey(surb.kTilde)
  const delta = lionessEncrypt(
    key,
    addPadding(b4a.concat([b4a.alloc(lambda), payload]), deltaBytes)
  )
  zeroInto(key)
  return {
    firstHop: b4a.from(surb.firstHop),
    header: {
      alpha: b4a.from(surb.header.alpha),
      beta: b4a.from(surb.header.beta),
      gamma: b4a.from(surb.header.gamma)
    },
    delta
  }
}

// Initiator: undo the network layers in reverse hop order (each hop applied
// one pi layer with E_k; the opener applies E_k in reverse, which is D_k in
// the LIONESS Feistel construction), then D_{k~}, then the 0^lambda marker
// check and unpadding.
function openReply(profile, reply, openToken) {
  const { lambda, deltaBytes } = profile
  if (!reply || typeof reply !== 'object' || !isBuffer(reply.delta, deltaBytes)) invalid()
  if (
    !openToken ||
    typeof openToken !== 'object' ||
    !isBuffer(openToken.kTilde, SECRET_KEY_BYTES) ||
    !Array.isArray(openToken.keys) ||
    openToken.keys.length === 0 ||
    openToken.keys.length > profile.maxHops
  ) {
    invalid()
  }
  let delta = b4a.from(reply.delta)
  for (let i = openToken.keys.length - 1; i >= 0; i--) {
    const key = openToken.keys[i]
    if (!isBuffer(key, BLOCK_KEY_BYTES)) {
      zeroInto(delta)
      invalid()
    }
    const stripped = lionessEncrypt(key, delta)
    zeroInto(delta)
    delta = stripped
  }
  const kTildeKey = blockCipherKey(openToken.kTilde)
  const plain = lionessDecrypt(kTildeKey, delta)
  zeroInto(kTildeKey, delta)
  for (let i = 0; i < lambda; i++) {
    if (plain[i] !== 0) {
      zeroInto(plain)
      invalid()
    }
  }
  const payload = b4a.from(removePadding(plain.subarray(lambda)))
  zeroInto(plain)
  return payload
}

// Relay hop (paper section 3.6): DH, mandatory replay-tag admission, MAC
// check, alpha blinding, beta shift, delta layer peel with pi. s stays live
// until every derived key exists; zeroized exactly once at the end.
function processSurbHop(profile, message, nodeSecretKey, guard) {
  const { lambda, idBytes, hopEntry, deltaBytes, maxHops, kinded } = profile
  const betaSize = betaSizeFor(profile)
  if (
    !message ||
    typeof message !== 'object' ||
    !message.header ||
    typeof message.header !== 'object' ||
    !isBuffer(message.header.alpha, GROUP_ELEMENT_BYTES) ||
    !isBuffer(message.header.beta, betaSize) ||
    !isBuffer(message.header.gamma, lambda) ||
    !isBuffer(message.delta, deltaBytes) ||
    !isBuffer(nodeSecretKey, SECRET_KEY_BYTES)
  ) {
    invalid()
  }
  if (!guard || typeof guard.hasSeen !== 'function' || typeof guard.setSeen !== 'function') replay()

  const header = message.header
  if (sameBytes(header.alpha, ZERO_32)) invalid()
  const shared = b4a.allocUnsafeSlow(SHARED_SECRET_BYTES)
  sodium.crypto_scalarmult(shared, nodeSecretKey, header.alpha)
  if (sharedIsZero(shared)) {
    zeroInto(shared)
    invalid()
  }
  const tag = replayTag(shared)
  // Paper 3.6: the replay check comes before the MAC check.
  if (guard.hasSeen(tag)) {
    zeroInto(shared)
    replay()
  }
  const expected = betaMac(shared, header.beta, lambda)
  if (!sameBytes(expected, header.gamma)) {
    zeroInto(shared)
    invalid()
  }
  guard.setSeen(tag)

  // Routing area: B = (beta || 0^hopEntry) XOR rho(s)[0..betaSize+hopEntry].
  const stream = chachaXor(streamKey(shared), b4a.alloc(betaSize + hopEntry))
  const area = b4a.alloc(betaSize + hopEntry)
  area.set(header.beta, 0)
  xorInto(area, stream)
  zeroInto(stream)

  // Parse the entry. Kinded: [0xff][id][gamma] relays; a client-destination
  // length byte (1..127) terminates. Unkinded (reference grammar): ids are
  // lambda bytes and begin 0xff; any other first byte is not a relay entry.
  const terminal = area[0] !== NODE_KIND
  let failed = false
  if (terminal && (area[0] < 1 || area[0] > 127 || 1 + area[0] > area.byteLength)) failed = true
  const nextHop = b4a.alloc(idBytes)
  const nextGamma = b4a.alloc(lambda)
  const nextBeta = b4a.alloc(betaSize)
  let destination = null
  if (terminal) {
    if (!failed) {
      destination = b4a.alloc(1 + area[0])
      destination.set(area.subarray(0, 1 + area[0]))
    }
  } else {
    if (!failed) {
      nextHop.set(area.subarray(kinded ? 1 : 0, (kinded ? 1 : 0) + idBytes))
      nextGamma.set(area.subarray((kinded ? 1 : 0) + idBytes, (kinded ? 1 : 0) + idBytes + lambda))
      nextBeta.set(area.subarray(hopEntry, hopEntry + betaSize))
    }
  }
  zeroInto(area)

  // Blind the alpha and peel one pi layer off the delta (paper: delta is
  // decrypted at each hop with the hop's pi layer).
  const blind = blindingFactor(header.alpha, shared)
  const nextAlpha = b4a.alloc(GROUP_ELEMENT_BYTES)
  sodium.crypto_scalarmult(nextAlpha, blind, header.alpha)
  zeroInto(blind)

  const layerKey = blockCipherKey(shared)
  zeroInto(shared)
  if (failed) {
    zeroInto(nextHop, nextGamma, nextBeta, nextAlpha, layerKey, destination)
    invalid()
  }

  const delta = lionessDecrypt(layerKey, message.delta)
  zeroInto(layerKey)
  if (terminal) {
    return {
      terminal: true,
      destination,
      delta,
      tag
    }
  }
  return {
    terminal: false,
    nextHop,
    forward: {
      header: { alpha: nextAlpha, beta: nextBeta, gamma: nextGamma },
      delta
    }
  }
}

module.exports = {
  VECTORS,
  PRODUCTION,
  betaSizeFor,
  maxPayloadFor,
  addPadding,
  removePadding,
  encodeClientDestination,
  decodeClientDestination,
  createReplayGuard,
  buildSurb,
  sealReply,
  openReply,
  processSurbHop
}
