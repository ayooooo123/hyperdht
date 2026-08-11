'use strict'

// EXPERIMENTAL — Gate C (Veilid-class "private routes" reply blocks).
// Reference implementation of the SURB construction in
// docs/superpowers/specs/2026-08-10-private-routing-surb-construction-design.md.
//
// Sphinx-style fixed-size header with per-hop independent X25519 DH (Step 0: no
// ristretto / no ed25519 scalar_mul in the pinned sodium, so no scalar blinding). Every
// hop sees a constant-size routing area `beta` (RHO bytes) regardless of its position —
// the filler makes upstream MACs verify after the shift, so a relay cannot infer its
// index from length. Each hop receives its ephemeral E_i in the clear and derives the
// key that decrypts its own block; the block reveals the next hop's clear E_{i+1}.
//
// The reply payload is sealed by the responder to a one-time public key E_pub
// (crypto_box_seal); relays only wrap ciphertext, and only the initiator (holding
// E_priv) can open it.
//
// NOT wired into the DHT and NOT wire-stable. Header integrity is a keyed-BLAKE2b MAC
// (mu). Round-trip for every path length 1..MAX_HOPS + length-invariance is tested, but
// statistical indistinguishability of the filler and the exact wire layout still need
// fixed test vectors + external cryptographic review before the format is frozen.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const ID_BYTES = 32
const KEY_BYTES = 32
const MAC_BYTES = 16
const SEAL_BYTES = sodium.crypto_box_SEALBYTES

const FLAG = 1
const HOP = FLAG + ID_BYTES + KEY_BYTES + MAC_BYTES // flag | nextHop | E_next | next_mac
const MAX_HOPS = 4
const RHO = MAX_HOPS * HOP // constant routing-area size seen by every hop

// Reply-payload budget. On-wire reply message ≈ ephem(32) + header(RHO) + mac(16) + P_0 +
// wrap tags; the largest leg ≈ 372 + (plaintext + 48) + 16*(MAX_HOPS-1). Keep well under
// the 1,200-byte cell (DHT/UDX/cell framing is extra), so cap conservatively.
const MAX_REPLY_BYTES = 700

const TERMINAL = 0
const MORE = 1

const PRG_LABEL = b4a.from('hyperdht-private-routes/surb/prg/v1')
const RHO_KEY = b4a.from('hyperdht-private-routes/surb/rho/v1')
const MU_KEY = b4a.from('hyperdht-private-routes/surb/mu/v1')
const WRAP_KEY = b4a.from('hyperdht-private-routes/surb/wrap-key/v1')
const WRAP_NONCE = b4a.from('hyperdht-private-routes/surb/wrap-nonce/v1')
const NULLIFIER = b4a.from('hyperdht-private-routes/surb/nullifier/v1')

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function isBuffer(value, size) {
  return b4a.isBuffer(value) && (size === undefined || value.byteLength === size)
}

function subkey(sharedSecret, label) {
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, label, sharedSecret)
  return out
}

function mac(muKey, message) {
  const out = b4a.allocUnsafeSlow(MAC_BYTES)
  sodium.crypto_generichash(out, message, muKey)
  return out
}

// BLAKE2b-CTR keystream keyed by `key`, domain-separated by PRG_LABEL.
function prg(key, length) {
  const out = b4a.allocUnsafeSlow(length)
  const block = b4a.allocUnsafeSlow(32)
  const input = b4a.allocUnsafeSlow(PRG_LABEL.byteLength + 4)
  input.set(PRG_LABEL, 0)
  let offset = 0
  let counter = 0
  while (offset < length) {
    const p = PRG_LABEL.byteLength
    input[p] = (counter >>> 24) & 0xff
    input[p + 1] = (counter >>> 16) & 0xff
    input[p + 2] = (counter >>> 8) & 0xff
    input[p + 3] = counter & 0xff
    sodium.crypto_generichash(block, input, key)
    const n = Math.min(32, length - offset)
    out.set(block.subarray(0, n), offset)
    offset += n
    counter++
  }
  return out
}

function xorInto(dst, src, dstOffset, srcOffset, length) {
  for (let i = 0; i < length; i++) dst[dstOffset + i] ^= src[srcOffset + i]
}

function nullifierOf(sharedSecret) {
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, sharedSecret, NULLIFIER)
  return out
}

function hopKeys(sharedSecret) {
  return {
    rhoKey: subkey(sharedSecret, RHO_KEY),
    muKey: subkey(sharedSecret, MU_KEY),
    wrapKey: subkey(sharedSecret, WRAP_KEY),
    wrapNoncePrefix: subkey(sharedSecret, WRAP_NONCE).subarray(0, 16)
  }
}

// Filler = the accumulated keystream tails that must appear at the end of each downstream
// beta so the shift reconstructs it exactly. Length (n-1)*HOP.
function makeFiller(rhoKeys, n) {
  let filler = b4a.alloc(0)
  for (let i = 0; i < n - 1; i++) {
    const grown = b4a.alloc(filler.byteLength + HOP)
    grown.set(filler, 0)
    filler = grown
    const stream = prg(rhoKeys[i], RHO + HOP)
    xorInto(filler, stream, 0, RHO + HOP - filler.byteLength, filler.byteLength)
  }
  return filler
}

// hops: [{ id: <32B>, routeKey: <32B relay X25519 pubkey> }, ...]  (1..MAX_HOPS)
// terminalId: 32B id the last hop forwards the wrapped payload to (the initiator).
function buildSurb(hops, terminalId, opts) {
  if (!Array.isArray(hops) || hops.length === 0 || hops.length > MAX_HOPS) invalid()
  if (!isBuffer(terminalId, ID_BYTES)) invalid()

  const n = hops.length
  // Optional deterministic key seeds (test vectors only); random otherwise.
  const ephemeralSeeds = opts === undefined ? undefined : opts.ephemeralSeeds
  const replySeed = opts === undefined ? undefined : opts.replySeed
  if (
    ephemeralSeeds !== undefined &&
    (!Array.isArray(ephemeralSeeds) || ephemeralSeeds.length !== n)
  ) {
    invalid()
  }
  if (replySeed !== undefined && !isBuffer(replySeed, 32)) invalid()
  const ephem = new Array(n)
  const rhoKeys = new Array(n)
  const muKeys = new Array(n)
  const wrapKeys = new Array(n)

  for (let i = 0; i < n; i++) {
    const h = hops[i]
    if (!isBuffer(h && h.routeKey, KEY_BYTES) || !isBuffer(h && h.id, ID_BYTES)) invalid()
    const eSecret = b4a.allocUnsafeSlow(KEY_BYTES)
    const ePublic = b4a.allocUnsafeSlow(KEY_BYTES)
    if (ephemeralSeeds === undefined) {
      sodium.crypto_box_keypair(ePublic, eSecret)
    } else {
      if (!isBuffer(ephemeralSeeds[i], 32)) invalid()
      sodium.crypto_box_seed_keypair(ePublic, eSecret, ephemeralSeeds[i])
    }
    const shared = cryptoSuite.keyAgreement(eSecret, h.routeKey)
    sodium.sodium_memzero(eSecret)
    const k = hopKeys(shared)
    sodium.sodium_memzero(shared)
    ephem[i] = ePublic
    rhoKeys[i] = k.rhoKey
    muKeys[i] = k.muKey
    wrapKeys[i] = { wrapKey: k.wrapKey, wrapNoncePrefix: k.wrapNoncePrefix }
  }

  const filler = makeFiller(rhoKeys, n)

  // Terminal beta: block at the front, pseudo-random padding, then filler overlaid on the
  // tail so upstream shifts reconstruct it.
  const block = b4a.alloc(HOP)
  block[0] = TERMINAL
  block.set(terminalId, FLAG)
  let beta = prg(subkey(ephem[n - 1], RHO_KEY), RHO) // pad; unread beyond the block
  beta.set(block, 0)
  xorInto(beta, prg(rhoKeys[n - 1], RHO), 0, 0, RHO)
  beta.set(filler, RHO - filler.byteLength)
  let hmac = mac(muKeys[n - 1], beta)

  for (let i = n - 2; i >= 0; i--) {
    const b = b4a.alloc(HOP)
    b[0] = MORE
    b.set(hops[i + 1].id, FLAG)
    b.set(ephem[i + 1], FLAG + ID_BYTES)
    b.set(hmac, FLAG + ID_BYTES + KEY_BYTES)
    const next = b4a.alloc(RHO)
    next.set(b, 0)
    next.set(beta.subarray(0, RHO - HOP), HOP)
    xorInto(next, prg(rhoKeys[i], RHO), 0, 0, RHO)
    beta = next
    hmac = mac(muKeys[i], beta)
  }

  const replyPublicKey = b4a.allocUnsafeSlow(KEY_BYTES)
  const replySecretKey = b4a.allocUnsafeSlow(KEY_BYTES)
  if (replySeed === undefined) sodium.crypto_box_keypair(replyPublicKey, replySecretKey)
  else sodium.crypto_box_seed_keypair(replyPublicKey, replySecretKey, replySeed)

  return {
    surb: {
      firstHop: b4a.from(hops[0].id),
      ephem: ephem[0],
      header: beta,
      mac: hmac,
      replyPubKey: replyPublicKey
    },
    openKeys: {
      replySecretKey,
      replyPubKey: b4a.from(replyPublicKey),
      wrapKeys
    }
  }
}

// Responder side: seal plaintext to the SURB's one-time public key. Relays never see
// plaintext. Returns the message to hand to surb.firstHop.
function sealReply(surb, plaintext) {
  if (!surb || !isBuffer(surb.replyPubKey, KEY_BYTES)) invalid()
  if (
    !isBuffer(surb.ephem, KEY_BYTES) ||
    !isBuffer(surb.header, RHO) ||
    !isBuffer(surb.mac, MAC_BYTES)
  ) {
    invalid()
  }
  if (!isBuffer(plaintext) || plaintext.byteLength > MAX_REPLY_BYTES) invalid()
  const sealed = b4a.allocUnsafeSlow(plaintext.byteLength + SEAL_BYTES)
  sodium.crypto_box_seal(sealed, plaintext, surb.replyPubKey)
  return {
    ephem: b4a.from(surb.ephem),
    header: b4a.from(surb.header),
    mac: b4a.from(surb.mac),
    payload: sealed
  }
}

// Relay side: process one hop. Constant-size beta in and out. Operates on ciphertext
// only. Throws INVALID_ROUTE on any authentication/validation failure (fail-closed).
function processSurbHop(message, routeSecretKey) {
  if (!message || !isBuffer(message.ephem, KEY_BYTES) || !isBuffer(message.header, RHO)) invalid()
  if (!isBuffer(message.mac, MAC_BYTES) || !isBuffer(message.payload)) invalid()
  if (!isBuffer(routeSecretKey, KEY_BYTES) || message.payload.byteLength < SEAL_BYTES) invalid()

  const shared = cryptoSuite.keyAgreement(routeSecretKey, message.ephem)
  const k = hopKeys(shared)
  const nullifier = nullifierOf(shared)
  sodium.sodium_memzero(shared)

  // Header integrity BEFORE anything else.
  const expected = mac(k.muKey, message.header)
  if (!sodium.sodium_memcmp(expected, message.mac)) invalid()

  // Decrypt + shift: b = (beta || 0^HOP) XOR prg(rhoKey, RHO+HOP). Constant-size result.
  const stream = prg(k.rhoKey, RHO + HOP)
  const b = b4a.alloc(RHO + HOP)
  b.set(message.header, 0)
  xorInto(b, stream, 0, 0, RHO + HOP)

  const flag = b[0]
  if (flag !== TERMINAL && flag !== MORE) invalid()

  // Only after the header is authenticated + parsed do we wrap the payload.
  const wrapped = cryptoSuite.seal({
    key: k.wrapKey,
    noncePrefix: k.wrapNoncePrefix,
    counter: 0n,
    associatedData: b4a.alloc(0),
    plaintext: message.payload
  })

  const nextHop = b4a.from(b.subarray(FLAG, FLAG + ID_BYTES))
  if (flag === TERMINAL) {
    return { terminal: true, nextHop, forward: { payload: wrapped }, nullifier }
  }
  const nextEphem = b4a.from(b.subarray(FLAG + ID_BYTES, FLAG + ID_BYTES + KEY_BYTES))
  const nextMac = b4a.from(b.subarray(FLAG + ID_BYTES + KEY_BYTES, HOP))
  const nextHeader = b4a.from(b.subarray(HOP, RHO + HOP))
  return {
    terminal: false,
    nextHop,
    forward: { ephem: nextEphem, header: nextHeader, mac: nextMac, payload: wrapped },
    nullifier
  }
}

// Initiator side: strip the wrap layers in reverse path order, then open the reply seal.
function openSurbPayload(payload, openKeys) {
  if (!isBuffer(payload) || !openKeys || !Array.isArray(openKeys.wrapKeys)) invalid()
  let current = b4a.from(payload)
  for (let i = openKeys.wrapKeys.length - 1; i >= 0; i--) {
    const w = openKeys.wrapKeys[i]
    const opened = cryptoSuite.open({
      key: w.wrapKey,
      noncePrefix: w.wrapNoncePrefix,
      counter: 0n,
      associatedData: b4a.alloc(0),
      ciphertext: current
    })
    if (opened === null) invalid()
    current = opened
  }
  if (current.byteLength < SEAL_BYTES) invalid()
  const out = b4a.allocUnsafeSlow(current.byteLength - SEAL_BYTES)
  const ok = sodium.crypto_box_seal_open(
    out,
    current,
    openKeys.replyPubKey,
    openKeys.replySecretKey
  )
  if (ok === false) invalid()
  return out
}

// Per-epoch, fail-closed replay cache for hop nullifiers. A relay calls admit() for each
// SURB it processes: a nullifier seen before in this epoch returns false (replay). It is
// STRICT single-use up to capacity — it never evicts, so a nullifier is never silently
// re-admitted within an epoch. On overflow with a fresh nullifier it throws (fail-closed):
// the relay must rotate the epoch (reset) or add capacity rather than risk admitting a
// replay. Size maxEntries above expected per-epoch volume; the flood-to-refuse DoS is
// bounded by the relay's own circuit quotas. reset() at epoch rollover.
function createNullifierGuard(maxEntries = 1 << 16) {
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) invalid()
  let seen = new Map()
  return {
    admit(nullifier) {
      if (!isBuffer(nullifier, 32)) invalid()
      const key = b4a.toString(nullifier, 'hex')
      if (seen.has(key)) return false // replay
      if (seen.size >= maxEntries) throw PrivateRouteError.ERR_QUOTA_EXCEEDED() // fail-closed: no eviction
      seen.set(key, true)
      return true
    },
    get size() {
      return seen.size
    },
    reset() {
      seen = new Map()
    }
  }
}

module.exports = {
  MAX_HOPS,
  RHO,
  MAX_REPLY_BYTES,
  buildSurb,
  sealReply,
  processSurbHop,
  openSurbPayload,
  nullifierOf,
  createNullifierGuard
}
