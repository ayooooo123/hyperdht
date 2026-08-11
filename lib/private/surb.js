'use strict'

// EXPERIMENTAL — Gate C (Veilid-class "private routes" reply blocks).
// Reference implementation of the SURB construction in
// docs/superpowers/specs/2026-08-10-private-routing-surb-construction-design.md.
//
// Per-hop independent X25519 DH (Step 0: no ristretto / no ed25519 scalar_mul in the
// pinned sodium, so the Sphinx blinding chain is not used). Each hop receives its
// ephemeral E_i in the clear and derives the key that decrypts its own header layer;
// decrypting that layer reveals the next hop's clear E_{i+1}. The reply payload is
// sealed by the responder to a one-time public key E_pub (crypto_box_seal); relays only
// wrap ciphertext, and only the initiator (holding E_priv) can open it.
//
// NOT wire-stable and NOT owner-approved. Off the DHT path — this module is the isolated
// primitive plus tests. KNOWN LIMITATION: the header is nested AEAD without Sphinx
// position-hiding filler, so its length shrinks per hop and a relay can infer its
// position. Roles (guard/safety/exit) are already positionally fixed in this stack, but
// constant-size filler is deferred to the reviewed wire-format step.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const ID_BYTES = 32
const KEY_BYTES = 32
const SEAL_BYTES = sodium.crypto_box_SEALBYTES
const MAX_HOPS = 8

const TERMINAL = 0
const MORE = 1
const AEAD_TAG_BYTES = 16
const MIN_SEALED = 1 + ID_BYTES + AEAD_TAG_BYTES // smallest header layer = a sealed terminal
const MORE_MIN_LAYER = 1 + ID_BYTES + KEY_BYTES + MIN_SEALED // MORE carries a sealed next header

const HDR_KEY = b4a.from('hyperdht-private-routes/surb/hdr-key/v1')
const HDR_NONCE = b4a.from('hyperdht-private-routes/surb/hdr-nonce/v1')
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

function noncePrefixOf(sharedSecret, label) {
  return subkey(sharedSecret, label).subarray(0, 16)
}

// Per-hop keys, deterministic from the X25519 DH secret. Each hop's shared secret is
// unique per SURB, so a fixed zero counter with a derived nonce prefix is safe.
function hopKeys(sharedSecret) {
  return {
    hdrKey: subkey(sharedSecret, HDR_KEY),
    hdrNoncePrefix: noncePrefixOf(sharedSecret, HDR_NONCE),
    wrapKey: subkey(sharedSecret, WRAP_KEY),
    wrapNoncePrefix: noncePrefixOf(sharedSecret, WRAP_NONCE)
  }
}

function nullifierOf(sharedSecret) {
  const out = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash(out, sharedSecret, NULLIFIER)
  return out
}

// hops: [{ id: <32B forward-target id>, routeKey: <32B relay X25519 pubkey> }, ...]
// terminalId: 32B id the last hop forwards the wrapped payload to (the initiator).
function buildSurb(hops, terminalId) {
  if (!Array.isArray(hops) || hops.length === 0 || hops.length > MAX_HOPS) invalid()
  if (!isBuffer(terminalId, ID_BYTES)) invalid()

  const m = hops.length
  const wrapKeys = new Array(m)
  const ephem = new Array(m) // E_i public keys, in path order
  const hdr = new Array(m) // per-hop { hdrKey, hdrNoncePrefix }

  for (let i = 0; i < m; i++) {
    const h = hops[i]
    if (!isBuffer(h && h.routeKey, KEY_BYTES) || !isBuffer(h && h.id, ID_BYTES)) invalid()
    const eSecret = b4a.allocUnsafeSlow(KEY_BYTES)
    const ePublic = b4a.allocUnsafeSlow(KEY_BYTES)
    sodium.crypto_box_keypair(ePublic, eSecret)
    const shared = cryptoSuite.keyAgreement(eSecret, h.routeKey)
    sodium.sodium_memzero(eSecret)
    const k = hopKeys(shared)
    sodium.sodium_memzero(shared)
    ephem[i] = ePublic
    wrapKeys[i] = { wrapKey: k.wrapKey, wrapNoncePrefix: k.wrapNoncePrefix }
    hdr[i] = { hdrKey: k.hdrKey, hdrNoncePrefix: k.hdrNoncePrefix }
  }

  // Build the nested header from the innermost (last) hop outward.
  let inner = null
  for (let i = m - 1; i >= 0; i--) {
    const isLast = i === m - 1
    const nextId = isLast ? terminalId : hops[i + 1].id
    let layer
    if (isLast) {
      layer = b4a.concat([b4a.from([TERMINAL]), nextId])
    } else {
      layer = b4a.concat([b4a.from([MORE]), nextId, ephem[i + 1], inner])
    }
    inner = cryptoSuite.seal({
      key: hdr[i].hdrKey,
      noncePrefix: hdr[i].hdrNoncePrefix,
      counter: 0n,
      associatedData: ephem[i], // bind the layer to its ephemeral
      plaintext: layer
    })
  }

  const replyPublicKey = b4a.allocUnsafeSlow(KEY_BYTES)
  const replySecretKey = b4a.allocUnsafeSlow(KEY_BYTES)
  sodium.crypto_box_keypair(replyPublicKey, replySecretKey)

  const surb = {
    firstHop: b4a.from(hops[0].id),
    ephem: ephem[0],
    header: inner,
    replyPubKey: replyPublicKey
  }
  const openKeys = {
    replySecretKey,
    replyPubKey: b4a.from(replyPublicKey),
    wrapKeys // in path order H_1..H_m
  }
  return { surb, openKeys }
}

// Responder side: seal plaintext to the SURB's one-time public key. Relays never see
// plaintext. Returns the message to hand to surb.firstHop.
function sealReply(surb, plaintext) {
  if (!surb || !isBuffer(surb.replyPubKey, KEY_BYTES)) invalid()
  if (!isBuffer(plaintext)) invalid()
  const sealed = b4a.allocUnsafeSlow(plaintext.byteLength + SEAL_BYTES)
  sodium.crypto_box_seal(sealed, plaintext, surb.replyPubKey)
  return {
    ephem: b4a.from(surb.ephem),
    header: b4a.from(surb.header),
    payload: sealed
  }
}

// Relay side: process one hop. Operates on ciphertext only. Returns the forwarding
// target, the message for the next hop, and this hop's nullifier (for single-use
// tracking by the relay). Throws INVALID_ROUTE on any authentication failure.
function processSurbHop(message, routeSecretKey) {
  if (!message || !isBuffer(message.ephem, KEY_BYTES) || !isBuffer(message.header)) invalid()
  if (!isBuffer(message.payload) || !isBuffer(routeSecretKey, KEY_BYTES)) invalid()
  // Fail-closed input bounds: a header is at least a sealed terminal layer; a payload is at
  // least the responder's box seal.
  if (message.header.byteLength < MIN_SEALED || message.payload.byteLength < SEAL_BYTES) invalid()

  const shared = cryptoSuite.keyAgreement(routeSecretKey, message.ephem)
  const k = hopKeys(shared)
  const nullifier = nullifierOf(shared)
  sodium.sodium_memzero(shared)

  const layer = cryptoSuite.open({
    key: k.hdrKey,
    noncePrefix: k.hdrNoncePrefix,
    counter: 0n,
    associatedData: message.ephem,
    ciphertext: message.header
  })
  if (layer === null) invalid() // header integrity / wrong key

  // Validate the decoded layer's structure BEFORE forwarding or wrapping any payload
  // (fail-closed against a malformed-but-authentic layer — e.g. a compromised initiator or
  // future wire drift — not just against ciphertext tampering, which the AEAD already
  // catches above).
  if (layer.byteLength < 1 + ID_BYTES) invalid()
  const flag = layer[0]
  if (flag === TERMINAL) {
    if (layer.byteLength !== 1 + ID_BYTES) invalid()
  } else if (flag === MORE) {
    if (layer.byteLength < MORE_MIN_LAYER) invalid()
  } else {
    invalid()
  }

  // Only after the layer is validated do we wrap the payload and emit anything.
  const wrapped = cryptoSuite.seal({
    key: k.wrapKey,
    noncePrefix: k.wrapNoncePrefix,
    counter: 0n,
    associatedData: b4a.alloc(0),
    plaintext: message.payload
  })

  const nextHop = b4a.from(layer.subarray(1, 1 + ID_BYTES))
  if (flag === TERMINAL) {
    return { terminal: true, nextHop, forward: { payload: wrapped }, nullifier }
  }
  const nextEphem = b4a.from(layer.subarray(1 + ID_BYTES, 1 + ID_BYTES + KEY_BYTES))
  const nextHeader = b4a.from(layer.subarray(1 + ID_BYTES + KEY_BYTES))
  return {
    terminal: false,
    nextHop,
    forward: { ephem: nextEphem, header: nextHeader, payload: wrapped },
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

module.exports = {
  MAX_HOPS,
  buildSurb,
  sealReply,
  processSurbHop,
  openSurbPayload,
  nullifierOf
}
