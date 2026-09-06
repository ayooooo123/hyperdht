'use strict'

// EXPERIMENTAL — Gate C (Veilid-class "private routes" reply blocks).
// Reference implementation of the SURB construction amended by the Gate C
// architecture review (no advertised relay runId; route-key + capability
// times as hop context).
//
// Sphinx-style fixed-size header with per-hop independent X25519 DH (Step 0: no
// ristretto / no ed25519 scalar_mul in the pinned sodium, so no scalar blinding).
// Every hop sees a constant-size routing area `beta` (RHO bytes). Hop keys bind
// a local HopContext (version || routeKey || capabilityEpoch || issuedAtMs ||
// expiresAtMs) that never appears on the return wire.
//
// Reply payload: fresh X25519 ephemeral + XChaCha20-Poly1305 bound to
// 'SURB-REPLY-V1' || replyBinding. Relays only wrap ciphertext.
//
// NOT wired into the DHT and NOT wire-stable. No anonymity claim. Public
// required mode stays disabled.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { cryptoSuite } = require('./crypto-suite')
const { PrivateRouteError } = require('./errors')

const ID_BYTES = 32
const KEY_BYTES = 32
const MAC_BYTES = 16
const AEAD_TAG_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
const REPLY_OVERHEAD = KEY_BYTES + AEAD_TAG_BYTES // 48: R || tag
const NONCE_PREFIX_BYTES = 16

const FLAG = 1
const HOP = FLAG + ID_BYTES + KEY_BYTES + MAC_BYTES // flag | nextHop | E_next | next_mac
const MAX_HOPS = 4
const RHO = MAX_HOPS * HOP // constant routing-area size seen by every hop

// Reply-payload budget (PROVISIONAL, SURB-only). Worst-case on-wire reply message on a
// full-header leg = ephem(32) + header(RHO=324) + mac(16) + P_0(pt+48) + 16*(MAX_HOPS-1)
// wrap tags = pt + 468. At this cap the worst SURB message is ~980 B.
const MAX_REPLY_BYTES = 512
const MAX_REPLY_BINDING_BYTES = 96
const HOP_CONTEXT_BYTES = 58
const HOP_CONTEXT_VERSION = 1
const TERMINAL = 0
const MORE = 1
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn

const PRG_LABEL = b4a.from('hyperdht-private-routes/surb/prg/v1')
const HOP_DOMAIN = b4a.from('hyperdht-private-routes/surb-hop/v1')
const REPLY_DOMAIN = b4a.from('hyperdht-private-routes/surb-reply/v1')
const REPLY_AD_PREFIX = b4a.from('SURB-REPLY-V1')
const LABEL_RHO = b4a.from('rho')
const LABEL_MU = b4a.from('mu')
const LABEL_WRAP_KEY = b4a.from('wrap-key')
const LABEL_WRAP_NONCE = b4a.from('wrap-nonce')
const LABEL_NULLIFIER = b4a.from('nullifier')
const LABEL_REPLY_KEY = b4a.from('key')
const LABEL_REPLY_NONCE = b4a.from('nonce')

const objectFreeze = Object.freeze
const WeakMapConstructor = WeakMap
const weakMapGet = WeakMap.prototype.get
const weakMapSet = WeakMap.prototype.set
const WeakSetConstructor = WeakSet
const weakSetAdd = WeakSet.prototype.add
const weakSetHas = WeakSet.prototype.has
const MapConstructor = Map
const mapHas = Map.prototype.has
const mapSet = Map.prototype.set
const mapClear = Map.prototype.clear

const openAuthorityRecords = new WeakMapConstructor()
const spentOpenAuthorities = new WeakSetConstructor()
const capabilityAuthorityRecords = new WeakMapConstructor()
const spentCapabilityAuthorities = new WeakSetConstructor()
const replayAuthorityRecords = new WeakMapConstructor()
const spentReplayAuthorities = new WeakSetConstructor()
const forwardingAuthorityRecords = new WeakMapConstructor()
const spentForwardingAuthorities = new WeakSetConstructor()

function invalid() {
  throw PrivateRouteError.INVALID_ROUTE()
}

function destroyed() {
  throw PrivateRouteError.ERR_DESTROYED()
}

function replay() {
  throw PrivateRouteError.ERR_REPLAY()
}

function quotaExceeded() {
  throw PrivateRouteError.ERR_QUOTA_EXCEEDED()
}

function clear(buf) {
  if (buf !== null && buf !== undefined && b4a.isBuffer(buf) && buf.byteLength > 0) {
    sodium.sodium_memzero(buf)
  }
}

function isBuffer(value, size) {
  return b4a.isBuffer(value) && (size === undefined || value.byteLength === size)
}

function isUint64(value) {
  return typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64
}

function isCanonicalPublicKey(key) {
  if (!isBuffer(key, KEY_BYTES)) return false
  const last = key[31]
  if (last > 0x7f) return false
  if (last < 0x7f) return true
  for (let i = 30; i >= 1; i--) {
    if (key[i] < 0xff) return true
  }
  return key[0] < 0xed
}

function isVerificationError(err) {
  return err !== null && typeof err === 'object' && err.message === 'could not verify data'
}

function isNativeLowOrderError(err) {
  try {
    return err !== null && err.constructor === Error && err.message === 'status: -1'
  } catch {
    return false
  }
}

function writeUint16BE(buffer, value, offset) {
  buffer[offset] = (value >>> 8) & 0xff
  buffer[offset + 1] = value & 0xff
}

function writeUint64(buffer, value, offset) {
  let v = value
  for (let index = offset + 7; index >= offset; index--) {
    buffer[index] = Number(v & 0xffn)
    v >>= 8n
  }
}

function keyedHash(key, message) {
  const out = b4a.allocUnsafeSlow(32)
  let success = false
  try {
    sodium.crypto_generichash(out, message, key)
    success = true
    return out
  } finally {
    if (!success) clear(out)
  }
}

function mac(muKey, message) {
  const out = b4a.allocUnsafeSlow(MAC_BYTES)
  let success = false
  try {
    sodium.crypto_generichash(out, message, muKey)
    success = true
    return out
  } finally {
    if (!success) clear(out)
  }
}

// BLAKE2b-CTR keystream keyed by `key`, domain-separated by PRG_LABEL.
function prg(key, length) {
  const out = b4a.allocUnsafeSlow(length)
  const block = b4a.allocUnsafeSlow(32)
  const input = b4a.allocUnsafeSlow(PRG_LABEL.byteLength + 4)
  let success = false
  try {
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
    success = true
    return out
  } finally {
    clear(block)
    clear(input)
    if (!success) clear(out)
  }
}

function xorInto(dst, src, dstOffset, srcOffset, length) {
  for (let i = 0; i < length; i++) dst[dstOffset + i] ^= src[srcOffset + i]
}

function encodeHopContext(routeKey, capabilityEpoch, issuedAtMs, expiresAtMs) {
  const ctx = b4a.allocUnsafeSlow(HOP_CONTEXT_BYTES)
  writeUint16BE(ctx, HOP_CONTEXT_VERSION, 0)
  ctx.set(routeKey, 2)
  writeUint64(ctx, capabilityEpoch, 34)
  writeUint64(ctx, issuedAtMs, 42)
  writeUint64(ctx, expiresAtMs, 50)
  return ctx
}

function deriveHopRoot(shared, hopContext) {
  const domainLen = HOP_DOMAIN.byteLength
  const input = b4a.allocUnsafeSlow(2 + domainLen + 2 + HOP_CONTEXT_BYTES)
  let success = false
  let root = null
  try {
    writeUint16BE(input, domainLen, 0)
    input.set(HOP_DOMAIN, 2)
    writeUint16BE(input, HOP_CONTEXT_BYTES, 2 + domainLen)
    input.set(hopContext, 2 + domainLen + 2)
    root = keyedHash(shared, input)
    success = true
    return root
  } finally {
    clear(input)
    if (!success) clear(root)
  }
}

function hopKeysFromRoot(hopRoot) {
  let rhoKey = null
  let muKey = null
  let wrapKey = null
  let fullNonce = null
  let wrapNoncePrefix = null
  let nullifier = null
  try {
    rhoKey = keyedHash(hopRoot, LABEL_RHO)
    muKey = keyedHash(hopRoot, LABEL_MU)
    wrapKey = keyedHash(hopRoot, LABEL_WRAP_KEY)
    fullNonce = keyedHash(hopRoot, LABEL_WRAP_NONCE)
    nullifier = keyedHash(hopRoot, LABEL_NULLIFIER)
    wrapNoncePrefix = b4a.allocUnsafeSlow(NONCE_PREFIX_BYTES)
    wrapNoncePrefix.set(fullNonce.subarray(0, NONCE_PREFIX_BYTES), 0)
    return { rhoKey, muKey, wrapKey, wrapNoncePrefix, nullifier }
  } catch (err) {
    clear(rhoKey)
    clear(muKey)
    clear(wrapKey)
    clear(wrapNoncePrefix)
    clear(nullifier)
    throw err
  } finally {
    clear(fullNonce)
  }
}

function deriveHopMaterial(shared, routeKey, capabilityEpoch, issuedAtMs, expiresAtMs) {
  let hopContext = null
  let hopRoot = null
  try {
    hopContext = encodeHopContext(routeKey, capabilityEpoch, issuedAtMs, expiresAtMs)
    hopRoot = deriveHopRoot(shared, hopContext)
    return hopKeysFromRoot(hopRoot)
  } finally {
    clear(hopContext)
    clear(hopRoot)
  }
}

function clearHopKeys(k) {
  if (k === null || k === undefined) return
  clear(k.rhoKey)
  clear(k.muKey)
  clear(k.wrapKey)
  clear(k.wrapNoncePrefix)
  clear(k.nullifier)
}

function buildMacInput(ephem, beta) {
  const input = b4a.allocUnsafeSlow(KEY_BYTES + RHO)
  input.set(ephem, 0)
  input.set(beta, KEY_BYTES)
  return input
}

function makeFiller(rhoKeys, n) {
  if (n <= 1) return b4a.alloc(0)
  const filler = b4a.alloc((n - 1) * HOP)
  let success = false
  try {
    for (let i = 0; i < n - 1; i++) {
      const currentLen = (i + 1) * HOP
      let stream = null
      try {
        stream = prg(rhoKeys[i], RHO + HOP)
        xorInto(filler, stream, 0, RHO + HOP - currentLen, currentLen)
      } finally {
        clear(stream)
      }
    }
    success = true
    return filler
  } finally {
    if (!success) clear(filler)
  }
}

function copyOwned(buf, size) {
  if (!isBuffer(buf, size)) invalid()
  const out = b4a.allocUnsafeSlow(size)
  out.set(buf, 0)
  return out
}

function validateReplyBinding(replyBinding) {
  if (!isBuffer(replyBinding)) invalid()
  if (replyBinding.byteLength > MAX_REPLY_BINDING_BYTES) invalid()
  return replyBinding
}

function buildReplyAssociatedData(replyBinding) {
  const binding = validateReplyBinding(replyBinding)
  const ad = b4a.allocUnsafeSlow(REPLY_AD_PREFIX.byteLength + binding.byteLength)
  ad.set(REPLY_AD_PREFIX, 0)
  ad.set(binding, REPLY_AD_PREFIX.byteLength)
  return ad
}

function deriveReplyKeys(shared, associatedData) {
  const domainLen = REPLY_DOMAIN.byteLength
  const adLen = associatedData.byteLength
  const input = b4a.allocUnsafeSlow(2 + domainLen + 2 + adLen)
  let root = null
  let key = null
  let fullNonce = null
  let noncePrefix = null
  try {
    writeUint16BE(input, domainLen, 0)
    input.set(REPLY_DOMAIN, 2)
    writeUint16BE(input, adLen, 2 + domainLen)
    input.set(associatedData, 2 + domainLen + 2)
    root = keyedHash(shared, input)
    key = keyedHash(root, LABEL_REPLY_KEY)
    fullNonce = keyedHash(root, LABEL_REPLY_NONCE)
    noncePrefix = b4a.allocUnsafeSlow(NONCE_PREFIX_BYTES)
    noncePrefix.set(fullNonce.subarray(0, NONCE_PREFIX_BYTES), 0)
    return { key, noncePrefix }
  } catch (err) {
    clear(key)
    clear(noncePrefix)
    throw err
  } finally {
    clear(input)
    clear(root)
    clear(fullNonce)
  }
}

function clearOpenState(state) {
  if (!state) return
  state.active = false
  clear(state.replySecretKey)
  clear(state.replyPubKey)
  clear(state.replyBinding)
  if (Array.isArray(state.wrapKeys)) {
    for (let i = 0; i < state.wrapKeys.length; i++) {
      const w = state.wrapKeys[i]
      if (w) {
        clear(w.wrapKey)
        clear(w.wrapNoncePrefix)
      }
    }
  }
  state.replySecretKey = null
  state.replyPubKey = null
  state.replyBinding = null
  state.wrapKeys = null
}

function clearCapabilityState(state) {
  if (!state) return
  state.active = false
  clear(state.routeSecretKey)
  clear(state.routeKey)
  state.routeSecretKey = null
  state.routeKey = null
}

function clearForwardingState(state) {
  if (!state) return
  state.active = false
  clear(state.nextHop)
  if (state.message) {
    clear(state.message.ephem)
    clear(state.message.header)
    clear(state.message.mac)
    clear(state.message.payload)
  }
  state.nextHop = null
  state.message = null
}

function clearReplayState(state) {
  if (!state) return
  state.active = false
  if (state.seen) mapClear.call(state.seen)
  state.seen = null
}

function claimOpenAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(openAuthorityRecords, authority)
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentOpenAuthorities, authority)
    ) {
      destroyed()
    }
    invalid()
  }
  openAuthorityRecords.delete(authority)
  weakSetAdd.call(spentOpenAuthorities, authority)
  state.active = false
  return state
}

function admitNullifier(state, nullifier) {
  if (!state || !state.active || !(state.seen instanceof MapConstructor)) invalid()
  if (!isBuffer(nullifier, 32)) invalid()
  const key = b4a.toString(nullifier, 'hex')
  if (mapHas.call(state.seen, key)) replay()
  if (state.seen.size >= state.maxEntries) quotaExceeded()
  mapSet.call(state.seen, key, true)
}

// hops: [{ id, routeKey, capabilityEpoch, issuedAtMs, expiresAtMs }, ...] (1..MAX_HOPS)
// terminalHandle: 32B opaque local delivery handle
// replyBinding: caller-supplied canonical bytes, max 96
function buildSurb(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const hops = options.hops
  const terminalHandle = options.terminalHandle
  const replyBinding = options.replyBinding
  const now = options.now
  const seeds = options.seeds

  if (!Array.isArray(hops) || hops.length === 0 || hops.length > MAX_HOPS) invalid()
  if (!isBuffer(terminalHandle, ID_BYTES)) invalid()
  if (!isUint64(now)) invalid()
  validateReplyBinding(replyBinding)

  const n = hops.length
  const seenIds = new MapConstructor()
  const hopMeta = new Array(n)

  for (let i = 0; i < n; i++) {
    const h = hops[i]
    if (!h || typeof h !== 'object') invalid()
    if (!isBuffer(h.id, ID_BYTES) || !isCanonicalPublicKey(h.routeKey)) invalid()
    if (!isUint64(h.capabilityEpoch) || !isUint64(h.issuedAtMs) || !isUint64(h.expiresAtMs)) {
      invalid()
    }
    if (h.expiresAtMs <= now) invalid()
    if (h.issuedAtMs > h.expiresAtMs) invalid()
    const idHex = b4a.toString(h.id, 'hex')
    if (mapHas.call(seenIds, idHex)) invalid()
    mapSet.call(seenIds, idHex, true)
    hopMeta[i] = {
      id: h.id,
      routeKey: h.routeKey,
      capabilityEpoch: h.capabilityEpoch,
      issuedAtMs: h.issuedAtMs,
      expiresAtMs: h.expiresAtMs
    }
  }

  let ephemeralSeeds = undefined
  let replySeed = undefined
  if (seeds !== undefined) {
    if (seeds === null || typeof seeds !== 'object' || Array.isArray(seeds)) invalid()
    ephemeralSeeds = seeds.ephemeralSeeds
    replySeed = seeds.replySeed
    if (ephemeralSeeds !== undefined) {
      if (!Array.isArray(ephemeralSeeds) || ephemeralSeeds.length !== n) invalid()
      for (let i = 0; i < n; i++) {
        if (!isBuffer(ephemeralSeeds[i], 32)) invalid()
      }
    }
    if (replySeed !== undefined) {
      if (!isBuffer(replySeed, 32)) invalid()
    }
  }

  const ephem = new Array(n)
  const rhoKeys = new Array(n)
  const muKeys = new Array(n)
  const wrapKeys = new Array(n)

  let replyPublicKey = null
  let replySecretKey = null
  let filler = null
  let hopBlock = null
  let beta = null
  let hmac = null
  let macInput = null
  let success = false
  let openAuthority = null

  try {
    for (let i = 0; i < n; i++) {
      const h = hopMeta[i]
      let eSecret = null
      let ePublic = null
      let shared = null
      let k = null
      try {
        eSecret = b4a.allocUnsafeSlow(KEY_BYTES)
        ePublic = b4a.allocUnsafeSlow(KEY_BYTES)
        if (ephemeralSeeds === undefined) {
          sodium.crypto_box_keypair(ePublic, eSecret)
        } else {
          sodium.crypto_box_seed_keypair(ePublic, eSecret, ephemeralSeeds[i])
        }
        try {
          shared = cryptoSuite.keyAgreement(eSecret, h.routeKey)
        } catch (err) {
          if (err instanceof PrivateRouteError && err.code === 'INVALID_KEY') invalid()
          throw err
        }
        k = deriveHopMaterial(shared, h.routeKey, h.capabilityEpoch, h.issuedAtMs, h.expiresAtMs)
        ephem[i] = ePublic
        rhoKeys[i] = k.rhoKey
        muKeys[i] = k.muKey
        wrapKeys[i] = { wrapKey: k.wrapKey, wrapNoncePrefix: k.wrapNoncePrefix }
        clear(k.nullifier)
        k = null
      } finally {
        clear(eSecret)
        clear(shared)
        if (k !== null) clearHopKeys(k)
      }
    }

    filler = makeFiller(rhoKeys, n)

    hopBlock = b4a.alloc(HOP)
    hopBlock[0] = TERMINAL
    hopBlock.set(terminalHandle, FLAG)

    let padKey = null
    try {
      // Deterministic pad under the last ephemeral public (public material only).
      padKey = keyedHash(ephem[n - 1], LABEL_RHO)
      beta = prg(padKey, RHO)
    } finally {
      clear(padKey)
    }
    beta.set(hopBlock, 0)

    let termStream = null
    try {
      termStream = prg(rhoKeys[n - 1], RHO)
      xorInto(beta, termStream, 0, 0, RHO)
    } finally {
      clear(termStream)
    }
    beta.set(filler, RHO - filler.byteLength)
    clear(filler)
    filler = null

    macInput = buildMacInput(ephem[n - 1], beta)
    hmac = mac(muKeys[n - 1], macInput)
    clear(macInput)
    macInput = null

    for (let i = n - 2; i >= 0; i--) {
      hopBlock[0] = MORE
      hopBlock.set(hopMeta[i + 1].id, FLAG)
      hopBlock.set(ephem[i + 1], FLAG + ID_BYTES)
      hopBlock.set(hmac, FLAG + ID_BYTES + KEY_BYTES)
      clear(hmac)
      hmac = null

      const next = b4a.alloc(RHO)
      next.set(hopBlock, 0)
      next.set(beta.subarray(0, RHO - HOP), HOP)
      clear(beta)
      beta = next

      let s = null
      try {
        s = prg(rhoKeys[i], RHO)
        xorInto(beta, s, 0, 0, RHO)
      } finally {
        clear(s)
      }
      macInput = buildMacInput(ephem[i], beta)
      hmac = mac(muKeys[i], macInput)
      clear(macInput)
      macInput = null
    }

    clear(hopBlock)
    hopBlock = null

    replyPublicKey = b4a.allocUnsafeSlow(KEY_BYTES)
    replySecretKey = b4a.allocUnsafeSlow(KEY_BYTES)
    if (replySeed === undefined) {
      sodium.crypto_box_keypair(replyPublicKey, replySecretKey)
    } else {
      sodium.crypto_box_seed_keypair(replyPublicKey, replySecretKey, replySeed)
    }

    let minExpires = hopMeta[0].expiresAtMs
    for (let i = 1; i < n; i++) {
      if (hopMeta[i].expiresAtMs < minExpires) minExpires = hopMeta[i].expiresAtMs
    }

    const ownedWrapKeys = new Array(n)
    for (let i = 0; i < n; i++) {
      ownedWrapKeys[i] = {
        wrapKey: wrapKeys[i].wrapKey,
        wrapNoncePrefix: wrapKeys[i].wrapNoncePrefix
      }
      wrapKeys[i] = undefined
    }

    const authority = objectFreeze({})
    const state = {
      active: true,
      replySecretKey,
      replyPubKey: b4a.from(replyPublicKey),
      replyBinding: b4a.from(replyBinding),
      wrapKeys: ownedWrapKeys,
      expiresAtMs: minExpires,
      hopCount: n
    }
    weakMapSet.call(openAuthorityRecords, authority, state)
    openAuthority = authority
    replySecretKey = null

    const descriptor = objectFreeze({
      firstHop: b4a.from(hopMeta[0].id),
      ephem: ephem[0],
      header: beta,
      mac: hmac,
      replyPubKey: replyPublicKey
    })

    success = true
    return { descriptor, openAuthority }
  } finally {
    for (let i = 0; i < n; i++) {
      clear(rhoKeys[i])
      clear(muKeys[i])
      if (!success) {
        if (wrapKeys[i] !== undefined) {
          clear(wrapKeys[i].wrapKey)
          clear(wrapKeys[i].wrapNoncePrefix)
        }
        clear(ephem[i])
      }
    }
    clear(filler)
    clear(hopBlock)
    clear(macInput)
    if (!success) {
      clear(replySecretKey)
      clear(replyPublicKey)
      clear(beta)
      clear(hmac)
      if (openAuthority !== null) {
        const st = weakMapGet.call(openAuthorityRecords, openAuthority)
        if (st !== undefined) {
          openAuthorityRecords.delete(openAuthority)
          clearOpenState(st)
        }
      }
    }
  }
}

function sealSurbReply(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const descriptor = options.descriptor
  const replyBinding = options.replyBinding
  const plaintext = options.plaintext

  if (!descriptor || typeof descriptor !== 'object') invalid()
  if (!isCanonicalPublicKey(descriptor.replyPubKey)) invalid()
  if (
    !isCanonicalPublicKey(descriptor.ephem) ||
    !isBuffer(descriptor.header, RHO) ||
    !isBuffer(descriptor.mac, MAC_BYTES)
  ) {
    invalid()
  }
  if (!isBuffer(plaintext) || plaintext.byteLength > MAX_REPLY_BYTES) invalid()

  let associatedData = null
  let rSecret = null
  let rPublic = null
  let shared = null
  let replyKeys = null
  let sealed = null
  let success = false

  try {
    associatedData = buildReplyAssociatedData(replyBinding)
    rSecret = b4a.allocUnsafeSlow(KEY_BYTES)
    rPublic = b4a.allocUnsafeSlow(KEY_BYTES)
    sodium.crypto_box_keypair(rPublic, rSecret)

    try {
      shared = cryptoSuite.keyAgreement(rSecret, descriptor.replyPubKey)
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'INVALID_KEY') invalid()
      throw err
    }

    replyKeys = deriveReplyKeys(shared, associatedData)

    let body = null
    try {
      body = cryptoSuite.seal({
        key: replyKeys.key,
        noncePrefix: replyKeys.noncePrefix,
        counter: 0n,
        associatedData,
        plaintext
      })
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'CELL_INVALID') invalid()
      throw err
    }

    sealed = b4a.allocUnsafeSlow(KEY_BYTES + body.byteLength)
    sealed.set(rPublic, 0)
    sealed.set(body, KEY_BYTES)
    clear(body)
    body = null

    const result = {
      ephem: b4a.from(descriptor.ephem),
      header: b4a.from(descriptor.header),
      mac: b4a.from(descriptor.mac),
      payload: sealed
    }
    success = true
    return result
  } finally {
    clear(associatedData)
    clear(rSecret)
    clear(rPublic)
    clear(shared)
    if (replyKeys !== null) {
      clear(replyKeys.key)
      clear(replyKeys.noncePrefix)
    }
    if (!success) clear(sealed)
  }
}

function createSurbCapabilityAuthority(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const routeSecretKey = options.routeSecretKey
  const routeKey = options.routeKey
  const capabilityEpoch = options.capabilityEpoch
  const issuedAtMs = options.issuedAtMs
  const expiresAtMs = options.expiresAtMs
  const now = options.now

  if (!isBuffer(routeSecretKey, KEY_BYTES)) invalid()
  if (!isCanonicalPublicKey(routeKey)) invalid()
  if (!isUint64(capabilityEpoch) || !isUint64(issuedAtMs) || !isUint64(expiresAtMs)) invalid()
  if (!isUint64(now)) invalid()
  if (expiresAtMs <= now) invalid()
  if (issuedAtMs > expiresAtMs) invalid()

  let computed = null
  let ownedSecret = null
  let ownedRouteKey = null
  try {
    computed = b4a.allocUnsafeSlow(KEY_BYTES)
    sodium.crypto_scalarmult_base(computed, routeSecretKey)
    if (!isCanonicalPublicKey(computed) || !sodium.sodium_memcmp(computed, routeKey)) invalid()

    ownedSecret = copyOwned(routeSecretKey, KEY_BYTES)
    ownedRouteKey = copyOwned(routeKey, KEY_BYTES)

    const authority = objectFreeze({})
    const state = {
      active: true,
      routeSecretKey: ownedSecret,
      routeKey: ownedRouteKey,
      capabilityEpoch,
      issuedAtMs,
      expiresAtMs,
      now
    }
    weakMapSet.call(capabilityAuthorityRecords, authority, state)
    ownedSecret = null
    ownedRouteKey = null
    return authority
  } catch (err) {
    clear(ownedSecret)
    clear(ownedRouteKey)
    throw err
  } finally {
    clear(computed)
  }
}

function createSurbReplayAuthority(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  let maxEntries = options.maxEntries
  if (maxEntries === undefined) maxEntries = 1 << 16
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) invalid()

  const authority = objectFreeze({})
  const state = {
    active: true,
    maxEntries,
    seen: new MapConstructor()
  }
  weakMapSet.call(replayAuthorityRecords, authority, state)
  return authority
}

function destroySurbReplayAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(replayAuthorityRecords, authority)
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentReplayAuthorities, authority)
    ) {
      return false
    }
    invalid()
  }
  replayAuthorityRecords.delete(authority)
  weakSetAdd.call(spentReplayAuthorities, authority)
  clearReplayState(state)
  return true
}

function liveCapability(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(capabilityAuthorityRecords, authority)
      : undefined
  if (state === undefined || !state.active) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentCapabilityAuthorities, authority)
    ) {
      destroyed()
    }
    invalid()
  }
  if (state.expiresAtMs <= state.now) invalid()
  return state
}

function liveReplay(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(replayAuthorityRecords, authority)
      : undefined
  if (state === undefined || !state.active) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentReplayAuthorities, authority)
    ) {
      destroyed()
    }
    invalid()
  }
  return state
}

function processSurbHop(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const message = options.message
  const capabilityAuthority = options.capabilityAuthority
  const replayAuthority = options.replayAuthority

  if (!message || typeof message !== 'object') invalid()
  if (!isCanonicalPublicKey(message.ephem) || !isBuffer(message.header, RHO)) invalid()
  if (!isBuffer(message.mac, MAC_BYTES) || !isBuffer(message.payload)) invalid()

  const maxPayload = MAX_REPLY_BYTES + REPLY_OVERHEAD + (MAX_HOPS - 1) * AEAD_TAG_BYTES
  if (message.payload.byteLength < REPLY_OVERHEAD || message.payload.byteLength > maxPayload) {
    invalid()
  }

  const cap = liveCapability(capabilityAuthority)
  const replayState = liveReplay(replayAuthority)

  let shared = null
  let k = null
  let stream = null
  let b = null
  let expectedMac = null
  let macInput = null
  let wrapped = null
  let success = false
  let forwardingAuthority = null

  try {
    try {
      shared = cryptoSuite.keyAgreement(cap.routeSecretKey, message.ephem)
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'INVALID_KEY') invalid()
      throw err
    }

    k = deriveHopMaterial(
      shared,
      cap.routeKey,
      cap.capabilityEpoch,
      cap.issuedAtMs,
      cap.expiresAtMs
    )

    macInput = buildMacInput(message.ephem, message.header)
    expectedMac = mac(k.muKey, macInput)
    if (!sodium.sodium_memcmp(expectedMac, message.mac)) invalid()

    stream = prg(k.rhoKey, RHO + HOP)
    b = b4a.alloc(RHO + HOP)
    b.set(message.header, 0)
    xorInto(b, stream, 0, 0, RHO + HOP)

    const flag = b[0]
    if (flag !== TERMINAL && flag !== MORE) invalid()

    const nextHop = b4a.from(b.subarray(FLAG, FLAG + ID_BYTES))
    let nextEphem = null
    let nextMac = null
    let nextHeader = null
    if (flag === MORE) {
      nextEphem = b4a.from(b.subarray(FLAG + ID_BYTES, FLAG + ID_BYTES + KEY_BYTES))
      nextMac = b4a.from(b.subarray(FLAG + ID_BYTES + KEY_BYTES, HOP))
      nextHeader = b4a.from(b.subarray(HOP, RHO + HOP))
      if (!isCanonicalPublicKey(nextEphem) || !isBuffer(nextMac, MAC_BYTES)) invalid()
    }

    // Atomic nullifier admission BEFORE payload transformation.
    admitNullifier(replayState, k.nullifier)

    try {
      wrapped = cryptoSuite.seal({
        key: k.wrapKey,
        noncePrefix: k.wrapNoncePrefix,
        counter: 0n,
        associatedData: b4a.alloc(0),
        plaintext: message.payload
      })
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'CELL_INVALID') invalid()
      throw err
    }

    const terminal = flag === TERMINAL
    const forwardMessage = terminal
      ? { payload: wrapped }
      : { ephem: nextEphem, header: nextHeader, mac: nextMac, payload: wrapped }

    const authority = objectFreeze({})
    const state = {
      active: true,
      terminal,
      nextHop,
      message: forwardMessage
    }
    weakMapSet.call(forwardingAuthorityRecords, authority, state)
    forwardingAuthority = authority
    success = true
    return authority
  } finally {
    clear(shared)
    clearHopKeys(k)
    clear(stream)
    clear(b)
    clear(expectedMac)
    clear(macInput)
    if (!success) {
      clear(wrapped)
      if (forwardingAuthority !== null) {
        const st = weakMapGet.call(forwardingAuthorityRecords, forwardingAuthority)
        if (st !== undefined) {
          forwardingAuthorityRecords.delete(forwardingAuthority)
          clearForwardingState(st)
        }
      }
    }
  }
}

function consumeSurbForwardingAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(forwardingAuthorityRecords, authority)
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentForwardingAuthorities, authority)
    ) {
      destroyed()
    }
    invalid()
  }
  if (!state.active) destroyed()

  forwardingAuthorityRecords.delete(authority)
  weakSetAdd.call(spentForwardingAuthorities, authority)
  state.active = false

  const result = {
    terminal: state.terminal,
    nextHop: state.nextHop,
    message: state.message
  }
  state.nextHop = null
  state.message = null
  return result
}

function openSurbReply(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) invalid()
  const openAuthority = options.openAuthority
  const replyBinding = options.replyBinding
  const payload = options.payload
  const now = options.now

  if (!isBuffer(payload)) invalid()
  if (!isUint64(now)) invalid()
  validateReplyBinding(replyBinding)

  // First open attempt CONSUMES the authority whether success or failure.
  const state = claimOpenAuthority(openAuthority)

  let current = null
  let out = null
  let associatedData = null
  let shared = null
  let replyKeys = null
  let rPublic = null
  let success = false

  try {
    if (now > state.expiresAtMs) invalid()
    if (
      !state.replyBinding ||
      state.replyBinding.byteLength !== replyBinding.byteLength ||
      !sodium.sodium_memcmp(state.replyBinding, replyBinding)
    ) {
      invalid()
    }

    const wrapCount = state.hopCount
    if (
      payload.byteLength < REPLY_OVERHEAD + wrapCount * AEAD_TAG_BYTES ||
      payload.byteLength > MAX_REPLY_BYTES + REPLY_OVERHEAD + MAX_HOPS * AEAD_TAG_BYTES
    ) {
      invalid()
    }

    for (let i = wrapCount - 1; i >= 0; i--) {
      const w = state.wrapKeys[i]
      const inputCiphertext = current === null ? payload : current
      let opened = null
      try {
        opened = cryptoSuite.open({
          key: w.wrapKey,
          noncePrefix: w.wrapNoncePrefix,
          counter: 0n,
          associatedData: b4a.alloc(0),
          ciphertext: inputCiphertext
        })
      } catch (err) {
        if (err instanceof PrivateRouteError && err.code === 'CELL_INVALID') invalid()
        throw err
      }
      if (opened === null) invalid()
      if (current !== null) clear(current)
      current = opened
    }

    if (current.byteLength < REPLY_OVERHEAD) invalid()

    rPublic = b4a.from(current.subarray(0, KEY_BYTES))
    if (!isCanonicalPublicKey(rPublic)) invalid()
    const body = current.subarray(KEY_BYTES)

    associatedData = buildReplyAssociatedData(replyBinding)

    try {
      shared = cryptoSuite.keyAgreement(state.replySecretKey, rPublic)
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'INVALID_KEY') invalid()
      throw err
    }

    replyKeys = deriveReplyKeys(shared, associatedData)

    let plain = null
    try {
      plain = cryptoSuite.open({
        key: replyKeys.key,
        noncePrefix: replyKeys.noncePrefix,
        counter: 0n,
        associatedData,
        ciphertext: body
      })
    } catch (err) {
      if (err instanceof PrivateRouteError && err.code === 'CELL_INVALID') invalid()
      throw err
    }
    if (plain === null) invalid()
    if (plain.byteLength > MAX_REPLY_BYTES) {
      clear(plain)
      invalid()
    }

    out = plain
    success = true
    return out
  } finally {
    clearOpenState(state)
    clear(current)
    clear(associatedData)
    clear(shared)
    clear(rPublic)
    if (replyKeys !== null) {
      clear(replyKeys.key)
      clear(replyKeys.noncePrefix)
    }
    if (!success && out !== null) clear(out)
  }
}

function revokeSurbOpenAuthority(authority) {
  const state =
    authority !== null && (typeof authority === 'object' || typeof authority === 'function')
      ? weakMapGet.call(openAuthorityRecords, authority)
      : undefined
  if (state === undefined) {
    if (
      authority !== null &&
      (typeof authority === 'object' || typeof authority === 'function') &&
      weakSetHas.call(spentOpenAuthorities, authority)
    ) {
      return false
    }
    invalid()
  }
  openAuthorityRecords.delete(authority)
  weakSetAdd.call(spentOpenAuthorities, authority)
  clearOpenState(state)
  return true
}

module.exports = {
  MAX_HOPS,
  RHO,
  MAX_REPLY_BYTES,
  buildSurb,
  sealSurbReply,
  processSurbHop,
  consumeSurbForwardingAuthority,
  openSurbReply,
  revokeSurbOpenAuthority,
  createSurbCapabilityAuthority,
  createSurbReplayAuthority,
  destroySurbReplayAuthority
}
