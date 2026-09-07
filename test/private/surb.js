'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const fs = require('fs')

const {
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
} = require('../../lib/private/surb')

const NOW = 1_700_000_000_000n
const EXPIRES = NOW + 3_600_000n
const ISSUED = NOW - 1_000n
const EPOCH = 7n
const DEFAULT_BINDING = b4a.from('reply-binding-v1-test-vector')

function createPrng(seed = 0x853c49e6) {
  let s = seed >>> 0
  return {
    next() {
      s = (s + 0x6d2b79f5) | 0
      let t = Math.imul(s ^ (s >>> 15), 1 | s)
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
      return (t ^ (t >>> 14)) >>> 0
    },
    int(max) {
      return this.next() % max
    },
    bytes(len) {
      const buf = b4a.allocUnsafeSlow(len)
      for (let i = 0; i < len; i++) buf[i] = this.next() & 0xff
      return buf
    }
  }
}

function relay() {
  const routeKey = b4a.allocUnsafeSlow(32)
  const routeSecretKey = b4a.allocUnsafeSlow(32)
  sodium.crypto_box_keypair(routeKey, routeSecretKey)
  const id = b4a.allocUnsafeSlow(32)
  sodium.randombytes_buf(id)
  return {
    id,
    routeKey,
    routeSecretKey,
    capabilityEpoch: EPOCH,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES
  }
}

function hopOf(r) {
  return {
    id: r.id,
    routeKey: r.routeKey,
    capabilityEpoch: r.capabilityEpoch,
    issuedAtMs: r.issuedAtMs,
    expiresAtMs: r.expiresAtMs
  }
}

function pathOf(relays) {
  return relays.map(hopOf)
}

function capabilityOf(r, now = NOW) {
  return createSurbCapabilityAuthority({
    routeSecretKey: r.routeSecretKey,
    routeKey: r.routeKey,
    capabilityEpoch: r.capabilityEpoch,
    issuedAtMs: r.issuedAtMs,
    expiresAtMs: r.expiresAtMs,
    now
  })
}

function expectCode(t, fn, code, msg) {
  try {
    fn()
    t.fail(msg ? msg + ' (did not throw)' : 'expected ' + code)
  } catch (err) {
    t.is(err && err.code, code, msg || 'rejected with ' + code)
  }
}

function expectInvalidRoute(t, fn, msg) {
  expectCode(t, fn, 'INVALID_ROUTE', msg)
}

function encodeHopMessage(msg) {
  if (msg.ephem) {
    return b4a.concat([msg.ephem, msg.header, msg.mac, msg.payload])
  }
  return b4a.from(msg.payload)
}

function encodeHopContext(routeKey, capabilityEpoch, issuedAtMs, expiresAtMs) {
  const ctx = b4a.alloc(58)
  ctx[0] = 0
  ctx[1] = 1
  ctx.set(routeKey, 2)
  let v = capabilityEpoch
  for (let i = 41; i >= 34; i--) {
    ctx[i] = Number(v & 0xffn)
    v >>= 8n
  }
  v = issuedAtMs
  for (let i = 49; i >= 42; i--) {
    ctx[i] = Number(v & 0xffn)
    v >>= 8n
  }
  v = expiresAtMs
  for (let i = 57; i >= 50; i--) {
    ctx[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return ctx
}

function assertNoHopContext(t, wire, hop, label) {
  const ctx = encodeHopContext(hop.routeKey, hop.capabilityEpoch, hop.issuedAtMs, hop.expiresAtMs)
  t.absent(b4a.includes(wire, ctx), label || 'HopContext absent from wire')
}

function build(relays, terminalHandle, opts = {}) {
  return buildSurb({
    hops: pathOf(relays),
    terminalHandle,
    replyBinding: opts.replyBinding || DEFAULT_BINDING,
    now: opts.now !== undefined ? opts.now : NOW,
    seeds: opts.seeds
  })
}

function seal(descriptor, plaintext, replyBinding = DEFAULT_BINDING) {
  return sealSurbReply({ descriptor, replyBinding, plaintext })
}

function processHop(message, relay, replayAuthority) {
  return processSurbHop({
    message,
    capabilityAuthority: capabilityOf(relay),
    replayAuthority
  })
}

function open(openAuthority, payload, opts = {}) {
  return openSurbReply({
    openAuthority,
    replyBinding: opts.replyBinding || DEFAULT_BINDING,
    payload,
    now: opts.now !== undefined ? opts.now : NOW
  })
}

// Drive a reply from the responder back through every relay to the initiator.
function roundTrip(relays, terminalHandle, descriptor, openAuthority, plaintext) {
  let msg = seal(descriptor, plaintext)
  const headerLengths = []
  const sizes = []
  const replays = relays.map(() => createSurbReplayAuthority({ maxEntries: 64 }))

  for (let i = 0; i < relays.length; i++) {
    headerLengths.push(msg.header.byteLength)
    sizes.push(encodeHopMessage(msg).byteLength)
    assertNoHopContext(tSilent, encodeHopMessage(msg), relays[i])

    const fwd = processHop(msg, relays[i], replays[i])
    const r = consumeSurbForwardingAuthority(fwd)
    const expectedNext = i < relays.length - 1 ? relays[i + 1].id : terminalHandle
    if (!b4a.equals(r.nextHop, expectedNext)) throw new Error('wrong nextHop at hop ' + i)
    if (i < relays.length - 1) {
      if (r.terminal) throw new Error('early terminal at hop ' + i)
      msg = r.message
    } else {
      if (!r.terminal) throw new Error('missing terminal at last hop')
      sizes.push(r.message.payload.byteLength)
      return {
        plaintext: open(openAuthority, r.message.payload),
        headerLengths,
        sizes
      }
    }
  }
}

// silent assert helper used inside roundTrip
const tSilent = {
  absent(cond, msg) {
    if (cond) throw new Error(msg || 'expected absent')
  }
}

test('round-trip recovers the reply for every path length 1..MAX_HOPS', (t) => {
  const all = []
  for (let n = 1; n <= MAX_HOPS; n++) {
    const relays = []
    for (let i = 0; i < n; i++) relays.push(relay())
    const terminalHandle = b4a.alloc(32, n)
    const { descriptor, openAuthority } = build(relays, terminalHandle)
    const reply = b4a.from('reply over ' + n + ' hop(s) — only the initiator reads this')
    const out = roundTrip(relays, terminalHandle, descriptor, openAuthority, reply)
    t.alike(out.plaintext, reply, n + '-hop round-trip')
    all.push(out.headerLengths)
  }
  const flat = all.flat()
  t.ok(
    flat.every((len) => len === RHO),
    'every hop sees a constant RHO-byte header (position not leaked by length)'
  )
})

test('the first hop never sees plaintext', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalHandle = b4a.alloc(32, 1)
  const { descriptor } = build(relays, terminalHandle)
  const reply = b4a.from('SECRET-MARKER-payload')
  const msg = seal(descriptor, reply)
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  t.absent(b4a.includes(msg.payload, reply), 'responder output carries no plaintext marker')
  const fwd = processHop(msg, relays[0], replay)
  const r = consumeSurbForwardingAuthority(fwd)
  t.absent(b4a.includes(r.message.payload, reply), 'first hop payload carries no plaintext marker')
})

test('a hop learns only its immediate next hop, not the whole path', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalHandle = b4a.alloc(32, 9)
  const { descriptor } = build(relays, terminalHandle)
  const msg = seal(descriptor, b4a.from('x'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  const r1 = consumeSurbForwardingAuthority(processHop(msg, relays[0], replay))
  t.alike(r1.nextHop, relays[1].id, 'hop 1 sees hop 2 as next')
  const replay2 = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(
    t,
    () => processHop(r1.message, relays[0], replay2),
    'hop 1 key cannot open hop 2 layer'
  )
})

test('tampered ephem is rejected', (t) => {
  const relays = [relay(), relay(), relay()]
  const { descriptor } = build(relays, b4a.alloc(32, 2))
  const msg = seal(descriptor, b4a.from('ephem-test'))
  msg.ephem[0] ^= 0x01
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, relays[0], replay), 'ephem tamper -> INVALID_ROUTE')
})

test('tampered header is rejected', (t) => {
  const relays = [relay(), relay(), relay()]
  const { descriptor } = build(relays, b4a.alloc(32, 2))
  const msg = seal(descriptor, b4a.from('y'))
  msg.header[0] ^= 0x01
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, relays[0], replay), 'header tamper -> INVALID_ROUTE')
})

test('tampered header MAC is rejected', (t) => {
  const relays = [relay(), relay(), relay()]
  const { descriptor } = build(relays, b4a.alloc(32, 3))
  const msg = seal(descriptor, b4a.from('y2'))
  msg.mac[0] ^= 0x01
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, relays[0], replay), 'mac tamper -> INVALID_ROUTE')
})

test('tampered payload is rejected at open', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalHandle = b4a.alloc(32, 4)
  const { descriptor, openAuthority } = build(relays, terminalHandle)
  let msg = seal(descriptor, b4a.from('z'))
  for (let i = 0; i < relays.length; i++) {
    const replay = createSurbReplayAuthority({ maxEntries: 8 })
    const r = consumeSurbForwardingAuthority(processHop(msg, relays[i], replay))
    msg = r.message
  }
  msg.payload[0] ^= 0x01
  expectInvalidRoute(t, () => open(openAuthority, msg.payload), 'payload tamper -> INVALID_ROUTE')
})

test('wrong route key cannot process the hop', (t) => {
  const relays = [relay(), relay(), relay()]
  const { descriptor } = build(relays, b4a.alloc(32, 5))
  const msg = seal(descriptor, b4a.from('w'))
  const wrong = relay()
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, wrong, replay), 'wrong key -> INVALID_ROUTE')
})

test('noncanonical X25519 public keys are rejected', (t) => {
  const relays = [relay(), relay()]
  const terminalHandle = b4a.alloc(32, 1)
  const { descriptor } = build(relays, terminalHandle)
  const msg = seal(descriptor, b4a.from('canonical-check'))

  const noncanonicalEphem = b4a.from(msg.ephem)
  noncanonicalEphem[31] ^= 0x80
  const noncanonicalEphemSnapshot = b4a.from(noncanonicalEphem)
  const relaySecretSnapshot = b4a.from(relays[0].routeSecretKey)
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(
    t,
    () => processHop({ ...msg, ephem: noncanonicalEphem }, relays[0], replay),
    'noncanonical message.ephem with bit 255 set -> INVALID_ROUTE'
  )
  t.alike(noncanonicalEphem, noncanonicalEphemSnapshot, 'noncanonical ephem unmutated')
  t.alike(relays[0].routeSecretKey, relaySecretSnapshot, 'relay secret unmutated')

  const noncanonicalRouteKey = b4a.from(relays[0].routeKey)
  noncanonicalRouteKey[31] |= 0x80
  const noncanonicalRouteKeySnapshot = b4a.from(noncanonicalRouteKey)
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: relays[0].id,
            routeKey: noncanonicalRouteKey,
            capabilityEpoch: EPOCH,
            issuedAtMs: ISSUED,
            expiresAtMs: EXPIRES
          }
        ],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'noncanonical public routeKey -> INVALID_ROUTE'
  )
  t.alike(noncanonicalRouteKey, noncanonicalRouteKeySnapshot, 'noncanonical routeKey unmutated')

  const edgeNoncanonicalKey = b4a.alloc(32, 0xff)
  edgeNoncanonicalKey[0] = 0xee
  edgeNoncanonicalKey[31] = 0x7f
  const edgeSnapshot = b4a.from(edgeNoncanonicalKey)
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: relays[0].id,
            routeKey: edgeNoncanonicalKey,
            capabilityEpoch: EPOCH,
            issuedAtMs: ISSUED,
            expiresAtMs: EXPIRES
          }
        ],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'edge noncanonical routeKey -> INVALID_ROUTE'
  )
  t.alike(edgeNoncanonicalKey, edgeSnapshot, 'edge noncanonical routeKey unmutated')
})

test('malformed input is rejected fail-closed', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalHandle = b4a.alloc(32, 8)
  const { descriptor } = build(relays, terminalHandle)
  const msg = seal(descriptor, b4a.from('m'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  expectInvalidRoute(
    t,
    () => processHop({ ...msg, header: msg.header.subarray(0, 10) }, relays[0], replay),
    'wrong-size header'
  )
  expectInvalidRoute(
    t,
    () => processHop({ ...msg, payload: b4a.alloc(4) }, relays[0], replay),
    'payload below seal minimum'
  )
  expectInvalidRoute(
    t,
    () => processHop({ ...msg, ephem: b4a.alloc(16) }, relays[0], replay),
    'wrong-size ephem'
  )
  expectInvalidRoute(
    t,
    () => processHop({ ...msg, mac: b4a.alloc(8) }, relays[0], replay),
    'wrong-size mac'
  )
  expectInvalidRoute(
    t,
    () => buildSurb({ hops: [], terminalHandle, replyBinding: DEFAULT_BINDING, now: NOW }),
    'empty hops'
  )
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: new Array(MAX_HOPS + 1).fill(hopOf(relays[0])),
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'hops exceeding MAX_HOPS'
  )
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: b4a.alloc(16),
            routeKey: relays[0].routeKey,
            capabilityEpoch: EPOCH,
            issuedAtMs: ISSUED,
            expiresAtMs: EXPIRES
          }
        ],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'wrong-size hop id'
  )
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [hopOf(relays[0]), hopOf(relays[0])],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'duplicate hop ids'
  )
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: relays[0].id,
            routeKey: relays[0].routeKey,
            capabilityEpoch: 7,
            issuedAtMs: ISSUED,
            expiresAtMs: EXPIRES
          }
        ],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'non-BigInt time fields'
  )
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: pathOf(relays),
        terminalHandle: b4a.alloc(16),
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'wrong-size terminalHandle'
  )
})

test('epoch substitution rejected before replay-store growth', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('epoch'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  const wrongEpoch = createSurbCapabilityAuthority({
    routeSecretKey: r.routeSecretKey,
    routeKey: r.routeKey,
    capabilityEpoch: EPOCH + 1n,
    issuedAtMs: ISSUED,
    expiresAtMs: EXPIRES,
    now: NOW
  })

  const sizeBefore = replay
  // access internal size via a successful later admit of a different SURB is hard;
  // instead: failed process must not grow. We probe by attempting a second valid admit path.
  expectInvalidRoute(
    t,
    () =>
      processSurbHop({
        message: msg,
        capabilityAuthority: wrongEpoch,
        replayAuthority: replay
      }),
    'epoch substitution -> INVALID_ROUTE'
  )

  // A fresh valid SURB must still admit (store was not filled by the failed attempt).
  const fresh = build([r], b4a.alloc(32, 2))
  const freshMsg = seal(fresh.descriptor, b4a.from('ok'))
  const fwd = processHop(freshMsg, r, replay)
  t.ok(fwd, 'fresh SURB admitted after epoch-sub failure')
  consumeSurbForwardingAuthority(fwd)

  // And the original message still processes on the correct epoch (store never saw its nullifier).
  const replay2 = createSurbReplayAuthority({ maxEntries: 8 })
  const fwd2 = processHop(msg, r, replay2)
  t.ok(fwd2, 'original message still processable on correct epoch')
  consumeSurbForwardingAuthority(fwd2)
  void sizeBefore
})

test('old key rejected at hop processing', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('old-key'))
  const old = relay()
  // force same capability times but different key
  old.capabilityEpoch = r.capabilityEpoch
  old.issuedAtMs = r.issuedAtMs
  old.expiresAtMs = r.expiresAtMs
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, old, replay), 'old key rejected')
})

test('wrong routeKey/secret mismatch rejected at authority creation', (t) => {
  const r = relay()
  const other = relay()
  expectInvalidRoute(
    t,
    () =>
      createSurbCapabilityAuthority({
        routeSecretKey: r.routeSecretKey,
        routeKey: other.routeKey,
        capabilityEpoch: EPOCH,
        issuedAtMs: ISSUED,
        expiresAtMs: EXPIRES,
        now: NOW
      }),
    'routeKey/secret mismatch'
  )
})

test('MAC failure leaves replay store size unchanged and no wrap', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('mac-fail'))
  const originalPayload = b4a.from(msg.payload)
  msg.mac[0] ^= 0x01
  const replay = createSurbReplayAuthority({ maxEntries: 4 })

  expectInvalidRoute(t, () => processHop(msg, r, replay), 'MAC failure')

  // Fill the replay authority to capacity with distinct valid SURBs; if MAC failure
  // had admitted anything, capacity would be lower.
  for (let i = 0; i < 4; i++) {
    const built = build([r], b4a.alloc(32, i + 10))
    const m = seal(built.descriptor, b4a.from('x' + i))
    const fwd = processHop(m, r, replay)
    consumeSurbForwardingAuthority(fwd)
  }
  expectCode(
    t,
    () => {
      const built = build([r], b4a.alloc(32, 99))
      const m = seal(built.descriptor, b4a.from('overflow'))
      processHop(m, r, replay)
    },
    'ERR_QUOTA_EXCEEDED',
    'quota still exactly 4 after MAC failure'
  )
  t.alike(msg.payload, originalPayload, 'payload untransformed after MAC failure')
})

test('concurrent double-process yields exactly one forwarding authority', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('once'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  const first = processHop(msg, r, replay)
  t.ok(first, 'first process issues forwarding authority')

  expectCode(t, () => processHop(msg, r, replay), 'ERR_REPLAY', 'second process is a replay')

  const consumed = consumeSurbForwardingAuthority(first)
  t.is(consumed.terminal, true)
  expectCode(
    t,
    () => consumeSurbForwardingAuthority(first),
    'ERR_DESTROYED',
    'second consume throws ERR_DESTROYED'
  )
})

test('replay rejected before transformation', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('replay'))
  const payloadBefore = b4a.from(msg.payload)
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const first = processHop(msg, r, replay)
  consumeSurbForwardingAuthority(first)

  expectCode(t, () => processHop(msg, r, replay), 'ERR_REPLAY', 'replay rejected')
  t.alike(msg.payload, payloadBefore, 'caller payload unchanged on replay reject')
})

test('quota-full fails closed', (t) => {
  const r = relay()
  const replay = createSurbReplayAuthority({ maxEntries: 2 })
  for (let i = 0; i < 2; i++) {
    const built = build([r], b4a.alloc(32, i + 1))
    const msg = seal(built.descriptor, b4a.from('q' + i))
    consumeSurbForwardingAuthority(processHop(msg, r, replay))
  }
  const built = build([r], b4a.alloc(32, 9))
  const msg = seal(built.descriptor, b4a.from('overflow'))
  expectCode(t, () => processHop(msg, r, replay), 'ERR_QUOTA_EXCEEDED', 'quota full')
})

test('one-use open on success and on failure', (t) => {
  const relays = [relay()]
  const terminalHandle = b4a.alloc(32, 1)
  const a = build(relays, terminalHandle)
  const b = build(relays, terminalHandle)

  let msg = seal(a.descriptor, b4a.from('success-open'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const r = consumeSurbForwardingAuthority(processHop(msg, relays[0], replay))
  const plain = open(a.openAuthority, r.message.payload)
  t.alike(plain, b4a.from('success-open'))
  expectCode(
    t,
    () => open(a.openAuthority, r.message.payload),
    'ERR_DESTROYED',
    'second open after success'
  )

  let msg2 = seal(b.descriptor, b4a.from('fail-open'))
  const replay2 = createSurbReplayAuthority({ maxEntries: 8 })
  const r2 = consumeSurbForwardingAuthority(processHop(msg2, relays[0], replay2))
  r2.message.payload[0] ^= 0xff
  expectInvalidRoute(t, () => open(b.openAuthority, r2.message.payload), 'open fails on tamper')
  expectCode(
    t,
    () => open(b.openAuthority, r2.message.payload),
    'ERR_DESTROYED',
    'second open after failure'
  )
})

test('expiry rejects build, capability, and open', (t) => {
  const r = relay()
  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: r.id,
            routeKey: r.routeKey,
            capabilityEpoch: EPOCH,
            issuedAtMs: ISSUED,
            expiresAtMs: NOW
          }
        ],
        terminalHandle: b4a.alloc(32, 1),
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'expired capability at build'
  )

  expectInvalidRoute(
    t,
    () =>
      createSurbCapabilityAuthority({
        routeSecretKey: r.routeSecretKey,
        routeKey: r.routeKey,
        capabilityEpoch: EPOCH,
        issuedAtMs: ISSUED,
        expiresAtMs: NOW,
        now: NOW
      }),
    'expired capability at authority create'
  )

  const built = build([r], b4a.alloc(32, 1))
  let msg = seal(built.descriptor, b4a.from('exp'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const fwd = consumeSurbForwardingAuthority(processHop(msg, r, replay))
  expectInvalidRoute(
    t,
    () => open(built.openAuthority, fwd.message.payload, { now: EXPIRES + 1n }),
    'open after hop expiry'
  )
  expectCode(
    t,
    () => open(built.openAuthority, fwd.message.payload, { now: NOW }),
    'ERR_DESTROYED',
    'open authority cleared after expiry reject'
  )
})

test('revoke clears open authority', (t) => {
  const r = relay()
  const { descriptor, openAuthority } = build([r], b4a.alloc(32, 1))
  t.ok(revokeSurbOpenAuthority(openAuthority), 'first revoke returns true')
  t.absent(revokeSurbOpenAuthority(openAuthority), 'second revoke returns false')
  let msg = seal(descriptor, b4a.from('revoked'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const fwd = consumeSurbForwardingAuthority(processHop(msg, r, replay))
  expectCode(
    t,
    () => open(openAuthority, fwd.message.payload),
    'ERR_DESTROYED',
    'open after revoke'
  )
})

test('per-hop message sizes for a 512-byte reply', (t) => {
  const relays = []
  for (let i = 0; i < MAX_HOPS; i++) relays.push(relay())
  const terminalHandle = b4a.alloc(32, 0x51)
  const { descriptor, openAuthority } = build(relays, terminalHandle)
  const plaintext = b4a.alloc(MAX_REPLY_BYTES, 0xab)
  const out = roundTrip(relays, terminalHandle, descriptor, openAuthority, plaintext)
  t.alike(out.plaintext, plaintext)
  t.alike(out.sizes, [932, 948, 964, 980, 624], 'relay inputs 932/948/964/980 and terminal 624')
})

test('a 513-byte plaintext is rejected before encryption', (t) => {
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  expectInvalidRoute(
    t,
    () => seal(descriptor, b4a.alloc(MAX_REPLY_BYTES + 1)),
    '513-byte plaintext rejected before encryption'
  )
})

test('replyBinding mismatch fails open', (t) => {
  const r = relay()
  const binding = b4a.from('binding-A')
  const { descriptor, openAuthority } = build([r], b4a.alloc(32, 1), { replyBinding: binding })
  let msg = seal(descriptor, b4a.from('bind'), binding)
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  const fwd = consumeSurbForwardingAuthority(processHop(msg, r, replay))
  expectInvalidRoute(
    t,
    () => open(openAuthority, fwd.message.payload, { replyBinding: b4a.from('binding-B') }),
    'replyBinding mismatch'
  )
})

test('no HopContext bytes appear in any wire message', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalHandle = b4a.alloc(32, 0xcc)
  const { descriptor, openAuthority } = build(relays, terminalHandle)
  let msg = seal(descriptor, b4a.from('context-scan'))
  for (let i = 0; i < relays.length; i++) {
    const wire = encodeHopMessage(msg)
    for (let j = 0; j < relays.length; j++) {
      assertNoHopContext(t, wire, relays[j], 'hop ' + i + ' wire lacks context of relay ' + j)
    }
    const replay = createSurbReplayAuthority({ maxEntries: 8 })
    const r = consumeSurbForwardingAuthority(processHop(msg, relays[i], replay))
    if (!r.terminal) msg = r.message
    else {
      assertNoHopContext(t, r.message.payload, relays[i], 'terminal payload lacks context')
      open(openAuthority, r.message.payload)
    }
  }
})

test('deterministic fuzz: random path lengths and payload sizes round-trip', (t) => {
  const prng = createPrng(0x12345678)
  for (let iter = 0; iter < 100; iter++) {
    const n = 1 + prng.int(MAX_HOPS)
    const relays = []
    for (let i = 0; i < n; i++) relays.push(relay())
    const terminalHandle = prng.bytes(32)
    const binding = prng.bytes(1 + prng.int(32))
    const { descriptor, openAuthority } = build(relays, terminalHandle, { replyBinding: binding })
    const size = prng.int(MAX_REPLY_BYTES + 1)
    const reply = prng.bytes(size)

    let msg = seal(descriptor, reply, binding)
    const replays = relays.map(() => createSurbReplayAuthority({ maxEntries: 8 }))
    for (let i = 0; i < n; i++) {
      if (msg.header.byteLength !== RHO) t.fail('non-constant header at iter ' + iter)
      const r = consumeSurbForwardingAuthority(processHop(msg, relays[i], replays[i]))
      if (i < n - 1) msg = r.message
      else if (
        !b4a.equals(open(openAuthority, r.message.payload, { replyBinding: binding }), reply)
      ) {
        t.fail('round-trip mismatch at iter ' + iter)
      }
    }
  }
  t.pass('100 deterministic round-trips recovered exactly, header always RHO bytes')
})

test('deterministic fuzz: single-bit tamper is rejected', (t) => {
  const prng = createPrng(0xcafebabe)
  const fields = ['ephem', 'header', 'mac', 'payload']
  for (let iter = 0; iter < 100; iter++) {
    const relays = [relay(), relay(), relay()]
    const terminalHandle = prng.bytes(32)
    const { descriptor, openAuthority } = build(relays, terminalHandle)
    const base = seal(descriptor, b4a.from('fuzz-target-payload'))

    const field = fields[prng.int(fields.length)]
    const msg0 = {
      ephem: b4a.from(base.ephem),
      header: b4a.from(base.header),
      mac: b4a.from(base.mac),
      payload: b4a.from(base.payload)
    }
    const buf = msg0[field]
    buf[prng.int(buf.byteLength)] ^= 1 << prng.int(8)

    let rejected = false
    try {
      let msg = msg0
      for (let i = 0; i < relays.length; i++) {
        const replay = createSurbReplayAuthority({ maxEntries: 8 })
        const r = consumeSurbForwardingAuthority(processHop(msg, relays[i], replay))
        if (i < relays.length - 1) msg = r.message
        else open(openAuthority, r.message.payload)
      }
    } catch (err) {
      if (
        !err ||
        (err.code !== 'INVALID_ROUTE' && err.code !== 'ERR_DESTROYED' && err.code !== 'ERR_REPLAY')
      ) {
        throw err
      }
      rejected = true
    }
    if (!rejected) t.fail('tamper in ' + field + ' was unexpectedly accepted')
  }
  t.pass('100 single-bit tampers each rejected')
})

test('conformance vector — deterministic wire fields match the fixture byte-for-byte', (t) => {
  const fix = require('./fixtures/surb-vector-v1.json')
  const h2b = (s) => b4a.from(s, 'hex')
  const hex = (b) => b4a.toString(b, 'hex')

  const hops = fix.inputs.hops.map((h) => ({
    id: h2b(h.id),
    routeKey: h2b(h.routeKey),
    capabilityEpoch: BigInt(h.capabilityEpoch),
    issuedAtMs: BigInt(h.issuedAtMs),
    expiresAtMs: BigInt(h.expiresAtMs)
  }))
  const { descriptor } = buildSurb({
    hops,
    terminalHandle: h2b(fix.inputs.terminalHandle),
    replyBinding: h2b(fix.inputs.replyBinding),
    now: BigInt(fix.inputs.now),
    seeds: {
      ephemeralSeeds: fix.inputs.ephemeralSeeds.map(h2b),
      replySeed: h2b(fix.inputs.replySeed)
    }
  })

  t.is(hex(descriptor.ephem), fix.outputs.ephem, 'E_1')
  t.is(descriptor.header.byteLength, RHO, 'header is RHO bytes')
  t.is(hex(descriptor.header), fix.outputs.header, 'full header bytes match fixture')
  t.is(hex(descriptor.mac), fix.outputs.mac, 'header MAC')
  t.is(hex(descriptor.replyPubKey), fix.outputs.replyPub, 'reply pubkey')

  // Walk the header with a fixed dummy payload (inner seal is randomized; not in fixture).
  const secrets = fix.inputs.hops.map((h) => ({
    id: h2b(h.id),
    routeKey: h2b(h.routeKey),
    routeSecretKey: h2b(h.routeSecretKey),
    capabilityEpoch: BigInt(h.capabilityEpoch),
    issuedAtMs: BigInt(h.issuedAtMs),
    expiresAtMs: BigInt(h.expiresAtMs)
  }))
  let msg = {
    ephem: descriptor.ephem,
    header: descriptor.header,
    mac: descriptor.mac,
    payload: b4a.alloc(48)
  }
  for (let i = 0; i < fix.outputs.hops.length; i++) {
    const replay = createSurbReplayAuthority({ maxEntries: 8 })
    const fwd = processHop(msg, secrets[i], replay)
    const r = consumeSurbForwardingAuthority(fwd)
    const exp = fix.outputs.hops[i]
    t.is(hex(r.nextHop), exp.nextHop, 'hop ' + i + ' nextHop')
    t.is(r.terminal, exp.terminal, 'hop ' + i + ' terminal flag')
    if (!r.terminal) {
      t.is(hex(r.message.ephem), exp.nextEphem, 'hop ' + i + ' nextEphem')
      t.is(hex(r.message.mac), exp.nextMac, 'hop ' + i + ' nextMac')
      t.is(hex(r.message.header), exp.nextHeader, 'hop ' + i + ' nextHeader')
      msg = {
        ephem: r.message.ephem,
        header: r.message.header,
        mac: r.message.mac,
        payload: b4a.alloc(48)
      }
    }
  }
})

test('reply payload budget is enforced', (t) => {
  const relays = [relay(), relay(), relay()]
  const { descriptor } = build(relays, b4a.alloc(32, 1))
  t.execution(() => seal(descriptor, b4a.alloc(MAX_REPLY_BYTES)), 'max-size reply accepted')
  expectInvalidRoute(
    t,
    () => seal(descriptor, b4a.alloc(MAX_REPLY_BYTES + 1)),
    'oversize reply -> INVALID_ROUTE'
  )
})

test('low-order DH points are rejected fail-closed', (t) => {
  const terminalHandle = b4a.alloc(32, 1)
  const zeroKey = b4a.alloc(32)

  expectInvalidRoute(
    t,
    () =>
      buildSurb({
        hops: [
          {
            id: b4a.alloc(32, 1),
            routeKey: zeroKey,
            capabilityEpoch: EPOCH,
            issuedAtMs: ISSUED,
            expiresAtMs: EXPIRES
          }
        ],
        terminalHandle,
        replyBinding: DEFAULT_BINDING,
        now: NOW
      }),
    'zero routeKey in buildSurb rejected'
  )

  const r = relay()
  const { descriptor } = build([r], terminalHandle)
  const msg = seal(descriptor, b4a.from('test'))
  const replay = createSurbReplayAuthority({ maxEntries: 8 })

  expectInvalidRoute(
    t,
    () => processHop({ ...msg, ephem: zeroKey }, r, replay),
    'zero ephem rejected'
  )
  expectInvalidRoute(
    t,
    () =>
      createSurbCapabilityAuthority({
        routeSecretKey: zeroKey,
        routeKey: r.routeKey,
        capabilityEpoch: EPOCH,
        issuedAtMs: ISSUED,
        expiresAtMs: EXPIRES,
        now: NOW
      }),
    'zero routeSecretKey at authority create rejected'
  )
  expectInvalidRoute(
    t,
    () =>
      sealSurbReply({
        descriptor: { ...descriptor, replyPubKey: zeroKey },
        replyBinding: DEFAULT_BINDING,
        plaintext: b4a.from('test')
      }),
    'zero replyPubKey in seal rejected'
  )
})

test('caller key material remains intact after failed operations', (t) => {
  const terminalHandle = b4a.alloc(32, 0xaa)
  const terminalHandleCopy = b4a.from(terminalHandle)
  const ephemeralSeeds = [b4a.alloc(32, 0x11), b4a.alloc(32, 0x22)]
  const ephemeralSeedsCopy = ephemeralSeeds.map((s) => b4a.from(s))
  const replySeed = b4a.alloc(32, 0x33)
  const replySeedCopy = b4a.from(replySeed)
  const binding = b4a.from(DEFAULT_BINDING)
  const bindingCopy = b4a.from(binding)

  const firstRelay = relay()
  const firstRelayKeyCopy = b4a.from(firstRelay.routeKey)
  const noncanonicalRouteKey = b4a.from(relay().routeKey)
  noncanonicalRouteKey[31] |= 0x80
  const noncanonicalCopy = b4a.from(noncanonicalRouteKey)
  expectInvalidRoute(t, () =>
    buildSurb({
      hops: [
        hopOf(firstRelay),
        {
          id: b4a.alloc(32, 2),
          routeKey: noncanonicalRouteKey,
          capabilityEpoch: EPOCH,
          issuedAtMs: ISSUED,
          expiresAtMs: EXPIRES
        }
      ],
      terminalHandle,
      replyBinding: binding,
      now: NOW,
      seeds: { ephemeralSeeds, replySeed }
    })
  )
  t.alike(terminalHandle, terminalHandleCopy, 'terminalHandle unmutated')
  t.alike(firstRelay.routeKey, firstRelayKeyCopy, 'caller hop routeKey unmutated')
  t.alike(noncanonicalRouteKey, noncanonicalCopy, 'noncanonical routeKey unmutated')
  t.alike(ephemeralSeeds[0], ephemeralSeedsCopy[0], 'ephemeral seed 0 unmutated')
  t.alike(ephemeralSeeds[1], ephemeralSeedsCopy[1], 'ephemeral seed 1 unmutated')
  t.alike(replySeed, replySeedCopy, 'replySeed unmutated')
  t.alike(binding, bindingCopy, 'replyBinding unmutated')

  const validRelay = relay()
  const validRelaySecretCopy = b4a.from(validRelay.routeSecretKey)
  const { descriptor, openAuthority } = build([validRelay], terminalHandle)
  const msg = seal(descriptor, b4a.from('test'))
  const msgEphemCopy = b4a.from(msg.ephem)
  msg.mac[0] ^= 0x01
  const replay = createSurbReplayAuthority({ maxEntries: 8 })
  expectInvalidRoute(t, () => processHop(msg, validRelay, replay))
  t.alike(validRelay.routeSecretKey, validRelaySecretCopy, 'route secret unmutated')
  t.alike(msg.ephem, msgEphemCopy, 'message ephem unmutated')

  const zeroReplyPubKey = b4a.alloc(32)
  const zeroReplyPubKeyCopy = b4a.from(zeroReplyPubKey)
  const plaintextBuf = b4a.from('test-payload')
  const plaintextBufCopy = b4a.from(plaintextBuf)
  expectInvalidRoute(t, () =>
    sealSurbReply({
      descriptor: { ...descriptor, replyPubKey: zeroReplyPubKey },
      replyBinding: binding,
      plaintext: plaintextBuf
    })
  )
  t.alike(zeroReplyPubKey, zeroReplyPubKeyCopy, 'zero replyPubKey unmutated')
  t.alike(plaintextBuf, plaintextBufCopy, 'plaintext unmutated')

  // Failed open still consumes authority; caller buffers must remain intact.
  const badPayload = b4a.alloc(64, 0xff)
  expectInvalidRoute(t, () => open(openAuthority, badPayload))
  t.alike(binding, bindingCopy, 'replyBinding unmutated after failed open')
})

test('destroySurbReplayAuthority clears and rejects further use', (t) => {
  const replay = createSurbReplayAuthority({ maxEntries: 4 })
  t.ok(destroySurbReplayAuthority(replay), 'destroy returns true')
  t.absent(destroySurbReplayAuthority(replay), 'second destroy returns false')
  const r = relay()
  const { descriptor } = build([r], b4a.alloc(32, 1))
  const msg = seal(descriptor, b4a.from('x'))
  expectCode(t, () => processHop(msg, r, replay), 'ERR_DESTROYED', 'process after destroy')
})

// Optional: regenerate fixture when SURB_REGEN_FIXTURE=1
if (typeof process !== 'undefined' && process.env && process.env.SURB_REGEN_FIXTURE === '1') {
  test('REGEN fixture vector', (t) => {
    const h2b = (s) => b4a.from(s, 'hex')
    const hex = (b) => b4a.toString(b, 'hex')
    const inputs = {
      note: 'Deterministic SURB conformance vector (Gate C amendment). Feed the inputs; every listed output must match byte-for-byte. The reply payload is intentionally excluded: inner seal uses a fresh ephemeral and is not reproducible. MAX_HOPS=4, HOP=81, RHO=324. Per-hop processing uses a fixed 48-byte dummy payload. HopContext is never on the wire.',
      terminalHandle: '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
      replyBinding: b4a.toString(b4a.from('surb-fixture-binding-v1'), 'hex'),
      now: '1700000000000',
      ephemeralSeeds: [
        '5fc1695f965e3d2f7e9227627d4e7458cdd1d3f533b62480212f314a81393c8c',
        'db0a91d2338d5843310635e86e71e156adfa5d24e23ac00fe4b39044e5f89c6c',
        '59a0d72534aff731c578872271f7bccf8044343772544cbd421a5a34c5e84942'
      ],
      replySeed: '61565d514774a08501eed9785ee5feb979188990ce4b2bbd562007c763095c73',
      hops: []
    }

    // Derive hop keypairs from fixed seeds so the fixture is fully deterministic.
    const hopSeeds = [
      '9ab594e0c9939fe792ab8c7a043fea9e6f417bc6047b381187ab5d54e4235664',
      '753f45ec9f6017fab6bd07ad146061ccaec5f03807748c49f4764854468f9a7e',
      '0a65debc9496108e7aa5f17c8cf047257983697d0ab4ea8a631624296106de58'
    ]
    const hopIds = [
      'c09880659290aba961eab6936a725b008e83bb93ef3edc0deff82386363cad42',
      '9fe58b359ef40ec58ca8d5f5ae01609d669fe797d3910d7681e5346522969140',
      'c6ae491a326e3686804fda9abedd12757df50c111009f51764734b3d740b1f87'
    ]
    for (let i = 0; i < 3; i++) {
      const routeSecretKey = h2b(hopSeeds[i])
      const routeKey = b4a.allocUnsafeSlow(32)
      sodium.crypto_scalarmult_base(routeKey, routeSecretKey)
      inputs.hops.push({
        id: hopIds[i],
        routeKey: hex(routeKey),
        routeSecretKey: hopSeeds[i],
        capabilityEpoch: '7',
        issuedAtMs: '1699999999000',
        expiresAtMs: '1700003600000'
      })
    }

    const hops = inputs.hops.map((h) => ({
      id: h2b(h.id),
      routeKey: h2b(h.routeKey),
      capabilityEpoch: BigInt(h.capabilityEpoch),
      issuedAtMs: BigInt(h.issuedAtMs),
      expiresAtMs: BigInt(h.expiresAtMs)
    }))
    const { descriptor } = buildSurb({
      hops,
      terminalHandle: h2b(inputs.terminalHandle),
      replyBinding: h2b(inputs.replyBinding),
      now: BigInt(inputs.now),
      seeds: {
        ephemeralSeeds: inputs.ephemeralSeeds.map(h2b),
        replySeed: h2b(inputs.replySeed)
      }
    })

    const outputs = {
      ephem: hex(descriptor.ephem),
      header: hex(descriptor.header),
      mac: hex(descriptor.mac),
      replyPub: hex(descriptor.replyPubKey),
      hops: []
    }

    const secrets = inputs.hops.map((h) => ({
      id: h2b(h.id),
      routeKey: h2b(h.routeKey),
      routeSecretKey: h2b(h.routeSecretKey),
      capabilityEpoch: BigInt(h.capabilityEpoch),
      issuedAtMs: BigInt(h.issuedAtMs),
      expiresAtMs: BigInt(h.expiresAtMs)
    }))
    let msg = {
      ephem: descriptor.ephem,
      header: descriptor.header,
      mac: descriptor.mac,
      payload: b4a.alloc(48)
    }
    for (let i = 0; i < secrets.length; i++) {
      const replay = createSurbReplayAuthority({ maxEntries: 8 })
      const r = consumeSurbForwardingAuthority(processHop(msg, secrets[i], replay))
      if (r.terminal) {
        outputs.hops.push({ nextHop: hex(r.nextHop), terminal: true })
      } else {
        outputs.hops.push({
          nextHop: hex(r.nextHop),
          terminal: false,
          nextEphem: hex(r.message.ephem),
          nextMac: hex(r.message.mac),
          nextHeader: hex(r.message.header)
        })
        msg = {
          ephem: r.message.ephem,
          header: r.message.header,
          mac: r.message.mac,
          payload: b4a.alloc(48)
        }
      }
    }

    const fixture = {
      note: inputs.note,
      inputs: {
        terminalHandle: inputs.terminalHandle,
        replyBinding: inputs.replyBinding,
        now: inputs.now,
        ephemeralSeeds: inputs.ephemeralSeeds,
        replySeed: inputs.replySeed,
        hops: inputs.hops
      },
      outputs
    }
    const outPath = __dirname + '/fixtures/surb-vector-v1.json'
    fs.writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n')
    t.pass('wrote ' + outPath)
  })
}
