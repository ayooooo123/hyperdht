'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const {
  MAX_HOPS,
  RHO,
  MAX_REPLY_BYTES,
  buildSurb,
  sealReply,
  processSurbHop,
  openSurbPayload,
  createNullifierGuard
} = require('../../lib/private/surb')

function relay() {
  const routeKey = b4a.allocUnsafeSlow(32)
  const routeSecretKey = b4a.allocUnsafeSlow(32)
  sodium.crypto_box_keypair(routeKey, routeSecretKey)
  const id = b4a.allocUnsafeSlow(32)
  sodium.randombytes_buf(id)
  return { id, routeKey, routeSecretKey }
}

function pathOf(relays) {
  return relays.map((r) => ({ id: r.id, routeKey: r.routeKey }))
}

// Drive a reply from the responder back through every relay to the initiator.
// Records the header length each hop observed (for the length-invariance property).
function roundTrip(relays, terminalId, surb, openKeys, plaintext) {
  let msg = sealReply(surb, plaintext)
  const nullifiers = []
  const headerLengths = []
  for (let i = 0; i < relays.length; i++) {
    headerLengths.push(msg.header.byteLength)
    const r = processSurbHop(msg, relays[i].routeSecretKey)
    nullifiers.push(r.nullifier)
    const expectedNext = i < relays.length - 1 ? relays[i + 1].id : terminalId
    if (!b4a.equals(r.nextHop, expectedNext)) throw new Error('wrong nextHop at hop ' + i)
    if (i < relays.length - 1) {
      if (r.terminal) throw new Error('early terminal at hop ' + i)
      msg = r.forward
    } else {
      if (!r.terminal) throw new Error('missing terminal at last hop')
      return { plaintext: openSurbPayload(r.forward.payload, openKeys), nullifiers, headerLengths }
    }
  }
}

test('round-trip recovers the reply for every path length 1..MAX_HOPS', (t) => {
  const all = []
  for (let n = 1; n <= MAX_HOPS; n++) {
    const relays = []
    for (let i = 0; i < n; i++) relays.push(relay())
    const terminalId = b4a.alloc(32, n)
    const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
    const reply = b4a.from('reply over ' + n + ' hop(s) — only the initiator reads this')
    const out = roundTrip(relays, terminalId, surb, openKeys, reply)
    t.alike(out.plaintext, reply, n + '-hop round-trip')
    all.push(out.headerLengths)
  }
  // Length-invariance: every hop on every path sees exactly RHO header bytes.
  const flat = all.flat()
  t.ok(
    flat.every((len) => len === RHO),
    'every hop sees a constant RHO-byte header (position not leaked by length)'
  )
})

test('the first hop never sees plaintext', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 1)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const reply = b4a.from('SECRET-MARKER-payload')
  const msg = sealReply(surb, reply)

  t.absent(b4a.includes(msg.payload, reply), 'responder output carries no plaintext marker')
  const r = processSurbHop(msg, relays[0].routeSecretKey)
  t.absent(b4a.includes(r.forward.payload, reply), 'first hop payload carries no plaintext marker')
})

test('a hop learns only its immediate next hop, not the whole path', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 9)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('x'))

  const r1 = processSurbHop(msg, relays[0].routeSecretKey)
  t.alike(r1.nextHop, relays[1].id, 'hop 1 sees hop 2 as next')
  t.exception(
    () => processSurbHop(r1.forward, relays[0].routeSecretKey),
    'hop 1 key cannot open hop 2 layer'
  )
})

test('tampered header is rejected', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 2)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('y'))
  msg.header[0] ^= 0x01
  t.exception(() => processSurbHop(msg, relays[0].routeSecretKey), 'header tamper -> reject')
})

test('tampered header MAC is rejected', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 3)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('y2'))
  msg.mac[0] ^= 0x01
  t.exception(() => processSurbHop(msg, relays[0].routeSecretKey), 'mac tamper -> reject')
})

test('tampered payload is rejected at open', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 4)
  const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('z'))
  const r1 = processSurbHop(msg, relays[0].routeSecretKey)
  const r2 = processSurbHop(r1.forward, relays[1].routeSecretKey)
  const r3 = processSurbHop(r2.forward, relays[2].routeSecretKey)
  r3.forward.payload[0] ^= 0x01
  t.exception(() => openSurbPayload(r3.forward.payload, openKeys), 'payload tamper -> reject')
})

test('wrong route key cannot process the hop', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 5)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('w'))
  const wrong = relay()
  t.exception(() => processSurbHop(msg, wrong.routeSecretKey), 'wrong key -> reject')
})

test('nullifiers are deterministic per hop and fresh per SURB', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 6)
  const first = buildSurb(pathOf(relays), terminalId)
  const a = roundTrip(relays, terminalId, first.surb, first.openKeys, b4a.from('a')).nullifiers
  const second = buildSurb(pathOf(relays), terminalId)
  const b = roundTrip(relays, terminalId, second.surb, second.openKeys, b4a.from('b')).nullifiers

  t.is(a.length, 3)
  t.unlike(a[0], a[1], 'distinct hops -> distinct nullifiers')
  t.unlike(a[0], b[0], 'fresh SURB -> fresh nullifier (single-use tracking works)')
})

test('malformed input is rejected fail-closed', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 8)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const msg = sealReply(surb, b4a.from('m'))

  t.exception(
    () => processSurbHop({ ...msg, header: msg.header.subarray(0, 10) }, relays[0].routeSecretKey),
    'wrong-size header -> reject'
  )
  t.exception(
    () => processSurbHop({ ...msg, payload: b4a.alloc(4) }, relays[0].routeSecretKey),
    'payload below the box-seal minimum -> reject'
  )
})

test('replay guard rejects a re-processed SURB and admits fresh ones', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 11)
  const { surb } = buildSurb(pathOf(relays), terminalId)
  const guard = createNullifierGuard()

  const r1 = processSurbHop(sealReply(surb, b4a.from('once')), relays[0].routeSecretKey)
  t.ok(guard.admit(r1.nullifier), 'first sight of the nullifier is admitted')

  // Same SURB replayed to the same hop -> identical nullifier -> rejected.
  const r1again = processSurbHop(sealReply(surb, b4a.from('again')), relays[0].routeSecretKey)
  t.alike(r1again.nullifier, r1.nullifier, 'same SURB+hop -> same nullifier')
  t.absent(guard.admit(r1again.nullifier), 'replayed nullifier is rejected')

  const fresh = buildSurb(pathOf(relays), terminalId)
  const r2 = processSurbHop(sealReply(fresh.surb, b4a.from('new')), relays[0].routeSecretKey)
  t.ok(guard.admit(r2.nullifier), 'a fresh SURB is admitted')

  guard.reset()
  t.ok(guard.admit(r1.nullifier), 'after epoch reset the old nullifier is admissible again')
})

test('replay guard is fail-closed on overflow (no eviction, no silent re-admit)', (t) => {
  const guard = createNullifierGuard(4)
  const ns = []
  for (let i = 0; i < 4; i++) {
    const n = b4a.alloc(32, i)
    ns.push(n)
    t.ok(guard.admit(n), 'admit ' + i)
  }
  t.is(guard.size, 4, 'size at capacity')
  t.absent(
    guard.admit(ns[0]),
    'an already-seen nullifier stays a replay (false) — never re-admitted'
  )
  t.exception(
    () => guard.admit(b4a.alloc(32, 99)),
    'a fresh nullifier at capacity fails closed (throws) instead of evicting'
  )
  guard.reset()
  t.ok(guard.admit(ns[0]), 'after epoch reset the cache is clear')
})

test('fuzz: random path lengths and payload sizes round-trip', (t) => {
  for (let iter = 0; iter < 200; iter++) {
    const n = 1 + Math.floor(Math.random() * MAX_HOPS)
    const relays = []
    for (let i = 0; i < n; i++) relays.push(relay())
    const terminalId = b4a.allocUnsafeSlow(32)
    sodium.randombytes_buf(terminalId)
    const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)

    const size = Math.floor(Math.random() * (MAX_REPLY_BYTES + 1)) // 0..MAX_REPLY_BYTES
    const reply = b4a.allocUnsafeSlow(size)
    sodium.randombytes_buf(reply)

    let msg = sealReply(surb, reply)
    for (let i = 0; i < n; i++) {
      if (msg.header.byteLength !== RHO) t.fail('non-constant header at iter ' + iter)
      const r = processSurbHop(msg, relays[i].routeSecretKey)
      if (i < n - 1) msg = r.forward
      else if (!b4a.equals(openSurbPayload(r.forward.payload, openKeys), reply)) {
        t.fail('round-trip mismatch at iter ' + iter)
      }
    }
  }
  t.pass('200 random round-trips recovered exactly, header always RHO bytes')
})

test('fuzz: a single-byte flip anywhere in the message is rejected', (t) => {
  for (let iter = 0; iter < 200; iter++) {
    const relays = [relay(), relay(), relay()]
    const terminalId = b4a.alloc(32, 1)
    const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
    const base = sealReply(surb, b4a.from('fuzz-target-payload'))

    // Flip one random bit in header, mac, or payload, then drive the path; expect a reject
    // somewhere (processSurbHop or the final open) — never a wrong-but-accepted plaintext.
    const which = Math.floor(Math.random() * 3)
    const field = which === 0 ? 'header' : which === 1 ? 'mac' : 'payload'
    const msg0 = {
      ephem: b4a.from(base.ephem),
      header: b4a.from(base.header),
      mac: b4a.from(base.mac),
      payload: b4a.from(base.payload)
    }
    const buf = msg0[field]
    buf[Math.floor(Math.random() * buf.byteLength)] ^= 1 << Math.floor(Math.random() * 8)

    let rejected = false
    let recovered = null
    try {
      let msg = msg0
      for (let i = 0; i < relays.length; i++) {
        const r = processSurbHop(msg, relays[i].routeSecretKey)
        if (i < relays.length - 1) msg = r.forward
        else recovered = openSurbPayload(r.forward.payload, openKeys)
      }
    } catch {
      rejected = true
    }
    if (!rejected && !b4a.equals(recovered, b4a.from('fuzz-target-payload'))) {
      t.fail('tamper produced a wrong-but-accepted plaintext at iter ' + iter)
    }
  }
  t.pass('200 single-bit tampers each rejected or (payload-preserving) benign, never forged')
})

test('conformance vector — deterministic wire fields match the fixture byte-for-byte', (t) => {
  const fix = require('./fixtures/surb-vector-v1.json')
  const h2b = (s) => b4a.from(s, 'hex')
  const hex = (b) => b4a.toString(b, 'hex')

  const hops = fix.inputs.hops.map((h) => ({ id: h2b(h.id), routeKey: h2b(h.routeKey) }))
  const { surb } = buildSurb(hops, h2b(fix.inputs.terminalId), {
    ephemeralSeeds: fix.inputs.ephemeralSeeds.map(h2b),
    replySeed: h2b(fix.inputs.replySeed)
  })

  t.is(hex(surb.ephem), fix.outputs.ephem, 'E_1')
  t.is(surb.header.byteLength, RHO, 'header is RHO bytes')
  t.is(hex(surb.header), fix.outputs.header, 'full header bytes match fixture')
  t.is(hex(surb.mac), fix.outputs.mac, 'header MAC')
  t.is(hex(surb.replyPubKey), fix.outputs.replyPub, 'reply pubkey')

  // Walk the header with a fixed dummy payload — the payload path uses crypto_box_seal
  // (randomized) so its wire bytes are intentionally NOT part of the conformance fixture.
  const secrets = fix.inputs.hops.map((h) => h2b(h.routeSecretKey))
  let msg = { ephem: surb.ephem, header: surb.header, mac: surb.mac, payload: b4a.alloc(48) }
  for (let i = 0; i < fix.outputs.hops.length; i++) {
    const r = processSurbHop(msg, secrets[i])
    const exp = fix.outputs.hops[i]
    t.is(hex(r.nextHop), exp.nextHop, 'hop ' + i + ' nextHop')
    t.is(hex(r.nullifier), exp.nullifier, 'hop ' + i + ' nullifier')
    t.is(r.terminal, exp.terminal, 'hop ' + i + ' terminal flag')
    if (!r.terminal) {
      t.is(hex(r.forward.ephem), exp.nextEphem, 'hop ' + i + ' nextEphem')
      t.is(hex(r.forward.mac), exp.nextMac, 'hop ' + i + ' nextMac')
      msg = {
        ephem: r.forward.ephem,
        header: r.forward.header,
        mac: r.forward.mac,
        payload: b4a.alloc(48)
      }
    }
  }
})

test('reply payload budget is enforced', (t) => {
  const relays = [relay(), relay(), relay()]
  const { surb } = buildSurb(pathOf(relays), b4a.alloc(32, 1))
  t.execution(() => sealReply(surb, b4a.alloc(MAX_REPLY_BYTES)), 'max-size reply accepted')
  t.exception(() => sealReply(surb, b4a.alloc(MAX_REPLY_BYTES + 1)), 'oversize reply rejected')
})

test('filler sanity — header padding is not degenerate (WEAK proxy, not a stat review)', (t) => {
  // 1-hop SURB: most of beta is pad/filler. Sanity floor only — NOT a substitute for the
  // statistical indistinguishability review the spec still gates on.
  const { surb } = buildSurb(pathOf([relay()]), b4a.alloc(32, 1))
  const h = surb.header
  let zeros = 0
  let run = 0
  let maxRun = 0
  const hist = new Array(256).fill(0)
  for (let i = 0; i < h.byteLength; i++) {
    hist[h[i]]++
    if (h[i] === 0) {
      zeros++
      run++
      maxRun = Math.max(maxRun, run)
    } else {
      run = 0
    }
  }
  t.ok(maxRun < 16, 'no long zero run')
  t.ok(zeros < h.byteLength / 4, 'header is not mostly zeros')
  t.ok(hist.filter((c) => c > 0).length > 128, 'wide byte-value range')
})
