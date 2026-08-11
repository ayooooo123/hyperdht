'use strict'

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const {
  buildSurb,
  sealReply,
  processSurbHop,
  openSurbPayload,
  nullifierOf
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
function roundTrip(relays, terminalId, surb, openKeys, plaintext) {
  let msg = sealReply(surb, plaintext)
  const nullifiers = []
  for (let i = 0; i < relays.length; i++) {
    const r = processSurbHop(msg, relays[i].routeSecretKey)
    nullifiers.push(r.nullifier)
    const expectedNext = i < relays.length - 1 ? relays[i + 1].id : terminalId
    if (!b4a.equals(r.nextHop, expectedNext)) throw new Error('wrong nextHop at hop ' + i)
    if (i < relays.length - 1) {
      if (r.terminal) throw new Error('early terminal at hop ' + i)
      msg = r.forward
    } else {
      if (!r.terminal) throw new Error('missing terminal at last hop')
      return {
        plaintext: openSurbPayload(r.forward.payload, openKeys),
        nullifiers,
        lastPayload: r.forward.payload
      }
    }
  }
}

test('surb round-trip through 3 hops recovers the reply', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 7)
  const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)

  const reply = b4a.from('hello from the responder, only the initiator reads this')
  const out = roundTrip(relays, terminalId, surb, openKeys, reply)
  t.alike(out.plaintext, reply, 'initiator recovers the exact plaintext')
})

test('single-hop path works', (t) => {
  const relays = [relay()]
  const terminalId = b4a.alloc(32, 3)
  const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
  const reply = b4a.from('one hop')
  const out = roundTrip(relays, terminalId, surb, openKeys, reply)
  t.alike(out.plaintext, reply)
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
  // Hop 1 cannot process as if it were a later hop: it holds no key for E_2's layer.
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

test('tampered payload is rejected at open', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 4)
  const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
  let msg = sealReply(surb, b4a.from('z'))
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

test('nullifiers are deterministic per hop and distinct across hops', (t) => {
  const relays = [relay(), relay(), relay()]
  const terminalId = b4a.alloc(32, 6)
  const { surb, openKeys } = buildSurb(pathOf(relays), terminalId)
  const a = roundTrip(relays, terminalId, surb, openKeys, b4a.from('a')).nullifiers

  // Rebuild a fresh SURB over the SAME relays: fresh ephemerals -> different nullifiers.
  const built2 = buildSurb(pathOf(relays), terminalId)
  const b = roundTrip(relays, terminalId, built2.surb, built2.openKeys, b4a.from('b')).nullifiers

  t.is(a.length, 3)
  t.unlike(a[0], a[1], 'distinct hops -> distinct nullifiers')
  t.unlike(a[0], b[0], 'fresh SURB -> fresh nullifier (single-use tracking works)')
})
