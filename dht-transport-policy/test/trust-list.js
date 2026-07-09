const test = require('brittle')
const b4a = require('b4a')
const id = require('hypercore-id-encoding')
const TrustList = require('../lib/trust-list')

const KEY_A = b4a.alloc(32, 1)
const KEY_B = b4a.alloc(32, 2)

test('add / has / remove', (t) => {
  const trust = new TrustList()
  t.absent(trust.has(KEY_A))
  trust.add(KEY_A, { alias: 'laptop' })
  t.ok(trust.has(KEY_A))
  t.is(trust.get(KEY_A).alias, 'laptop')
  t.is(trust.size, 1)
  t.ok(trust.remove(KEY_A))
  t.absent(trust.has(KEY_A))
  t.absent(trust.remove(KEY_A), 'removing a missing key returns false')
})

test('accepts hex, z-base-32, and buffer forms of the same key', (t) => {
  const trust = new TrustList()
  trust.add(KEY_A)
  t.ok(trust.has(KEY_A.toString('hex')), 'hex resolves to the same entry')
  t.ok(trust.has(id.encode(KEY_A)), 'z32 resolves to the same entry')
  t.is(trust.size, 1)
})

test('invalid keys never throw from has()', (t) => {
  const trust = new TrustList()
  t.absent(trust.has('not-a-key'))
  t.absent(trust.has(''))
})

test('emits update on change', (t) => {
  t.plan(3)
  const trust = new TrustList()
  trust.once('update', (e) => t.is(e.type, 'add'))
  trust.add(KEY_A)
  trust.once('update', (e) => t.is(e.type, 'remove'))
  trust.remove(KEY_A)
  trust.once('update', (e) => t.is(e.type, 'import'))
  trust.import([KEY_A, KEY_B])
})

test('import / toJSON / fromJSON round-trips', (t) => {
  const trust = new TrustList()
  trust.import([
    { publicKey: KEY_A, alias: 'laptop' },
    { id: id.encode(KEY_B), note: 'phone' }
  ])
  t.is(trust.size, 2)

  const json = trust.toJSON()
  t.is(json.length, 2)
  t.ok(
    json.every((e) => typeof e.id === 'string'),
    'ids serialise as strings'
  )

  const restored = TrustList.fromJSON(json)
  t.ok(restored.has(KEY_A) && restored.has(KEY_B))
  t.is(restored.get(KEY_A).alias, 'laptop')
  t.is(restored.get(KEY_B).note, 'phone')
})

test('constructor seeds silently (no update event)', (t) => {
  t.plan(1)
  const trust = new TrustList([KEY_A])
  trust.on('update', () => t.fail('should not emit while seeding'))
  t.ok(trust.has(KEY_A))
})
