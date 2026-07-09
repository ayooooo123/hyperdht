const test = require('brittle')
const b4a = require('b4a')
const { TrustList, TransportRouter } = require('..')

const KEY_A = b4a.alloc(32, 1)
const KEY_B = b4a.alloc(32, 2)

// A stub transport that records which keys it was asked to connect to.
function stub(label) {
  const calls = []
  return {
    calls,
    connect(publicKey, options) {
      calls.push(b4a.toString(publicKey, 'hex'))
      return { label, publicKey, options }
    }
  }
}

test('trusted peer -> direct, others -> masked (default policy)', (t) => {
  const trust = new TrustList([KEY_A])
  const direct = stub('direct')
  const masked = stub('masked')
  const router = new TransportRouter({ direct, masked, trust })

  t.is(router.mode(KEY_A), 'direct')
  t.is(router.mode(KEY_B), 'masked')

  t.is(router.connect(KEY_A).label, 'direct', 'trusted routes direct')
  t.is(router.connect(KEY_B).label, 'masked', 'untrusted routes masked')
  t.is(direct.calls.length, 1)
  t.is(masked.calls.length, 1)
})

test('flipped policy: direct by default, mask only listed peers', (t) => {
  const trust = new TrustList([KEY_B])
  const direct = stub('direct')
  const masked = stub('masked')
  const router = new TransportRouter({
    direct,
    masked,
    trust,
    defaultMode: 'direct',
    trustedMode: 'masked'
  })

  t.is(router.connect(KEY_A).label, 'direct')
  t.is(router.connect(KEY_B).label, 'masked')
})

test('describe() explains the decision for a UI', (t) => {
  const trust = new TrustList([{ publicKey: KEY_A, alias: 'laptop' }])
  const router = new TransportRouter({ direct: stub('d'), masked: stub('m'), trust })

  const a = router.describe(KEY_A)
  t.is(a.mode, 'direct')
  t.ok(a.trusted)
  t.is(a.entry.alias, 'laptop')

  const b = router.describe(KEY_B)
  t.is(b.mode, 'masked')
  t.absent(b.trusted)
  t.is(b.entry, null)
})

test('emits connection with the chosen mode', (t) => {
  t.plan(2)
  const trust = new TrustList([KEY_A])
  const router = new TransportRouter({ direct: stub('d'), masked: stub('m'), trust })
  const seen = []
  router.on('connection', (info) => seen.push(info.mode))
  router.connect(KEY_A)
  router.connect(KEY_B)
  t.alike(seen, ['direct', 'masked'])
  t.pass('connection events fired')
})

test('strict mode refuses to expose IP when no masked transport is configured', (t) => {
  const router = new TransportRouter({ direct: stub('d'), trust: new TrustList() })
  t.exception(() => router.connect(KEY_B), /no masked transport/)
})

test('non-strict falls back to direct when masked is absent', (t) => {
  const direct = stub('direct')
  const router = new TransportRouter({ direct, trust: new TrustList(), strict: false })
  t.is(router.connect(KEY_B).label, 'direct')
})

test('lazy masked factory resolves via ready()', async (t) => {
  const masked = stub('masked')
  let built = 0
  const router = new TransportRouter({
    direct: stub('direct'),
    masked: async () => {
      built++
      return masked
    },
    trust: new TrustList()
  })

  t.exception(() => router.connect(KEY_B), /call await router.ready/)
  await router.ready()
  t.is(built, 1)
  t.is(router.connect(KEY_B).label, 'masked')
})
