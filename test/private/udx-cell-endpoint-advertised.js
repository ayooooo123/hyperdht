'use strict'

// An endpoint behind a translation binds one address and is reached at another. The
// ownership check on a link handle compares against the advertised pair, because
// that is what a signed capability names; comparing against the bound pair rejects
// every link on such a host, which is KI-7.

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { LinkDirectory, signTopologyGrant } = require('../../lib/private/topology-grant')
const {
  LINK_OPERATION,
  PROTOCOL_VERSION,
  ROLE,
  TOPOLOGY_ROLE,
  roleForIdentity
} = require('../../lib/private/protocol')
const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')

const seed = (value) => b4a.alloc(32, value)

function safetyIdentity(start = 100) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(seed(value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

// A handle carrying the local address a signed grant names, which is what a role
// behind a translation publishes. Mirrors the helper in udx-cell-endpoint.js.
function acceptHandleFor(localHost, localPort, peerHost, peerPort) {
  const authority = cryptoSuite.keyPair(seed(90))
  const initiator = cryptoSuite.keyPair(seed(91))
  const accepter = safetyIdentity(92)
  const runId32 = seed(93)
  const grant = signTopologyGrant(
    {
      version: PROTOCOL_VERSION,
      format: 0,
      grantId32: seed(94),
      endpointA: {
        identity32: initiator.publicKey,
        role: TOPOLOGY_ROLE.SOURCE,
        host: peerHost,
        port: peerPort,
        operations: LINK_OPERATION.INITIATE
      },
      endpointB: {
        identity32: accepter.publicKey,
        role: TOPOLOGY_ROLE.SAFETY_GUARD,
        host: localHost,
        port: localPort,
        operations: LINK_OPERATION.ACCEPT
      },
      epoch: 7n,
      notBefore: 0n,
      expiresAt: 60_000n,
      runId32
    },
    authority.secretKey
  )
  const directory = new LinkDirectory({
    localIdentity32: accepter.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    authorityPublicKey: authority.publicKey,
    epoch: 7n,
    runId32,
    now: () => 1n,
    // No timers: this helper only needs a handle, and a pending expiry would keep
    // the test process alive after the assertions.
    schedule: () => null,
    cancel: () => {},
    onClose() {}
  })
  const digest32 = directory.add(grant)
  const handle = directory.authorize({
    digest32,
    operation: LINK_OPERATION.ACCEPT,
    localIdentity32: accepter.publicKey,
    localRole: TOPOLOGY_ROLE.SAFETY_GUARD,
    peerIdentity32: initiator.publicKey,
    peerRole: TOPOLOGY_ROLE.SOURCE,
    epoch: 7n,
    runId32
  })
  return { directory, handle }
}

function options(extra = {}) {
  return {
    host: '127.0.0.1',
    port: 42501,
    onBootstrap() {},
    onCell() {},
    onLinkFailure() {},
    ...extra
  }
}

function refuses(t, extra, message) {
  let threw = false
  let endpoint = null
  try {
    endpoint = new UdxCellEndpoint(options(extra))
  } catch {
    threw = true
  }
  if (endpoint && typeof endpoint.close === 'function') void endpoint.close()
  t.ok(threw, message)
}

test('an advertised address is optional and stated as a pair', async (t) => {
  const bound = new UdxCellEndpoint(options())
  t.ok(bound, 'an endpoint that binds what it advertises is unchanged')
  await bound.close()

  const translated = new UdxCellEndpoint(
    options({ advertisedHost: '203.0.113.7', advertisedPort: 51000 })
  )
  t.ok(translated, 'an endpoint may state the address peers reach it at')
  await translated.close()

  refuses(t, { advertisedHost: '203.0.113.7' }, 'a host without a port is refused')
  refuses(t, { advertisedPort: 51000 }, 'a port without a host is refused')
  refuses(
    t,
    { advertisedHost: 'example.com', advertisedPort: 51000 },
    'a name instead of an address is refused'
  )
  refuses(t, { advertisedHost: '203.0.113.7', advertisedPort: 0 }, 'port zero is refused')
  refuses(
    t,
    { advertisedHost: '203.0.113.7', advertisedPort: 65536 },
    'a port above 65535 is refused'
  )
})

test('openLink judges ownership by the advertised address', async (t) => {
  // Bound where this host can bind, published where peers reach it.
  const endpoint = new UdxCellEndpoint(
    options({
      host: '127.0.0.1',
      port: 42601,
      advertisedHost: '203.0.113.7',
      advertisedPort: 51601
    })
  )
  await endpoint.bind()

  // Session options here are deliberately minimal, so a handle that passes the
  // ownership check fails later on those instead. The two codes are what separate
  // "not this endpoint's link" from "accepted, then rejected for another reason".
  const codeFor = (handle) => {
    try {
      endpoint.openLink(handle, { mode: 'accept' })
      return null
    } catch (err) {
      return err && err.code
    }
  }

  const advertised = acceptHandleFor('203.0.113.7', 51601, '203.0.113.9', 51609)
  t.is(
    codeFor(advertised.handle),
    'INVALID_ROUTE',
    'a handle naming the advertised address passes the ownership check'
  )

  const bound = acceptHandleFor('127.0.0.1', 42601, '203.0.113.9', 51610)
  t.is(
    codeFor(bound.handle),
    'UNAUTHORIZED',
    "a handle naming the bound address is not this endpoint's link"
  )

  await endpoint.close()
})
