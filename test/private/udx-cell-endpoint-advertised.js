'use strict'

// An endpoint behind a translation binds one address and is reached at another. The
// ownership check on a link handle compares against the advertised pair, because
// that is what a signed capability names; comparing against the bound pair rejects
// every link on such a host, which is KI-7.

const test = require('brittle')

const { UdxCellEndpoint } = require('../../lib/private/udx-cell-endpoint')

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
