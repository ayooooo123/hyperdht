'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { PEER_MESSAGE_ID } = require('../../lib/private/peer-protocol')
const { encodePeerSemantic, decodePeerSemantic } = require('../../lib/private/peer-semantic-wire')
const {
  PRESENCE_CIRCUIT_LIMITS,
  PRESENCE_PARAMETERS_DIGEST,
  TOMBSTONE_SCOPE,
  derivePublicReaderSecret,
  lookupPresence,
  publishPresence,
  revokePresence
} = require('../../lib/private/peer-presence')
const {
  OVERLAP_MS,
  PERIOD_MS,
  deriveBlindedPublicKey,
  periodOf,
  publishPeriods
} = require('../../lib/private/blinded-presence')
const { nativeNetwork } = require('./peer-native-network')

// Presence stores need at least three DHT nodes beyond the terminal to take a write.
const NETWORK_SIZE = 8

function recordValue(revision, fill) {
  const value = b4a.alloc(895, fill)
  value[0] = 1
  for (let index = 4; index >= 1; index--, revision = Math.floor(revision / 256)) {
    value[index] = revision & 0xff
  }
  return value
}

test('presence messages round-trip at their exact sizes and reject malformed bodies', (t) => {
  const requestNonce = b4a.alloc(16, 0x11)
  const blindedPublicKey = b4a.alloc(32, 0x22)
  const signature = b4a.alloc(64, 0x33)
  const value = recordValue(7, 0x44)
  const cases = [
    [PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2, { requestNonce, blindedPublicKey }, 48],
    [
      PEER_MESSAGE_ID.PRESENCE_STORE_V2,
      { requestNonce, blindedPublicKey, revision: 7, signature, value },
      1011
    ],
    [PEER_MESSAGE_ID.PRESENCE_RECORD_V2, { requestNonce, revision: 7, signature, value }, 979],
    [PEER_MESSAGE_ID.PRESENCE_ABSENT_V2, { requestNonce }, 16],
    [
      PEER_MESSAGE_ID.PRESENCE_STORED_V2,
      { requestNonce, revision: 7, written: 5, confirmed: 3 },
      22
    ],
    [PEER_MESSAGE_ID.PRESENCE_UNAVAILABLE_V2, { requestNonce }, 16]
  ]
  for (const [messageId, fields, bodyBytes] of cases) {
    const wire = encodePeerSemantic(messageId, fields)
    t.is(wire.byteLength, 8 + bodyBytes, `0x${messageId.toString(16)} carries ${bodyBytes} bytes`)
    const decoded = decodePeerSemantic(wire)
    t.is(decoded.messageId, messageId)
    t.alike(decoded.fields, fields)
    t.exception(() => decodePeerSemantic(wire.subarray(0, wire.byteLength - 1)), /invalid/i)
  }
  const rejected = [
    [PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2, { requestNonce: b4a.alloc(16), blindedPublicKey }],
    [PEER_MESSAGE_ID.PRESENCE_LOOKUP_V2, { requestNonce, blindedPublicKey: b4a.alloc(32) }],
    [
      PEER_MESSAGE_ID.PRESENCE_STORE_V2,
      { requestNonce, blindedPublicKey, revision: 8, signature, value }
    ],
    [
      PEER_MESSAGE_ID.PRESENCE_RECORD_V2,
      {
        requestNonce,
        revision: 7,
        signature,
        value: b4a.concat([b4a.from([2]), value.subarray(1)])
      }
    ],
    [PEER_MESSAGE_ID.PRESENCE_STORED_V2, { requestNonce, revision: 7, written: 0, confirmed: 3 }],
    [PEER_MESSAGE_ID.PRESENCE_STORED_V2, { requestNonce, revision: 7, written: 3, confirmed: 0 }]
  ]
  for (const [messageId, fields] of rejected) {
    t.exception(() => encodePeerSemantic(messageId, fields), /invalid/i)
  }
})

test('the public reader secret and the presence parameters digest are fixed derivations', (t) => {
  const identity = cryptoSuite.keyPair()
  t.alike(
    derivePublicReaderSecret(identity.publicKey),
    derivePublicReaderSecret(identity.publicKey)
  )
  t.unlike(
    derivePublicReaderSecret(identity.publicKey),
    derivePublicReaderSecret(cryptoSuite.keyPair().publicKey)
  )
  t.exception(() => derivePublicReaderSecret(b4a.alloc(31)), /key/i)
  t.is(PRESENCE_PARAMETERS_DIGEST.byteLength, 32)
  t.is(PRESENCE_CIRCUIT_LIMITS.maxCells, 66, 'the 50-cell build minimum plus 16 attempts')
})

test(
  'a source publishes, resolves and revokes its presence through a native terminal',
  { timeout: 180_000 },
  async (t) => {
    const { topology, runtimes, source, arrived } = await nativeNetwork(t, {}, NETWORK_SIZE)
    const sends = []
    source.observeSendAttempts((event) => {
      if (event.kind === 'attempt') sends.push(event)
    })
    const identity = cryptoSuite.keyPair()
    const descriptor = b4a.from('a native presence descriptor the terminal never reads')

    const published = await publishPresence(source, {
      signerKeyPair: identity,
      descriptor,
      revision: 1
    })
    const periods = publishPeriods(Date.now())
    t.alike(
      published.map((record) => record.period),
      periods,
      'one record per publish period'
    )
    for (const record of published) {
      t.alike(record.blindedPublicKey, deriveBlindedPublicKey(identity.publicKey, record.period))
      t.is(record.revision, 1)
    }

    const found = await lookupPresence(source, { publicKey: identity.publicKey })
    t.is(found.present, true, 'the published descriptor resolves')
    t.alike(found.descriptor, descriptor)
    t.is(found.revision, 1)
    t.alike(found.recordDigest, published[0].recordDigest)

    // The terminal handled the blinded key and the sealed record only.
    const stored = await topology.testnet.nodes[NETWORK_SIZE - 1].mutableGet(
      published[0].blindedPublicKey
    )
    t.is(stored.seq, 1)
    t.is(stored.value.byteLength, 895, 'the DHT holds the sealed 895-byte record')
    t.is(b4a.indexOf(stored.value, descriptor), -1, 'the stored record hides the descriptor')
    t.is(b4a.indexOf(stored.value, identity.publicKey), -1, 'and the identity')

    const revoked = await revokePresence(source, {
      signerKeyPair: identity,
      revision: 2,
      scope: TOMBSTONE_SCOPE.PERIOD
    })
    t.is(revoked.length, periods.length)
    const absent = await lookupPresence(source, { publicKey: identity.publicKey, previous: found })
    t.is(absent.present, false, 'a period tombstone is an authenticated absence')
    t.is(absent.revision, 2)

    const unknown = await lookupPresence(source, { publicKey: cryptoSuite.keyPair().publicKey })
    t.is(unknown, null, 'an identity that never published resolves to nothing')

    const guardPort = topology.guard.node.dht.port
    t.ok(sends.length > 0, 'the source sent circuit traffic')
    t.ok(
      sends.every((event) => event.remote.port === guardPort),
      'the source sends only to its guard'
    )
    t.is(arrived.length, 0, 'the route owner never receives a presence circuit')
    const presence = runtimes.terminal.diagnostics().presence
    t.ok(presence.served >= 4, 'the terminal answered every operation')
    t.is(presence.refused, 0)
  }
)

test(
  'presence crosses a period boundary and an explicit period is read on its own',
  { timeout: 180_000 },
  async (t) => {
    const { source } = await nativeNetwork(t, {}, NETWORK_SIZE)
    const identity = cryptoSuite.keyPair()
    const descriptor = b4a.from('presence across the boundary')
    const current = periodOf(Date.now())
    const boundary = (current + 1n) * PERIOD_MS
    const beforeBoundary = Number(boundary - OVERLAP_MS / 2n)
    const afterBoundary = Number(boundary + OVERLAP_MS / 2n)

    const published = await publishPresence(source, {
      signerKeyPair: identity,
      descriptor,
      revision: 3,
      now: () => beforeBoundary
    })
    t.alike(
      published.map((record) => record.period),
      [current, current + 1n],
      'inside the overlap a record is published for both periods'
    )

    const next = await lookupPresence(source, {
      publicKey: identity.publicKey,
      now: () => afterBoundary
    })
    t.is(next.present, true)
    t.is(next.period, current + 1n, 'after the boundary the new period is read first')
    t.alike(next.descriptor, descriptor)

    const earlier = await lookupPresence(source, { publicKey: identity.publicKey, period: current })
    t.is(earlier.period, current, 'an explicit period is read on its own')
    t.alike(earlier.descriptor, descriptor)
  }
)

test(
  'a terminal without presence ends presence circuits and never hands them on',
  { timeout: 120_000 },
  async (t) => {
    const { runtimes, source, arrived } = await nativeNetwork(
      t,
      { terminal: (config) => ({ ...config, relay: { ...config.relay, presence: false } }) },
      NETWORK_SIZE
    )
    t.is(runtimes.terminal.diagnostics().presence, null, 'presence is disabled')
    await t.exception(
      lookupPresence(source, { publicKey: cryptoSuite.keyPair().publicKey }),
      /unavailable/i,
      'the lookup fails as unavailable'
    )
    t.is(arrived.length, 0, 'the route owner never receives the presence circuit')
  }
)
