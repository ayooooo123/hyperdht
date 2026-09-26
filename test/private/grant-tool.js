'use strict'

const test = require('brittle')
const b4a = require('b4a')

const { cryptoSuite } = require('../../lib/private/crypto-suite')
const { ROLE, roleForIdentity } = require('../../lib/private/protocol')
const { verifyTopologyGrantV1 } = require('../../lib/private/topology-grant')
const { GrantToolError, run } = require('../../lib/private/grant-tool')

function safetyIdentity(start) {
  for (let value = start; value < 256; value++) {
    const pair = cryptoSuite.keyPair(b4a.alloc(32, value))
    if (roleForIdentity(pair.publicKey) === ROLE.SAFETY) return pair
  }
  throw new Error('missing safety identity')
}

function operators() {
  const guard = safetyIdentity(20)
  const safety = safetyIdentity(60)
  const guardAuthority = cryptoSuite.keyPair()
  const files = {
    guard: b4a.toString(guardAuthority.secretKey, 'hex'),
    // A 32-byte seed file is accepted too.
    safety: b4a.toString(b4a.alloc(32, 0x42), 'hex')
  }
  const safetySeeded = cryptoSuite.keyPair(b4a.alloc(32, 0x42))
  const io = { readFile: (name) => files[name] }
  const draft = run(
    [
      'draft',
      ...['--local-identity', b4a.toString(guard.publicKey, 'hex')],
      ...['--local-role', 'safety-guard', '--local-host', '192.0.2.1', '--local-port', '41001'],
      ...[
        '--local-ops',
        'initiate',
        '--local-authority',
        b4a.toString(guardAuthority.publicKey, 'hex')
      ],
      ...['--peer-identity', b4a.toString(safety.publicKey, 'hex')],
      ...['--peer-role', 'safety-final', '--peer-host', '192.0.2.2', '--peer-port', '41002'],
      ...['--peer-ops', 'accept', '--peer-authority', b4a.toString(safetySeeded.publicKey, 'hex')],
      ...['--epoch', '7', '--run-id', '5a'.repeat(32)],
      ...['--not-before', '1000', '--expires', '9000']
    ],
    io
  )
  return { guard, safety, guardAuthority, safetySeeded, io, draft }
}

test('operators sign separately and assemble a grant each side admits', (t) => {
  const o = operators()
  const guardSignature = run(['sign', '--grant', o.draft, '--key', 'guard'], o.io)
  const safetySignature = run(['sign', '--grant', o.draft, '--key', 'safety'], o.io)
  // Either operator may assemble, with the signatures in any order.
  const one = run(
    ['assemble', '--grant', o.draft, '--signature', guardSignature, '--signature', safetySignature],
    o.io
  )
  const other = run(
    ['assemble', '--grant', o.draft, '--signature', safetySignature, '--signature', guardSignature],
    o.io
  )
  t.is(one, other)
  const grant = b4a.from(one, 'hex')
  t.ok(
    verifyTopologyGrantV1(grant, [o.guardAuthority.publicKey], {
      localIdentity32: o.guard.publicKey,
      now: 2000n
    })
  )
  t.ok(
    verifyTopologyGrantV1(grant, [o.safetySeeded.publicKey], {
      localIdentity32: o.safety.publicKey,
      now: 2000n
    })
  )
  const inspected = JSON.parse(run(['inspect', '--grant', one], o.io))
  t.is(inspected.signed, true)
  t.is(inspected.signaturesValid, true)
  t.is(JSON.parse(run(['inspect', '--grant', o.draft], o.io)).signed, false)
})

test('assemble refuses signatures that do not cover both authorities', (t) => {
  const o = operators()
  const guardSignature = run(['sign', '--grant', o.draft, '--key', 'guard'], o.io)
  t.exception(
    () =>
      run(
        [
          'assemble',
          '--grant',
          o.draft,
          '--signature',
          guardSignature,
          '--signature',
          guardSignature
        ],
        o.io
      ),
    GrantToolError
  )
  t.exception(
    () => run(['draft', '--local-role', 'relay'], o.io),
    GrantToolError,
    'unknown input is reported, not guessed'
  )
})
