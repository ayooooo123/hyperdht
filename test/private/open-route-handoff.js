'use strict'

const test = require('brittle')

const { PrivateRouteError } = require('../../lib/private/errors')
const openRouteHandoff = require('../../lib/private/open-route-handoff')

function expectCode(t, operation, code, message) {
  let error = null
  try {
    operation()
  } catch (err) {
    error = err
  }
  t.ok(error instanceof PrivateRouteError, message)
  t.is(error && error.code, code, message)
}

test('open-route handoff deep import exposes no issuer surface', (t) => {
  t.alike(Object.keys(openRouteHandoff).sort(), [
    'consumeEndpointDhtExitOpenAuthority',
    'consumeOpenRouteHandoff',
    'destroyEndpointDhtExitOpenAuthority',
    'destroyOpenRouteMaterial',
    'revokeOpenRouteHandoff'
  ])
  t.absent(openRouteHandoff.createOpenRouteHandoff)
  t.absent(openRouteHandoff.issueOpenRouteHandoff)
})

test('open-route handoff rejects arbitrary and replayed external handles', (t) => {
  const handoff = Object.freeze({})
  expectCode(
    t,
    () => openRouteHandoff.consumeOpenRouteHandoff(handoff),
    'ERR_AUTHENTICATION',
    'arbitrary handoff cannot be consumed'
  )
  t.is(openRouteHandoff.revokeOpenRouteHandoff(handoff), false, 'arbitrary handoff revoke is inert')
  t.is(openRouteHandoff.destroyOpenRouteMaterial(null), false, 'non-material destroy is inert')
})
