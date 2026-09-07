'use strict'

const {
  consumeEndpointDhtExitOpenAuthority,
  consumeOpenRouteHandoff,
  destroyEndpointDhtExitOpenAuthority,
  destroyOpenRouteMaterial: destroyFinalExitOpenRouteMaterial,
  revokeOpenRouteHandoff
} = require('./final-exit-activation')
const { destroyOpenRouteTransport } = require('./live-route-authority')

function destroyOpenRouteMaterial(material) {
  try {
    destroyOpenRouteTransport(material)
  } catch {}
  return destroyFinalExitOpenRouteMaterial(material)
}

module.exports = {
  consumeEndpointDhtExitOpenAuthority,
  consumeOpenRouteHandoff,
  destroyEndpointDhtExitOpenAuthority,
  destroyOpenRouteMaterial,
  revokeOpenRouteHandoff
}
