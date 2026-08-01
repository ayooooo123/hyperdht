'use strict'

const {
  consumeOpenRouteHandoff,
  destroyOpenRouteMaterial,
  revokeOpenRouteHandoff
} = require('./final-exit-activation')

module.exports = {
  consumeOpenRouteHandoff,
  revokeOpenRouteHandoff,
  destroyOpenRouteMaterial
}
