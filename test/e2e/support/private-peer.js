'use strict'

const peer = require('../../../lib/private/private-peer-controller')

const {
  createAdvancingClock,
  createPrivatePeerTestScope
} = require('../../private/helpers/private-peer')

// Retain controller handles only for test fixture setup and fault targeting.
// Observation and protocol time belong to the settled controller-local scope.
function createScope() {
  const scope = createPrivatePeerTestScope()
  const controllers = new Map()
  return {
    controllers,
    create(factory, options = {}) {
      let controller
      const original = peer.createPrivatePeerController
      peer.createPrivatePeerController = function (...args) {
        controller = original.apply(this, args)
        return controller
      }
      try {
        const node = scope.create(factory, options)
        controllers.set(node, controller)
        return node
      } finally {
        peer.createPrivatePeerController = original
      }
    },
    guards(node) {
      return scope.guards(node)
    },
    close() {
      scope.close()
      controllers.clear()
    }
  }
}

module.exports = { createScope, createAdvancingClock }
