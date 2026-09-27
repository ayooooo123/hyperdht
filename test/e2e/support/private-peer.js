'use strict'

const fs = require('fs')
const path = require('path')
const peer = require('../../../lib/private/private-peer-controller')

const seamPath = path.join(__dirname, '../../private/helpers/private-peer.js')
const seam = fs.existsSync(seamPath) ? require(seamPath) : null

// The baseline capture is confined to tests so the same intended-contract tests
// can demonstrate failures before B1 adds its scoped observation entry point.
function createScope() {
  const scope = seam ? seam.createPrivatePeerTestScope() : null
  const controllers = new Map()
  return {
    controllers,
    hasSeam: scope !== null,
    create(factory, options = {}) {
      let controller
      const original = peer.createPrivatePeerController
      peer.createPrivatePeerController = function (config) {
        controller = original(config)
        if (!scope && options.observer)
          controller.observer = (event) => {
            options.observer(event)
            return undefined
          }
        return controller
      }
      try {
        const node = scope ? scope.create(factory, options) : factory()
        controllers.set(node, controller)
        return node
      } finally {
        peer.createPrivatePeerController = original
      }
    },
    guards(node) {
      if (!scope) throw new Error('B1 read-only pinned-guard seam is not installed')
      return scope.guards(node)
    },
    close() {
      if (scope) scope.close()
      for (const controller of controllers.values()) {
        if (controller && Object.hasOwn(controller, 'observer')) controller.observer = null
      }
    }
  }
}

function createAdvancingClock(options) {
  if (!seam) throw new Error('B1 scoped advancing clock is not installed; E4 requires it')
  return seam.createAdvancingClock(options)
}

module.exports = { createScope, createAdvancingClock, hasClock: seam !== null }
