'use strict'

const { createAdvancingClock, isAdvancingClock } = require('./advancing-clock')
const b4a = require('b4a')
const peer = require('../../../lib/private/private-peer-controller')

function guardSnapshot(guard, role) {
  if (!guard) return null
  return Object.freeze({
    role,
    publicKey: b4a.from(guard.publicKey),
    diversityKey: guard.diversityKey || null
  })
}

function guardSetSnapshot(guards, role) {
  return Object.freeze({
    current: guardSnapshot(guards && guards.current, role),
    alternates: Object.freeze(
      guards ? guards.alternates.map((guard) => guardSnapshot(guard, role)) : []
    )
  })
}

function createPrivatePeerTestScope() {
  const controllers = new Map()
  let closed = false

  function assertOpen() {
    if (closed) throw new Error('Private peer test scope is closed')
  }

  return Object.freeze({
    create(createNode, { observer = null, clock, spliced, controlLimits } = {}) {
      assertOpen()
      if (
        typeof createNode !== 'function' ||
        (observer !== null && typeof observer !== 'function')
      ) {
        throw new TypeError('Invalid private peer test factory or observer')
      }
      if (clock !== undefined && !isAdvancingClock(clock)) {
        throw new TypeError('Test scope requires a clock created by createAdvancingClock')
      }
      const original = peer.createPrivatePeerController
      const captured = []
      const observe =
        observer === null
          ? null
          : (event) => {
              if (closed) return
              try {
                const result = observer(event)
                if (result && typeof result.then === 'function')
                  Promise.resolve(result).catch(() => {})
              } catch {}
            }
      peer.createPrivatePeerController = (options) => {
        const controller = original({
          ...options,
          observer: observe,
          clock,
          spliced,
          controlLimits
        })
        captured.push(controller)
        return controller
      }
      let node
      try {
        node = createNode()
        if (
          !node ||
          typeof node.then === 'function' ||
          captured.length !== 1 ||
          captured[0].dht !== node
        ) {
          throw new TypeError(
            'Test scope factory must synchronously create exactly one private DHT node'
          )
        }
        controllers.set(node, { controller: captured[0], observer: observe })
        return node
      } catch (error) {
        for (const controller of captured) {
          if (controller.observer === observe) controller.observer = null
        }
        throw error
      } finally {
        peer.createPrivatePeerController = original
      }
    },

    guards(node) {
      assertOpen()
      const captured = controllers.get(node)
      if (!captured) throw new TypeError('Node does not belong to this private peer test scope')
      const { controller } = captured
      const destinations = []
      for (const server of controller.servers) {
        if (server.closed || !server.publicKey) continue
        destinations.push(
          Object.freeze({
            publicKey: b4a.from(server.publicKey),
            ...guardSetSnapshot(server._guards, 'destination-guard')
          })
        )
      }
      return Object.freeze({
        source: guardSetSnapshot(controller.sourceGuards, 'source-safety'),
        destinations: Object.freeze(destinations)
      })
    },

    close() {
      if (closed) return
      closed = true
      for (const { controller, observer } of controllers.values()) {
        if (controller.observer === observer) controller.observer = null
      }
      controllers.clear()
    }
  })
}

module.exports = { createAdvancingClock, createPrivatePeerTestScope }
