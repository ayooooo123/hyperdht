'use strict'

const b4a = require('b4a')

const { BRANCH_CLASS } = require('../../lib/private/protocol')
const { clearRoutedRequest, decodeRoutedRequest } = require('../../lib/private/routed-dht')
const { TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER } = require('../../lib/private/live-route-authority')

class FakeRouteAuthority {
  constructor() {
    this.calls = {
      ready: 0,
      suspend: 0,
      resume: 0,
      destroy: 0,
      bootstrap: 0,
      closest: 0,
      request: 0,
      cancel: 0
    }
    this.lookup = []
    this.announce = []
    this.requests = []
    this.semanticEdges = []
    this.topologies = new Map()
    this.response = null
    this.requestHook = null
  }

  installTopology(branch, topology) {
    const referrals = new Map()
    for (const seed of topology.seeds) referrals.set(seed, seed)
    this.topologies.set(branch, { topology, referrals })
  }

  ready() {
    this.calls.ready++
  }

  suspend() {
    this.calls.suspend++
  }

  resume() {
    this.calls.resume++
  }

  destroy() {
    this.calls.destroy++
  }

  bootstrap(options) {
    this.calls.bootstrap++
    return Promise.resolve(this.#records(options))
  }

  closest(options) {
    this.calls.closest++
    return this.#records(options)
  }

  request(options) {
    this.calls.request++
    const copied = b4a.from(options.encodedRequest)
    const state = {
      branch: options.branch,
      destinationRef: b4a.from(options.destinationRef),
      encodedRequest: copied,
      attempt: options.attempt,
      operationDeadlineMs: options.operationDeadlineMs,
      cancelled: false,
      cancelReason: null
    }
    this.requests.push(state)

    if (this.requestHook !== null) {
      try {
        return this.requestHook(
          {
            branch: state.branch,
            destinationRef: state.destinationRef,
            encodedRequest: state.encodedRequest,
            attempt: state.attempt,
            operationDeadlineMs: state.operationDeadlineMs
          },
          state
        )
      } catch (error) {
        revoke(state)
        throw error
      }
    }

    if (this.topologies.has(options.branch)) {
      try {
        return this.#topologyRequest(state)
      } catch (error) {
        revoke(state)
        throw error
      }
    }

    return operation(Promise.resolve(this.response), state, this)
  }

  #records(options) {
    const installed = this.topologies.get(options.branch)
    if (installed !== undefined) {
      const topology = installed.topology
      return topology.seeds.slice(0, options.limit).map((index) => topology.records[index])
    }
    const records = options.branch === BRANCH_CLASS.LOOKUP ? this.lookup : this.announce
    return records.slice(0, options.limit)
  }

  #topologyRequest(state) {
    let routed = null
    try {
      routed = decodeRoutedRequest(state.encodedRequest)
      const installed = this.topologies.get(state.branch)
      const topology = installed.topology
      const index = topology.records.findIndex((record) =>
        b4a.equals(record.destinationRef, state.destinationRef)
      )
      if (index === -1) throw new Error('destination is outside the selected branch')

      const parent = installed.referrals.get(index)
      if (parent === undefined) throw new Error('destination was not referred by the topology')
      this.semanticEdges.push({
        branch: state.branch,
        fromId: b4a.from(topology.records[parent].id),
        toId: b4a.from(topology.records[index].id),
        commandId: routed.commandId,
        attempt: state.attempt
      })

      if (topology.pending && topology.pending.includes(index)) {
        return operation(new Promise(() => {}), state, this)
      }
      if (topology.retryOnce && topology.retryOnce.includes(index) && state.attempt === 1) {
        return operation(Promise.reject(new Error('deterministic retry')), state, this)
      }

      const closer = topology.closer[index].map((closer) => topology.records[closer])
      for (const closerIndex of topology.closer[index]) {
        if (!installed.referrals.has(closerIndex)) installed.referrals.set(closerIndex, index)
      }
      const response = {
        rtt: index + 1,
        from: topology.records[index],
        to: null,
        token: null,
        closerNodes: closer,
        error: 0,
        value: topology.values[index]
      }
      return operation(Promise.resolve(response), state, this)
    } finally {
      if (routed !== null) clearRoutedRequest(routed)
    }
  }
}

function operation(promise, state, authority) {
  return {
    promise: promise.then(
      (value) => {
        const authenticated = TEST_ONLY_LIVE_ROUTE_AUTHORITY_ISSUER.authenticateResponse(
          authority,
          state,
          value
        )
        revoke(state)
        return authenticated
      },
      (error) => {
        revoke(state)
        throw error
      }
    ),
    cancel: (reason) => {
      if (state.cancelled) return
      state.cancelled = true
      state.cancelReason = reason
      revoke(state)
      authority.calls.cancel++
    }
  }
}

function revoke(state) {
  state.encodedRequest.fill(0)
  state.destinationRef.fill(0)
}

module.exports = { FakeRouteAuthority }
