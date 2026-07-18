'use strict'

const b4a = require('b4a')

const { BRANCH_CLASS } = require('../../lib/private/protocol')

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
    this.response = null
    this.requestHook = null
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
            attempt: state.attempt
          },
          state
        )
      } catch (error) {
        revoke(state)
        throw error
      }
    }

    const response = this.response
    return {
      promise: Promise.resolve(response).then((value) => {
        revoke(state)
        return value
      }),
      cancel: (reason) => {
        if (state.cancelled) return
        state.cancelled = true
        state.cancelReason = reason
        revoke(state)
        this.calls.cancel++
      }
    }
  }

  #records(options) {
    const records = options.branch === BRANCH_CLASS.LOOKUP ? this.lookup : this.announce
    return records.slice(0, options.limit)
  }
}

function revoke(state) {
  state.encodedRequest.fill(0)
  state.destinationRef.fill(0)
}

module.exports = { FakeRouteAuthority }
