'use strict'

const UDX = require('udx-native')

// Ported from the reviewed private-routes prototype at commit
// 0305df915b6a767093f9e75e6c06bc0a35da6169 and narrowed to Gate 3B1.

const UDX_SEND_DISPATCH = Symbol('udx-send-dispatch')
const UDX_LINK_OPEN = Symbol('udx-link-open')
const UDX_LINK_CLOSE = Symbol('udx-link-close')
const UDX_LINK_DESTROY_CIRCUIT = Symbol('udx-link-destroy-circuit')
const UDX_SEND_CELL = Symbol('udx-send-cell')
const UDX_TRY_SEND_CELL = Symbol('udx-try-send-cell')
const UDX_SEND_ACTOR_CONTROL = Symbol('udx-send-actor-control')
const UDX_LINK_STATS = Symbol('udx-link-stats')
const UDX_LINK_STREAM_PROGRESS = Symbol('udx-link-stream-progress')
const UDX_ENDPOINT_RESERVATION_STATS = Symbol('udx-endpoint-reservation-stats')
const TEST_ONLY_UDX_STREAM_COUNTER = Symbol('test-only-udx-stream-counter')

function selectUdxLoopbackHosts({ platform, forceDistinct = false } = {}) {
  if (platform !== 'linux' && platform !== 'darwin' && platform !== 'win32') {
    throw new TypeError('unsupported loopback platform')
  }
  return platform === 'darwin' && !forceDistinct
    ? ['127.0.0.1', '127.0.0.1']
    : ['127.0.0.1', '127.0.0.2']
}

class UdxAdapter {
  create() {
    return new UDX()
  }
}

module.exports = {
  UDX_SEND_DISPATCH,
  UDX_LINK_OPEN,
  UDX_LINK_CLOSE,
  UDX_LINK_DESTROY_CIRCUIT,
  UDX_SEND_CELL,
  UDX_TRY_SEND_CELL,
  UDX_SEND_ACTOR_CONTROL,
  UDX_LINK_STATS,
  UDX_LINK_STREAM_PROGRESS,
  UDX_ENDPOINT_RESERVATION_STATS,
  TEST_ONLY_UDX_STREAM_COUNTER,
  selectUdxLoopbackHosts,
  UdxAdapter
}
