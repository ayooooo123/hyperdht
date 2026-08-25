'use strict'

const UDX = require('udx-native')

const { BOOTSTRAP_SIZE } = require('../../../lib/private/bootstrap-envelope')
const { CELL_CLASS, PROTOCOL_VERSION } = require('../../../lib/private/protocol')
const endpointModule = require('../../../lib/private/udx-cell-endpoint')

const { TEST_ONLY_UDX_ADAPTER_ISSUER } = endpointModule
const issuer = endpointModule[TEST_ONLY_UDX_ADAPTER_ISSUER]

// Silent death: a hop that stops relaying without any party forming the intent to say so.
// The two existing fault verbs cannot express it, because both are local destroys that
// produce exactly the clean `BRANCH_DESTROY` the branch-liveness design exists to survive
// the absence of. Dropping has to happen below the M3 install, because the install replaces
// the taken issuer with its own transfer object, so a flag on the pre-install physical
// channel is bypassed - the same reason destroying the issuer is a no-op in
// `faultOutgoingPhysicalLink`. The lowest seam a test may hold is the UDX adapter, which is
// consulted once at endpoint construction, so the adapter is installed for every role from
// start and carries a flag that is read per datagram when the verb arrives later.

// Classification needs no key material, because the two byte positions that separate a
// route cell from everything else on this socket are cleartext framing. A cell writes
// `header[0] = PROTOCOL_VERSION` and `header[1] = cellClass` (`cell-codec.js`, the only
// writer of those two bytes for cells); a bootstrap envelope writes `packet[1] =
// BOOTSTRAP_CLASS` (0x80, `bootstrap-envelope.js`); a direct caps request writes 0xd3 to
// byte 0 (`isAuthenticatedCapsRequestPacket`, `udx-cell-endpoint.js`). So only route cells
// are dropped: link bootstrap, guard setup and DHT traffic still flow, which is what makes
// this a dead relay rather than a dead host that would also stop answering the harness.
function isRouteCellDatagram(packet) {
  if (packet === null || typeof packet !== 'object' || packet.byteLength !== BOOTSTRAP_SIZE) {
    return false
  }
  if (packet[0] !== PROTOCOL_VERSION) return false
  const cellClass = packet[1]
  return (
    cellClass === CELL_CLASS.CONTROL ||
    cellClass === CELL_CLASS.STREAM ||
    cellClass === CELL_CLASS.DATAGRAM
  )
}

let armed = false
let installedSockets = 0
let droppedInbound = 0
let droppedOutbound = 0

// `UdxCellEndpoint` reaches for exactly `bind`, `send`, `close`, `on` and `off`/
// `removeListener`, and it is the sole consumer of the socket it constructs. `address` is
// delegated too so a caller can still read where the socket is bound, which is how the
// verb's central negative property - still bound, nothing destroyed - is checked. Nothing
// is added, so an unarmed adapter is the real socket plus one boolean test per datagram.
function createRouteCellDroppingSocket(socket) {
  const wrappers = new Map()
  const facade = {
    address() {
      return socket.address()
    },
    bind(port, host) {
      return socket.bind(port, host)
    },
    send(packet, port, host) {
      if (!armed || !isRouteCellDatagram(packet)) return socket.send(packet, port, host)
      droppedOutbound++
      // A dropped datagram must look delivered to its sender. UDP reports nothing, and
      // `pump` in `udx-cell-endpoint.js` treats any resolution other than `true` as a send
      // failure, which reaches `reportOwnedRouteFailure` and reports a branch loss - a
      // detected failure, the opposite of what this verb produces.
      return Promise.resolve(true)
    },
    close() {
      return socket.close()
    },
    on(event, listener) {
      if (event !== 'message' || typeof listener !== 'function') {
        socket.on(event, listener)
        return facade
      }
      const wrapper = (packet, from) => {
        if (armed && isRouteCellDatagram(packet)) {
          droppedInbound++
          return
        }
        listener(packet, from)
      }
      wrappers.set(listener, wrapper)
      socket.on(event, wrapper)
      return facade
    },
    off(event, listener) {
      const wrapper = wrappers.get(listener)
      if (wrapper === undefined) socket.off(event, listener)
      else {
        wrappers.delete(listener)
        socket.off(event, wrapper)
      }
      return facade
    }
  }
  facade.removeListener = facade.off
  return facade
}

// `createUdxCellEndpointForTest` calls this once for the endpoint under construction and
// retains it as the `freshAdapterFactory` the endpoint uses to mint sibling endpoints, so it
// must be callable repeatedly and every adapter it yields must read the one shared flag.
function routeCellBlackholeAdapterFactory() {
  return {
    create() {
      const udx = new UDX()
      return {
        createSocket() {
          installedSockets++
          return createRouteCellDroppingSocket(udx.createSocket())
        }
      }
    }
  }
}

// Drop-in for `new UdxCellEndpoint(options)`: same options, same class, one adapter seam.
function createProjectedCellEndpoint(options) {
  return issuer.createUdxCellEndpointForTest(
    options,
    issuer.createTestUdxAdapterAuthority(routeCellBlackholeAdapterFactory)
  )
}

// The verb. Nothing is destroyed, nothing is closed, no socket is unbound and no local
// object is released - the only state change in the process is this flag. Returns false on
// replay and false when there is no socket to blackhole, so a role that reports success has
// actually gone dark.
function blackholeRouteCells() {
  if (armed || installedSockets === 0) return false
  armed = true
  return true
}

function routeCellBlackholeSnapshot() {
  return Object.freeze({ armed, droppedInbound, droppedOutbound, sockets: installedSockets })
}
function resetRouteCellBlackholeForTest() {
  armed = false
  installedSockets = 0
  droppedInbound = 0
  droppedOutbound = 0
}

module.exports = {
  blackholeRouteCells,
  createProjectedCellEndpoint,
  isRouteCellDatagram,
  resetRouteCellBlackholeForTest,
  routeCellBlackholeAdapterFactory,
  routeCellBlackholeSnapshot
}
