'use strict'

// Drives role-bridge.js's punch round directly, against a plan that is part real and
// part black hole, and prints what it reports for each.
//
//   node test/remote-peer/punch-report-probe.js
//
// Why this exists. A rehearsal on loopback answers every punch, so it exercises only
// the success path: three container runs reported `punch matrix 140/140 directed pairs
// arrived, 0 silent`. The line that matters when a real dispatch goes wrong is the
// other one, and nothing local was reaching it. This provokes both in one run so the
// unanswered reporting is observed rather than assumed from reading the source.
//
// What it does NOT do: prove anything about NAT traversal. There is no NAT here. It
// proves that a socket which never answers is named, as a directed pair, with the
// peer index and which of its two sockets stayed silent.

const UDX = require('udx-native')
const b4a = require('b4a')
const { PUNCH_KIND, PUNCH_TAG, PUNCH_BYTES, runPunchPhase } = require('./role-bridge')

// A port nothing binds. Chosen high and fixed so a failure to punch it is a real
// black hole rather than a port some other test happened to take.
const BLACK_HOLE_PORT = 42_099
const SELF_INDEX = 1
const SELF_CELL_PORT = 42_071
const PEER_INDEX = 2
const PEER_CELL_PORT = 42_072
const SILENT_INDEX = 3

function ok(label, actual, expected) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected)
  console.log(`${pass ? 'ok' : 'NOT OK'} - ${label}: ${JSON.stringify(actual)}`)
  return pass
}

async function main() {
  const udx = new UDX()

  // One real peer, which answers by punching back the moment it hears anything. That
  // mutual send is what a live peer does, so its arrival is what the report should
  // count as heard.
  const peer = udx.createSocket()
  const peerPayload = b4a.concat([PUNCH_TAG, b4a.from([PEER_INDEX, PUNCH_KIND.CELL])])
  let peerHeard = 0
  peer.on('message', (message, from) => {
    if (message.byteLength !== PUNCH_BYTES) return
    if (!b4a.equals(message.subarray(0, PUNCH_TAG.byteLength), PUNCH_TAG)) return
    peerHeard++
    try {
      peer.send(peerPayload, from.port, from.host)
    } catch {}
  })
  const peerBind = peer.bind(PEER_CELL_PORT)
  if (peerBind && typeof peerBind.then === 'function') await peerBind

  // Role 2 is real and answers. Role 3 is a black hole: an address in the plan that
  // nothing is listening on, which is exactly what an unreachable runner looks like
  // from here.
  const plan = {
    [SELF_INDEX]: { host: '127.0.0.1', cellPort: SELF_CELL_PORT },
    [PEER_INDEX]: { host: '127.0.0.1', cellPort: PEER_CELL_PORT },
    [SILENT_INDEX]: {
      host: '127.0.0.1',
      cellPort: BLACK_HOLE_PORT,
      dhtHost: '127.0.0.1',
      dhtPort: BLACK_HOLE_PORT + 1
    }
  }

  const report = await runPunchPhase({
    plan,
    index: SELF_INDEX,
    cellPort: SELF_CELL_PORT,
    exitPort: null,
    udx
  })
  await peer.close()

  console.log(JSON.stringify(report, null, 2))

  let passed = true
  // The role's own sockets are never punched, and the black hole contributes two
  // targets, so three of the four plan sockets are addressed.
  passed = ok('targets addressed', report.targets, 3) && passed
  passed = ok('punched from its own cell port', report.from, [`cell:${SELF_CELL_PORT}`]) && passed
  passed = ok('a peer that answers is named as heard', report.heardFrom, ['2/cell']) && passed
  // The whole point: one line names both black-holed sockets as directed pairs.
  passed =
    ok('a peer that never answers is named', report.silent, ['3/cell', '3/exit-dht']) && passed
  passed = ok('every send left the socket', report.refused, 0) && passed
  passed = ok('the role port re-bound for the punch', report.bindErrors, []) && passed
  passed = ok('the peer really did hear the punches', peerHeard > 0, true) && passed

  // The port must be free again, or the role process could not bind it after the
  // punch. This is the claim the whole design rests on and it is cheap to check.
  const after = udx.createSocket()
  let rebound = true
  try {
    const bind = after.bind(SELF_CELL_PORT)
    if (bind && typeof bind.then === 'function') await bind
  } catch {
    rebound = false
  }
  await after.close()
  passed = ok('the punch probe released the role port', rebound, true) && passed

  console.log(passed ? '\n# ok - punch reporting names both outcomes' : '\n# NOT OK')
  process.exit(passed ? 0 : 1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
