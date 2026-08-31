'use strict'

// Tiny UDP probe executed inside a role namespace by the namespace projection
// test. It exists so the test can prove reachability and unreachability with
// real datagrams instead of trusting the firewall readback.
//
//   namespace-probe.js send <bindHost> <bindPort> <host> <port> <hexPayload>
//   namespace-probe.js recv <bindHost> <bindPort> <timeoutMs>
//
// `recv` prints the first payload as hex and exits 0, or exits 3 on timeout.

const dgram = require('dgram')

const [mode, bindHost, bindPortText, ...rest] = process.argv.slice(2)
const bindPort = Number(bindPortText)

function fail(code) {
  process.stderr.write(`${code}\n`)
  process.exit(2)
}

if (mode !== 'send' && mode !== 'recv') fail('PROBE_MODE_INVALID')
if (!Number.isInteger(bindPort) || bindPort < 1 || bindPort > 65535) fail('PROBE_PORT_INVALID')

const socket = dgram.createSocket({ reuseAddr: false, type: 'udp4' })
socket.on('error', () => fail('PROBE_SOCKET_ERROR'))

if (mode === 'send') {
  const [host, portText, hex] = rest
  const port = Number(portText)
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail('PROBE_TARGET_INVALID')
  if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0)
    fail('PROBE_PAYLOAD_INVALID')
  const payload = Buffer.from(hex, 'hex')
  socket.bind(bindPort, bindHost, () => {
    socket.send(payload, port, host, (err) => {
      if (err) fail('PROBE_SEND_FAILED')
      socket.close(() => process.exit(0))
    })
  })
} else {
  const timeout = Number(rest[0])
  if (!Number.isInteger(timeout) || timeout < 1) fail('PROBE_TIMEOUT_INVALID')
  const timer = setTimeout(() => {
    socket.close(() => process.exit(3))
  }, timeout)
  socket.on('message', (message) => {
    clearTimeout(timer)
    process.stdout.write(message.toString('hex'))
    socket.close(() => process.exit(0))
  })
  socket.bind(bindPort, bindHost)
}
