const test = require('brittle')
const path = require('path')
const fs = require('fs')
const os = require('os')
const { start } = require('..')

// Verifies the sidecar launcher logic — spawn the proxy, parse the SOCKS port it
// prints on stdout, and stop it — using a fake executable in place of the real
// arti-socks (which needs Tor network access to finish bootstrapping). The fake
// mimics the contract: print "<port>\n", then stay alive.
function fakeBinary(name, body) {
  const p = path.join(os.tmpdir(), name + '-' + process.pid + '.sh')
  fs.writeFileSync(p, '#!/bin/sh\n' + body + '\n', { mode: 0o755 })
  return p
}

test('start() parses the printed port and returns a working handle', async (t) => {
  const bin = fakeBinary('arti-ok', 'echo 41337\nwhile true; do sleep 1; done')

  const handle = await start({ bin, timeout: 5000 })
  t.is(handle.port, 41337, 'port parsed from stdout')
  t.is(handle.backend, 'sidecar')
  t.is(typeof handle.stop, 'function')

  handle.stop()
  fs.unlinkSync(bin)
})

test('start() rejects when the proxy exits before printing a port', async (t) => {
  const bin = fakeBinary('arti-die', 'exit 3')
  await t.exception(start({ bin, timeout: 5000 }), /exited early/)
  fs.unlinkSync(bin)
})

test('start() times out if no port is ever printed', async (t) => {
  const bin = fakeBinary('arti-hang', 'while true; do sleep 1; done')
  await t.exception(start({ bin, timeout: 500 }), /timed out/)
  fs.unlinkSync(bin)
})
