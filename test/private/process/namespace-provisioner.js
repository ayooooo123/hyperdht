'use strict'

// Realizes the `namespaceProjection()` contract from `topology-fixture.js` as
// real Linux network namespaces. Every role gets its own namespace, its own
// veth pair, and routes only to the peers named by `ALLOW_EDGES`. Forwarding
// between the namespaces happens in the root namespace under a dedicated
// iptables chain that ends in DROP for our own devices, so a packet between two
// non-adjacent roles is not merely unasserted, it has no path.
//
// This is privileged test infrastructure. It requires Linux and non-interactive
// root, it mutates root-namespace network state, and it always tears that state
// down. It is never loaded by the portable suites.

const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const IFNAME_MAX = 15
const ROLE_COUNT = 11

class NamespaceProvisionError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code)
    this.code = code
    this.name = 'NamespaceProvisionError'
  }
}

function invalid(detail) {
  throw new NamespaceProvisionError('NAMESPACE_PROVISION_INVALID', detail)
}

function run(argv, options = {}) {
  try {
    return execFileSync('sudo', ['-n', ...argv], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      ...options
    })
  } catch (err) {
    if (options.tolerate === true) return null
    const stderr = err && err.stderr ? String(err.stderr).trim() : ''
    throw new NamespaceProvisionError('NAMESPACE_COMMAND_FAILED', `${argv.join(' ')} :: ${stderr}`)
  }
}

function tolerate(argv) {
  return run(argv, { tolerate: true })
}

// A provisioner is only ever handed projection data that
// `validateNamespaceProjection` already accepted, but these run as root, so
// every interpolated field is re-checked against a strict shape here too.
const HOST = /^(?:\d{1,3}\.){3}\d{1,3}$/
const CIDR = /^(?:\d{1,3}\.){3}\d{1,3}\/32$/
const DEVICE = /^pr-veth-(?:\d{1,2}|auditor|decoy)$/

function checkHost(value) {
  if (typeof value !== 'string' || !HOST.test(value)) invalid(`host ${String(value)}`)
  for (const part of value.split('.')) {
    const octet = Number(part)
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) invalid(`host ${value}`)
  }
  return value
}

function checkCidr(value) {
  if (typeof value !== 'string' || !CIDR.test(value)) invalid(`cidr ${String(value)}`)
  checkHost(value.slice(0, -3))
  return value
}

function checkDevice(value) {
  if (typeof value !== 'string' || !DEVICE.test(value)) invalid(`device ${String(value)}`)
  return value
}

function checkPort(value) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) invalid(`port ${String(value)}`)
  return String(value)
}

function checkSuffix(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{4}$/.test(value)) invalid(`suffix ${String(value)}`)
  return value
}

function createNames(suffix) {
  checkSuffix(suffix)
  const chain = `PR-FWD-${suffix.toUpperCase()}`
  const prefix = `pr-rt-${suffix}-`
  const namespace = (key) => `pr-ns-${suffix}-${key}`
  const rootDevice = (key) => {
    const name = `${prefix}${key}`
    if (name.length > IFNAME_MAX) invalid(`root device ${name}`)
    return name
  }
  return { chain, namespace, prefix, rootDevice }
}

// `pr-veth-3` -> `3`, `pr-veth-auditor` -> `a`. The projection names devices by
// their in-namespace identity; the root side needs globally unique short names.
function deviceKey(device) {
  const tail = checkDevice(device).slice('pr-veth-'.length)
  if (tail === 'auditor') return 'a'
  if (tail === 'decoy') return 'd'
  return tail
}

function gatewayFor(host) {
  const parts = checkHost(host).split('.')
  return `${parts[0]}.${parts[1]}.${parts[2]}.1`
}

function attachEndpoint(names, spec) {
  const key = deviceKey(spec.device)
  const ns = names.namespace(key)
  const rootDevice = names.rootDevice(key)
  const host = checkHost(spec.host)
  const gateway = checkHost(spec.gateway)
  const prefix = Number.isInteger(spec.prefix) ? spec.prefix : 24
  if (prefix < 8 || prefix > 30) invalid(`prefix ${String(spec.prefix)}`)
  if (gateway !== gatewayFor(host)) invalid(`gateway ${gateway} does not serve ${host}`)

  run(['ip', 'netns', 'add', ns])
  run(['ip', 'link', 'add', rootDevice, 'type', 'veth', 'peer', 'name', spec.device, 'netns', ns])
  run(['ip', 'addr', 'add', `${gateway}/${prefix}`, 'dev', rootDevice])
  run(['ip', 'link', 'set', rootDevice, 'up'])
  run(['ip', '-n', ns, 'addr', 'add', `${host}/${prefix}`, 'dev', spec.device])
  run(['ip', '-n', ns, 'link', 'set', spec.device, 'up'])
  run(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
  for (const route of spec.routes) {
    if (checkDevice(route.device) !== spec.device) invalid(`route device ${route.device}`)
    run([
      'ip',
      '-n',
      ns,
      'route',
      'add',
      checkCidr(route.destination),
      'via',
      checkHost(route.gateway),
      'dev',
      spec.device
    ])
  }
  return Object.freeze({ device: spec.device, host, key, namespace: ns, rootDevice })
}

function acceptRule(names, chain, rule) {
  run([
    'iptables',
    '-A',
    chain,
    '-i',
    names.rootDevice(deviceKey(rule.ingress)),
    '-o',
    names.rootDevice(deviceKey(rule.egress)),
    '-p',
    rule.protocol === 'udp' ? 'udp' : invalid(`protocol ${String(rule.protocol)}`),
    '-s',
    checkHost(rule.source),
    '--sport',
    checkPort(rule.sourcePort),
    '-d',
    checkHost(rule.destination),
    '--dport',
    checkPort(rule.destinationPort),
    '-j',
    'ACCEPT'
  ])
}

function readForwarding() {
  const value = execFileSync('cat', ['/proc/sys/net/ipv4/ip_forward'], { encoding: 'utf8' })
  return value.trim() === '1'
}

/**
 * Realize `namespace` (a validated `namespaceProjection()` result).
 *
 * Returns a handle that names each role's namespace, wraps a command so it runs
 * inside that namespace, captures every root-side veth to a pcap file, and
 * removes every object it created.
 */
function provisionNamespaceProjection(namespace, options = {}) {
  if (process.platform !== 'linux') {
    throw new NamespaceProvisionError('NAMESPACE_PLATFORM_UNSUPPORTED', process.platform)
  }
  if (!namespace || typeof namespace !== 'object') invalid('namespace')
  if (!Array.isArray(namespace.roles) || namespace.roles.length !== ROLE_COUNT) {
    invalid('namespace.roles')
  }
  if (!Array.isArray(namespace.firewall)) invalid('namespace.firewall')
  if (namespace.forwarding.ipv4 !== true || namespace.forwarding.defaultPolicy !== 'deny') {
    invalid('namespace.forwarding')
  }

  const suffix = checkSuffix(options.suffix || 'a000')
  const names = createNames(suffix)
  const captureDir =
    options.captureDir || fs.mkdtempSync(path.join(os.tmpdir(), `pr-capture-${suffix}-`))
  const forwardingWasOn = readForwarding()
  const endpoints = new Map()
  const captures = new Map()
  let live = true
  let chained = false

  function teardown() {
    if (!live) return false
    live = false
    for (const capture of captures.values()) stopCapture(capture)
    if (chained) {
      tolerate(['iptables', '-D', 'FORWARD', '-j', names.chain])
      tolerate(['iptables', '-F', names.chain])
      tolerate(['iptables', '-X', names.chain])
    }
    for (const endpoint of endpoints.values()) {
      // A role placed with `enter` is a grandchild behind sudo, so stopping the
      // coordinator's child does not necessarily reap it. Deleting a namespace
      // with live processes leaves them stranded on a dead interface.
      tolerate([
        'sh',
        '-c',
        `for pid in $(ip netns pids ${endpoint.namespace} 2>/dev/null); do kill -KILL $pid 2>/dev/null; done`
      ])
      tolerate(['ip', 'netns', 'del', endpoint.namespace])
      tolerate(['ip', 'link', 'del', endpoint.rootDevice])
    }
    if (!forwardingWasOn) tolerate(['sysctl', '-q', '-w', 'net.ipv4.ip_forward=0'])
    return true
  }

  function stopCapture(capture) {
    if (capture.stopped) return
    capture.stopped = true
    tolerate(['sh', '-c', `kill -INT $(cat ${capture.pidFile}) 2>/dev/null`])
    // tcpdump flushes and closes its savefile on SIGINT; give it a bounded
    // moment so the pcap is complete before any reader opens it.
    const deadline = Date.now() + 3000
    while (Date.now() < deadline) {
      const running = tolerate(['sh', '-c', `kill -0 $(cat ${capture.pidFile}) 2>/dev/null`])
      if (running === null) break
      execFileSync('sleep', ['0.05'])
    }
    tolerate(['sh', '-c', `kill -KILL $(cat ${capture.pidFile}) 2>/dev/null`])
    tolerate(['rm', '-f', capture.pidFile])
    tolerate(['chmod', '0644', capture.file])
  }

  try {
    run(['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1'])
    for (const role of namespace.roles) {
      const endpoint = attachEndpoint(names, role)
      endpoints.set(endpoint.key, Object.freeze({ ...endpoint, role: role.role }))
    }
    for (const key of ['auditor', 'decoy']) {
      const marker = namespace.marker[key]
      const endpoint = attachEndpoint(names, { ...marker, prefix: 24 })
      endpoints.set(endpoint.key, Object.freeze({ ...endpoint, role: key }))
    }

    run(['iptables', '-N', names.chain])
    chained = true
    for (const rule of namespace.firewall) acceptRule(names, names.chain, rule)
    // Anything else touching our devices is denied. Unrelated host forwarding
    // falls through this chain untouched.
    run(['iptables', '-A', names.chain, '-i', `${names.prefix}+`, '-j', 'DROP'])
    run(['iptables', '-A', names.chain, '-o', `${names.prefix}+`, '-j', 'DROP'])
    run(['iptables', '-I', 'FORWARD', '1', '-j', names.chain])
  } catch (err) {
    teardown()
    throw err
  }

  return Object.freeze({
    captureDir,
    endpoints: Object.freeze(Array.from(endpoints.values())),

    namespaceFor(roleIndex) {
      const endpoint = endpoints.get(String(roleIndex))
      if (!endpoint) invalid(`role ${String(roleIndex)}`)
      return endpoint.namespace
    },

    markerNamespace(key) {
      const endpoint = endpoints.get(key === 'auditor' ? 'a' : 'd')
      if (!endpoint) invalid(`marker ${String(key)}`)
      return endpoint.namespace
    },
    // Packets the kernel refused between our devices. A correct run never
    // attempts a forbidden pair, so this is an independent leak signal that
    // does not depend on reading any capture.
    dropStatistics() {
      const listing = run(['iptables', '-L', names.chain, '-v', '-n', '-x'])
      let packets = 0
      for (const line of String(listing).split('\n')) {
        const fields = line.trim().split(/\s+/)
        if (fields[2] !== 'DROP') continue
        packets += Number(fields[0]) || 0
      }
      return packets
    },

    // Wrap a command so it executes inside a role's namespace.
    enter(roleIndex, command, args) {
      if (typeof command !== 'string' || !Array.isArray(args)) invalid('enter')
      return Object.freeze({
        args: Object.freeze([
          '-n',
          'ip',
          'netns',
          'exec',
          this.namespaceFor(roleIndex),
          command,
          ...args
        ]),
        command: 'sudo'
      })
    },

    startCapture() {
      if (!live) invalid('destroyed')
      for (const endpoint of endpoints.values()) {
        if (captures.has(endpoint.key)) continue
        const file = path.join(captureDir, `${endpoint.key}.pcap`)
        const pidFile = path.join(captureDir, `${endpoint.key}.pid`)
        run([
          'sh',
          '-c',
          // tcpdump is the only capture path available; -U keeps the savefile
          // current so an interrupted run still yields complete records.
          // stdio must be detached: execFileSync waits for the inherited pipes
          // to close, and a backgrounded tcpdump never closes them.
          `tcpdump -i ${endpoint.rootDevice} -s 0 -U -n -w ${file} ip </dev/null >/dev/null 2>&1 & echo $! > ${pidFile}`
        ])
        captures.set(endpoint.key, {
          file,
          pidFile,
          rootDevice: endpoint.rootDevice,
          stopped: false
        })
      }
      // tcpdump needs its socket bound before traffic starts or early packets
      // are lost, and it offers no readiness signal other than the savefile.
      const deadline = Date.now() + 5000
      for (const capture of captures.values()) {
        while (!fs.existsSync(capture.file) && Date.now() < deadline) {
          execFileSync('sleep', ['0.05'])
        }
        if (!fs.existsSync(capture.file)) {
          throw new NamespaceProvisionError('NAMESPACE_CAPTURE_UNAVAILABLE', capture.rootDevice)
        }
      }
      return Object.freeze(Array.from(captures.keys()))
    },

    stopCapture() {
      for (const capture of captures.values()) stopCapture(capture)
      return Object.freeze(
        Array.from(captures.entries()).map(([key, capture]) =>
          Object.freeze({ file: capture.file, key })
        )
      )
    },

    get live() {
      return live
    },

    teardown
  })
}

function namespaceProvisioningAvailable() {
  if (process.platform !== 'linux') return false
  try {
    execFileSync('sudo', ['-n', 'ip', 'netns', 'list'], { stdio: 'ignore' })
    execFileSync('sh', ['-c', 'command -v tcpdump'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

module.exports = Object.freeze({
  NamespaceProvisionError,
  namespaceProvisioningAvailable,
  provisionNamespaceProjection
})
