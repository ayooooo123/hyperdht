'use strict'

// Node/Linux only: no native DHT module is loaded by the preflight/plan surface.
const { spawnSync } = require('child_process')
const { randomBytes } = require('hypercore-crypto')

const plan = {
  gate: 'peer:diversity',
  kind: 'inspection only; not a passed network scenario',
  prerequisites: ['Linux', 'root with CAP_NET_ADMIN', 'iproute2', 'native Node dependencies'],
  positive: '8 relays: 4 hosts in one /24, plus 4 separate /24s; 3 private transfers',
  negative: '8 distinct, live relay identities in one /24; private route must fail closed',
  infrastructure:
    '6 storage nodes with production descriptor services; explicit non-loopback binds',
  addressing: 'owned dummy interfaces in an unused 10.x.0.0/16; kernel-allocated UDP ports',
  evidence: 'authenticated Noise rawStream remote tuples, not advertised relayAddresses',
  dependency: 'intended C6 diversity contract; current baseline is not expected to pass',
  limits: 'IPv4 /24 only; local downstream evidence is not source certification or operator honesty'
}

function ip(args) {
  const result = spawnSync('ip', args, { encoding: 'utf8', timeout: 10000 })
  if (result.error || result.status !== 0) {
    throw new Error(
      'ip ' +
        args.join(' ') +
        ' failed: ' +
        (result.error ? result.error.message : result.stderr.trim()) +
        '; run in the privileged Linux gate container (CAP_NET_ADMIN required)'
    )
  }
  return result.stdout
}

function preflight() {
  if (process.platform !== 'linux') {
    throw new Error(
      'peer:diversity requires privileged Linux, not ' +
        process.platform +
        '. Coordinator command: bash scripts/linux-gates.sh peer:diversity. ' +
        'Use --describe for inspection only.'
    )
  }
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) {
    throw new Error(
      'peer:diversity requires root plus CAP_NET_ADMIN; use the privileged Linux runner'
    )
  }
  ip(['-Version'])
}

function isIPv4(host) {
  if (typeof host !== 'string') return false
  const parts = host.split('.')
  return (
    parts.length === 4 &&
    parts.every((part) => {
      const octet = Number(part)
      return Number.isInteger(octet) && octet >= 0 && octet <= 255 && String(octet) === part
    })
  )
}

function number(host) {
  return host.split('.').reduce((value, part) => value * 256 + Number(part), 0)
}

function range(cidr) {
  const [host, width = '32'] = cidr.split('/')
  if (!isIPv4(host)) throw new Error('expected IPv4 route/address: ' + cidr)
  const size = 2 ** (32 - Number(width))
  const start = Math.floor(number(host) / size) * size
  return [start, start + size - 1]
}

function overlaps(a, b) {
  return a[0] <= b[1] && b[0] <= a[1]
}

function prefix(host) {
  if (!isIPv4(host)) throw new Error('established remote host must be IPv4: ' + host)
  const parts = host.split('.')
  if (parts[0] === '127' || parts[0] === '0') {
    throw new Error('loopback/wildcard is not E7 evidence')
  }
  return parts.slice(0, 3).join('.') + '.0/24'
}

function provision(t, diverse) {
  const addresses = JSON.parse(ip(['-j', '-4', 'address', 'show']))
  const routes = JSON.parse(ip(['-j', '-4', 'route', 'show', 'table', 'all']))
  const occupied = []
  for (const link of addresses) {
    for (const addr of link.addr_info || []) occupied.push(range(addr.local + '/' + addr.prefixlen))
  }
  for (const route of routes) {
    if (route.dst && route.dst !== 'default') occupied.push(range(route.dst))
  }
  const second = Array.from({ length: 112 }, (_, i) => 128 + i).find(
    (part) => !occupied.some((used) => overlaps(range('10.' + part + '.0.0/16'), used))
  )
  if (second === undefined) {
    throw new Error('no unused 10.x.0.0/16 available; refusing to alter existing routes')
  }
  const base = '10.' + second + '.'
  const hosts = {
    storage: Array.from({ length: 6 }, (_, i) => base + '1.' + (10 + i)),
    source: base + '2.10',
    destination: base + '2.11',
    relays: Array.from(
      { length: 8 },
      (_, i) => base + (diverse && i >= 4 ? 11 + i - 4 : 10) + '.' + (10 + i)
    )
  }
  const groups = new Map()
  for (const host of [...hosts.storage, hosts.source, hosts.destination, ...hosts.relays]) {
    const key = prefix(host)
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(host)
  }
  const owned = []
  const stem = 'c2d' + randomBytes(4).toString('hex')
  function close() {
    const errors = []
    for (const name of owned.slice().reverse()) {
      try {
        ip(['link', 'delete', 'dev', name])
        owned.splice(owned.indexOf(name), 1)
      } catch (error) {
        errors.push(error)
      }
    }
    if (errors.length) throw new AggregateError(errors, 'could not delete owned dummy interfaces')
  }
  try {
    for (const group of groups.values()) {
      const name = stem + owned.length
      // Record ownership only after successful creation; never delete a pre-existing link.
      ip(['link', 'add', 'name', name, 'type', 'dummy'])
      owned.push(name)
      ip(['link', 'set', 'dev', name, 'up'])
      for (const host of group) ip(['address', 'add', host + '/24', 'dev', name])
      const actual = JSON.parse(ip(['-j', '-4', 'address', 'show', 'dev', name]))
      const bound = new Set(actual.flatMap((link) => link.addr_info.map((addr) => addr.local)))
      for (const host of group)
        t.ok(bound.has(host), 'dummy address was actually installed: ' + host)
    }
    return { hosts, close }
  } catch (error) {
    try {
      close()
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], 'topology provisioning and cleanup failed')
    }
    throw error
  }
}

module.exports = { plan, preflight, provision, prefix }
