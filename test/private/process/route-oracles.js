'use strict'

// Oracles that read the namespace captures and decide what the wire actually
// showed. They answer four separate questions:
//
//   1. edges     - did any datagram cross a pair the topology forbids?
//   2. authority - did the endpoint ever send to anything but its guard?
//   3. leakage   - did a secret survive into a hop that must not carry it?
//   4. relaying  - was any cell payload forwarded unchanged across two hops?
//
// Nothing here trusts the implementation's own accounting; every answer comes
// from bytes captured off the veths.

const b4a = require('b4a')
const sodium = require('sodium-universal')

const { ALLOW_EDGES, ROLES } = require('./topology-fixture')
const { contains, readPcap } = require('./pcap')

const ENDPOINT_ROLE_INDEX = 1
const GUARD_ROLE_INDEX = 2
// Hops that carry route cells. Exit-to-DHT traffic is ordinary DHT by design:
// "an exit sees the routed DHT operation" is a stated visible property, so those
// edges are excluded from the plaintext and relay checks and are used instead as
// the positive control that the search finds a secret when one is present.
const DHT_ROLE_INDICES = new Set([9, 10, 11])

function digest(bytes) {
  const out = b4a.alloc(16)
  sodium.crypto_generichash(out, bytes)
  return b4a.toString(out, 'hex')
}

function pairKey(left, right) {
  return left < right ? `${left}-${right}` : `${right}-${left}`
}

function allowedPairs() {
  const pairs = new Set()
  for (const [left, right] of ALLOW_EDGES) pairs.add(pairKey(left, right))
  return pairs
}

function isCellEdge(left, right) {
  return !DHT_ROLE_INDICES.has(left) && !DHT_ROLE_INDICES.has(right)
}
// Wire form of a role tuple: four address bytes then the port, big endian.
function encodeTuple(tuple) {
  const bytes = b4a.alloc(6)
  tuple.host.split('.').forEach((part, index) => {
    bytes[index] = Number(part)
  })
  bytes.writeUInt16BE(tuple.port, 4)
  return bytes
}

function roleIndexByHost(oracle) {
  const roleByHost = new Map()
  oracle.tuples.forEach((tuple, index) => roleByHost.set(tuple.host, index + 1))
  return roleByHost
}

function edgeFor(roleByHost, datagram) {
  const source = roleByHost.get(datagram.source)
  const destination = roleByHost.get(datagram.destination)
  if (source === undefined || destination === undefined) return null
  return pairKey(source, destination)
}
/**
 * Byte strings whose presence in a route cell would be a leak.
 *
 * `everywhere` markers are pure secrets: identity and route secret keys, MAC
 * keys and sentinels that must not appear on any edge at all. The value and the
 * target hash are only forbidden inside route cells, because an exit performing
 * the DHT operation necessarily shows them to the DHT.
 *
 * `oracle.eventForbiddenBytes` repeats the sentinel and the value, so entries
 * are de-duplicated by content and the explicit classification wins.
 */
function secretMarkers(oracle) {
  const named = [
    { bytes: oracle.leakSentinel, everywhere: true, name: 'leak sentinel' },
    { bytes: oracle.immutableValue, everywhere: false, name: 'immutable value' },
    { bytes: oracle.targetHash, everywhere: false, name: 'target hash' }
  ]
  const markers = []
  const claimed = new Set()
  for (const marker of named) {
    if (!marker.bytes || marker.bytes.byteLength < 8) continue
    claimed.add(digest(marker.bytes))
    markers.push(marker)
  }
  for (const [index, value] of oracle.eventForbiddenBytes.entries()) {
    if (!value || value.byteLength < 8 || claimed.has(digest(value))) continue
    claimed.add(digest(value))
    markers.push({ bytes: value, everywhere: true, name: `forbidden event bytes ${index}` })
  }
  return markers
}

/**
 * Fold every capture into one view of the run.
 *
 * A forwarded datagram is seen twice, once on each veth, so datagrams are
 * de-duplicated by source, destination, timing and payload before counting.
 */
function summarizeRouteCaptures(captures, oracle) {
  const roleByHost = roleIndexByHost(oracle)

  const allowed = allowedPairs()
  const markers = secretMarkers(oracle)
  const edges = new Map()
  const forbidden = []
  const endpointDestinations = new Set()
  const payloadEdges = new Map()
  const markerHits = new Map(markers.map((marker) => [marker.name, new Set()]))
  const seen = new Set()
  let markerDatagrams = 0
  let undecodableFrames = 0

  for (const capture of captures) {
    const { datagrams, otherFrames } = readPcap(capture.file)
    undecodableFrames += otherFrames
    for (const datagram of datagrams) {
      const source = roleByHost.get(datagram.source)
      const destination = roleByHost.get(datagram.destination)
      if (source === undefined || destination === undefined) {
        // The auditor/decoy control pair is not part of the route topology.
        markerDatagrams++
        continue
      }
      const payloadDigest = digest(datagram.payload)
      const identity = `${datagram.source}:${datagram.sourcePort}>${datagram.destination}:${datagram.destinationPort}|${datagram.seconds}.${datagram.micros}|${payloadDigest}`
      if (seen.has(identity)) continue
      seen.add(identity)

      const key = pairKey(source, destination)
      if (!allowed.has(key)) {
        forbidden.push({
          destination: ROLES[destination - 1],
          observedOn: capture.key,
          source: ROLES[source - 1]
        })
        continue
      }
      if (source === ENDPOINT_ROLE_INDEX) endpointDestinations.add(destination)

      const cell = isCellEdge(source, destination)
      let edge = edges.get(key)
      if (edge === undefined) {
        edge = { cell, count: 0, sizes: new Map() }
        edges.set(key, edge)
      }
      edge.count++
      edge.sizes.set(
        datagram.payload.byteLength,
        (edge.sizes.get(datagram.payload.byteLength) || 0) + 1
      )

      for (const marker of markers) {
        if (contains(datagram.payload, marker.bytes)) markerHits.get(marker.name).add(key)
      }

      if (cell && datagram.payload.byteLength >= 32) {
        let carriers = payloadEdges.get(payloadDigest)
        if (carriers === undefined) {
          carriers = new Set()
          payloadEdges.set(payloadDigest, carriers)
        }
        carriers.add(key)
      }
    }
  }

  const relayed = []
  for (const [payloadDigest, carriers] of payloadEdges) {
    if (carriers.size > 1) relayed.push({ edges: Array.from(carriers).sort(), payloadDigest })
  }

  const cellEdges = new Set(
    Array.from(edges)
      .filter(([, edge]) => edge.cell)
      .map(([key]) => key)
  )

  return Object.freeze({
    cellEdges,
    edges,
    endpointDestinations,
    forbidden,
    markerDatagrams,
    markerHits,
    markers,
    relayed,
    undecodableFrames
  })
}

function edgeName(key) {
  const [left, right] = key.split('-').map(Number)
  return `${ROLES[left - 1]} <-> ${ROLES[right - 1]}`
}

/**
 * Assert the oracles against a completed run.
 *
 * `t` is a brittle test. Every assertion names the property it defends.
 */
function assertRouteCaptures(t, captures, oracle) {
  const summary = summarizeRouteCaptures(captures, oracle)
  const roleByHost = roleIndexByHost(oracle)

  // 1. Edge oracle.
  t.alike(summary.forbidden, [], 'no datagram crosses a pair the topology forbids')
  t.ok(summary.cellEdges.size > 0, 'the capture observed route cell traffic')

  // 2. Direct-authority oracle.
  t.alike(
    Array.from(summary.endpointDestinations).sort(),
    [GUARD_ROLE_INDEX],
    'the endpoint only ever sends to its guard'
  )

  // 3. Leak oracle. A marker must never appear on an edge that carries route
  // cells. Sentinels must not appear anywhere at all.
  t.ok(summary.markers.length >= 3, 'the run supplies leak markers to search for')
  const leaked = []
  for (const marker of summary.markers) {
    const hits = summary.markerHits.get(marker.name)
    for (const key of hits) {
      if (marker.everywhere || summary.cellEdges.has(key)) {
        leaked.push({ edge: edgeName(key), marker: marker.name })
      }
    }
  }
  t.alike(leaked, [], 'no leak marker appears on any edge that carries route cells')

  // The guard is allowed to know the endpoint's address; nothing past it is.
  // Six encoded bytes are specific enough to matter here: across a run of this
  // size the chance of a given six-byte string occurring by accident is far
  // below one in a billion.
  const endpointTuple = encodeTuple(oracle.tuples[ENDPOINT_ROLE_INDEX - 1])
  const guardEdge = pairKey(ENDPOINT_ROLE_INDEX, GUARD_ROLE_INDEX)
  const propagated = []
  for (const capture of captures) {
    for (const datagram of readPcap(capture.file).datagrams) {
      if (!contains(datagram.payload, endpointTuple)) continue
      const key = edgeFor(roleByHost, datagram)
      if (key === null || key === guardEdge || !summary.cellEdges.has(key)) continue
      propagated.push(edgeName(key))
    }
  }
  t.alike(propagated, [], 'the endpoint address never travels inside a cell past its guard')

  // The same search must find the value where it is legitimately plaintext,
  // between an exit and a DHT node. Without this the leak check could pass by
  // simply never matching anything.
  const valueHits = summary.markerHits.get('immutable value')
  t.ok(
    valueHits && valueHits.size > 0,
    'the value search is not vacuous: the value is visible on an exit-to-DHT edge'
  )

  // 4. Relay oracle: each hop re-encrypts, so a cell payload never repeats.
  t.alike(summary.relayed, [], 'no cell payload is relayed unchanged across two hops')

  // Route cells are indistinguishable by length.
  const cellSizes = new Set()
  for (const [key, edge] of summary.edges) {
    if (!summary.cellEdges.has(key)) continue
    for (const size of edge.sizes.keys()) cellSizes.add(size)
  }
  t.alike(Array.from(cellSizes), [1200], 'every route cell is the same size on every hop')

  return summary
}

/** Human-readable capture statistics, used to report evidence. */
function describeRouteCaptures(summary) {
  const lines = []
  for (const [key, edge] of Array.from(summary.edges).sort()) {
    const sizes = Array.from(edge.sizes)
      .sort((a, b) => b[1] - a[1])
      .map(([size, count]) => `${size}x${count}`)
      .join(' ')
    lines.push(
      `${edgeName(key)}: ${edge.count} datagrams${edge.cell ? ' [cell]' : ' [dht]'} sizes ${sizes}`
    )
  }
  lines.push(`marker datagrams: ${summary.markerDatagrams}`)
  lines.push(`undecodable frames: ${summary.undecodableFrames}`)
  return lines
}

module.exports = Object.freeze({
  assertRouteCaptures,
  describeRouteCaptures,
  summarizeRouteCaptures
})
