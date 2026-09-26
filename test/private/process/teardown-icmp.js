'use strict'

const b4a = require('b4a')

function invalid(detail) {
  const err = new Error(`ERR_TEARDOWN_ICMP: ${detail}`)
  err.code = 'ERR_TEARDOWN_ICMP'
  throw err
}

function checksum(bytes) {
  let sum = 0
  for (let i = 0; i < bytes.byteLength; i += 2) {
    sum += (bytes[i] << 8) | (bytes[i + 1] || 0)
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16)
  return ~sum & 0xffff
}

function host(packet, offset) {
  return `${packet[offset]}.${packet[offset + 1]}.${packet[offset + 2]}.${packet[offset + 3]}`
}

function time(value) {
  return Number.isSafeInteger(value) && value >= 0
}

function roleKey(key) {
  return typeof key === 'string' && /^[1-9][0-9]*$/.test(key)
}

function ipv4(packet, quoted = false) {
  if (!b4a.isBuffer(packet) || packet.byteLength < 20 || packet[0] !== 0x45) {
    invalid('requires options-free IPv4')
  }
  const length = packet.readUInt16BE(2)
  if (length < 20 || (quoted ? packet.byteLength > length : packet.byteLength !== length)) {
    invalid('IPv4 length mismatch')
  }
  if (packet.readUInt16BE(6) & 0xbfff) invalid('fragmented or reserved IPv4 flags')
  if (checksum(packet.subarray(0, 20)) !== 0) invalid('IPv4 checksum')
  return length
}

function udpTuple(packet, quoted = false) {
  // TX offload can leave captured UDP checksums unfinished. Quote provenance
  // uses exact observed bytes; only IPv4 and ICMP checksums are required here.
  const length = ipv4(packet, quoted)
  if (packet[9] !== 17 || packet.byteLength < 28 || packet.readUInt16BE(24) !== length - 20) {
    invalid('incoherent UDP header')
  }
  return `${host(packet, 12)}:${packet.readUInt16BE(20)}->${host(packet, 16)}:${packet.readUInt16BE(22)}`
}

// Native-close intervals are test-side observations of the actual close call
// and its successful completion, not coordinator receipt times. A reply may
// fall inside that interval or after it. Its exact destination socket must have
// completed closure before the audit; all quoted bytes must already be known.
function reconcileTeardownIcmp(captures, firewall, socketCloses, completedBeforeMicros, rawDrop) {
  if (!time(completedBeforeMicros) || !time(rawDrop)) invalid('invalid time or counter')
  if (!Array.isArray(captures) || !Array.isArray(firewall) || !(socketCloses instanceof Map)) {
    invalid('invalid evidence containers')
  }
  for (const [key, records] of socketCloses) {
    if (!roleKey(key) || !Array.isArray(records)) invalid('invalid socket-close role')
    const tuples = new Set()
    for (const record of records) {
      if (
        !record ||
        typeof record.host !== 'string' ||
        !Number.isInteger(record.port) ||
        record.port < 1 ||
        record.port > 65535 ||
        !time(record.startMicros) ||
        !time(record.endMicros) ||
        record.startMicros > record.endMicros ||
        record.endMicros > completedBeforeMicros
      )
        invalid('invalid socket-close interval')
      const tuple = `${record.host}:${record.port}`
      if (tuples.has(tuple)) invalid('ambiguous socket-close tuple')
      tuples.add(tuple)
    }
  }

  const allowed = new Map()
  for (const rule of firewall) {
    if (
      !rule ||
      rule.protocol !== 'udp' ||
      typeof rule.source !== 'string' ||
      typeof rule.destination !== 'string' ||
      !Number.isInteger(rule.sourcePort) ||
      !Number.isInteger(rule.destinationPort) ||
      rule.sourcePort < 1 ||
      rule.sourcePort > 65535 ||
      rule.destinationPort < 1 ||
      rule.destinationPort > 65535 ||
      typeof rule.ingress !== 'string' ||
      typeof rule.egress !== 'string'
    ) {
      invalid('invalid UDP firewall rule')
    }
    const tuple = `${rule.source}:${rule.sourcePort}->${rule.destination}:${rule.destinationPort}`
    if (allowed.has(tuple)) invalid('ambiguous firewall tuple')
    allowed.set(tuple, rule)
  }

  const keys = new Set()
  let classifiedTeardownIcmp = 0
  for (const capture of captures) {
    if (
      !capture ||
      (!roleKey(capture.key) && capture.key !== 'a' && capture.key !== 'd') ||
      !Array.isArray(capture.records)
    )
      invalid('invalid capture')
    if (keys.has(capture.key)) invalid('duplicate capture key')
    keys.add(capture.key)
    const prior = new Map()
    const seenPackets = new Map()
    const candidates = []
    for (let index = 0; index < capture.records.length; index++) {
      const { packet, timestampMicros } = capture.records[index]
      if (!time(timestampMicros)) invalid('invalid capture timestamp')
      let sameTime = seenPackets.get(timestampMicros)
      if (!sameTime) seenPackets.set(timestampMicros, (sameTime = []))
      if (sameTime.some((seen) => b4a.equals(seen, packet))) invalid('duplicate physical packet')
      sameTime.push(packet)
      ipv4(packet)
      if (packet[9] === 17) {
        const tuple = udpTuple(packet)
        let records = prior.get(tuple)
        if (!records) prior.set(tuple, (records = []))
        records.push({ packet, timestampMicros, index })
        continue
      }
      candidates.push({ packet, timestampMicros, index })
    }
    // libpcap may queue unrelated packets out of timestamp order. Provenance
    // still requires both an earlier file record and an earlier timestamp.
    for (const { packet, timestampMicros, index } of candidates) {
      // Marker captures are still parsed and checked, but never qualify for a
      // teardown exception, even if a caller supplies forged marker close data.
      if (!roleKey(capture.key) || packet[9] !== 1 || packet.byteLength < 56) {
        invalid('unmatched non-UDP packet')
      }
      if (
        packet[20] !== 3 ||
        packet[21] !== 3 ||
        packet.readUInt32BE(24) !== 0 ||
        checksum(packet.subarray(20)) !== 0
      )
        invalid('ICMP type, code, reserved bytes or checksum')
      const quote = packet.subarray(28)
      const tuple = udpTuple(quote, true)
      const rule = allowed.get(tuple)
      if (
        !rule ||
        rule.egress !== `pr-veth-${capture.key}` ||
        !/^pr-veth-[1-9][0-9]*$/.test(rule.ingress) ||
        host(packet, 12) !== rule.destination ||
        host(packet, 16) !== rule.source
      ) {
        invalid('ICMP does not reverse an allowed edge on its origin veth')
      }
      const closing = socketCloses
        .get(capture.key)
        ?.find((record) => record.host === rule.destination && record.port === rule.destinationPort)
      if (
        !closing ||
        timestampMicros < closing.startMicros ||
        timestampMicros > completedBeforeMicros
      )
        invalid('outside native socket-close window')
      if (
        !(prior.get(tuple) || []).some(
          (record) =>
            record.index < index &&
            record.timestampMicros < timestampMicros &&
            b4a.equals(record.packet.subarray(0, quote.byteLength), quote)
        )
      )
        invalid('no earlier exact quoted-prefix evidence')
      classifiedTeardownIcmp++
    }
  }
  if (rawDrop !== classifiedTeardownIcmp) {
    invalid(`raw DROP=${rawDrop}, classified=${classifiedTeardownIcmp}`)
  }
  return Object.freeze({ rawDrop, classifiedTeardownIcmp })
}

module.exports = Object.freeze({ reconcileTeardownIcmp })
