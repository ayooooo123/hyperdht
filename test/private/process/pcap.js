'use strict'

// Classic pcap readers for namespace veth captures. The UDP oracles retain
// their existing decoder; the teardown audit uses the strict IPv4 record reader
// so malformed or non-UDP traffic cannot disappear from reconciliation.

const fs = require('fs')
const b4a = require('b4a')

const PCAP_MAGIC_MICROS = 0xa1b2c3d4
const PCAP_MAGIC_NANOS = 0xa1b23c4d
const GLOBAL_HEADER_BYTES = 24
const RECORD_HEADER_BYTES = 16
const LINKTYPE_ETHERNET = 1
const LINKTYPE_RAW = 101
const ETHERTYPE_IPV4 = 0x0800
const ETHERNET_HEADER_BYTES = 14
const PROTOCOL_UDP = 17

class PcapError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code)
    this.code = code
    this.name = 'PcapError'
  }
}

function readGlobalHeader(buffer) {
  if (buffer.byteLength < GLOBAL_HEADER_BYTES) throw new PcapError('PCAP_TRUNCATED', 'header')
  const big = buffer.readUInt32BE(0)
  const little = buffer.readUInt32LE(0)
  let littleEndian = null
  let nanos = false
  for (const [value, isLittle] of [
    [big, false],
    [little, true]
  ]) {
    if (value === PCAP_MAGIC_MICROS) littleEndian = isLittle
    else if (value === PCAP_MAGIC_NANOS) {
      littleEndian = isLittle
      nanos = true
    }
  }
  if (littleEndian === null) throw new PcapError('PCAP_MAGIC_INVALID')
  const linkType = littleEndian ? buffer.readUInt32LE(20) : buffer.readUInt32BE(20)
  if (linkType !== LINKTYPE_ETHERNET && linkType !== LINKTYPE_RAW) {
    throw new PcapError('PCAP_LINKTYPE_UNSUPPORTED', String(linkType))
  }
  return { linkType, littleEndian, nanos }
}

function decodeIpv4Udp(frame, linkType) {
  let offset = 0
  if (linkType === LINKTYPE_ETHERNET) {
    if (frame.byteLength < ETHERNET_HEADER_BYTES) return null
    if (frame.readUInt16BE(12) !== ETHERTYPE_IPV4) return null
    offset = ETHERNET_HEADER_BYTES
  }
  if (frame.byteLength < offset + 20) return null
  const versionAndLength = frame[offset]
  if (versionAndLength >> 4 !== 4) return null
  const headerBytes = (versionAndLength & 0x0f) * 4
  if (headerBytes < 20 || frame.byteLength < offset + headerBytes + 8) return null
  if (frame[offset + 9] !== PROTOCOL_UDP) return null
  const source = Array.from(frame.subarray(offset + 12, offset + 16)).join('.')
  const destination = Array.from(frame.subarray(offset + 16, offset + 20)).join('.')
  const udp = offset + headerBytes
  const sourcePort = frame.readUInt16BE(udp)
  const destinationPort = frame.readUInt16BE(udp + 2)
  const length = frame.readUInt16BE(udp + 4)
  // The declared UDP length includes its own eight-byte header and must not
  // claim more than the frame actually carries.
  if (length < 8) return null
  const end = Math.min(udp + length, frame.byteLength)
  return Object.freeze({
    destination,
    destinationPort,
    payload: frame.subarray(udp + 8, end),
    source,
    sourcePort
  })
}

function computeIpv4Checksum(buffer, offset, headerBytes) {
  let sum = 0
  for (let i = 0; i < headerBytes; i += 2) {
    sum += buffer.readUInt16BE(offset + i)
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return ~sum & 0xffff
}

/**
 * Strict classic-pcap IPv4 reader.
 *
 * Returns a frozen array of frozen `{ packet, timestampMicros }` records.
 */
function readPcapPackets(file) {
  const buffer = b4a.isBuffer(file) ? file : fs.readFileSync(file)
  if (buffer.byteLength < GLOBAL_HEADER_BYTES) {
    throw new PcapError('PCAP_TRUNCATED', 'global header')
  }
  const header = readGlobalHeader(buffer)
  const u16 = (offset) =>
    header.littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset)
  const u32 = (offset) =>
    header.littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)

  const versionMajor = u16(4)
  const versionMinor = u16(6)
  if (versionMajor !== 2 || versionMinor !== 4) {
    throw new PcapError('PCAP_VERSION_UNSUPPORTED', `${versionMajor}.${versionMinor}`)
  }
  const snaplen = u32(16)
  if (snaplen === 0) {
    throw new PcapError('PCAP_SNAPLEN_INVALID', String(snaplen))
  }
  const records = []
  let offset = GLOBAL_HEADER_BYTES

  while (offset < buffer.byteLength) {
    if (offset + RECORD_HEADER_BYTES > buffer.byteLength) {
      throw new PcapError('PCAP_TRUNCATED', 'record header')
    }
    const seconds = u32(offset)
    const fraction = u32(offset + 4)
    const captured = u32(offset + 8)
    const original = u32(offset + 12)
    offset += RECORD_HEADER_BYTES

    if (header.nanos) {
      if (fraction >= 1000000000) {
        throw new PcapError('PCAP_TIME_FRACTION_INVALID', String(fraction))
      }
    } else {
      if (fraction >= 1000000) {
        throw new PcapError('PCAP_TIME_FRACTION_INVALID', String(fraction))
      }
    }

    if (captured > snaplen) {
      throw new PcapError('PCAP_RECORD_SNAPLEN_EXCEEDED', `${captured} > ${snaplen}`)
    }

    if (captured !== original) {
      throw new PcapError('PCAP_CAPTURE_TRUNCATED', `${captured} != ${original}`)
    }

    if (offset + captured > buffer.byteLength) {
      throw new PcapError('PCAP_TRUNCATED', 'record body')
    }

    const frame = buffer.subarray(offset, offset + captured)
    offset += captured

    let ipOffset = 0
    if (header.linkType === LINKTYPE_ETHERNET) {
      if (frame.byteLength < ETHERNET_HEADER_BYTES) {
        throw new PcapError('PCAP_FRAME_TRUNCATED', 'ethernet header')
      }
      const ethertype = frame.readUInt16BE(12)
      if (ethertype !== ETHERTYPE_IPV4) {
        throw new PcapError(
          'PCAP_NON_IPV4',
          `ethertype 0x${ethertype.toString(16).padStart(4, '0')}`
        )
      }
      ipOffset = ETHERNET_HEADER_BYTES
    } else if (header.linkType === LINKTYPE_RAW) {
      ipOffset = 0
    }

    const networkBytes = frame.byteLength - ipOffset
    if (networkBytes < 20) {
      throw new PcapError('PCAP_IPV4_INVALID', 'header too short')
    }

    const versionAndIhl = frame[ipOffset]
    const version = versionAndIhl >> 4
    if (version !== 4) {
      throw new PcapError('PCAP_NON_IPV4', `version ${version}`)
    }
    const ihl = versionAndIhl & 0x0f
    const headerBytes = ihl * 4
    if (headerBytes < 20 || headerBytes > networkBytes) {
      throw new PcapError('PCAP_IPV4_INVALID', `invalid ihl ${ihl}`)
    }

    const totalLength = frame.readUInt16BE(ipOffset + 2)
    if (totalLength < headerBytes) {
      throw new PcapError(
        'PCAP_IPV4_INVALID',
        `total length ${totalLength} < header length ${headerBytes}`
      )
    }
    if (totalLength > networkBytes) {
      throw new PcapError(
        'PCAP_IPV4_TRUNCATED',
        `total length ${totalLength} > captured network bytes ${networkBytes}`
      )
    }
    const padding = frame.subarray(ipOffset + totalLength)
    const maxPadding = header.linkType === LINKTYPE_ETHERNET ? Math.max(0, 46 - totalLength) : 0
    if (padding.byteLength > maxPadding || padding.some((byte) => byte !== 0)) {
      throw new PcapError('PCAP_IPV4_TRAILING_BYTES')
    }

    const flagsAndFragment = frame.readUInt16BE(ipOffset + 6)
    if ((flagsAndFragment & 0x8000) !== 0) {
      throw new PcapError('PCAP_IPV4_FRAGMENTED', 'reserved bit set')
    }
    if ((flagsAndFragment & 0x2000) !== 0) {
      throw new PcapError('PCAP_IPV4_FRAGMENTED', 'more fragments (MF) set')
    }
    if ((flagsAndFragment & 0x1fff) !== 0) {
      throw new PcapError('PCAP_IPV4_FRAGMENTED', `fragment offset ${flagsAndFragment & 0x1fff}`)
    }

    if (computeIpv4Checksum(frame, ipOffset, headerBytes) !== 0) {
      throw new PcapError('PCAP_IPV4_CHECKSUM_INVALID')
    }

    const packet = frame.subarray(ipOffset, ipOffset + totalLength)

    const fractionMicros = header.nanos ? Math.floor(fraction / 1000) : fraction
    const timestampMicros = seconds * 1000000 + fractionMicros
    if (!Number.isSafeInteger(timestampMicros)) {
      throw new PcapError('PCAP_TIMESTAMP_OVERFLOW', String(timestampMicros))
    }

    records.push(
      Object.freeze({
        packet,
        timestampMicros
      })
    )
  }

  return Object.freeze(records)
}

/**
 * Read one savefile into its UDP/IPv4 datagrams.
 *
 * Returns `{ datagrams, otherFrames }` so a caller can tell "no leaked packets"
 * apart from "packets the decoder skipped".
 */
function readPcap(file) {
  const buffer = fs.readFileSync(file)
  if (buffer.byteLength === 0)
    return Object.freeze({ datagrams: Object.freeze([]), otherFrames: 0 })
  const header = readGlobalHeader(buffer)
  const u32 = (offset) =>
    header.littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)
  const datagrams = []
  let otherFrames = 0
  let offset = GLOBAL_HEADER_BYTES
  while (offset + RECORD_HEADER_BYTES <= buffer.byteLength) {
    const seconds = u32(offset)
    const fraction = u32(offset + 4)
    const captured = u32(offset + 8)
    const original = u32(offset + 12)
    offset += RECORD_HEADER_BYTES
    if (captured > buffer.byteLength - offset) break
    const frame = buffer.subarray(offset, offset + captured)
    offset += captured
    const decoded = decodeIpv4Udp(frame, header.linkType)
    if (decoded === null) {
      otherFrames++
      continue
    }
    datagrams.push(
      Object.freeze({
        ...decoded,
        micros: header.nanos ? Math.floor(fraction / 1000) : fraction,
        seconds,
        truncated: captured < original
      })
    )
  }
  return Object.freeze({ datagrams: Object.freeze(datagrams), otherFrames })
}

/** Every distinct `source:sourcePort -> destination:destinationPort` seen. */
function datagramEdges(datagrams) {
  const edges = new Set()
  for (const datagram of datagrams) {
    edges.add(
      `${datagram.source}:${datagram.sourcePort}->${datagram.destination}:${datagram.destinationPort}`
    )
  }
  return edges
}

/** True when `needle` occurs anywhere in `haystack`. */
function contains(haystack, needle) {
  if (needle.byteLength === 0 || haystack.byteLength < needle.byteLength) return false
  return b4a.indexOf(haystack, needle) !== -1
}

module.exports = Object.freeze({
  PcapError,
  contains,
  datagramEdges,
  readPcap,
  readPcapPackets
})
