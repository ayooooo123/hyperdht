'use strict'

// Minimal reader for the classic pcap savefiles that `tcpdump -w` produces on
// the namespace veths. The oracles only need Ethernet/IPv4/UDP, so this decodes
// exactly that and counts everything else rather than guessing at it.

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
  readPcap
})
