'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { readPcapPackets } = require('./process/pcap')

function computeIpv4HeaderChecksum(header) {
  let sum = 0
  for (let i = 0; i < header.byteLength; i += 2) {
    if (i === 10) continue // checksum field itself is 0 during computation
    sum += header.readUInt16BE(i)
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return ~sum & 0xffff
}

function buildIpv4Packet({
  version = 4,
  ihl = 5,
  tos = 0,
  totalLength = null,
  id = 0x1234,
  flags = 0, // e.g. 0x4000 for DF
  ttl = 64,
  protocol = 1, // ICMP
  src = [192, 168, 1, 10],
  dst = [192, 168, 1, 20],
  payload = b4a.from([8, 0, 0xf7, 0xff, 0, 1, 0, 1]) // ICMP echo request
} = {}) {
  const headerLen = ihl * 4
  const actualTotal = totalLength !== null ? totalLength : headerLen + payload.byteLength
  const buf = b4a.alloc(actualTotal)
  buf[0] = (version << 4) | (ihl & 0x0f)
  buf[1] = tos
  buf.writeUInt16BE(actualTotal, 2)
  buf.writeUInt16BE(id, 4)
  buf.writeUInt16BE(flags, 6)
  buf[8] = ttl
  buf[9] = protocol
  buf.set(src, 12)
  buf.set(dst, 16)

  const csum = computeIpv4HeaderChecksum(buf.subarray(0, headerLen))
  buf.writeUInt16BE(csum, 10)

  if (payload.byteLength > 0 && actualTotal > headerLen) {
    buf.set(payload.subarray(0, actualTotal - headerLen), headerLen)
  }
  return buf
}

function buildPcapFile({
  magic = 0xa1b2c3d4, // little or big endian or nanos
  littleEndian = true,
  versionMajor = 2,
  versionMinor = 4,
  thiszone = 0,
  sigfigs = 0,
  snaplen = 65535,
  linkType = 1, // 1 = Ethernet, 101 = Raw
  records = []
} = {}) {
  const gh = b4a.alloc(24)
  if (littleEndian) {
    gh.writeUInt32LE(magic, 0)
    gh.writeUInt16LE(versionMajor, 4)
    gh.writeUInt16LE(versionMinor, 6)
    gh.writeInt32LE(thiszone, 8)
    gh.writeUInt32LE(sigfigs, 12)
    gh.writeUInt32LE(snaplen, 16)
    gh.writeUInt32LE(linkType, 20)
  } else {
    gh.writeUInt32BE(magic, 0)
    gh.writeUInt16BE(versionMajor, 4)
    gh.writeUInt16BE(versionMinor, 6)
    gh.writeInt32BE(thiszone, 8)
    gh.writeUInt32BE(sigfigs, 12)
    gh.writeUInt32BE(snaplen, 16)
    gh.writeUInt32BE(linkType, 20)
  }

  const chunks = [gh]
  for (const rec of records) {
    const rh = b4a.alloc(16)
    const sec = rec.sec || 0
    const frac = rec.frac || 0
    const captured = rec.captured !== undefined ? rec.captured : rec.data.byteLength
    const original = rec.original !== undefined ? rec.original : rec.data.byteLength

    if (littleEndian) {
      rh.writeUInt32LE(sec, 0)
      rh.writeUInt32LE(frac, 4)
      rh.writeUInt32LE(captured, 8)
      rh.writeUInt32LE(original, 12)
    } else {
      rh.writeUInt32BE(sec, 0)
      rh.writeUInt32BE(frac, 4)
      rh.writeUInt32BE(captured, 8)
      rh.writeUInt32BE(original, 12)
    }
    chunks.push(rh)
    if (rec.data) {
      chunks.push(rec.data.subarray(0, captured))
    }
  }

  return b4a.concat(chunks)
}

function wrapEthernet(ipv4Buf, ethertype = 0x0800, paddingBytes = 0) {
  const eth = b4a.alloc(14 + ipv4Buf.byteLength + paddingBytes)
  // dst mac: 00:11:22:33:44:55
  // src mac: 66:77:88:99:aa:bb
  eth.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 0)
  eth.writeUInt16BE(ethertype, 12)
  eth.set(ipv4Buf, 14)
  return eth
}

test('readPcapPackets: valid little-endian microsecond pcap with Ethernet frame', (t) => {
  const ip = buildIpv4Packet({ protocol: 1 })
  const frame = wrapEthernet(ip, 0x0800, 4) // 4 bytes Ethernet padding
  const pcap = buildPcapFile({
    littleEndian: true,
    magic: 0xa1b2c3d4,
    linkType: 1,
    records: [{ sec: 1725500000, frac: 123456, data: frame }]
  })

  const packets = readPcapPackets(pcap)
  t.is(packets.length, 1)
  t.alike(packets[0].packet, ip)
  t.is(packets[0].timestampMicros, 1725500000 * 1000000 + 123456)
})

test('readPcapPackets: accepts large snaplen (e.g. 262144 from tcpdump -s 0)', (t) => {
  const ip = buildIpv4Packet({ protocol: 1 })
  const pcap = buildPcapFile({
    snaplen: 262144,
    linkType: 101,
    records: [{ sec: 100, frac: 50, data: ip }]
  })
  const packets = readPcapPackets(pcap)
  t.is(packets.length, 1)
  t.alike(packets[0].packet, ip)
})
test('readPcapPackets: valid big-endian nanosecond pcap with raw IPv4 frame', (t) => {
  const ip = buildIpv4Packet({ protocol: 6 }) // TCP

  const pcap = buildPcapFile({
    littleEndian: false,
    magic: 0xa1b23c4d,
    linkType: 101, // Raw IP
    records: [{ sec: 1725500000, frac: 500999, data: ip }]
  })

  const packets = readPcapPackets(pcap)
  t.is(packets.length, 1)
  t.alike(packets[0].packet, ip)
  t.is(packets[0].timestampMicros, 1725500000 * 1000000 + 500) // floor(500999 / 1000)
})

test('readPcapPackets: DF flag allowed, non-UDP protocols preserved', (t) => {
  const ipIcmp = buildIpv4Packet({ protocol: 1, flags: 0x4000 }) // DF set
  const ipOspf = buildIpv4Packet({ protocol: 89, flags: 0x4000 }) // OSPF
  const pcap = buildPcapFile({
    linkType: 101,
    records: [
      { sec: 1, frac: 100, data: ipIcmp },
      { sec: 2, frac: 200, data: ipOspf }
    ]
  })

  const packets = readPcapPackets(pcap)
  t.is(packets.length, 2)
  t.is(packets[0].packet[9], 1)
  t.is(packets[1].packet[9], 89)
})

test('readPcapPackets: reject truncated global header and malformed magic/version/snaplen/linktype', (t) => {
  t.exception(() => readPcapPackets(b4a.alloc(10)), /PCAP_TRUNCATED/)

  const badMagic = buildPcapFile()
  badMagic.writeUInt32LE(0xdeadbeef, 0)
  t.exception(() => readPcapPackets(badMagic), /PCAP_MAGIC_INVALID/)

  const badVer = buildPcapFile({ versionMajor: 2, versionMinor: 3 })
  t.exception(() => readPcapPackets(badVer), /PCAP_VERSION_UNSUPPORTED/)

  const badSnaplen = buildPcapFile({ snaplen: 0 })
  t.exception(() => readPcapPackets(badSnaplen), /PCAP_SNAPLEN_INVALID/)

  const badLink = buildPcapFile({ linkType: 105 })
  t.exception(() => readPcapPackets(badLink), /PCAP_LINKTYPE_UNSUPPORTED/)
})

test('readPcapPackets: reject record truncation and snaplen overflow', (t) => {
  const ip = buildIpv4Packet()
  const pcapOk = buildPcapFile({
    linkType: 101,
    records: [{ sec: 1, frac: 10, data: ip }]
  })

  // Partial record header
  t.exception(() => readPcapPackets(pcapOk.subarray(0, 24 + 10)), /PCAP_TRUNCATED/)

  // Partial record body
  t.exception(() => readPcapPackets(pcapOk.subarray(0, pcapOk.byteLength - 2)), /PCAP_TRUNCATED/)

  // Capture truncation (captured != original)
  const pcapTruncCap = buildPcapFile({
    linkType: 101,
    records: [{ sec: 1, frac: 10, captured: 10, original: 20, data: ip }]
  })
  t.exception(() => readPcapPackets(pcapTruncCap), /PCAP_CAPTURE_TRUNCATED/)

  // Captured length exceeding snaplen
  const pcapSnapOverflow = buildPcapFile({
    snaplen: 100,
    linkType: 101,
    records: [{ sec: 1, frac: 10, captured: 120, original: 120, data: b4a.alloc(120) }]
  })
  t.exception(() => readPcapPackets(pcapSnapOverflow), /PCAP_RECORD_SNAPLEN_EXCEEDED/)
})

test('readPcapPackets: reject invalid timestamp fraction', (t) => {
  const ip = buildIpv4Packet()
  const pcapMicrosBad = buildPcapFile({
    magic: 0xa1b2c3d4,
    linkType: 101,
    records: [{ sec: 1, frac: 1000000, data: ip }]
  })
  t.exception(() => readPcapPackets(pcapMicrosBad), /PCAP_TIME_FRACTION_INVALID/)

  const pcapNanosBad = buildPcapFile({
    magic: 0xa1b23c4d,
    linkType: 101,
    records: [{ sec: 1, frac: 1000000000, data: ip }]
  })
  t.exception(() => readPcapPackets(pcapNanosBad), /PCAP_TIME_FRACTION_INVALID/)
})

test('readPcapPackets: reject non-IPv4 ethertype or truncated ethernet frame', (t) => {
  const ip = buildIpv4Packet()
  const pcapTruncEth = buildPcapFile({
    linkType: 1,
    records: [{ sec: 1, frac: 1, data: b4a.alloc(10) }]
  })
  t.exception(() => readPcapPackets(pcapTruncEth), /PCAP_FRAME_TRUNCATED/)

  const arpFrame = wrapEthernet(b4a.alloc(28), 0x0806)
  const pcapArp = buildPcapFile({
    linkType: 1,
    records: [{ sec: 1, frac: 1, data: arpFrame }]
  })
  t.exception(() => readPcapPackets(pcapArp), /PCAP_NON_IPV4/)
})

test('readPcapPackets: reject IPv4 header invalidity, checksum mismatch, and fragments', (t) => {
  // Version != 4 (IPv6 in IPv4 linktype)
  const badVer = buildIpv4Packet()
  badVer[0] = (6 << 4) | 5
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: badVer }] })),
    /PCAP_NON_IPV4/
  )

  // IHL < 5
  const badIhl = buildIpv4Packet()
  badIhl[0] = (4 << 4) | 4
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: badIhl }] })),
    /PCAP_IPV4_INVALID/
  )

  // Total length > captured network bytes
  const badTotal = buildIpv4Packet({ totalLength: 100, payload: b4a.alloc(10) })
  // Total length in header is 100, but buffer is only 20 + 10 = 30
  t.exception(
    () =>
      readPcapPackets(
        buildPcapFile({ linkType: 101, records: [{ captured: 30, original: 30, data: badTotal }] })
      ),
    /PCAP_IPV4_TRUNCATED/
  )

  // Checksum mismatch
  const badCsum = buildIpv4Packet()
  badCsum[10] ^= 0xff
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: badCsum }] })),
    /PCAP_IPV4_CHECKSUM_INVALID/
  )

  // Reserved bit set
  const resBit = buildIpv4Packet({ flags: 0x8000 })
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: resBit }] })),
    /PCAP_IPV4_FRAGMENTED/
  )

  // More Fragments (MF) set
  const mfBit = buildIpv4Packet({ flags: 0x2000 })
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: mfBit }] })),
    /PCAP_IPV4_FRAGMENTED/
  )

  // Fragment offset > 0
  const fragOff = buildIpv4Packet({ flags: 0x0001 })
  t.exception(
    () => readPcapPackets(buildPcapFile({ linkType: 101, records: [{ data: fragOff }] })),
    /PCAP_IPV4_FRAGMENTED/
  )
})

test('readPcapPackets: IP trailing bytes cannot be hidden as Ethernet padding', (t) => {
  const ip = buildIpv4Packet()
  const raw = b4a.concat([ip, b4a.from([0])])
  t.exception(
    () =>
      readPcapPackets(
        buildPcapFile({
          linkType: 101,
          records: [{ data: raw }]
        })
      ),
    /PCAP_IPV4_TRAILING_BYTES/
  )
  const excessive = wrapEthernet(ip, 0x0800, 19)
  t.exception(
    () =>
      readPcapPackets(
        buildPcapFile({
          records: [{ data: excessive }]
        })
      ),
    /PCAP_IPV4_TRAILING_BYTES/
  )
  const nonzero = wrapEthernet(ip, 0x0800, 4)
  nonzero[nonzero.byteLength - 1] = 1
  t.exception(
    () =>
      readPcapPackets(
        buildPcapFile({
          records: [{ data: nonzero }]
        })
      ),
    /PCAP_IPV4_TRAILING_BYTES/
  )
})
