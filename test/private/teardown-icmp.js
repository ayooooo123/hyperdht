'use strict'

const test = require('brittle')
const b4a = require('b4a')
const { reconcileTeardownIcmp } = require('./process/teardown-icmp')

function computeIpv4HeaderChecksum(header) {
  let sum = 0
  for (let i = 0; i < header.byteLength; i += 2) {
    if (i === 10) continue
    sum += header.readUInt16BE(i)
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return ~sum & 0xffff
}

function computeChecksum(buf) {
  let sum = 0
  for (let i = 0; i < buf.byteLength - 1; i += 2) {
    sum += buf.readUInt16BE(i)
  }
  if (buf.byteLength % 2 === 1) {
    sum += buf[buf.byteLength - 1] << 8
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return ~sum & 0xffff
}

function buildUdpPacket({
  src = [10, 203, 1, 2],
  dst = [10, 203, 2, 2],
  srcPort = 42001,
  dstPort = 42002,
  payload = b4a.alloc(1200, 0xaa)
} = {}) {
  const ipHeaderLen = 20
  const udpHeaderLen = 8
  const totalLength = ipHeaderLen + udpHeaderLen + payload.byteLength
  const buf = b4a.alloc(totalLength)

  buf[0] = 0x45 // IPv4, IHL=5
  buf[1] = 0
  buf.writeUInt16BE(totalLength, 2)
  buf.writeUInt16BE(0x1111, 4)
  buf.writeUInt16BE(0, 6)
  buf[8] = 64
  buf[9] = 17 // UDP
  buf.set(src, 12)
  buf.set(dst, 16)

  const ipCsum = computeIpv4HeaderChecksum(buf.subarray(0, 20))
  buf.writeUInt16BE(ipCsum, 10)

  buf.writeUInt16BE(srcPort, 20)
  buf.writeUInt16BE(dstPort, 22)
  buf.writeUInt16BE(udpHeaderLen + payload.byteLength, 24)
  buf.writeUInt16BE(0, 26) // optional UDP checksum zero
  buf.set(payload, 28)

  return buf
}

function buildIcmpTeardownPacket({
  src = [10, 203, 2, 2],
  dst = [10, 203, 1, 2],
  type = 3,
  code = 3,
  reserved = [0, 0, 0, 0],
  quotedUdpPacket,
  quoteLength = 548, // e.g. Linux 576 outer length quotes 548 bytes of IP+UDP+payload
  corruptIcmpChecksum = false
} = {}) {
  const ipHeaderLen = 20
  const icmpHeaderLen = 8
  const quoted = quotedUdpPacket.subarray(0, Math.min(quoteLength, quotedUdpPacket.byteLength))
  const totalLength = ipHeaderLen + icmpHeaderLen + quoted.byteLength
  const buf = b4a.alloc(totalLength)

  buf[0] = 0x45 // IPv4, IHL=5
  buf[1] = 0
  buf.writeUInt16BE(totalLength, 2)
  buf.writeUInt16BE(0x2222, 4)
  buf.writeUInt16BE(0, 6)
  buf[8] = 64
  buf[9] = 1 // ICMP
  buf.set(src, 12)
  buf.set(dst, 16)

  const ipCsum = computeIpv4HeaderChecksum(buf.subarray(0, 20))
  buf.writeUInt16BE(ipCsum, 10)

  buf[20] = type
  buf[21] = code
  buf.writeUInt16BE(0, 22) // checksum placeholder
  buf.set(reserved, 24)
  buf.set(quoted, 28)

  const icmpCsum = corruptIcmpChecksum ? 0x1234 : computeChecksum(buf.subarray(20))
  buf.writeUInt16BE(icmpCsum, 22)

  return buf
}

function fixture() {
  const udp = buildUdpPacket()
  const icmp = buildIcmpTeardownPacket({ quotedUdpPacket: udp })
  // The complete key set returned by namespace-provisioner: eleven roles and
  // the two marker devices (deviceKey maps auditor/decoy to a/d).
  const captures = [...Array.from({ length: 11 }, (_, i) => String(i + 1)), 'a', 'd'].map(
    (key) => ({ key, records: [] })
  )
  captures[1].records.push(
    { packet: udp, timestampMicros: 1000 },
    { packet: icmp, timestampMicros: 2000 }
  )
  const firewall = [
    {
      protocol: 'udp',
      source: '10.203.1.2',
      destination: '10.203.2.2',
      sourcePort: 42001,
      destinationPort: 42002,
      ingress: 'pr-veth-1',
      egress: 'pr-veth-2'
    }
  ]
  const closes = new Map([
    [
      '2',
      [
        {
          host: '10.203.2.2',
          port: 42002,
          startMicros: 1500,
          endMicros: 2500
        }
      ]
    ]
  ])
  return { captures, firewall, closes, until: 3000, raw: 1, udp, icmp }
}

function verify(f) {
  return reconcileTeardownIcmp(f.captures, f.firewall, f.closes, f.until, f.raw)
}

function reject(t, change) {
  const f = fixture()
  change(f)
  t.exception(() => verify(f), /ERR_TEARDOWN_ICMP/)
}

function repairIcmp(packet) {
  packet.writeUInt16BE(0, 22)
  packet.writeUInt16BE(computeChecksum(packet.subarray(20)), 22)
}

test('teardown ICMP: full capture set accepts a truncated quote during native close', (t) => {
  const f = fixture()
  // This arrives before native close completion and before the later closed
  // control event. Coordinator-receipt timing cannot qualify this real race.
  t.alike(verify(f), { rawDrop: 1, classifiedTeardownIcmp: 1 })
  f.closes.get('2')[0].endMicros = 1800
  t.alike(verify(f), { rawDrop: 1, classifiedTeardownIcmp: 1 })
})

test('teardown ICMP: marker UDP is audited but marker ICMP never qualifies', (t) => {
  const f = fixture()
  f.captures[11].records.push({
    packet: buildUdpPacket({
      src: [10, 204, 1, 2],
      dst: [10, 204, 2, 2],
      srcPort: 42990,
      dstPort: 42991
    }),
    timestampMicros: 900
  })
  t.alike(verify(f), { rawDrop: 1, classifiedTeardownIcmp: 1 })
  f.captures[11].records.push({ packet: f.icmp, timestampMicros: 2000 })
  f.raw = 2
  t.exception(() => verify(f), /ERR_TEARDOWN_ICMP/)
  reject(t, (f) => {
    f.captures[12].records.push({ packet: f.icmp, timestampMicros: 2000 })
  })
})

test('teardown ICMP: altered quote bytes and extra bytes cannot hide in checksums', (t) => {
  reject(t, (f) => {
    f.icmp[70] ^= 1
    repairIcmp(f.icmp)
  })
  reject(t, (f) => {
    const extended = b4a.concat([f.icmp, b4a.from([0x7f])])
    extended.writeUInt16BE(extended.byteLength, 2)
    extended.writeUInt16BE(computeIpv4HeaderChecksum(extended.subarray(0, 20)), 10)
    repairIcmp(extended)
    f.captures[1].records[1].packet = extended
  })
  reject(t, (f) => {
    f.icmp[28 + 10] ^= 1
    repairIcmp(f.icmp)
  })
})

test('teardown ICMP: checksums, type, reserved bytes, and IP protocol are enforced', (t) => {
  reject(t, (f) => {
    f.icmp[22] ^= 1
  })
  reject(t, (f) => {
    f.icmp[20] = 8
    repairIcmp(f.icmp)
  })
  reject(t, (f) => {
    f.icmp[24] = 1
    repairIcmp(f.icmp)
  })
  reject(t, (f) => {
    f.icmp[9] = 6
    f.icmp.writeUInt16BE(computeIpv4HeaderChecksum(f.icmp.subarray(0, 20)), 10)
  })
})

test('teardown ICMP: exact firewall edge, origin veth, and socket identity are required', (t) => {
  reject(t, (f) => {
    f.firewall[0].destinationPort++
  })
  reject(t, (f) => {
    f.firewall[0].protocol = 'tcp'
  })
  reject(t, (f) => {
    f.firewall[0].egress = 'pr-veth-3'
  })
  reject(t, (f) => {
    f.closes.get('2')[0].port++
  })
  reject(t, (f) => {
    f.icmp[12] ^= 1
    f.icmp.writeUInt16BE(computeIpv4HeaderChecksum(f.icmp.subarray(0, 20)), 10)
  })
})

test('teardown ICMP: missing, future, and pre-close evidence fails closed', (t) => {
  reject(t, (f) => {
    f.closes.clear()
  })
  reject(t, (f) => {
    f.closes.get('2')[0].startMicros = 2100
  })
  reject(t, (f) => {
    f.closes.get('2')[0].endMicros = 3100
  })
  reject(t, (f) => {
    f.closes.get('2')[0].endMicros = 1400
  })
  reject(t, (f) => {
    f.captures[1].records[1].timestampMicros = 3001
  })
})

test('teardown ICMP: provenance must be earlier on the same captured edge', (t) => {
  reject(t, (f) => {
    f.captures[1].records.shift()
  })
  reject(t, (f) => {
    f.captures[0].records.push(f.captures[1].records.shift())
  })
  reject(t, (f) => {
    f.captures[1].records[0].timestampMicros = 2000
  })
})

test('teardown ICMP: unrelated timestamp regressions do not change quote proof', (t) => {
  const f = fixture()
  const earlier = {
    packet: buildUdpPacket({ payload: b4a.alloc(1200, 0xbb) }),
    timestampMicros: 900
  }
  f.captures[1].records.splice(1, 0, earlier)
  t.alike(verify(f), { rawDrop: 1, classifiedTeardownIcmp: 1 })
  // Duplicate detection spans intervening records with a different timestamp.
  f.captures[1].records.push(
    { packet: buildUdpPacket({ payload: b4a.alloc(1200, 0xcc) }), timestampMicros: 1500 },
    f.captures[1].records[2]
  )
  f.raw = 2
  t.exception(() => verify(f), /ERR_TEARDOWN_ICMP/)
})

test('teardown ICMP: a later identical UDP record cannot replace earlier evidence', (t) => {
  const f = fixture()
  // The only matching UDP record is later in the file, despite its lower time.
  f.captures[1].records.reverse()
  t.exception(() => verify(f), /ERR_TEARDOWN_ICMP/)
})

test('teardown ICMP: duplicated captures or packets cannot inflate reconciliation', (t) => {
  reject(t, (f) => {
    f.captures.push(f.captures[1])
    f.raw = 2
  })
  reject(t, (f) => {
    f.captures[1].records.push(f.captures[1].records[1])
    f.raw = 2
  })
})

test('teardown ICMP: raw counters must agree in both directions', (t) => {
  reject(t, (f) => {
    f.raw = 0
  })
  reject(t, (f) => {
    f.raw = 2
  })
  const f = fixture()
  f.captures[1].records.pop()
  f.raw = 0
  t.alike(verify(f), { rawDrop: 0, classifiedTeardownIcmp: 0 })
})

test('native close still releases its port when audit timing fails', (t) => {
  // Isolate clock injection from all other aggregate tests and native owners.
  const { spawnSync } = require('child_process')
  const observer = require.resolve('./process/socket-close-observer')
  const script = `
    const fs = require('fs')
    const os = require('os')
    const path = require('path')
    const UDX = require('udx-native')
    const observe = require(${JSON.stringify(observer)})
    ;(async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr-close-regression-'))
      try {
        const finish = observe(UDX, () => true, path.join(dir, 'closes.json'))
        const socket = new UDX().createSocket()
        socket.bind(0, '127.0.0.1')
        const { port } = socket.address()
        const now = Date.now
        Date.now = () => now() + 100
        try { await socket.close() } finally { Date.now = now }
        let auditRefused = false
        try { finish() } catch { auditRefused = true }
        const replacement = new UDX().createSocket()
        replacement.bind(port, '127.0.0.1')
        const portReleased = replacement.address().port === port
        await replacement.close()
        console.log(JSON.stringify({ portReleased, auditRefused }))
      } finally { fs.rmSync(dir, { recursive: true, force: true }) }
    })().catch(err => { console.error(err); process.exit(1) })
  `
  const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 10000 })
  t.is(result.status, 0, result.stderr || 'native close completes despite audit failure')
  if (result.status === 0) {
    t.alike(JSON.parse(result.stdout), { portReleased: true, auditRefused: true })
  }
})
