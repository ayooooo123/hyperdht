const test = require('brittle')
const net = require('net')
const socks5Connect = require('../lib/socks5')

// A no-auth SOCKS5 proxy that CONNECTs to the requested domain:port and pipes.
function mockProxy() {
  const server = net.createServer((client) => {
    let stage = 'greeting'
    let bufs = []

    client.on('data', (d) => {
      bufs.push(d)
      let b = Buffer.concat(bufs)

      if (stage === 'greeting') {
        if (b.length < 2) return
        const glen = 2 + b[1]
        if (b.length < glen) return
        client.write(Buffer.from([0x05, 0x00]))
        stage = 'request'
        b = b.subarray(glen)
        bufs = b.length ? [b] : []
      }

      if (stage === 'request') {
        b = Buffer.concat(bufs)
        if (b.length < 5) return
        const len = b[4]
        const total = 4 + 1 + len + 2
        if (b.length < total) return
        const host = b.subarray(5, 5 + len).toString()
        const port = b.readUInt16BE(5 + len)
        stage = 'done'
        const up = net.connect(port, host, () => {
          client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
          const rest = b.subarray(total)
          if (rest.length) up.write(rest)
          client.pipe(up)
          up.pipe(client)
        })
        up.on('error', () => client.destroy())
      }
    })
  })

  return server
}

test('socks5 CONNECT tunnels to the destination', async (t) => {
  const target = net.createServer((s) =>
    s.on('data', (d) => s.write(Buffer.concat([Buffer.from('T:'), d])))
  )
  await new Promise((r) => target.listen(0, '127.0.0.1', r))

  const proxy = mockProxy()
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r))

  const socket = await socks5Connect({
    proxyHost: '127.0.0.1',
    proxyPort: proxy.address().port,
    destHost: '127.0.0.1',
    destPort: target.address().port
  })

  const reply = await new Promise((resolve, reject) => {
    socket.on('error', reject)
    socket.on('data', (d) => resolve(d.toString()))
    socket.write(Buffer.from('ping'))
  })

  t.is(reply, 'T:ping', 'bytes flow end to end through the SOCKS5 tunnel')

  socket.destroy()
  await new Promise((r) => proxy.close(r))
  await new Promise((r) => target.close(r))
})

test('socks5 surfaces a failing CONNECT reply', async (t) => {
  const proxy = net.createServer((client) => {
    let stage = 'greeting'
    let bufs = []
    client.on('data', (d) => {
      bufs.push(d)
      let b = Buffer.concat(bufs)

      if (stage === 'greeting') {
        if (b.length < 2) return
        client.write(Buffer.from([0x05, 0x00])) // accept greeting
        stage = 'request'
        b = b.subarray(2 + b[1])
        bufs = b.length ? [b] : []
      }

      if (stage === 'request' && Buffer.concat(bufs).length >= 5) {
        stage = 'done'
        // reply: host unreachable
        client.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
      }
    })
  })
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r))

  await t.exception(
    socks5Connect({
      proxyHost: '127.0.0.1',
      proxyPort: proxy.address().port,
      destHost: 'unreachable.onion',
      destPort: 8080,
      timeout: 5000
    }),
    /host unreachable/
  )

  await new Promise((r) => proxy.close(r))
})
