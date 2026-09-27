'use strict'

const UDX = require('udx-native')

function normalize(host) {
  if (!host || host === '::ffff:127.0.0.1') return '127.0.0.1'
  return host.toLowerCase().replace(/^::ffff:/, '')
}

// Install before creating the testnet. Native stream associations complement the
// datagram hooks; this is an attempted-send oracle, not independent packet capture.
module.exports = function observeUDP() {
  const sockets = []
  const attempts = []
  const restore = []
  let phase = 'setup'
  let generation = 0

  function wrap(object, name, replacement) {
    const original = object[name]
    object[name] = replacement(original)
    restore.push(() => {
      object[name] = original
    })
  }

  function record(udx, socket, method, port, host) {
    host = normalize(host)
    const row = { udx, socket, method, port, host, phase, ordinal: attempts.length }
    attempts.push(row)
    if (host !== '127.0.0.1' && host !== '::1') {
      throw new Error('Nonlocal UDP attempt: ' + host + ':' + port)
    }
  }

  wrap(
    UDX.prototype,
    'createSocket',
    (original) =>
      function (...args) {
        const socket = original.apply(this, args)
        const row = { socket, udx: this, generation: ++generation, tuples: [] }
        sockets.push(row)
        wrap(
          socket,
          'bind',
          (bind) =>
            function (...args) {
              const result = bind.apply(this, args)
              const address = this.address()
              row.tuples.push({
                host: normalize(address.host),
                port: address.port,
                start: attempts.length,
                end: Infinity
              })
              return result
            }
        )
        socket.once('close', () => {
          for (const tuple of row.tuples) tuple.end = attempts.length
        })
        for (const name of ['send', 'trySend']) {
          wrap(
            socket,
            name,
            (send) =>
              function (packet, port, host, ...args) {
                record(this.udx, this, name, port, host)
                return send.call(this, packet, port, host, ...args)
              }
          )
        }
        return socket
      }
  )

  wrap(
    UDX.prototype,
    'createStream',
    (original) =>
      function (...args) {
        const stream = original.apply(this, args)
        for (const name of ['connect', 'changeRemote']) {
          wrap(
            stream,
            name,
            (connect) =>
              function (socket, remoteId, port, host, ...rest) {
                record(this.udx, socket, name, port, typeof host === 'object' ? null : host)
                return connect.call(this, socket, remoteId, port, host, ...rest)
              }
          )
        }
        wrap(
          stream,
          'relayTo',
          (relayTo) =>
            function (destination) {
              record(
                this.udx,
                this.socket,
                'relayTo',
                destination.remotePort,
                destination.remoteHost
              )
              return relayTo.call(this, destination)
            }
        )
        for (const name of ['send', 'trySend', '_writev', '_final']) {
          wrap(
            stream,
            name,
            (send) =>
              function (...rest) {
                if (this.remotePort)
                  record(this.udx, this.socket, 'stream.' + name, this.remotePort, this.remoteHost)
                return send.apply(this, rest)
              }
          )
        }
        return stream
      }
  )

  function forbidden(source, destination, selectedPhase = null) {
    return attempts
      .filter(
        (attempt) =>
          attempt.udx === source.udx &&
          (selectedPhase === null || attempt.phase === selectedPhase) &&
          sockets.some(
            (row) =>
              row.udx === destination.udx &&
              row.tuples.some(
                (tuple) =>
                  tuple.port === attempt.port &&
                  attempt.ordinal >= tuple.start &&
                  attempt.ordinal < tuple.end &&
                  (tuple.host === attempt.host || tuple.host === '0.0.0.0' || tuple.host === '::')
              )
          )
      )
      .map(({ udx, socket, ...row }) => row)
  }

  return {
    sockets,
    attempts,
    phase(value) {
      phase = value
    },
    forbidden,
    assertNoDirect(source, destination, selectedPhase = null) {
      const violations = forbidden(source, destination, selectedPhase)
      if (violations.length)
        throw new Error('Forbidden destination UDP attempts: ' + JSON.stringify(violations))
    },
    restore() {
      for (const undo of restore.reverse()) undo()
    }
  }
}
