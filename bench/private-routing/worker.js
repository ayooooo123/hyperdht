'use strict'

const process = require('process')
const b4a = require('b4a')
const installDelay = require('./delay')
const {
  now,
  deferred,
  deadline,
  payload,
  writeControl,
  writePayload,
  track
} = require('./protocol')

const config = JSON.parse(process.argv[2])
const latency = installDelay(config.delayMs)
const DHT = require('../..')
let node = null
let server = null
let trial = null
let cpuMark = null
let stopping = false
const active = new Set()
const serving = new Set()
const connections = []

function tracked(stream) {
  const connection = track(stream)
  active.add(connection)
  stream.once('close', () => active.delete(connection))
  return connection
}

function failure(error, reader = null) {
  return { ok: false, error: error.code || error.message, bytes: reader ? reader.bytes : 0 }
}

function receipt(value, index) {
  if (
    !value ||
    value.id !== trial.id ||
    value.index !== index ||
    value.bytes !== trial.size ||
    value.ok !== true
  ) {
    throw new Error('invalid payload verification receipt')
  }
  return value
}

async function serve(connection) {
  const { stream, reader, closed } = connection
  let index = -1
  let result = null
  try {
    const request = await reader.control()
    if (
      !request ||
      request.id !== trial.id ||
      !Number.isInteger(request.index) ||
      request.index < 0 ||
      request.index >= trial.streams ||
      trial.accepted.has(request.index)
    ) {
      throw new Error('unexpected benchmark stream')
    }
    index = request.index
    trial.accepted.add(index)
    const data = trial.data[index]
    await writeControl(stream, { ready: true, id: trial.id, index })
    const command = await reader.control()
    if (command.start !== true) throw new Error('invalid start command')
    if (trial.direction === 'up') {
      const received = await reader.payload(
        data,
        trial.ping ? () => writePayload(stream, data) : null
      )
      result = { ok: true, id: trial.id, index, ...received }
      if (!trial.ping) {
        await writeControl(stream, result)
      }
    } else {
      const startNs = now().toString()
      await writePayload(stream, data)
      if (trial.ping) {
        result = { ok: true, startNs, ...(await reader.payload(data)) }
      } else {
        const ack = receipt(await reader.control(), index)
        result = { ...ack, startNs }
      }
    }
  } catch (error) {
    result = failure(error, reader)
    stream.destroy()
    await closed.catch(() => {})
  }
  if (index >= 0) trial.results[index].resolve(result)
  else trial.errors.push(result.error)
}

async function closeStreams() {
  const pending = [...active]
  for (const { stream } of pending) stream.destroy()
  await Promise.allSettled(pending.map((connection) => connection.closed))
  await Promise.allSettled([...serving])
  connections.length = 0
}

async function transfer(connection, index) {
  const { stream, reader, closed } = connection
  const data = trial.data[index]
  try {
    await writeControl(stream, { start: true })
    let result
    if (trial.direction === 'up') {
      const startNs = now().toString()
      await writePayload(stream, data)
      if (trial.ping) {
        result = { ok: true, startNs, ...(await reader.payload(data)) }
      } else {
        result = { ...receipt(await reader.control(), index), startNs }
      }
    } else {
      const received = await reader.payload(
        data,
        trial.ping ? () => writePayload(stream, data) : null
      )
      result = { ok: true, id: trial.id, index, ...received }
      if (!trial.ping) {
        await writeControl(stream, result)
      }
    }
    return result
  } catch (error) {
    stream.destroy()
    await closed.catch(() => {})
    return failure(error, reader)
  }
}

const operations = {
  async start() {
    node = new DHT({
      bootstrap: config.bootstrap,
      host: '127.0.0.1',
      ephemeral: false,
      firewalled: false,
      privateRouting: {
        release: 'alpha',
        acknowledgeAlpha: true,
        profile: 'standard',
        mode: 'optional',
        relay: config.role === 'relay'
      }
    })
    await node.ready()
    await node.privateRouting.ready()
    return { pid: process.pid, address: node.address(), role: config.role }
  },

  async prepare(options) {
    await closeStreams()
    if (server) await server.close()
    server = null
    trial = {
      ...options,
      data: Array.from({ length: options.streams }, (_, index) =>
        payload(options.id, index, options.size)
      ),
      results: Array.from({ length: options.streams }, () => deferred()),
      accepted: new Set(),
      errors: []
    }
    if (config.role !== 'destination') return true
    const onconnection = (stream) => {
      const connection = tracked(stream)
      const task = serve(connection)
      serving.add(task)
      task.finally(() => serving.delete(task)).catch(() => {})
    }
    server =
      options.mode === 'direct'
        ? node.createServer(onconnection)
        : node.privateRouting.createServer(onconnection)
    const keyPair = DHT.keyPair()
    await server.listen(keyPair)
    return { key: b4a.toString(keyPair.publicKey, 'hex') }
  },

  async connect({ key }) {
    const builds = []
    for (let index = 0; index < trial.streams; index++) {
      const start = now()
      const publicKey = b4a.from(key, 'hex')
      const stream =
        trial.mode === 'direct' ? node.connect(publicKey) : node.privateRouting.connect(publicKey)
      const connection = tracked(stream)
      let build = null
      try {
        if ((await deadline(stream.opened, config.timeout, 'connection open')) !== true) {
          throw new Error('connection did not open')
        }
        build = { ok: true, ms: Number(now() - start) / 1e6 }
        await writeControl(stream, { id: trial.id, index })
        const ready = await deadline(connection.reader.control(), config.timeout, 'stream ready')
        if (ready.ready !== true || ready.id !== trial.id || ready.index !== index) {
          throw new Error('invalid stream readiness reply')
        }
        connections.push(connection)
      } catch (error) {
        if (build === null) build = { ok: false, error: error.code || error.message }
        build.readyError = error.code || error.message
        stream.destroy()
        await connection.closed.catch(() => {})
      }
      builds.push(build)
    }
    return { builds, ready: connections.length === trial.streams }
  },

  async run() {
    if (connections.length !== trial.streams) throw new Error('not all streams are ready')
    return Promise.all(connections.map(transfer))
  },

  async collect() {
    return {
      streams: await Promise.all(trial.results.map((result) => result.promise)),
      errors: trial.errors
    }
  },

  cpuBegin() {
    cpuMark = process.cpuUsage()
    return true
  },

  cpuEnd() {
    const cpu = process.cpuUsage(cpuMark)
    return { pid: process.pid, ms: (cpu.user + cpu.system) / 1000, latency: { ...latency.stats } }
  },

  delayStats() {
    return { scope: 'process-cumulative', ...latency.stats }
  },

  async abort() {
    await closeStreams()
    return true
  },

  async stop() {
    if (stopping) return true
    stopping = true
    await closeStreams()
    if (server) await server.close()
    if (node) await node.destroy({ force: true })
    latency.close()
    return true
  }
}

process.on('message', async ({ id, op, args }) => {
  try {
    const result = await deadline(operations[op](args || {}), config.timeout, op)
    process.send({ id, result })
  } catch (error) {
    for (const { stream } of active) stream.destroy()
    process.send({ id, error: error.stack || error.message })
  }
  if (op === 'stop') process.disconnect()
})

process.on('disconnect', () => {
  operations.stop().catch(() => {
    process.exitCode = 1
  })
})

process.send({ hello: true })
