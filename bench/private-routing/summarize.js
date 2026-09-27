'use strict'

function median(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b)
  if (sorted.length === 0) return null
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid]
}

function text(value) {
  return String(value)
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ')
}

function cell(rows, value) {
  const values = rows.map(value).filter(Number.isFinite)
  const result = median(values)
  return (
    (result === null ? '—' : result.toFixed(2)) + ' (' + values.length + '/' + rows.length + ')'
  )
}

module.exports = function summarize(all) {
  const samples = all.filter((row) => row.kind === 'sample')
  if (samples.length === 0) return
  const environment = all.find((row) => row.kind === 'environment')
  console.log('# Direct vs alpha: local-testnet benchmark of the current checkout')
  console.log('')
  console.log(
    'Medians; parentheses show successful measurements / attempts, separately in each direction.'
  )
  console.log(
    'Up = source → destination; down = destination → source, on source-opened connections.'
  )
  console.log(
    'Each attempt publishes a new server through the public API; no in-flight refresh or retry.'
  )
  console.log(
    'Build = connect() → opened, excluding server publication and benchmark readiness framing.'
  )
  console.log(
    'First byte = first verified payload chunk after the sender starts writing on an open stream.'
  )
  console.log(
    'Ping = one verified 64-byte echo round trip on an open stream with explicit finish framing.'
  )
  console.log(
    'Throughput spans earliest payload send to latest payload receipt; exact bytes and finish frames must verify.'
  )
  console.log(
    'Failed/incomplete transfers have no throughput or CPU/MiB value, even if some streams finish.'
  )
  console.log(
    'Relay CPU is the sum of six separate processes, including background work and measurement IPC.'
  )
  console.log(
    'Direct relay CPU is idle/background cost, not direct-path forwarding; no baseline is subtracted.'
  )
  console.log(
    'The 5 ms condition delays each UDX write batch at every endpoint/relay, with original backpressure.'
  )
  console.log(
    'This bounded application-send/UDX-write latency is not WAN/netem: UDP discovery, ACKs and retransmits are not delayed.'
  )
  console.log(
    'The delay queue is limited to 2 MiB / 256 pending writes per process; overflow fails the stream.'
  )
  console.log('')
  if (environment) {
    console.log(
      'Environment: ' +
        environment.node +
        ', ' +
        environment.platform +
        '/' +
        environment.arch +
        ', ' +
        environment.cpus +
        ' logical CPUs; ' +
        environment.options.reps +
        ' repetitions per condition/direction.'
    )
    console.log('')
  }
  console.log('| Metric | Direction | Direct | Alpha |')
  console.log('| --- | --- | ---: | ---: |')
  const groups = new Map()
  for (const sample of samples) {
    const key = sample.scenario + '/' + sample.delayMs + '/' + sample.direction
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(sample)
  }
  for (const rows of groups.values()) {
    const { scenario, direction, delayMs } = rows[0]
    const suffix = delayMs === 5 ? ', 5 ms UDX-write latency' : ''
    const direct = rows.filter((row) => row.mode === 'direct')
    const alpha = rows.filter((row) => row.mode === 'alpha')
    const output = (label, value) => {
      console.log(
        '| ' + [label, direction, cell(direct, value), cell(alpha, value)].join(' | ') + ' |'
      )
    }
    if (scenario === 'probe') {
      output('Build (ms)', (row) => (row.builds[0] && row.builds[0].ok ? row.builds[0].ms : null))
      output('First byte, 64 B (ms)', (row) => (row.ok ? row.firstByteMs[0] : null))
    } else if (scenario === 'ping') {
      output('64-byte ping (ms)' + suffix, (row) => (row.ok ? row.pingMs : null))
    } else {
      const label = scenario === '4x4mib' ? '4 concurrent × 4 MiB' : rows[0].size / 1048576 + ' MiB'
      output(label + ' (MiB/s)' + suffix, (row) => (row.ok ? row.mibPerSecond : null))
      output(label + ' relay CPU (ms/MiB)' + suffix, (row) =>
        row.ok ? row.relayCpuMsPerMiB : null
      )
    }
  }
  console.log('')
  console.log('## Verified attempts')
  console.log('')
  for (const mode of ['direct', 'alpha']) {
    for (const direction of ['up', 'down']) {
      const rows = samples.filter((row) => row.mode === mode && row.direction === direction)
      if (rows.length === 0) continue
      console.log(
        '- ' +
          mode +
          ' ' +
          direction +
          ': ' +
          rows.filter((row) => row.ok).length +
          '/' +
          rows.length
      )
    }
  }
  const failed = samples.filter((row) => !row.ok)
  console.log('')
  console.log('## Failed attempts (' + failed.length + ')')
  console.log('')
  if (failed.length === 0) console.log('None.')
  else {
    console.log(
      '| Mode | Condition | Direction | Repetition | Phase | Verified payload bytes by receiver | Error |'
    )
    console.log('| --- | --- | --- | ---: | --- | --- | --- |')
    for (const row of failed) {
      const received =
        row.direction === 'up' ? row.destination && row.destination.streams : row.source
      const bytes = received ? received.map((result) => result.bytes).join(', ') : 'unavailable'
      const errors = row.errors.concat(
        row.builds.flatMap((build) => (build.readyError ? [build.readyError] : []))
      )
      console.log(
        '| ' +
          [
            row.mode,
            row.scenario + ', ' + row.delayMs + ' ms',
            row.direction,
            row.rep,
            row.phase,
            bytes,
            errors.join('; ')
          ]
            .map(text)
            .join(' | ') +
          ' |'
      )
    }
  }
  const cleanup = all
    .filter((row) => row.kind === 'cleanup')
    .flatMap((row) => row.workers)
    .filter((worker) => worker.forced || worker.code !== 0 || worker.error)
  const cpuErrors = samples.flatMap((row) => (row.relayCpu || []).filter((cpu) => cpu.error))
  const trialCleanupErrors = samples.flatMap((row) => row.cleanupErrors || [])
  if (cleanup.length || cpuErrors.length || trialCleanupErrors.length) {
    console.log('')
    console.log('## Measurement/cleanup failures')
    console.log('')
    for (const error of [...cleanup, ...cpuErrors, ...trialCleanupErrors]) {
      console.log('- ' + text(typeof error === 'string' ? error : JSON.stringify(error)))
    }
  }
}
