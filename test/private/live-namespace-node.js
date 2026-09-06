'use strict'

// The eleven-process scenario run with every role in its own network namespace,
// with every veth captured, followed by the edge, direct-authority, and leak
// oracles over the captured bytes.
//
// Privileged and Linux-only. Run with `npm run test:private:namespace:live`.

const b4a = require('b4a')
const test = require('brittle')
const { execFileSync } = require('child_process')
const { hrtime } = require('process')
const fs = require('fs')
const path = require('path')

const registerLiveProcessSuite = require('./live-process-suite')
const { PROCESS_PLANS } = require('./process/topology-fixture')
const {
  namespaceProvisioningAvailable,
  provisionNamespaceProjection
} = require('./process/namespace-provisioner')
const { assertRouteCaptures, describeRouteCaptures } = require('./process/route-oracles')
const { readPcapPackets } = require('./process/pcap')
const { reconcileTeardownIcmp } = require('./process/teardown-icmp')

if (!namespaceProvisioningAvailable()) {
  test('live private route lifecycle in eleven node role processes on linux-namespace', (t) => {
    t.comment(
      `skipped: needs Linux with non-interactive sudo and tcpdump (platform ${process.platform})`
    )
    t.pass('namespace provisioning unavailable on this host')
  })
} else {
  registerLiveProcessSuite({
    createPlacement(topology) {
      const suffix = b4a.toString(topology.oracle.run.subarray(0, 2), 'hex')
      const provision = provisionNamespaceProjection(topology.oracle.namespace, { suffix })
      provision.startCapture()
      const wallStart = Date.now()
      const monotonicStart = hrtime.bigint()
      // Capture and coordinator use this Linux host's realtime clock. Refuse
      // observed drift beyond 2 ms, also checked inside each socket observer.
      function auditMillis() {
        const wall = Date.now()
        const elapsed = Number(hrtime.bigint() - monotonicStart) / 1e6
        if (Math.abs(wall - wallStart - elapsed) > 2) {
          throw new Error('namespace audit realtime clock changed')
        }
        return wall
      }
      return {
        async audit(t) {
          const beforeCaptureStop = provision.dropStatistics()
          const captures = provision.stopCapture()
          const dropped = provision.dropStatistics()
          const completedBeforeMicros = (auditMillis() - 2) * 1000
          t.comment(`kernel raw DROP=${dropped} (before capture stop=${beforeCaptureStop})`)
          if (dropped !== 0) {
            for (const capture of captures) {
              const nonUdp = execFileSync(
                'tcpdump',
                ['-nn', '-vv', '-r', capture.file, 'not udp'],
                { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
              )
              if (nonUdp.trim()) t.comment(`non-UDP traffic on ${capture.key}:\n${nonUdp}`)
            }
          }
          for (const line of describeRouteCaptures(
            assertRouteCaptures(t, captures, topology.oracle)
          )) {
            t.comment(line)
          }
          if (dropped !== beforeCaptureStop) {
            throw new Error('namespace drop counter changed while capture stopped')
          }
          const windows = new Map(
            topology.oracle.namespace.roles.map(({ roleIndex }) => [
              String(roleIndex),
              JSON.parse(
                fs.readFileSync(path.join(provision.captureDir, `${roleIndex}.close.json`), 'utf8')
              )
            ])
          )
          const result = reconcileTeardownIcmp(
            captures.map(({ file, key }) => ({ key, records: readPcapPackets(file) })),
            topology.oracle.namespace.firewall,
            windows,
            completedBeforeMicros,
            dropped
          )
          t.comment(`classified teardown ICMP=${result.classifiedTeardownIcmp}`)
          t.is(
            result.rawDrop,
            result.classifiedTeardownIcmp,
            'every kernel drop is a proven native-close ICMP reply'
          )
        },
        enter(roleIndex, command, args) {
          return provision.enter(roleIndex, 'env', [
            `PR_SOCKET_CLOSE_LOG=${path.join(provision.captureDir, `${roleIndex}.close.json`)}`,
            command,
            ...args
          ])
        },
        teardown() {
          provision.teardown()
        }
      }
    },
    label: 'linux-namespace',
    plan: PROCESS_PLANS.LINUX_NAMESPACE,
    runtime: 'node',
    runtimeVersion: process.version
  })
}
