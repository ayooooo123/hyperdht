'use strict'

// The eleven-process scenario run with every role in its own network namespace,
// with every veth captured, followed by the edge, direct-authority, and leak
// oracles over the captured bytes.
//
// Privileged and Linux-only. Run with `npm run test:private:namespace:live`.

const b4a = require('b4a')
const test = require('brittle')

const registerLiveProcessSuite = require('./live-process-suite')
const { PROCESS_PLANS } = require('./process/topology-fixture')
const {
  namespaceProvisioningAvailable,
  provisionNamespaceProjection
} = require('./process/namespace-provisioner')
const { assertRouteCaptures, describeRouteCaptures } = require('./process/route-oracles')

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
      return {
        async audit(t) {
          // An independent signal that needs no capture: the kernel counts every
          // packet it refused between our devices, and a correct run never
          // addresses a forbidden pair in the first place.
          t.is(provision.dropStatistics(), 0, 'the kernel refused no packet between roles')
          const captures = provision.stopCapture()
          for (const line of describeRouteCaptures(
            assertRouteCaptures(t, captures, topology.oracle)
          )) {
            t.comment(line)
          }
        },
        enter(roleIndex, command, args) {
          return provision.enter(roleIndex, command, args)
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
