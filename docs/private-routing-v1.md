# Native Private Routing v1

**Status:** owner-approved experimental design  
**Date:** 2026-07-16  
**Canonical repository:** `ayooooo123/hyperdht`  
**Related forks:** `ayooooo123/dht-rpc`, `ayooooo123/hyperswarm`,
`ayooooo123/hyperswarm-testnet`

## Summary

Native Private Routing adds an opt-in, fail-closed routing mode to the
Holepunch stack. A private endpoint sends DHT operations and peer streams
through short, independently selected relay paths instead of exposing its
network address to DHT nodes or peers. Existing Hyperswarm Noise and
SecretStream encryption remains end to end between the actual peers. Relays
forward fixed-size authenticated cells and do not terminate the peer's Noise
session.

The feature is developed in drop-in-compatible forks before any PearTube
integration. Existing constructors, exports, package names, and direct-mode
behavior remain unchanged when private routing is absent or explicitly off.
Private routing is experimental and must not be represented as production
anonymity before the complete testnet gates and an external security review
pass.

## Compatibility Contract

- Existing DHT-RPC, HyperDHT, and Hyperswarm behavior is the default.
- Private routing is enabled only through an explicit option.
- Initial modes are `off` and `required`; there is no `preferred` mode.
- `required` mode never silently retries through a direct transport.
- Existing package names and exports remain unchanged in the forks.
- A private client may connect anonymously to an unchanged public peer through
  a legacy-egress exit.
- Two private-capable peers use destination-selected private routes.
- Relaying is separately enabled on public nodes and is off by default on
  clients, including mobile clients.
- UDX remains unchanged until packet-oracle evidence demonstrates that a
  required invariant cannot be enforced above it.

Small, generally useful integration hooks are kept in isolated commits that
can be proposed upstream. Privacy-specific path selection, wire formats, and
cryptography remain explicitly experimental in the forks.

## Security Contract

After a guard is pinned, a `required`-mode endpoint sends packets only to that
guard. DHT nodes, DHT exits, legacy peers, and private peers do not observe the
endpoint's network address.

Before guard pinning, a bounded set of configured bootstrap candidates and
prospective guards may observe the endpoint address. The selected guard also
observes it. These contacts are included in a readiness report and are outside
the post-guard address-separation guarantee.

### End-to-end encryption

All peer and application stream bytes are encrypted end to end by the existing
Hyperswarm Noise/SecretStream session:

```text
source peer ======= Noise / SecretStream E2EE ======= destination peer
             guard -> middle -> exit/entry -> relays
```

An exit or relay may adapt or forward the transport but never receives Noise
session keys. The destination decrypts the stream because it is the intended
endpoint. It learns the source's Noise identity and application-visible
metadata, but not the source's network address.

### DHT metadata

Private routing provides network-location privacy, not query privacy. A DHT
exit sees the operation, lookup or announce key, contacted DHT node, timing,
and approximate volume needed to execute a bounded request. The contacted DHT
node sees the request it processes. Intermediate route relays cannot read this
metadata. None of these parties can decrypt a later peer-to-peer Noise stream.

### Protected properties

- After readiness, the endpoint has no direct DHT or peer send authority.
- A legacy peer observes an egress exit address rather than the client address.
- Private-capable peers do not learn one another's network addresses.
- Lookup results and private announcements contain no endpoint dial address.
- Route failure, expiry, overload, network change, and unsupported operations
  cannot trigger direct fallback.
- Route identities and route keys rotate independently from stable Noise
  identities.
- A value learned solely through private route material never grants direct
  dial authority.

### Explicitly visible

- The guard sees the endpoint address and its next hop.
- An exit sees the routed DHT operation or the legacy peer it contacts.
- Adjacent relays see timing, packet count, and volume.
- DHT storage nodes see stored record keys and bounded descriptor bytes.
- A destination peer sees the remote Noise identity and plaintext delivered to
  the destination application.

### Out of scope for v1

- A global passive observer.
- Timing correlation by colluding guards and exits.
- Complete Sybil resistance or relay incentives.
- Query privacy from DHT exits and processing DHT nodes.
- Host compromise or application-level identity correlation.
- Constant-rate cover traffic, especially on mobile.

## Repository Boundaries

### `dht-rpc`

DHT-RPC owns only generic integration seams:

- a per-request transport contract usable by the query engine;
- propagation of transport context through retries and iterative traversal;
- an enforceable outbound policy that can reject direct sends;
- lifecycle and cancellation behavior for injected transports;
- observability sufficient to prove which transport handled a request.

DHT-RPC does not own onion routing, relay selection, private records,
Hyperswarm identities, or destination descriptors. Existing direct IO remains
the default and retains its current wire behavior.

### `hyperdht`

HyperDHT is the canonical protocol owner. It contains:

- route cells, cryptographic contexts, replay protection, and fragmentation;
- guard selection, path construction, diversity rules, and rotation;
- signed relay capability advertisements;
- typed and bounded DHT exit operations;
- private presence records and destination route descriptors;
- relay service quotas, backpressure, teardown, and secret erasure;
- the legacy-egress bridge;
- private routing readiness, errors, metrics, and lifecycle.

### `hyperswarm`

Hyperswarm exposes the ergonomic `privacy` option and applies it consistently
to discovery and peer connections. In `required` mode it prohibits direct
connection races, hole punching, direct retries, and relay-to-direct upgrades.
It preserves existing Noise identity, connection events, firewall semantics,
and stream behavior.

### `hyperswarm-testnet`

The testnet fork is the cross-repository conformance authority. It runs real
multi-process topologies, records network edges, exercises Node and Bare, and
pins exact commits of the other three forks.

### PearTube

The existing PearTube implementation branch is frozen as research evidence.
PearTube is neither a dependency nor an implementation host. No product switch
is exposed until all low-level gates in this document pass.

## Public API

Direct mode remains unchanged:

```js
const dht = new HyperDHT()
const swarm = new Hyperswarm()
```

Private routing may be enabled at the Hyperswarm level:

```js
const swarm = new Hyperswarm({
  privacy: {
    mode: 'required',
    allowLegacyEgress: true
  }
})

await swarm.dht.ready()
```

The lower-level equivalent is:

```js
const dht = new HyperDHT({
  privateRouting: {
    mode: 'required',
    allowLegacyEgress: true
  }
})

const swarm = new Hyperswarm({ dht })
```

If both `privacy` and an injected `dht` are provided, Hyperswarm validates that
the injected instance satisfies the requested policy. It must not silently
construct or select another DHT.

Relay service configuration is explicit and separate from client privacy
configuration. Exact names and capacity fields are fixed only when the relay
service implementation is designed and tested.

## Architecture

```text
Hypercore / Corestore replication
              |
        Hyperswarm + Noise
              |
          HyperDHT
   private records and routes
              |
   DHT-RPC transport contract
              |
             UDX
```

The private route layer sits above UDX and below DHT-RPC, HyperDHT, and
Hyperswarm semantics. UDX supplies datagram and stream primitives but remains
unaware of DHT identities, privacy domains, routes, and path selection.

### Route components

- `RouteManager` selects guards and diverse relays, constructs branches,
  rotates generations, and exposes structured readiness.
- `RelayService` forwards bounded opaque cells between authenticated adjacent
  links and removes state on failure or expiry.
- `CellCodec` produces fixed-size padded, hop-authenticated cells with
  direction-specific counters and replay windows.
- `RoutedTransport` presents bounded request and duplex-stream semantics to the
  existing DHT and Noise layers.
- `PrivateRouteDescriptor` is a signed, short-lived record naming a public
  route entry and encrypted nested private-hop material, never a destination
  address.
- `PrivacyProvenance` keeps public discovery and private-only knowledge
  separate. Importing private material never grants public-dial authority.

The existing verified PearTube prototype may supply implementation material,
tests, and commit attribution. It is not copied as an application package or
treated as the canonical module boundary.

## Traffic Flows

### Routed DHT request

```text
private client -> guard -> middle -> DHT exit -> ordinary DHT node
```

The client retains control of iterative Kademlia traversal. An exit executes
one allowlisted, bounded operation against one live destination selected by the
client and returns a normalized response through the route. It does not become
a trusted query engine or unrestricted UDP proxy.

Lookup and announce use separate middle and exit branches while sharing a
stable guard lease. This reduces trivial linkability without requiring
continuous cover traffic.

### Connection to an unchanged peer

```text
private client -> guard -> middle -> egress exit -> legacy HyperDHT peer
       `------------- end-to-end Noise ----------------------'
```

The egress exit adapts the routed stream to existing HyperDHT relaying and
forwards opaque Noise bytes. The legacy peer sees the exit's address. Required
mode disables hole punching, direct races, direct retries, and direct upgrade.
This path provides source privacy during gradual adoption. A legacy peer cannot
initiate a connection to a private-only listener without private descriptor
support.

### Connection between private-capable peers

```text
source safety route -> public private entry -> destination route -> destination
          `---------------- end-to-end Noise ---------------------'
```

The destination builds and publishes a short-lived signed descriptor. The
source verifies its endpoint binding, expiry, protocol parameters, and route
entry before compiling its safety route with the destination-selected route.
Neither endpoint selects the complete path. Existing Hyperswarm then performs
its normal Noise handshake inside the opened route.

## Lifecycle and Failure Semantics

The private endpoint progresses through explicit states:

```text
OFF -> BOOTSTRAPPING -> GUARD_PINNED -> READY -> ROTATING
                                  `-> UNAVAILABLE
```

- `BOOTSTRAPPING` owns the only general direct discovery authority.
- Pinning a guard destroys bootstrap sockets before readiness.
- `READY` permits only guard-bound endpoint traffic.
- Rotation is make-before-break and preserves the pinned guard while possible.
- Existing streams may drain on a previous valid generation.
- Network change invalidates observed reachability and triggers private rebuild,
  never direct fallback.
- Suspend removes timers and ephemeral send authority without creating a direct
  reconnect path. Resume revalidates only the pinned guard or returns to bounded
  bootstrap after explicit route teardown.
- Shutdown closes Hyperswarm and DHT activity before destroying routes and
  zeroizing owned secrets.

Errors are structured and never recommend a direct retry. Stable categories
include privacy unavailable, insufficient diverse relays, guard unavailable,
route lost or expired, route rotating, unsupported private command, relay busy,
routed request timeout, descriptor invalid, authentication failure, and network
changed.

Metrics may contain aggregate transitions, latency, generation, capacity, and
error category. They must not log route keys, complete paths, topics, raw
descriptors, private endpoints, or stable cross-generation identifiers.

## Authoritative Test Oracle

The cross-repository testnet runs each role in a distinct Linux network
namespace with a unique address. It records every source/destination edge and
the process that created each socket. It also installs an in-process authority
trap so attempted direct sends fail even when a host firewall would otherwise
hide the attempt.

Packet capture is authoritative. After guard pinning:

- the endpoint contacts only its guard;
- the guard contacts only selected adjacent relays for circuit traffic;
- each relay contacts only its installed adjacent route hops;
- DHT exits contact only live provenance-qualified DHT destinations through
  allowlisted operations;
- an egress exit, not the endpoint, contacts a legacy peer;
- neither private endpoint appears on the other's captured network edges;
- no private-only address enters a public routing table or direct probe;
- teardown leaves no process, socket, route, queue, or owned secret state.

The readiness report separately lists the bounded pre-guard contacts.

## Required Test Scenarios

### Compatibility

- Every unchanged upstream test passes in each fork.
- Default constructors retain existing direct behavior.
- Direct wire encodings are unchanged when private routing is off.
- Existing applications can substitute a fork without source changes.

### Private DHT

- Lookup, announce, unannounce, mutable and immutable get/put.
- Client-controlled iterative traversal through typed exit requests.
- Separate lookup and announce exits.
- No ordinary DHT send after readiness.

### Peer streams

- A private client completes end-to-end Noise with an unchanged peer while the
  peer observes only the egress exit address.
- Two private-capable peers complete end-to-end Noise without learning either
  endpoint address.
- Real Hypercore replication succeeds over the private stream.

### Adversarial and failure behavior

- Guard, middle, exit, and destination failure.
- Expiry during lookup and active streams.
- Malformed, duplicated, reordered, replayed, and forged cells.
- Forged, stale, oversized, and identity-mismatched descriptors.
- Relay overload, queue exhaustion, and bounded fragmentation.
- Insufficient relays or diversity.
- Network changes, suspend/resume, and rotation races.
- Every unavailable path fails or rebuilds privately without direct fallback.

### Mobile lifecycle

Portable deterministic tests simulate background suspension, long expiry,
resume, and Wi-Fi/cellular address changes without continuous cover traffic.
Actual Android and iOS tests begin only after the portable Node and Bare suites
pass.

## CI Responsibilities

### `dht-rpc`

- Existing Node and Bare suites on Linux, macOS, and Windows.
- Routed transport contract and cancellation tests.
- Direct-authority rejection and unchanged-default tests.

### `hyperdht`

- Existing full suite.
- Codec, state-machine, replay, quota, and deterministic fuzz tests.
- Multi-process private DHT integration.
- Privileged Linux namespace and packet-oracle job.

### `hyperswarm`

- Existing full suite.
- Legacy-egress and private-peer Noise tests.
- Connection lifecycle and direct-upgrade prohibition tests.

### `hyperswarm-testnet`

- Portable Node and Bare topologies.
- Privileged Linux capture gate.
- Scheduled seeded fuzz and churn suite.
- Exact commit pins for all integration dependencies.

## Repository Workflow

Development occurs on `private-routing-v1` branches in all four forks. During
development, downstream integration locks exact upstream fork commits rather
than floating branches. No experimental fork is published over an official npm
package name.

Every cross-repository change must pass its local upstream regression suite and
the pinned testnet privacy suite before merging. Generic changes are isolated
for possible upstream pull requests. Fork-specific protocol changes retain
experimental notices and their upstream license and authorship.

## Delivery Gates

1. **Fork baseline:** fork `hyperswarm-testnet`, create feature branches, and
   reproduce all unchanged upstream tests.
2. **DHT-RPC transport seam:** add generic transport and outbound-policy hooks
   with compatibility proof.
3. **Private DHT:** migrate the verified route substrate into HyperDHT and pass
   routed DHT operations under the packet oracle.
4. **Legacy egress:** complete Noise and bidirectional data with an unchanged
   peer without source-address disclosure.
5. **Native private peers:** add destination descriptors, private-to-private
   Hyperswarm, and real Hypercore replication.
6. **Reliability:** pass churn, rotation, quotas, network changes, Node/Bare,
   and simulated mobile lifecycle suites.

PearTube integration remains blocked until every gate passes. Passing the gates
does not by itself authorize production anonymity claims; the cryptographic
construction and wire format require external review before stabilization.
