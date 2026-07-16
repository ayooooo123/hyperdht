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

### Active-relay adversary

V1 assumes that any one guard, middle, exit, private-route relay, or storage
node may be actively malicious. A single malicious participant may drop,
delay, duplicate, reorder, replay, truncate, tag, or mutate traffic and may
return dishonest unsigned DHT results. It may cause denial of service. Without
collusion, it must not:

- decrypt a source-to-exit or source-to-destination inner payload outside its
  own terminal role;
- learn a non-adjacent endpoint address from protocol state;
- substitute a cell, control message, descriptor, or destination reference
  across circuits, directions, branches, generations, or identities;
- forge route readiness, route opening, storage receipts, or endpoint Noise
  authentication;
- turn an exit into an arbitrary network proxy.

Collusion between the guard and an exit, one operator obtaining multiple path
positions through distinct identities, and global timing correlation remain
out of scope. The topology rules still prohibit one known identity or endpoint
from occupying multiple positions in a route.

### Minimum cryptographic invariants

The experimental v1 implementation inherits the verified prototype's minimum
cryptographic construction:

- Ed25519-compatible Hypercore identity signatures;
- X25519 ephemeral/static key agreement with all-zero shared-secret rejection;
- domain-separated keyed BLAKE2b (`crypto_generichash`) derivation;
- independent 32-byte keys and 16-byte nonce prefixes for every direction,
  cell class, context, circuit, and generation;
- XChaCha20-Poly1305 AEAD with a 24-byte nonce formed from the 16-byte prefix
  and one unsigned 64-bit big-endian counter;
- exact transcript binding of protocol version, identities, roles, branch and
  circuit IDs, generation, direction, class, negotiated limits, and descriptor
  or advertisement digests relevant to that context;
- fixed 1,200-byte randomly padded outer cells;
- source-to-exit and source-to-destination inner AEAD contexts, so removing one
  hop layer never exposes DHT or application plaintext to an intermediate;
- authentication before any counter, replay, route, or application state
  changes.

CONTROL and STREAM contexts accept exactly the next authenticated counter.
DATAGRAM contexts use a bounded 64-counter replay window and deliver a counter
at most once. Duplicate counters are always rejected. Gaps outside the
applicable bound fail the circuit. Counter wrap is forbidden; approaching
exhaustion starts rotation and exhaustion destroys the circuit.

Every route generation creates fresh keys, nonce prefixes, circuit IDs,
counters, replay state, and destination capabilities. Authentication failure,
counter exhaustion, failed confirmation, close, or expiry tears down dependent
state. Owned secret buffers are erased on transfer or teardown to the extent
the JavaScript and native runtimes permit. Fixed-vector, substitution,
property, fuzz, and external cryptographic review are required before the wire
format may be called stable.

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
    allowLegacyEgress: true,
    capabilityStore
  }
})

await swarm.dht.ready()
```

The lower-level equivalent is:

```js
const dht = new HyperDHT({
  privateRouting: {
    mode: 'required',
    allowLegacyEgress: true,
    capabilityStore
  }
})

const swarm = new Hyperswarm({ dht })
```

If both `privacy` and an injected `dht` are provided, Hyperswarm validates that
the injected instance satisfies the requested policy. It must not silently
construct or select another DHT.

`allowLegacyEgress: true` requires a durable `capabilityStore` implementing
asynchronous `get(noisePublicKey)`, `put(noisePublicKey, record)`, and
`delete(noisePublicKey, signedTombstone)` operations. Construction rejects
without it. Node, Bare, Android, and iOS adapters must persist atomically in an
application-private location and survive process restart.

Relay service configuration is explicit and separate from client privacy:

```js
const relay = new HyperDHT({
  privateRelay: {
    capabilities: ['CIRCUIT_RELAY_V1', 'DHT_EXIT_V1', 'LEGACY_EGRESS_V1', 'PRIVATE_RECORDS_V1'],
    limits: {
      maxCircuits: 128,
      maxCircuitsPerNeighbor: 32,
      maxCircuitQueuedBytes: 256 * 1024,
      maxQueuedBytes: 8 * 1024 * 1024
    }
  }
})
```

Capabilities may be enabled independently except that every terminating exit
also requires `CIRCUIT_RELAY_V1`. An advertisement is signed and binds the
exact enabled capabilities, experimental protocol version, limits, identity,
route-encryption key, epoch, and expiry. Client privacy never enables relay
service implicitly.

### Required-mode method contract

| Surface                                                         | `required` behavior                                                                                                                          |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `ready()`                                                       | Waits for private readiness, not merely socket binding. Rejects if no valid guard and routes are available.                                  |
| `destroy()`, `suspend()`, `resume()`                            | Use the private lifecycle and erase or rebuild route authority without direct fallback.                                                      |
| `lookup`, `announce`, `unannounce`                              | Use native address-free private presence records only.                                                                                       |
| `immutableGet`, `immutablePut`, `mutableGet`, `mutablePut`      | Use typed routed DHT requests; mutation prepare and commit remain on one branch generation and exit.                                         |
| `findPeer`                                                      | Returns verified private descriptors or opaque legacy-egress targets, never caller-dialable private addresses.                               |
| `connect`                                                       | Uses a verified private descriptor, or an opaque legacy-egress target when explicitly allowed.                                               |
| `createServer`, `listen`                                        | Maintain and publish private route descriptors; never advertise or accept a direct endpoint route.                                           |
| `pool`, raw streams                                             | May use only a routed implementation that carries no direct address/send authority; otherwise reject with `ERR_PRIVATE_COMMAND_UNSUPPORTED`. |
| raw `query` or unregistered commands                            | Reject unless an immutable private command policy defines codecs, bounds, cost, amplification, destination provenance, and branch class.     |
| Hyperswarm `join`, `joinPeer`, `flush`                          | Preserve current lifecycle semantics while discovery and connection attempts remain routed.                                                  |
| Hyperswarm `leave`, `leavePeer`, `suspend`, `resume`, `destroy` | Cancel and tear down private work with the same externally visible completion semantics as direct mode.                                      |

Existing firewall callbacks execute at the actual endpoint against the remote
Noise public key and payload, not against an exit identity. Cancellation,
timeout, half-close, error, and teardown propagate through the route and retain
their ordinary stream meaning.

`dht.privateRouting` exposes a read-only controller with `mode`, `ready()`,
`status()`, and `exposureReport()`. The report contains only bounded bootstrap
contact categories, counts, timestamps, and redacted endpoint hashes; it never
contains route keys or complete paths. Stable private errors include
`ERR_PRIVACY_UNAVAILABLE`, `ERR_PRIVATE_GUARD_UNAVAILABLE`,
`ERR_PRIVATE_ROUTE_LOST`, `ERR_PRIVATE_ROUTE_ROTATING`,
`ERR_PRIVATE_COMMAND_UNSUPPORTED`, `ERR_PRIVATE_RELAY_BUSY`,
`ERR_PRIVATE_DESCRIPTOR_INVALID`, `ERR_PRIVATE_DOWNGRADE`,
`ERR_PRIVATE_CAPABILITY_STORE_FULL`, and `ERR_PRIVATE_AUTHENTICATION`.

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

### Normative v1 topology and diversity

A routed DHT or legacy-egress branch has exactly three relay positions:

```text
endpoint -> guard -> safety middle -> DHT/egress exit
```

A private-to-private compiled route has two independently selected segments:

```text
source -> guard -> safety middle -> private entry -> private middle
       -> private final -> destination
```

The source selects only the safety segment. The destination selects and
publishes only the private segment. A source safety segment may carry multiple
independent stream circuits, but every circuit and generation has fresh keys,
counters, IDs, limits, and replay state.

All identities in a compiled route are distinct. Safety and private roles are
derived exactly as:

```text
digest = BLAKE2b-256(
  UTF8("hyperdht-private-routes/role/v0") || identityPublicKey32
)
role = (digest[0] & 1) === 0 ? SAFETY : PRIVATE
```

The domain's `v0` is the inherited prototype role-format version; changing the
domain, input encoding, hash, selected bit, or mapping requires a protocol
version bump. An advertisement cannot choose its role.

Selection rejects repeated identities, repeated endpoints, any two route
positions in the same IPv4 `/24`, any two route positions in the same IPv6
`/48`, incompatible versions or cell parameters, role mismatch, loops,
expired advertisements, and locally quarantined nodes. IPv4-mapped IPv6 is
normalized and evaluated as IPv4. There is no prefix-diversity relaxation in
`required` mode; insufficient candidates fail closed. Lookup and announce
branches share only the guard identity and endpoint; their middles and exits
are pairwise distinct. Diversity is a placement heuristic, not Sybil proof.

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

#### Opaque destination references

The client never authorizes a raw host, port, or caller-computed DHT node ID.
After branch opening, an exit creates a fresh branch handle secret and a
bounded destination table. It mints an unpredictable `DESTINATION_REF_V1` only
for a node learned from the exit's configured bootstrap set, current routing
table, actively validated capability cache, recent valid protocol traffic, or
a protocol-valid response from an already admitted reference.

A referral is only evidence. Before exposing a reference, the exit applies
probe and amplification budgets, validates reachability through the ordinary
DHT exchange, derives the address-based node ID, and records provenance. A
client-supplied address or self-signed advertisement alone never triggers an
exit probe.

Before any probe or table admission, the exit requires a globally routable
unicast address and a port from 1 through 65,535. It rejects unspecified,
loopback, private, carrier-grade NAT, link-local, unique-local, site-local,
multicast, documentation, benchmarking, reserved, IPv4-mapped special-use,
and other IANA special-purpose ranges. The check precedes network IO, signature
work that depends on the target, and destination allocation. Production code
has no override. The isolated namespace test harness injects a non-exported
test authority that allowlists its exact synthetic endpoints; it cannot admit
an address not signed into that test topology.

Each reference maps server-side to the issuing exit, branch and circuit IDs,
generation, address, derived DHT node ID, provenance, expiry, and allowed
command classes. It is unforgeable under the branch handle secret and cannot
be used at another exit, after rotation, or for a different command. Exit
policy restricts targets to valid DHT address families and ports and restricts
requests to registered DHT codecs and exact request/response and amplification
bounds. Arbitrary UDP, hostname resolution, private-network scanning, and raw
socket destinations are not registered commands.

Mutation tokens remain bound to the destination reference, exit, observed
exit address, branch generation, command, and expiry. If a branch rotates
between prepare and commit, the client discards the token and restarts the
operation. An exit may omit or lie about unsigned routing results, but cannot
expand the permitted network or command surface.

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

The bridge reuses HyperDHT's existing `relayThrough` handshake and
`blind-relay` stream pairing. Private discovery yields the expected remote
Noise public key plus a single-use opaque egress target reference, never direct
send authority. The source opens a routed stream to the egress exit. The exit
binds that stream to one blind-relay session and issues the ordinary peer
handshake with itself as `relayThrough`, `holepunch: false`, and local-address
sharing disabled. The unchanged destination opens its normal raw relay stream
to the exit and the exit pairs the two sides by the single-use session
capability.

The exit forwards stream bytes byte-for-byte and does not instantiate
SecretStream. Source and destination each bind the existing Noise handshake to
the expected remote public key; exit substitution therefore fails endpoint
authentication. The routed source starts Noise only after authenticated relay
pairing. Backpressure propagates between both bounded queues. Cancellation,
firewall rejection, timeout, half-close, or either transport closing closes
the paired side and erases the session capability. No signaling or data path
may enable punch, direct race, address sharing, or relay-to-direct upgrade.

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

#### Private rendezvous and stream handoff

A descriptor binds the destination Noise identity, descriptor ID and digest,
public entry advertisement, private route-encryption key, protocol parameters,
route epoch, expiry, and encrypted nested hop material under an endpoint
signature or endpoint-scoped delegation.

Opening uses this idempotent state machine:

```text
DESCRIPTOR_VERIFIED -> ACTIVATE -> READY -> ACK -> OPEN
                `------ failure/timeout ------> DESTROYED
```

1. The source creates a fresh circuit identity, ephemeral route key, activation
   nonce, circuit ID, and generation. `ACTIVATE` binds those values, the exact
   descriptor digest, both expected Noise public keys, and negotiated bounds.
2. Each private relay decrypts only its nested instruction, installs bounded
   adjacent forwarding state, and forwards the remainder. The destination
   verifies the complete destination-visible activation tuple and reserves the
   redemption key `(descriptor ID, epoch, activation nonce, source route key)`.
3. The destination returns authenticated `READY`. The source verifies it and
   returns `ACK`. Neither side exposes a duplex or accepts Noise bytes yet.
4. The destination atomically consumes the single-use redemption, installs the
   final reverse state, returns authenticated `OPEN`, and transfers exactly one
   routed duplex to its HyperDHT server.
5. Only after verifying `OPEN` does the source transfer exactly one routed
   duplex to HyperDHT `connect`. Existing Noise then authenticates the peers and
   encrypts all stream bytes end to end.

The complete open deadline is five seconds. Semantic messages use one initial
send and at most four bounded retries under fresh datagram counters while
retaining identical authenticated bodies. An identical duplicate receives the
cached next response; a conflicting tuple, wrong identity or generation,
expired descriptor, reused redemption, authentication failure, or deadline
destroys all half-open state. Concurrent redemption of one capability has
exactly one winner. Delayed setup messages are accepted only by bounded
receive-only tombstones and can never reopen or transfer a second duplex.

#### Capability negotiation and downgrade

Private capability is authenticated only by an endpoint-signed live descriptor
or signed capability/tombstone record. A valid private descriptor always wins
over legacy egress. Once a destination identity has presented a valid private
capability, its durable capability pin survives descriptor expiry and process
restart until an identity-signed downgrade tombstone is accepted. Missing,
suppressed, malformed, or expired replacement data cannot select legacy egress
and returns `ERR_PRIVATE_DOWNGRADE`.

The capability store is bounded to 4,096 identities by default. It never
evicts a live privacy pin to make room: reaching capacity returns
`ERR_PRIVATE_CAPABILITY_STORE_FULL` and disables legacy egress for untracked
identities. A pin is deleted only by a valid identity-signed downgrade
tombstone or an explicit user security reset that clearly warns that downgrade
memory will be lost. Cache cleanup, application upgrade, descriptor expiry,
ordinary LRU pressure, and crash recovery cannot turn a known private identity
back into a first contact.

On first contact, an identity for which no authenticated private capability has
ever been observed may use legacy egress only when `allowLegacyEgress` is true
and a valid legacy DHT result produced the opaque egress target. This preserves
source address privacy but cannot prove that a first-contact attacker did not
suppress an unknown destination's private descriptor. Applications requiring
mutual private routing must disable legacy egress.

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

Cold start is numerically bounded. V1 accepts only numeric IPv4 or IPv6
bootstrap and guard endpoints and performs no DNS. `BootstrapIO` contacts at
most three configured bootstrap endpoints sequentially and actively
challenges at most three distinct prospective guards total across all
referrals. Endpoints are
deduplicated before contact; retries do not expand either set; only one direct
challenge is in flight; and one ten-second global deadline covers cookies,
challenges, and the first guard link. A hostname, multiple-address container,
or nonnumeric referral is rejected before IO. Exhausting any bound returns
`ERR_PRIVATE_GUARD_UNAVAILABLE`.

The exposure report records phase, contact category, redacted endpoint hash,
first/last attempt time, attempt count, and outcome for no more than those six
distinct endpoints. Before `GUARD_PINNED`, the implementation proves that all
bootstrap sockets, routing entries, DNS/discovery scratch state, callbacks, and
generic send capabilities are destroyed. Post-readiness guard revalidation can
contact exactly the pinned guard and cannot follow referrals or resolve another
endpoint.

Errors are structured and never recommend a direct retry. Stable categories
include privacy unavailable, insufficient diverse relays, guard unavailable,
route lost or expired, route rotating, unsupported private command, relay busy,
routed request timeout, descriptor invalid, authentication failure, and network
changed.

Metrics may contain aggregate transitions, latency, generation, capacity, and
error category. They must not log route keys, complete paths, topics, raw
descriptors, private endpoints, or stable cross-generation identifiers.

### Prototype resource ceilings

The first implementation and all tests use explicit ceilings rather than
unbounded configuration:

- outer cell: exactly 1,200 bytes; outer payload: at most 1,146 bytes;
- end-to-end route payload: at most 1,073 bytes per cell;
- one internal route message: at most eight route fragments, or 8,584 bytes;
- queued/in-flight and read data: at most eight route fragments and 8,584 bytes
  per duplex direction by default;
- half-open route or reassembly deadline: 5,000 ms;
- remote actors: 128; pending remote requests: 64; replay and tombstone entries:
  64 each per host;
- relay circuits: 128 globally and 32 per observed neighbor;
- relay queued bytes: 256 KiB per circuit and 8 MiB globally;
- finalization: one initial send plus four retries inside five seconds;
- DATAGRAM replay window: 64 counters.

Every limit is checked before allocation or callback. A peer may negotiate
smaller limits, never larger values than local policy. Queue admission is
atomic per fragment/message, fair across circuits, and returns bounded `BUSY`
or destroys the affected circuit without direct fallback. Production tuning
may lower defaults; increasing a wire or security ceiling requires a reviewed
spec amendment and adversarial memory/amplification tests.

The public duplex accepts arbitrary legal write sizes. It lazily segments a
large caller write across as many internal route messages as required and uses
ordinary backpressure while keeping no more than the negotiated queued/in-flight
ceiling. It does not reject a public write merely because it exceeds 8,584
bytes. Ownership of the caller's buffer follows the existing stream contract;
write completion occurs only after its segments have crossed the local bounded
queue. This preserves transparent Hypercore replication without making an
internal message unbounded.

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

Network capture is paired with a semantic leak oracle. Test endpoints receive
distinctive numeric addresses and byte sentinels. The harness inspects decoded
DHT messages, capability advertisements, presence records, descriptors,
connection metadata, routing and destination tables, public events, structured
errors, metrics, logs, and teardown snapshots. Outside the explicitly allowed
bootstrap/guard observations, it fails if an endpoint address or sentinel is
present in plaintext, promoted to public dial authority, or returned through a
public API. This detects address disclosure inside an otherwise correctly
routed packet, which namespace edges alone cannot prove absent.

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
- Single malicious relay tagging, payload substitution, cross-circuit
  injection, delayed replay, counter exhaustion, and selective forwarding.
- Dishonest exit responses and response amplification attempts.
- Descriptor replay across topics, endpoint identities, epochs, and route
  generations, including concurrent single-use redemption.
- Truncated or modified routed Noise streams; exits never obtain application
  plaintext and tampering fails Noise authentication.

### Mobile lifecycle

Portable deterministic tests simulate background suspension, long expiry,
resume, and Wi-Fi/cellular address changes without continuous cover traffic.
Actual Android and iOS tests begin only after the portable Node and Bare suites
pass. PearTube integration remains blocked until both native platforms also
pass background/resume and network-transition tests with socket-edge and
no-direct-fallback assertions.

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

- Portable Node and Bare topologies on Linux, macOS, and Windows.
- Privileged Linux capture gate.
- Scheduled seeded fuzz and churn suite.
- Exact commit pins for all integration dependencies.
- Android emulator and iOS simulator lifecycle gates before PearTube work.

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
7. **Native mobile:** pass Android and iOS background/resume and network-change
   leak gates using the same required-mode policy.

PearTube integration remains blocked until all seven gates pass. Passing the
gates does not by itself authorize production anonymity claims; the
cryptographic construction and wire format require external review before
stabilization.
