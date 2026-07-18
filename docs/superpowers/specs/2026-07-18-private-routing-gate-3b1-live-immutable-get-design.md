# HyperDHT Private Routing Gate 3B1: Live Routed Immutable Get

**Status:** Approved design draft

**Date:** 2026-07-18

**Canonical protocol:** [Private Routing Protocol v1](../../private-routing-v1.md)

**Migration boundary:** [Gate 3A Migration Record](../../private-routing-migration.md)

**Implementation repository:** `ayooooo123/hyperdht`, branch `private-routing-v1`

**Runtime targets:** Node and Bare

## Summary

Gate 3B1 is the first live vertical slice of HyperDHT private routing. It
replaces Gate 3A's trusted in-process route authority with signed relay
discovery, bounded numeric bootstrap, a pinned guard, two authenticated
three-position route branches, and a live DHT exit. One immutable DHT value is
retrieved through the lookup branch while the endpoint retains control of
iterative Kademlia traversal and receives no raw network address or direct-send
authority.

The endpoint topology is:

```text
                         +-> lookup middle   -> lookup DHT exit   -> DHT nodes
endpoint -> pinned guard |
                         +-> announce middle -> announce DHT exit -> DHT nodes
```

Gate 3B1 keeps all private-routing constructors internal. Direct mode remains
the only public HyperDHT behavior. This milestone does not enable Hyperswarm,
peer streams, mutable operations, public required mode, mobile integration, or
a production anonymity claim.

## Approved Approach

Migrate the reviewed live-route kernel from the existing private-routes
prototype into HyperDHT's internal `lib/private/` boundary, then adapt it to
Gate 3A's hardened codecs, ownership rules, and DHT-RPC request-transport seam.

The implementation source is read-only evidence:

```text
repository: /Users/jd/.config/superpowers/worktrees/peartube/private-routing
commit: 0305df915b6a767093f9e75e6c06bc0a35da6169
source root: packages/private-routes
```

Relevant prototype units include relay capabilities, bootstrap IO, guard links,
link setup/control, route management, relay service, live UDX endpoints,
multi-process Node/Bare integration, and the Linux namespace capture oracle.
Migrated code must preserve provenance in the migration record and file-level
comments. Prototype behavior is not accepted automatically: every migrated
unit is narrowed to this spec, reconciled with the canonical v1 protocol, and
covered by HyperDHT-native tests.

Two alternatives were rejected:

- rebuilding the live route kernel from the Gate 3A primitives would repeat
  substantial security-sensitive work and discard existing process and capture
  evidence;
- retaining a separate runtime package would create dependency/version skew and
  split lifecycle ownership across UDX, DHT-RPC, and HyperDHT.

## Goals

- Verify signed, short-lived relay advertisements before contact or allocation.
- Bound cold-start exposure to numeric bootstrap and prospective-guard
  endpoints.
- Pin one stable authenticated guard and revoke general direct authority before
  route readiness.
- Construct pairwise-diverse lookup and announce branches that share only the
  guard.
- Run authenticated fixed-cell traffic over live adjacent UDX links.
- Enforce relay quotas, expiry, rotation, cancellation, and complete teardown.
- Give a DHT exit the sole ordinary DHT socket and a provenance-qualified,
  generation-bound destination table.
- Replace Gate 3A's trusted logical immutable-get response with exact live
  request and reply bytes.
- Retrieve and locally verify one immutable DHT value through the lookup route
  in separate Node and Bare process suites.
- Prove by packet capture and semantic inspection that an endpoint contacts
  only its guard after readiness.

## Non-goals

- Public `privateRouting`, `privacy`, or required-mode constructor options.
- Hyperswarm discovery, connection routing, Noise streams, or Hypercore
  replication.
- Announce, unannounce, mutable get/put, immutable put, private presence, or
  peer-descriptor operations. The announce branch is built and kept live to
  prove branch separation, but it carries no application request in Gate 3B1.
- Legacy-peer egress or private-to-private rendezvous.
- DNS, public Internet relay selection, NAT traversal, hole punching, direct
  races, direct retries, or direct upgrades.
- Persistent mobile guard state, iOS/Android background execution, radio
  migration, or application UI integration.
- Cover traffic, timing-analysis resistance, Sybil resistance, relay
  incentives, collusion resistance, or protection from a global observer.
- Production readiness or an anonymity guarantee.

## Security Boundary

Before guard pinning, `BootstrapIO` is the only component with general direct
network authority. It may contact only the bounded numeric endpoints described
below. After guard pinning, the endpoint retains one opaque link capability for
the pinned guard and no API capable of converting an identity, advertisement,
referral, host, port, or destination reference into a direct send.

The guard sees the endpoint address and adjacent route middles. Each middle sees
only its adjacent guard and exit. Each exit sees its adjacent middle and the
ordinary DHT destinations it contacts. Ordinary DHT nodes see the exit address,
not the endpoint address. Relays see timing, packet count, direction, and fixed
cell volume. These observations are explicit, not treated as failures.

Route knowledge and send authority remain separate. A component may inspect a
verified advertisement while selecting a path, but only an authenticated,
role-scoped adjacent-link capability may send to that advertisement's endpoint.
No route consumer receives a general UDX socket or host/port send function.

## Protocol Ownership

The canonical v1 protocol document remains normative for role derivation,
topology, diversity, fixed-cell dimensions, counters, fragmentation, resource
ceilings, lifecycle, and packet/leak oracles. Gate 3B1 narrows that protocol to
the live immutable-get slice. Where the prototype's milestone-2 static graph
differs from canonical v1, canonical v1 wins.

Gate 3B1 must add exact constructors and known vectors for every transcript it
uses. Each transcript binds at least:

- protocol and format versions;
- role and branch purpose;
- both adjacent identities and verified advertisement digests;
- circuit ID and route generation where applicable;
- direction and message class where applicable;
- negotiated fixed-cell and resource parameters;
- nonces, ephemeral keys, epochs, and expiry where applicable.

The implementation may reuse the prototype's `m3-context.js`, `tail-control.js`,
and live route-state derivation material only after its exact bytes are reviewed
against the canonical v1 domains. The resulting vectors are frozen in Node and
Bare tests. A wire-visible byte cannot be chosen implicitly from JavaScript
object enumeration, platform endianness, wall-clock formatting, or runtime
string conversion.

## Components and Interfaces

### `RelayAdvertisement`

Owns canonical encode, decode, digest, signature verification, role derivation,
and expiry validation for one relay advertisement. The signed body contains:

- protocol and advertisement format versions;
- relay Ed25519 identity;
- one numeric IPv4 or IPv6 address and UDP port;
- role derived from the identity by canonical v1 rules;
- supported cell/version parameters and bounded capacity classes;
- advertisement epoch, not-before time, and expiry.

Verification rejects noncanonical encodings, hostnames, multiple-address
containers, invalid ports, identity/role mismatch, unsupported parameters,
unknown fields, trailing bytes, invalid time intervals, expired/future records,
and bad signatures before candidate allocation or contact. Decoded results are
defensive owned copies and do not themselves grant send authority.

### `BootstrapIO`

Owns the only pre-guard general direct-send capability. It accepts no more than
three configured, deduplicated numeric bootstrap endpoints. Across all valid
bootstrap responses it may actively challenge no more than three distinct
prospective guards. Contacts are sequential, only one challenge is in flight,
and one ten-second monotonic deadline covers bootstrap cookies, advertisement
validation, guard challenges, and first-link completion.

Retries cannot expand either endpoint set. Referrals that are hostnames,
nonnumeric, duplicated, invalid, expired, or beyond either numeric bound are
rejected without IO. Exhaustion returns `ERR_PRIVATE_GUARD_UNAVAILABLE`.

The exposure report contains at most six distinct entries and records only
phase, contact category, a keyed/redacted endpoint digest, first and last
attempt times, attempt count, and allowlisted outcome. It never records a raw
endpoint, route key, topic, descriptor, or stable cross-generation identifier.

### `GuardLease`

Owns one verified guard identity, advertisement digest, adjacent-link
capability, lease epoch, expiry, and liveness state. Pinning is atomic:

1. authenticate the guard link and bind its exact transcript;
2. freeze the selected guard identity and endpoint;
3. revoke and destroy bootstrap sockets, callbacks, candidate tables, routing
   scratch state, and generic send capabilities;
4. verify those resources are absent;
5. publish `GUARD_PINNED` to the internal controller.

Post-pinning revalidation may contact only the pinned guard through its existing
authority. It cannot follow a referral, resolve another endpoint, or substitute
an advertisement. Losing the guard invalidates every dependent branch and
destination capability.

### `RouteManager`

Owns the endpoint lifecycle and exactly two branch slots: `LOOKUP` and
`ANNOUNCE`. It selects one middle and one DHT exit for each branch. Both branches
share the pinned guard identity and endpoint; their middle and exit identities
and endpoints are pairwise distinct.

Selection enforces canonical role, version, expiry, identity, endpoint, IPv4
`/24`, IPv6 `/48`, IPv4-mapped IPv6 normalization, loop, and local-quarantine
rules. There is no diversity relaxation. Insufficient candidates fail with
`ERR_PRIVATE_INSUFFICIENT_RELAYS`.

Each branch has fresh route keys, nonce prefixes, circuit ID, generation,
counters, replay state, quotas, and expiry. The manager exposes only opaque
branch/query capabilities to `RoutedDHTIO`; it exposes no addresses or path
array.

### `AdjacentLink`

Owns one authenticated UDX adjacency. Link bootstrap/setup messages use the
reserved bootstrap cell class and exact Gate 3B1 transcript vectors.
Established CONTROL, STREAM, and DATAGRAM cells use the existing Gate 3A
fixed-cell codecs and counters. Bootstrap and established encodings cannot be
decoded as each other.

The link accepts traffic only from the verified numeric tuple and identity
bound into its grant and transcript. Address change, spoofed tuple, mutation,
replay, wrong direction, wrong branch, wrong generation, counter exhaustion,
expiry, or liveness failure closes the link and notifies dependent circuits.
No caller can use the link to send to an arbitrary tuple.

### `RelayService`

Owns opaque adjacent forwarding state. A relay installs only previous-hop and
next-hop capabilities for one authenticated circuit and generation. It cannot
enumerate a full path or unwrap the end-to-end routed DHT body.

Canonical v1 ceilings apply: 128 circuits globally, 32 per observed neighbor,
256 KiB queued per circuit, 8 MiB globally, bounded pending requests/replay/
tombstones, five-second half-open/reassembly deadlines, and atomic queue
admission. Negotiation may lower but not raise ceilings. Exhaustion returns a
bounded `RELAY_BUSY` response or destroys the affected circuit without direct
fallback. Fair scheduling prevents one circuit from monopolizing the global
queue.

### `DHTExitAuthority`

Owns one allowlisted ordinary DHT socket, one branch handle secret, and one
bounded destination table per active branch generation. A table entry binds:

- issuing exit identity;
- branch, circuit ID, and generation;
- numeric address and derived address-based DHT node ID;
- provenance and validation time;
- allowed command classes;
- capability expiry and usage/amplification counters.

Initial entries may come only from the exit's configured numeric DHT bootstrap
set. Later entries may come from its current routing table, actively validated
capability cache, recent valid protocol traffic, or a protocol-valid referral
from an already admitted destination. A referral is evidence, not authority.
Before admission, the exit validates globally routable unicast address/port,
derives the node ID, applies probe and amplification budgets, and completes the
ordinary DHT validation exchange.

The production path rejects special-use, private, loopback, link-local,
multicast, documentation, benchmark, carrier-grade NAT, and invalid mapped
ranges before target-dependent crypto, allocation, or IO. A non-exported test
authority may admit only exact endpoints signed into the isolated test topology.

The public destination reference is unpredictable and branch-bound. The exit
accepts only exact immutable-get requests against a live reference issued by
that same exit, branch, circuit, generation, command policy, and expiry.
Arbitrary UDP, raw destinations, hostname resolution, private scanning, and
caller-computed node IDs are impossible through this interface.

### `RoutedDHTIO`

Retains the existing internal nine-method DHT-RPC request-transport contract and
per-instance query capabilities. Gate 3B1 replaces the trusted in-process
logical authority with a live branch authority that:

- obtains opaque closest/bootstrap destination objects from exit-issued
  references;
- encodes one exact immutable-get request body;
- sends it through the lookup route;
- decodes one exact normalized reply body;
- imports only exit-qualified referrals;
- propagates cancellation to the active routed operation.

The adapter never accepts or returns a host, port, socket, direct node object,
path array, or generic send callback. Unsupported DHT commands fail before
candidate discovery or authority IO. Logical response size and all encoded
fixed-cell/framing overhead count toward amplification budgets.

## Immutable-get Data Flow

1. `BootstrapIO` contacts its bounded numeric bootstrap set and receives signed
   relay advertisements.
2. The client verifies canonical bytes, signatures, roles, parameters, and
   expiry before retaining candidates.
3. It challenges and pins one guard. Pinning destroys all pre-guard general
   direct authority.
4. `RouteManager` selects pairwise-diverse lookup and announce middles/exits and
   establishes authenticated adjacent links and branch generations.
5. Both branches become live. Internal readiness remains false until both are
   authenticated, diverse, within quota, and unexpired.
6. The lookup exit mints opaque references for its configured DHT bootstrap
   destinations and returns them through the lookup branch.
7. DHT-RPC performs client-controlled iterative traversal. For each candidate,
   `RoutedDHTIO` sends the exact immutable-get request through the route.
8. The exit validates the reference and command, sends one ordinary DHT request,
   validates the reply, qualifies any referrals, and returns normalized reply
   bytes through the same branch.
9. The endpoint continues traversal using only imported opaque references. It
   accepts the value only when the existing immutable-value hash verification
   succeeds locally.
10. Cancellation, timeout, rotation, or teardown revokes the active operation
    and every no-longer-valid reference without creating direct authority.

## Lifecycle and Failure Semantics

The internal state machine is:

```text
OFF -> BOOTSTRAPPING -> GUARD_PINNED -> BUILDING -> READY
                                              READY -> ROTATING -> READY
                                                |          |
                                                +-> UNAVAILABLE -> DESTROYED
```

Only one transition function may mutate controller state. Every transition
checks current state, owned capabilities, generation, and destruction status
before side effects. Reentrant callbacks cannot observe or publish partial
readiness.

- `READY` requires both lookup and announce branches.
- After `READY`, the endpoint may emit packets only to its pinned guard.
- Middle or exit loss rotates only the affected branch while preserving the
  guard. New operations use the new generation.
- Rotation is make-before-break when capacity permits. Bounded in-flight work
  may drain on the old generation; no new operation can start there.
- Old destination capabilities are invalid for new work immediately and are
  erased when drain completes or its deadline expires.
- Guard loss destroys both branches and returns
  `ERR_PRIVATE_GUARD_UNAVAILABLE` without contacting a replacement.
- A fresh bounded bootstrap phase is possible only after complete teardown of
  the former guard and route authority.
- Suspend cancels timers and pending operations and destroys ephemeral send
  authority. It retains only the minimal non-general authority needed to name
  and revalidate the pinned guard.
- Resume may contact only the pinned guard. Failure enters `UNAVAILABLE`.
- Network change invalidates observed reachability, branch generations, and
  destination capabilities. It never enables DNS, direct DHT, hole punching,
  referral dialing, or fallback.
- Shutdown closes routed DHT work first, then branches, relay circuits, adjacent
  links, the guard lease, and remaining sockets, and finally zeroes owned
  secrets and tombstones.

Authentication, replay, counter, malformed-body, hash, expiry, quota, and
amplification failures destroy the narrowest affected operation or circuit. If
shared link integrity is uncertain, the adjacent link and all dependent
circuits are destroyed. No error path returns a dialable address.

Stable errors include `ROUTE_UNAVAILABLE`, `GUARD_UNAVAILABLE`,
`INSUFFICIENT_RELAYS`, `AUTHENTICATION_FAILED`, `RELAY_BUSY`,
`ROUTED_REQUEST_TIMEOUT`, `NETWORK_CHANGED`, `INVALID_DESTINATION`, and
`UNSUPPORTED_PRIVATE_COMMAND`. Error objects and logs contain no endpoints,
route keys, topics, raw advertisements, full paths, or direct-retry advice.

## Resource and Amplification Accounting

Existing canonical v1 fixed-cell and fragment ceilings remain unchanged. Every
limit is checked before allocation or callback. Gate 3B1 additionally accounts
for a request as:

```text
encoded routed body
+ fragment headers
+ route-payload framing
+ fixed-cell framing and authentication
+ exit-side ordinary DHT request bytes
```

The reply budget uses the analogous complete encoded cost and includes every
returned referral. A malformed or oversized reply is rejected before
normalization or destination admission. Probe, request, response, referral,
and destination-table budgets are charged to the issuing branch/circuit and
cannot be reset by retrying a semantically identical request under fresh cell
counters. The implementation exposes only aggregate counters suitable for
tests and redacted metrics.

## Testing Strategy

### Unit and vector tests

Node and Bare run identical focused suites for:

- advertisement canonical bytes, signatures, role derivation, time bounds,
  defensive ownership, and hostile shapes;
- exact role/branch/link/circuit/generation transcript and KDF vectors;
- bootstrap endpoint/challenge/deadline bounds and exposure redaction;
- guard pinning atomicity and direct-authority revocation;
- branch diversity, independent generations, rotation, and teardown;
- adjacent authentication, tuple binding, replay, liveness, and counters;
- relay quotas, fair queueing, expiry, cancellation, and tombstones;
- immutable-get request/reply bytes, trailing-data rejection, and hash checks;
- destination provenance, special-use rejection, probing, capability binding,
  generation invalidation, and table bounds;
- logical and encoded-byte amplification accounting;
- sanitized errors, metrics, logs, and zero owned state after destruction.

Property/adversarial cases cover mutation, truncation, extension, cross-branch
substitution, wrong generation, stale capability, replay, duplicated setup,
conflicting retry, allocation failure, reentrant destroy, malicious referral,
oversized response, counter exhaustion, and simulated clock boundaries.

### Deterministic topology tests

An in-process controlled topology exercises candidate selection, stable guard
reuse, independent lookup/announce branches, immutable-get traversal,
cancellation, link/route loss, make-before-break rotation, suspend/resume,
network change, and complete teardown. Deep inspection is test-only and is not
exported by `lib/private/`.

### Portable multi-process integration

The coordinator launches distinct processes for:

- endpoint;
- pinned guard;
- lookup middle and lookup DHT exit;
- announce middle and announce DHT exit;
- enough ordinary DHT nodes to store, route, and retrieve one immutable value.

The same suite runs once with Node child processes and once with Bare child
processes. Each process receives a role-scoped audited configuration and only
its permitted adjacent capabilities. The coordinator stores a known immutable
value through the ordinary DHT, starts the private endpoint, waits for both
branches to become ready, retrieves the value through the lookup route, and
verifies the hash and exact bytes at the endpoint.

The portable suite proves runtime compatibility and process isolation. Bare
success is not evidence for iOS/Android backgrounding, radio changes,
app-private persistence, or real-device lifecycle behavior.

### Privileged Linux namespace oracle

GitHub Actions runs the same topology with every role in its own Linux network
namespace on unique synthetic addresses. Packet capture attributes each packet
to its process/interface and enforces phase-aware edges.

Before guard pinning, only the exposure report's bounded bootstrap and
prospective-guard edges are allowed. After readiness:

- endpoint traffic is only endpoint to/from pinned guard;
- the guard contacts only the two selected middles for route traffic;
- each middle contacts only its guard and branch exit;
- each exit contacts only its middle and provenance-qualified DHT destinations;
- no endpoint contacts an exit or ordinary DHT node;
- no role emits DNS, TCP, IPv6 outside an explicitly selected IPv6 topology, or
  traffic on an unconfigured interface;
- teardown produces no later packet.

A separately isolated negative-control packet must be captured and rejected by
the oracle, proving that forbidden-capability traffic is observable. Missing or
malformed capture evidence fails the job.

### Semantic leak oracle

Every endpoint receives a distinctive numeric address and byte sentinel. The
harness inspects decoded route/DHT messages, advertisements, candidate and
destination tables, errors, metrics, logs, events, process configuration, and
teardown snapshots. Outside the documented pre-guard observations and the
pinned guard's adjacent state, the test fails if an endpoint address or sentinel
appears in plaintext, becomes public dial authority, or crosses a public API.

An in-process authority trap separately fails any attempted endpoint direct
send, even if a firewall or namespace rule would have hidden the packet.

### Compatibility and CI

- All unchanged HyperDHT tests pass in Node and Bare.
- The pinned DHT-RPC fork remains exact and its Node/Bare tests pass.
- Direct constructors and direct wire encodings remain unchanged.
- GitHub Actions runs formatting and Node/Bare tests on Linux, macOS, and
  Windows where supported.
- Portable multi-process Node and Bare jobs run on unprivileged runners.
- The packet/leak oracle runs as a separate privileged Linux job with pinned
  action revisions and installed `iproute2`, `tcpdump`, and firewall tooling.
- Exact-head workflow evidence is recorded in the baseline before Gate 3B1 is
  declared complete.

## Completion Contract

Gate 3B1 is complete only when all of the following pass fork-native CI:

1. Signed relay advertisements and bounded numeric bootstrap select and pin an
   authenticated guard.
2. Pinning demonstrably destroys all pre-guard general direct authority.
3. Pairwise-diverse lookup and announce branches are independently ready and
   share only the pinned guard.
4. Adjacent UDX links, three-position routes, quotas, rotation, cancellation,
   expiry, and teardown pass Node and Bare tests.
5. Exact live immutable-get request/reply and transcript vectors pass Node and
   Bare.
6. The exit admits only provenance-qualified destinations and invalidates every
   reference on generation expiry or rotation.
7. One immutable value is retrieved and locally hash-verified over the live
   lookup route in separate Node and Bare process suites.
8. Linux packet capture proves endpoint-to-guard-only traffic after readiness,
   and its negative control proves the oracle can detect a forbidden edge.
9. The semantic oracle finds no endpoint-address or sentinel leak outside the
   documented exposure boundary.
10. Route loss, guard loss, suspend/resume, network change, and teardown fail
    closed with zero remaining processes, sockets, routes, queues, destination
    capabilities, callbacks, timers, or owned secret state.
11. Existing direct-mode HyperDHT and DHT-RPC behavior remains green.
12. No public private-routing option, Hyperswarm integration, unsupported DHT
    operation, or production anonymity claim is introduced.

Passing Gate 3B1 does not close Delivery Gate 3. Later separately reviewed
slices must add the remaining DHT operations, public required-mode controller,
Hyperswarm/private and legacy peer streams, mobile lifecycle/device evidence,
and the complete canonical v1 readiness matrix.
