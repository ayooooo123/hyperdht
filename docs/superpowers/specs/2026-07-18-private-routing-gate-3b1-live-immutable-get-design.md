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
GitHub: https://github.com/ayooooo123/peartube/tree/0305df915b6a767093f9e75e6c06bc0a35da6169
commit: 0305df915b6a767093f9e75e6c06bc0a35da6169
source root: packages/private-routes
wire registry: docs/superpowers/specs/2026-07-14-native-dht-private-routing-m3-wire-registry.md
```

Relevant prototype units include relay capabilities, bootstrap IO, guard links,
link setup/control, route management, relay service, live UDX endpoints,
multi-process Node/Bare integration, and the Linux namespace capture oracle.
Migrated code must preserve provenance in the migration record and file-level
comments. Prototype behavior is not accepted automatically: every migrated
unit is narrowed to this spec, reconciled with the canonical v1 protocol, and
covered by HyperDHT-native tests.

That exact-commit wire registry, together with the exact prototype functions
named in this document, is the byte-level normative baseline for Gate 3B1. A
format marked "adopt" below is migrated byte-for-byte, including its message
ID, field order, integer width/endianness, size, domain, authentication suffix,
validation, and known vectors. Gate 3B1 defines an explicit amendment where its
narrower immutable-get scope differs. An implementation plan may split the work
into dependency stages but may not invent replacement wire bytes.

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
  only its guard from the instant guard pinning commits.

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

Gate 3B1 adopts the following exact formats from prototype commit
`0305df915b6a767093f9e75e6c06bc0a35da6169`:

| Format                                     | Exact source symbol(s)                                                                                    | Gate 3B1 rule                                                                                                                          |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| M3 object header and ID/size registry      | `lib/protocol.js`: `encodeM3Object`, `decodeM3Object`, `M3_MESSAGE_ID`, `M3_OBJECT_LAYOUT`                | Adopt. Header is `u32be protocolVersion=1`, `u16be messageId`, `u16be bodyBytes`, body, then the registered fixed auth suffix.         |
| Relay advertisements and CAPS discovery    | `lib/relay-capability.js`: advertisement, CAPS cookie/query/response, active-challenge codecs and domains | Adopt, with the capability and freshness restrictions below.                                                                           |
| Adjacent bootstrap envelope and link setup | `lib/bootstrap-envelope.js`, `lib/link-setup.js`, `lib/guard-link.js`                                     | Adopt. Every bootstrap datagram is exactly 1,200 bytes and signed under `hyperdht-private-routes/udx-bootstrap/v0`.                    |
| Tail/extension control and M3 contexts     | `lib/tail-control.js`, `lib/m3-context.js`, `lib/extension-*`, `lib/branch-*-authority.js`                | Adopt only the safety guard/middle/exit path used by this spec.                                                                        |
| Terminal DHT-exit finalization             | `lib/final-exit.js`, `lib/final-exit-activation.js`                                                       | Adopt `DHT_EXIT_ACTIVATE/READY/READY_ACK/OPEN`, final-exit transcript, policy/parameter digests, and all twelve final-exit KDF labels. |
| Destination reference and routed request   | local `lib/private/routed-dht.js`                                                                         | Retain Gate 3A bytes: 172-byte `DESTINATION_REF_V1` and fixed 221-byte `ROUTED_REQUEST_V1` body.                                       |
| Routed reply                               | exact registry Section 10.3                                                                               | Implement unchanged as specified below; this is the Gate 3A deferred codec.                                                            |
| DHT exit seed delivery                     | new `DHT_EXIT_DHT_SEEDS_V1 = 0x0045`                                                                      | Gate 3B1 DHT-only object defined below. Registered `DHT_EXIT_SEEDS_V1 = 0x0044` is unchanged and unused.                               |
| Fixed cells, route payload, fragmentation  | local Gate 3A `cell-codec.js`, `route-payload.js`, `fragments.js`                                         | Retain reviewed Gate 3A bytes and ceilings.                                                                                            |

Gate 3B1 adds one previously unassigned M3 message without changing an existing
layout: `DHT_EXIT_DHT_SEEDS_V1 = 0x0045`. Its M3 registry entry is body range
310..654 with a 64-byte auth suffix. Its exact body is:

```text
u8   branchClass
16B  branchId
16B  circuitId
u64  generation
32B  exitIdentity
32B  seedSetNonce
u8   dhtSeedCount                  // 1..3
dhtSeedCount * 172B DESTINATION_REF_V1
32B  seedSetDigest
64B  exit Ed25519 signature suffix
```

The fixed body is 138 bytes before references, so total body length is
`138 + 172*dhtSeedCount`. The signature domain is
`hyperdht-private-routes/m3/dht-exit-dht-seeds/v1`. The set digest domain is
`hyperdht-private-routes/m3/dht-exit-dht-seeds/set/v1` over the one-byte count
and complete DHT-reference bytes. References are unique and sorted by
destination ID, then complete handle bytes. Signature,
branch/circuit/generation/exit equality, set digest, count, order, handle class,
and table-backed liveness are checked before any reference enters client state.
Both domains and one exact minimum/maximum vector are frozen before the object
is used. Registered `DHT_EXIT_SEEDS_V1 = 0x0044`, its 905..4,265-byte body, and
its existing domains remain byte-for-byte unchanged.

The adopted signature/KDF domains used by this slice are frozen UTF-8 strings:

```text
hyperdht-private-routes/m3/capability-advertisement/v1
hyperdht-private-routes/m3/capability-advertisement-digest/v1
hyperdht-private-routes/m3/active-challenge-response/v1
hyperdht-private-routes/m3/active-challenge/route-key-proof/v1
hyperdht-private-routes/m3/caps-return-cookie/v1
hyperdht-private-routes/udx-bootstrap/v0
hyperdht-private-routes/final-exit/service-policy/v1
hyperdht-private-routes/final-exit/payload-parameters/v1
hyperdht-private-routes/final-exit/transcript/v1
hyperdht-private-routes/m3/final-exit/transcript-digest/v1
hyperdht-private-routes/m3/dht-exit-ready/v1
hyperdht-private-routes/m3/dht-exit-ready-digest/v1
hyperdht-private-routes/m3/dht-exit-ready-ack-digest/v1
hyperdht-private-routes/m3/dht-exit-dht-seeds/v1
hyperdht-private-routes/m3/dht-exit-dht-seeds/set/v1
hyperdht-private-routes/m3/destination/server-binding/v1
hyperdht-private-routes/m3/destination/handle-auth/v1
```

The twelve final-exit KDF labels are the exact `FINAL_LABELS` strings in
prototype `lib/final-exit.js`: forward/reverse `payload`, `control`, and
`finalize`, each with one `key` and one `nonce`. No shorter alias is accepted.

Gate 3B1 adds exact constructors and known vectors for every adopted transcript
it uses. Every route transcript binds:

- protocol and format versions;
- role and branch purpose;
- both adjacent identities and verified advertisement digests;
- circuit ID and route generation in every adopted format that contains them;
- direction and message class in every adopted format that contains them;
- negotiated fixed-cell and resource parameters;
- nonces, ephemeral keys, epochs, and expiry required by its exact adopted
  codec.

The resulting vectors are frozen in Node and Bare tests. A wire-visible byte
cannot be chosen implicitly from JavaScript object enumeration, platform
endianness, wall-clock formatting, or runtime string conversion. Any intended
change to a listed source layout or domain requires a design amendment and a
protocol-version change before implementation.

## Components and Interfaces

### `RelayAdvertisement`

Owns canonical encode, decode, digest, signature verification, role derivation,
and expiry validation for one relay advertisement. The signed body contains:

- protocol and advertisement format versions;
- relay Ed25519 identity;
- one canonical 19-byte numeric IPv4 endpoint and its derived DHT node ID;
- role derived from the identity by canonical v1 rules;
- the exact capability bit mask, route-encryption X25519 public key,
  protocol/cell parameters, capacity class, circuit/byte/command/idle/queue
  ceilings, and capability-selected service-policy entries;
- advertisement epoch, not-before time, and expiry.

Gate 3B1 uses the adopted `CAPABILITY_ADVERTISEMENT_V1` body layout exactly:

| Body offset | Bytes        | Field                                    |
| ----------- | ------------ | ---------------------------------------- |
| 0           | 32           | relay Ed25519 identity                   |
| 32          | 32           | current derived DHT node ID              |
| 64          | 19           | canonical numeric endpoint               |
| 83          | 32           | route-encryption X25519 public key       |
| 115         | 4            | capability mask                          |
| 119         | 4            | minimum protocol version                 |
| 123         | 4            | maximum protocol version                 |
| 127         | 14           | seven `u16be` cell/route/circuit scalars |
| 141         | 1            | capacity class                           |
| 142         | 20           | five `u32be` resource ceilings           |
| 162         | 8            | epoch                                    |
| 170         | 8            | issued-at Unix epoch milliseconds        |
| 178         | 8            | expires-at Unix epoch milliseconds       |
| 186         | 2            | service-policy entry count               |
| 188         | `32 * count` | exact capability-selected policy entries |
| after body  | 64           | relay Ed25519 signature auth suffix      |

Every integer is big-endian. A circuit-only guard or middle has capability mask
`CIRCUIT_RELAY_V1 = 1`, derived `SAFETY` role, and zero policy entries. A Gate
3B1 DHT exit has mask `CIRCUIT_RELAY_V1 | DHT_EXIT_V1 = 3`, derived `PRIVATE`
role, and exactly the four DHT policy entries in immutable order. Gate 3B1
supports only the immutable-get entry operationally, but the signed four-entry
subset remains byte-identical to the adopted capability format. An exit missing
either capability cannot be selected.

Verification rejects noncanonical encodings, hostnames, multiple-address
containers, invalid ports, identity/role mismatch, unsupported parameters,
unknown fields, trailing bytes, invalid time intervals, expired/future records,
and bad signatures before candidate allocation or contact. Decoded results are
defensive owned copies and do not themselves grant send authority.

The canonical endpoint codec can represent IPv6, but Gate 3B1 capability
advertisements and live topology require IPv4 because the adopted DHT node-ID
derivation is defined only for the compact six-byte IPv4 endpoint. An IPv6
advertisement fails `ERR_INCOMPATIBLE_RELAY` before contact. IPv6 support needs
a later protocol-reviewed sub-gate; this fail-closed narrowing does not relax
the canonical v1 diversity rule.

The signed lifetime is at most 1,800,000 ms. Validation uses wall-clock Unix
milliseconds and requires `issuedAt <= now + 30,000`, `expiresAt > now`, and
`expiresAt - issuedAt <= 1,800,000`. Per relay identity, the directory retains
the highest accepted nonzero epoch and up to sixteen distinct route-encryption
keys for that epoch history. A lower epoch is replay; a byte-identical object at
the current epoch is idempotent; a different digest at the same epoch is
equivocation and quarantines that identity for the remainder of the later of
the two expiries. A seventeenth distinct route key poisons/quarantines the
identity instead of evicting history.

Monotonic clocks own elapsed deadlines and scheduled expiry timers. A timer
never extends signed wall-clock expiry. A backward wall-clock jump exceeding
30,000 ms from the controller's last accepted sample invalidates all
advertisements and branches and enters `UNAVAILABLE`; a forward jump expires
state immediately. Active challenge completion must also occur inside the
adopted 5,000 ms challenge deadline and prove possession of the advertised
route-encryption secret key.

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

Before guard pinning, `BootstrapIO` may collect at most sixteen unique,
signature-verified, unexpired relay advertisements across its bounded CAPS
responses. It never contacts a middle or exit candidate. Immediately before
revoking bootstrap authority it transfers owned canonical advertisement bytes
and digests into one `RelayCandidateDirectory`; it transfers no socket,
callback, address-to-send function, routing entry, or referral authority.

### `RelayCandidateDirectory`

Owns the bounded post-bootstrap advertisement evidence used for initial branch
selection and rotation. It is an immutable-by-default, non-dialing directory:
lookups accept only branch role/capability/diversity predicates and return
defensive advertisement/digest projections. It exposes no host/port lookup,
socket, arbitrary enumeration to public code, refresh method, or network IO.

The directory is scoped to the pinned guard lease, retains no more than sixteen
identities, revalidates signed expiry/epoch on every selection, and quarantines
equivocation as specified above. `RouteManager` may consume a candidate once
per branch generation. Extension requests carry the complete signed
advertisement through the pinned guard using the adopted in-route
`RELAY_DISCOVER_V1`/link-extension formats; the endpoint itself never dials the
candidate tuple. Gate 3B1 performs no post-pinning discovery. Initial build or
rotation fails closed when the retained set cannot satisfy diversity. Guard
loss, suspend, network change, or controller destroy clears the directory.

### `GuardLease`

Owns one verified guard identity, advertisement digest, adjacent-link
capability, lease epoch, expiry, and liveness state. Pinning is atomic:

1. authenticate the guard link and bind its exact transcript;
2. freeze the selected guard identity and endpoint;
3. atomically seal and transfer the verified non-dialing
   `RelayCandidateDirectory`;
4. revoke and destroy bootstrap sockets, callbacks, unsealed candidate tables,
   routing scratch state, and generic send capabilities;
5. verify those resources are absent and the sealed directory exposes no send
   authority;
6. publish `GUARD_PINNED` to the internal controller.

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
`ERR_INCOMPATIBLE_RELAY`.

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
bounded `ERR_BUSY` response or destroys the affected circuit without direct
fallback. Fair scheduling prevents one circuit from monopolizing the global
queue.

### `TerminalExitSession`

Owns end-to-end authentication between the endpoint and the selected DHT exit;
adjacent-link authentication alone is insufficient. The source uses a fresh
X25519 ephemeral secret and the route-encryption public key from the exact
selected exit advertisement. The exit uses the corresponding advertised secret.
Only those endpoints derive the final-exit payload/control/finalize keys.

The session adopts the prototype `DHT_EXIT_ACTIVATE_V1` (96-byte body),
`DHT_EXIT_READY_V1` (233-byte body plus 64-byte exit signature),
`DHT_EXIT_READY_ACK_V1` (105-byte body), and `DHT_EXIT_OPEN_V1` (169-byte body)
state machine. Its final-exit transcript is exactly 287 bytes and binds branch
class, 16-byte branch ID, 16-byte circuit ID, generation, tail-control transcript
digest, selected exit-advertisement digest, exit identity, client activation
nonce, exact four-entry exit-policy digest, and payload-parameter digest.

The endpoint verifies `READY` under the selected advertised exit identity and
checks byte equality for the branch, circuit, generation, advertisement/policy/
parameter transcript bindings before sending `ACK`. The exit enters OPEN only
after validating ACK; the endpoint publishes the branch only after validating
OPEN. A guard or middle that substitutes an exit identity, advertisement,
route key, policy, parameters, transcript, nonce, circuit, or generation cannot
derive the source-to-exit AEAD or produce the exit signature.

The complete finalization deadline is 5,000 monotonic milliseconds from the
initial ACTIVATE. Exact semantic send times are 0, 250, 750, 1,750, and 3,750
ms; retries reuse identical semantic bytes under fresh datagram counters.
Duplicate messages receive only the cached next response. Conflict or expiry
destroys the circuit. After OPEN, finalization receive-only tombstones and the
cached OPEN survive for exactly 5,000 ms, then all retired keys and semantic
caches are erased. Route payload and routed DHT bodies use the derived inner
AEAD, so relays forward opaque fixed-size cells and cannot read or replace them.

### `DHTExitAuthority`

Owns one allowlisted ordinary DHT socket, one branch handle secret, and one
bounded destination table per active branch generation. A table entry binds:

- issuing exit identity;
- branch, circuit ID, and generation;
- numeric address and derived address-based DHT node ID;
- provenance and validation time;
- allowed command classes;
- capability expiry and usage/amplification counters.

Gate 3B1 permits only two provenance classes:

- `CONFIGURED_BOOTSTRAP`: an exact numeric tuple in the exit's immutable
  branch configuration, successfully pinged after terminal OPEN;
- `VALIDATED_PROTOCOL_REFERRAL`: a closer-node tuple decoded from a valid
  HyperDHT immutable-get reply whose DHT-RPC transaction correlates to an
  outstanding request sent to an already admitted reference.

`PUBLIC_ROUTING_TABLE`, `ACTIVE_CAPABILITY_CACHE`, and
`RECENT_VALID_PROTOCOL_TRAFFIC` are rejected in Gate 3B1. A referral is
evidence, not authority. The exit requires the upstream response source tuple
to byte-equal the requested binding, its transaction/session correlation to
match the outstanding request, and every closer tuple to pass canonical
globally-routable validation before any probe allocation.

Reachability validation is exactly one ordinary DHT-RPC `PING` (`command 0`)
with retry disabled and a fresh transaction/cookie generated by the exit. The
probe has a 1,000 ms monotonic deadline. Success requires a correlated reply
from the exact candidate tuple before the deadline and equality between the
candidate's address-derived DHT node ID and the proposed ID. There is no second
packet, delayed ping, NAT ping, hostname lookup, or fallback. One upstream
reply admits at most eight candidate probes, at most three probes run
concurrently, one admitted destination may cause at most eight probes per
60-second monotonic window, and one branch generation permits at most 32 total
probes and 64 live table entries. Duplicate tuples/IDs consume no new probe but
cannot refresh expiry. Exhausting a bound omits the excess candidates rather
than expanding authority.

Before sending the ping, the exit installs one non-public
`EXIT_VALIDATION_PROBE` audit record containing branch/circuit/generation,
issuing admitted-reference digest or configured-bootstrap index, candidate
tuple and derived ID, DHT transaction correlation, monotonic deadline, and
charged budget slot. The record authorizes exactly that one ping and matching
reply edge; it is removed on reply, timeout, cancellation, rotation, or
teardown. It is validation evidence only and cannot authorize an immutable-get
or mint a destination reference.

The production path rejects special-use, private, loopback, link-local,
multicast, documentation, benchmark, carrier-grade NAT, and invalid mapped
ranges before target-dependent crypto, allocation, or IO. A non-exported test
authority may admit only exact endpoints signed into the isolated test topology.

The public destination reference is exactly the existing 172-byte
`DESTINATION_REF_V1`. Its 130-byte opaque handle is:

```text
u8   handleVersion = 1
u8   destinationValidationClass = DHT_NODE_HANDLE
u64  expiresAtMs
32B  issuingExitIdentity
16B  branchId
16B  circuitId
u64  branchGeneration
32B  handleNonce
16B  handleAuthTag
```

The exit creates one fresh 32-byte handle secret only after terminal OPEN. The
tag and mandatory server-side table entry bind the complete prefix,
destination ID, canonical endpoint, derived DHT ID, provenance class/digest,
immutable-get command bit, and all-zero capability-advertisement digest under
the adopted server-binding and handle-auth domains. A valid tag without a live
table entry is invalid. Handles expire no later than five minutes after minting
and no later than their branch, circuit, generation, or exit advertisement.
The secret and complete table are erased on rotation, expiry, guard loss,
network change, suspend, or teardown.

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

Gate 3B1 implements `ROUTED_REPLY_V1` (`0x0102`) exactly as the reviewed wire
registry:

```text
16B  requestId
u16  commandId
u16  commandVersion
u8   operationClass
172B from
u16  errorCode
u16  tokenByteLength
tokenByteLength bytes token
u8   closerNodeCount
closerNodeCount * 172B closerNode
u16  encodedResponseByteLength
encodedResponseByteLength bytes encodedResponse
```

The fixed body is 200 bytes and the complete wire size is
`208 + tokenBytes + 172*closerNodeCount + responseBytes`. For immutable get,
the token is zero or 32 bytes, closer count is at most 20, and the encoded
response is the existing HyperDHT immutable-get response body, at most 1,026
bytes. The complete reply is at most 4,706 bytes and amplification over the
complete request is at most 4,445 bytes.

Request ID, command `IMMUTABLE_GET_V1`, command version 1, operation class, and
the complete `from` reference must byte-equal the request before retaining a
token, importing a referral, or decoding a value. Closer references are unique
and sorted by unsigned XOR distance from the target, then destination ID, and
must all be live `DHT_NODE_HANDLE` references issued by the same exit branch
generation. On nonzero routed error, token, closer nodes, and encoded response
are empty. The only accepted error IDs are the frozen `0x0180..0x018e`
`ROUTED_ERROR` registry already present in `lib/private/protocol.js`; unknown
IDs reject the reply.

Immutable-get body encoding remains exactly 32 target bytes. A successful
decoded value is accepted only after the existing HyperDHT immutable hash check
matches that target. An absent value is represented by the existing HyperDHT
response codec, not by a JavaScript-only sentinel.

## Immutable-get Data Flow

1. `BootstrapIO` contacts its bounded numeric bootstrap set and receives signed
   relay advertisements.
2. The client verifies canonical bytes, signatures, roles, parameters, and
   expiry before retaining candidates.
3. It challenges and pins one guard. Pinning destroys all pre-guard general
   direct authority.
4. `RouteManager` selects pairwise-diverse lookup and announce middles/exits and
   establishes authenticated adjacent links and branch generations.
5. Each `TerminalExitSession` completes source-to-selected-exit
   ACTIVATE/READY/ACK/OPEN, verifies the exit signature and full transcript,
   and installs inner payload/control AEAD keys.
6. Both branches become live. Internal readiness remains false until both are
   adjacent- and terminal-authenticated, diverse, within quota, and unexpired.
7. The lookup exit mints opaque references for its configured DHT bootstrap
   destinations and returns them through the lookup branch.
8. DHT-RPC performs client-controlled iterative traversal. For each candidate,
   `RoutedDHTIO` sends the exact immutable-get request through the route.
9. The exit validates the reference and command, sends one ordinary DHT request,
   validates the reply, qualifies any referrals, and returns normalized reply
   bytes through the same branch.
10. The endpoint continues traversal using only imported opaque references. It
    accepts the value only when the existing immutable-value hash verification
    succeeds locally.
11. Cancellation, timeout, rotation, or teardown revokes the active operation
    and every no-longer-valid reference without creating direct authority.

## Lifecycle and Failure Semantics

The internal state machine is:

```text
OFF -> BOOTSTRAPPING -> GUARD_PINNED -> BUILDING -> READY
                                              READY -> ROTATING -> READY
                                                |          |
                                                +-> SUSPENDED -> BUILDING
                                                |                |
                                                +-> UNAVAILABLE <-+
                                                        |
                                                   DESTROYED
```

Only one transition function may mutate controller state. Every transition
checks current state, owned capabilities, generation, and destruction status
before side effects. Reentrant callbacks cannot observe or publish partial
readiness.

| State           | Endpoint-owned network authority                           | Permitted endpoint packet edge                                           |
| --------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------ |
| `OFF`           | none                                                       | none                                                                     |
| `BOOTSTRAPPING` | bounded `BootstrapIO`                                      | configured bootstrap or one of at most three challenged guard candidates |
| `GUARD_PINNED`  | pinned adjacent guard link only                            | pinned guard only                                                        |
| `BUILDING`      | pinned guard link plus opaque in-route setup capabilities  | pinned guard only                                                        |
| `READY`         | pinned guard link plus opaque lookup/announce capabilities | pinned guard only                                                        |
| `ROTATING`      | pinned guard link plus bounded old/new route generations   | pinned guard only                                                        |
| `SUSPENDED`     | at most one unexpired one-shot guard reconnect authority   | none                                                                     |
| `UNAVAILABLE`   | none                                                       | none                                                                     |
| `DESTROYED`     | none                                                       | none                                                                     |

- `READY` requires both lookup and announce branches.
- From the instant `GUARD_PINNED` is committed through BUILDING, READY,
  ROTATING, UNAVAILABLE, resume, and teardown, every endpoint packet is either
  to the exact pinned guard or forbidden. Teardown may send one authenticated
  destroy sequence to the guard before closing the link; it cannot contact any
  other tuple.
- Both initial branches construct concurrently under one 5,000 ms monotonic
  deadline starting at `GUARD_PINNED`. Each terminal session uses its adopted
  five-send schedule inside that same deadline. Candidate selection, link
  extension, terminal authentication, seed validation, and readiness do not
  extend it. Failure destroys both half-built branches and enters
  `UNAVAILABLE`. Cold start therefore has a maximum of ten seconds to pin the
  guard plus five seconds to reach two-branch readiness.
- Middle or exit loss rotates only the affected branch while preserving the
  guard. New operations use the new generation.
- Rotation is make-before-break when capacity permits. Bounded in-flight work
  may drain on the old generation; no new operation can start there. One
  replacement attempt has the same single 5,000 ms construction deadline and
  fixed setup retry schedule. Its half-built state is destroyed at the deadline.
  If an old generation remains live it continues until its already signed
  expiry while the controller reports `ERR_PRIVATE_BRANCH_ROTATING`; otherwise
  the branch enters `UNAVAILABLE`. Repeated attempts cannot overlap, extend an
  advertisement/generation expiry, or retain failed state.
- Old destination capabilities are invalid for new work immediately and are
  erased when drain completes or its deadline expires.
- Guard loss destroys both branches and returns
  `ERR_PRIVATE_GUARD_UNAVAILABLE` without contacting a replacement.
- A fresh bounded bootstrap phase is possible only after complete teardown of
  the former guard and route authority.
- Before suspend closes the guard socket, it may create one opaque
  `GuardReconnectAuthority` bound to the exact guard identity, 19-byte endpoint,
  advertisement digest/epoch/expiry, local identity, and a fresh one-use nonce.
  It exposes only `reconnect()`; it has no host/port argument, referral path,
  DHT method, or generic send. It may execute only the adopted CAPS self-query,
  active challenge, and guard LINK OFFER/ACCEPT against that tuple, once, under
  one 5,000 ms deadline. It is revoked on first call, advertisement expiry,
  network change, guard substitution, controller destroy, or failure.
- Suspend cancels timers and pending operations, destroys the socket and all
  other ephemeral send authority, and retains at most that reconnect object.
  Resume atomically consumes it while transitioning from SUSPENDED to BUILDING,
  then may contact only the pinned guard. Success installs a fresh guard link
  and fresh branch generations; failure enters `UNAVAILABLE` with no network
  authority.
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

Gate 3B1 does not invent a second error vocabulary. Internal conditions map
exactly to the existing Gate 3A registry and command-policy code:

| Condition                                  | Exact JavaScript error code       |
| ------------------------------------------ | --------------------------------- |
| malformed route/capability/reference/reply | `INVALID_ROUTE`                   |
| no route, request timeout, network change  | `ROUTE_UNAVAILABLE`               |
| no valid guard after bounded bootstrap     | `ERR_PRIVATE_GUARD_UNAVAILABLE`   |
| insufficient/incompatible diverse relays   | `ERR_INCOMPATIBLE_RELAY`          |
| branch rotating                            | `ERR_PRIVATE_BRANCH_ROTATING`     |
| authentication or terminal substitution    | `ERR_AUTHENTICATION`              |
| replay                                     | `ERR_REPLAY`                      |
| relay capacity temporarily unavailable     | `ERR_BUSY`                        |
| hard quota exhausted                       | `ERR_QUOTA_EXCEEDED`              |
| unsupported DHT command                    | `ERR_PRIVATE_COMMAND_UNSUPPORTED` |
| destroyed/suspended authority              | `ERR_DESTROYED`                   |

`ERR_PRIVATE_GUARD_UNAVAILABLE` is the sole Gate 3B1 addition to
`PrivateRouteError` and matches canonical v1. The existing command-policy error
remains the module error already asserted by Gate 3A. Wire routed errors remain
the separate numeric `0x0180..0x018e` registry and map to the table only after
an authenticated, request-bound reply is decoded. A later public controller
may map internal codes to the canonical public API without changing Gate 3B1
wire bytes. Error objects and logs contain no endpoints, route keys, topics,
raw advertisements, full paths, or direct-retry advice.

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

- advertisement canonical bytes, capability/policy/key binding, signatures,
  role derivation, epoch replay/equivocation, clock rollback, time bounds,
  defensive ownership, and hostile shapes;
- exact role/branch/link/circuit/generation transcript and KDF vectors;
- bootstrap endpoint/challenge/deadline bounds and exposure redaction;
- sealed non-dialing candidate-directory transfer, consumption, expiry, and
  destruction;
- guard pinning atomicity and direct-authority revocation;
- branch diversity, independent generations, the global construction deadline,
  rotation, and teardown;
- adjacent authentication, tuple binding, replay, liveness, and counters;
- terminal exit identity/key/transcript substitution, finalization retries,
  OPEN gating, inner AEAD, and retired-context erasure;
- relay quotas, fair queueing, expiry, cancellation, and tombstones;
- immutable-get request/reply bytes, exact `from` equality, routed-error rules,
  trailing-data rejection, and hash checks;
- new `DHT_EXIT_DHT_SEEDS_V1 = 0x0045` minimum/maximum vectors, signature/digest
  domains, ordering, and strict rejection by legacy `0x0044` decoders;
- destination provenance, DHT transaction/source correlation, special-use
  rejection, single-packet probe deadlines/rate bounds, capability binding,
  generation invalidation, and table bounds;
- logical and encoded-byte amplification accounting;
- one-shot guard reconnect restriction/revocation, phase-owned authority, and
  phase-permitted packet edges;
- validation-probe audit-record creation/removal and rejection of unrecorded
  probes or ordinary requests to probed-but-unadmitted tuples;
- sanitized exact errors, metrics, logs, and zero owned state after destruction.

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
prospective-guard edges are allowed. Starting with the packet that commits
`GUARD_PINNED`, all later phases use these rules:

- endpoint traffic is only endpoint to/from pinned guard;
- during BUILDING and ROTATING, the guard may contact only the bounded selected
  old/new middles and each middle only its adjacent guard/exit candidates;
- during READY, the guard contacts only the two selected middles for route
  traffic and each middle only its guard and branch exit;
- an exit may emit one `EXIT_VALIDATION_PROBE` ping and receive its correlated
  reply only while the exact bounded audit record above is live;
- ordinary exit requests may contact only fully admitted,
  provenance-qualified DHT destinations with live table entries;
- during suspend there is no endpoint packet; resume may contact only the exact
  pinned guard under the one-shot reconnect authority;
- UNAVAILABLE emits no packet, and teardown permits only the authenticated
  endpoint-to-guard destroy sequence before silence;
- no endpoint contacts an exit or ordinary DHT node;
- no role emits DNS, TCP, IPv6 outside an explicitly selected IPv6 topology, or
  traffic on an unconfigured interface;
- teardown produces no later packet.

A separately isolated negative-control packet must be captured and rejected by
the oracle, proving that forbidden-capability traffic is observable. Separate
negative controls attempt an unrecorded validation ping and an immutable-get to
a probed-but-unadmitted tuple; both must fail the oracle and authority trap.
Missing or malformed capture evidence fails the job.

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
8. Linux packet capture proves endpoint-to-guard-only traffic from guard
   pinning through build, ready, rotation, suspend/resume, failure, and teardown,
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
