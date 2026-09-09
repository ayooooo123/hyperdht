# Private Routing: Peer Streams — Design Packet

**Date:** 2026-09-09
**Status:** review packet, not an approved design. No wire byte, message ID,
controller method, or test in the tree implements peer streams. Every layout
below is a proposal for JD to ratify; the M3 registry rule stands (a new message
family is a versioned wire change and is JD's decision).
**Inputs:** [`private-routing-v1.md`](../../private-routing-v1.md) §"Connection
to an unchanged peer", §"Connection between private-capable peers", §"Private
rendezvous and stream handoff"; the
[M3 wire registry](./2026-07-14-native-dht-private-routing-m3-wire-registry.md)
§1.5, §10, §11, §17; the
[blinded presence note](./2026-08-10-private-routing-blinded-presence-keys-note.md);
[`private-routing-migration.md`](../../private-routing-migration.md)
§"Current implementation".

## 1. What exists, and what it already fixes

- **Adjacent links carry three cell classes.** Every established link derives
  independent CONTROL, STREAM and DATAGRAM contexts (`guard-link.js`
  `deriveState`; `m3-adjacency-runtime.js` accepts exactly those three classes
  in the forwarding facade). STREAM contexts are keyed, counted with the
  ordered receiver, and already carried by production code: the cell endpoint
  sends `CELL_CLASS.STREAM` (`udx-cell-endpoint.js`) and the link-control
  session receives it (`link-control-session.js`), because the registry maps
  `ROUTE_PAYLOAD` (context 3) onto M2 `STREAM = 1`. A peer stream is therefore
  the class the transport was built for, not a new class; what is new is the
  object family inside it.
- **Endpoint↔exit inner AEAD exists.** Routed DHT requests are sealed to the exit
  under a route-payload context an intermediate relay cannot open
  (`ROUTED_REQUEST_V1` / `ROUTED_REPLY_V1`, nine-command inventory, outer
  reply ceiling 8,270 bytes over nine fragments, the nested 8,062-byte lookup
  response over eight). Authority to reach anything through the exit is an
  exit-issued live `DESTINATION_REF_V1` (164-byte body, 172-byte object,
  table-bound, at most 300 s). No command outside the inventory is executable:
  peer streams cannot be smuggled through the routed-request family and must
  not be.
- **Reply paths.** Correlated replies ride the reverse route; `SURB_REQUIRED`
  replies are single-use, relay-peeled, bounded (3,936 bytes). A SURB is a
  request/response primitive, not a duplex; it is the right carrier for the
  rendezvous _setup_ messages, not for stream bytes.
- **Presence (Gate D).** A responder publishes a blinded, reader-key-encrypted
  record under `A' = blind(A, period)`; the plaintext body carries an opaque
  descriptor of at most `MAX_DESCRIPTOR_BYTES = 814` bytes
  (`blinded-presence.js`). Resolution proves presence at a revision and hands
  the application the descriptor bytes verbatim. The descriptor _content_ is
  unspecified today; that is where a private route descriptor goes.
- **Relay service.** Per-circuit quotas (`maxCells`, `maxBytes`, `maxCommands`,
  `idleTimeoutMs`) are admitted limits signed in `LINK_ACCEPT_V1`; teardown
  erases contexts and closes physical ownership. A long-lived stream sits inside
  those quotas or renegotiates by rotation; nothing new at the relay for v1.
- **Registry room.** `0x0300–0xffff` is unassigned and rejected in M3 v1; the
  private-storage overlay IDs `0x0280–0x02a3` are superseded and stay reserved
  (D10). A stream family therefore takes a fresh block at or above `0x0300` and
  bumps the negotiated protocol version, or it does not ship.

## 2. Two flows, one order

The v1 document approves two flows. Recommended sequencing: **legacy egress
first**, because it needs no descriptor format, no destination-side route, and
exercises the one genuinely new mechanism (a routed duplex terminating at an
exit) against an unchanged peer; **private-to-private rendezvous second**,
reusing that duplex plus the Gate D descriptor slot.

### 2.1 Legacy egress: routed duplex to an exit that speaks `relayThrough`

```text
private client -> guard -> middle -> egress exit ==(blind-relay)== legacy peer
       `-------------- end-to-end Noise ------------------------'
```

- Discovery: not solved, and a dependency. D11 refuses routed public `findPeer`,
  `lookup` and raw `query` in protocol v1, and no current exit command can mint
  a `LEGACY_EGRESS_V1` target. The v1 document assumes "a valid legacy DHT
  result produced the opaque egress target"; nothing in the tree produces one.
  Two options for JD: (a) an explicit first-contact input contract — the
  application supplies the legacy peer's Noise public key and the exit
  resolves it upstream inside a new bounded command that returns only an
  opaque single-use egress reference (a `DESTINATION_REF_V1`-class value bound
  to `LEGACY_EGRESS_V1` provenance, never an address); or (b) a routed
  `findPeer` limited to that same opaque output, which reopens D11. Either is
  the tenth exit command policy entry and a versioned wire change.
- Open: a new object family, proposed `STREAM_OPEN_V1 / STREAM_OPENED_V1 /
STREAM_CLOSE_V1`, carried as `ROUTE_PAYLOAD` on the STREAM context of the
  branch, sealed endpoint↔exit like a routed request. `STREAM_OPEN_V1` binds:
  the destination reference, the expected remote Noise public key (32),
  `holepunch: false`, local-address sharing disabled, a fresh 32-byte session
  capability, negotiated bounds (per-direction byte budget, idle timeout ≤
  admitted `idleTimeoutMs`), and the operation budget as a _duration_ (KI-15
  rule: no cross-host absolute time).
- Pairing: the exit runs the existing HyperDHT peer handshake with itself as
  `relayThrough` and pairs the unchanged peer's raw relay stream to the routed
  duplex by the session capability, exactly as v1 §"Connection to an unchanged
  peer" prescribes; it forwards Noise bytes byte-for-byte and never
  instantiates SecretStream.
- Data: `STREAM_DATA_V1` cells on the STREAM context, ordered receiver, exact
  next counter (CONTROL/STREAM rule), fixed 1,200-byte outer cell, at most
  1,073 bytes of logical route payload after the route frame, of which the
  `STREAM_DATA_V1` decoder will bound a smaller slice once its header is
  tabulated. No fragmentation layer: Noise and UDX framing already tolerate
  arbitrary segmentation, so each cell carries an opaque slice and a 16-bit
  length.
- Close: `STREAM_CLOSE_V1` in either direction; either transport closing
  closes the paired side and erases the session capability. Half-close is a
  flag on `STREAM_CLOSE_V1`, never an implicit state.
- What the exit learns: the legacy peer's address and the Noise identities it
  can observe on the blind-relay handshake (unchanged HyperDHT exposure), the
  stream's timing and volume. What it cannot do: substitute the peer (the
  source binds Noise to the expected key) or turn itself into a general proxy
  (the destination reference is provenance-qualified and single-use).

### 2.2 Private-to-private: descriptor in the presence slot, rendezvous at the destination's entry

```text
source safety route -> destination entry relay -> destination route -> destination
          `---------------- end-to-end Noise ---------------------'
```

- Descriptor: the 814-byte Gate D descriptor slot carries a
  `PRIVATE_ROUTE_DESCRIPTOR_V1`: descriptor ID (16), destination Noise public
  key (32), entry relay advertisement digest (32) plus the entry's reachable
  endpoint and route-encryption key as the v1 text requires (or the full 420 /
  548-byte advertisement if the budget allows — a decision), the destination's
  ephemeral route key (32), protocol parameters digest (32), route epoch (8),
  expiry as a wall time in the _destination's_ domain (8), a nested hop
  instruction sealed to the entry relay (bounded; this is the "encrypted nested
  hop material"), and an endpoint signature under the _blinded_ key `A'` of the
  period (so a descriptor never carries or is signed by the stable identity;
  the Noise identity inside is the only stable value and is what the connecting
  peer intends to authenticate anyway). Size must be tabulated against 814
  before this is ratified; if the full advertisement does not fit, the
  descriptor carries the digest and the entry's canonical endpoint, and the
  source fetches the advertisement over the routed DHT as it does for relays.
- Open: the v1 state machine verbatim — `DESCRIPTOR_VERIFIED → ACTIVATE →
READY → ACK → OPEN`, five-second open deadline, at most four retries with
  identical authenticated bodies, single-use redemption
  `(descriptor ID, epoch, activation nonce, source route key)` consumed
  atomically at the destination. `ACTIVATE` binds both expected Noise keys,
  the descriptor digest, and negotiated bounds. Carrier: the outer M3
  `ROUTE_PAYLOAD` context is inherited STREAM, but the route-payload codec
  carries an inner class of its own, and the routed DHT already sends its
  requests and replies as inner `CELL_CLASS.DATAGRAM` over `ROUTE_PAYLOAD`
  (`route-payload.js` `routeClass`, `live-route-authority.js`,
  `dht-exit-io.js`) with the 64-wide replay window. The four rendezvous
  messages ride that same inner datagram class, retried under fresh logical
  counters with identical bodies; no new outer context is needed for them. A
  new outer context is reserved only if the destination-entry ownership
  (decision 7) cannot reuse route-payload framing across the entry boundary
  (decision 9). The duplex transfers exactly once, after `OPEN`, onto the
  inner STREAM class.
- Entry relay: this is the largest gap, not a detail. `M3_LINK_ROLE` has exactly
  `CLIENT`, `SAFETY_RELAY` and `DHT_EXIT` (`protocol.js`), the branch is a fixed
  three-position path that terminates in a DHT exit, and every finalization
  transcript, admitted-limits digest and forwarding owner is built for that
  shape. A destination entry is a fourth authenticated role: it must accept a
  source-side extension (or a datagram-carried ACTIVATE) at one edge and own a
  destination-side route at the other, with a route-construction and
  finalization transcript that binds both circuits, and forwarding ownership
  that crosses that boundary without either side gaining the other's send
  authority. The nested hop instruction is only the carrier for that admission.
  None of the transcript, role, capability bit, advertisement field or
  forwarding owner exists; each is a versioned wire and ownership decision.
- Data and close: identical to 2.1 (`STREAM_DATA_V1` / `STREAM_CLOSE_V1`), both
  endpoints being private; no exit exists on this path.
- What each party learns: the entry relay holds an authenticated association
  between the source's safety-route circuit and the destination's route
  circuit. That is a deterministic protocol-state linkage at one relay,
  stronger than the timing/volume correlation KI-1 concedes, and it must be
  disclosed as an entry-role property in its own right. The entry never sees
  the source address. Other relays see timing and volume (KI-1); the
  destination learns the source Noise identity and nothing about its address;
  the source learns the destination's Noise identity.

## 3. Message family (proposed IDs, all new, all above `0x0300`)

| ID       | Object                        | Carrier                                                       | Auth                                                                                                        |
| -------- | ----------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `0x0300` | `STREAM_OPEN_V1`              | STREAM `ROUTE_PAYLOAD`, endpoint→exit                         | route-payload AEAD                                                                                          |
| `0x0301` | `STREAM_OPENED_V1`            | STREAM `ROUTE_PAYLOAD`, exit→endpoint                         | route-payload AEAD                                                                                          |
| `0x0302` | `STREAM_DATA_V1`              | STREAM `ROUTE_PAYLOAD`, both directions                       | route-payload AEAD, exact next counter                                                                      |
| `0x0303` | `STREAM_CLOSE_V1`             | STREAM `ROUTE_PAYLOAD`, both directions                       | route-payload AEAD                                                                                          |
| `0x0310` | `PRIVATE_ROUTE_DESCRIPTOR_V1` | Gate D descriptor slot (≤ 814 bytes)                          | Gate D mutable signature under `A'`; an inner signature only if a delegation contract needs it (decision 4) |
| `0x0311` | `ACTIVATE_V1`                 | inner DATAGRAM over `ROUTE_PAYLOAD`, source→entry→destination | nested per-hop AEAD + destination tuple                                                                     |
| `0x0312` | `READY_V1`                    | inner DATAGRAM over `ROUTE_PAYLOAD`, destination→source       | destination signature over the tuple                                                                        |
| `0x0313` | `ACK_V1`                      | inner DATAGRAM over `ROUTE_PAYLOAD`, source→destination       | source route-key signature                                                                                  |
| `0x0314` | `OPEN_V1`                     | inner DATAGRAM over `ROUTE_PAYLOAD`, destination→source       | destination signature, redemption bound                                                                     |

Every body is fixed-size or carries one explicit length; every AEAD context is
domain-separated by class, direction, circuit, generation and the descriptor
digest where one exists; counters follow the v1 rules: STREAM exact-next, and
for a datagram-class carrier the M3 route/finalization 64-wide window (the
adjacent-link DATAGRAM receiver in `guard-link.js` is configured at 256 and is
not that window). Byte layouts are deliberately not proposed here: the
registry's precedent is that layouts are tabulated with size bounds and
justified field by field in the design that ratifies them.

## 4. Decisions JD must ratify before any build

1. New message block at `0x0300` and the protocol-version bump it implies.
2. Legacy egress first (2.1) with `LEGACY_EGRESS_V1` as the tenth exit-policy
   entry, or private-to-private first.
3. Whether the Gate D descriptor carries the full entry advertisement or its
   digest plus canonical endpoint (the 814-byte budget decides).
4. Descriptor signature under the blinded period key (recommended) versus a
   fresh per-descriptor key certified by the blinded key.
5. Stream quotas: reuse admitted `maxBytes` / `idleTimeoutMs` unchanged, or a
   separate stream budget negotiated in `STREAM_OPEN_V1`.
6. Whether the source's duplex transfer to HyperDHT `connect` happens inside
   the controller (required mode) or through a new `createRawStream`-class
   surface; the v1 table says `pool`/raw streams may exist only as a routed
   implementation carrying no direct authority.
7. The destination entry role itself (§2.2): a fourth `M3_LINK_ROLE`, its
   capability bit in the advertisement, the two-circuit finalization
   transcript, and which existing owner (relay service, tail control, or a new
   one) holds the cross-boundary forwarding state. Without this decision §2.2
   cannot be scheduled at all; §2.1 does not depend on it.
8. The legacy-egress discovery input (§2.1): first-contact key supplied by the
   application with exit-side resolution to an opaque reference, or a bounded
   routed `findPeer` that reopens D11. §2.1 cannot be scheduled without it.
9. Whether route-payload framing (inner DATAGRAM for setup, inner STREAM for
   the duplex) crosses the destination-entry boundary unchanged, or the entry
   needs a newly registered outer context. Only decision 7 can force the
   second; the rendezvous messages themselves do not.

## 5. Review questions for the lane

1. Does 2.1's session capability plus expected-key binding leave any way for
   the exit to pair the routed duplex with a peer of its choosing that Noise
   would not reject? Name the check that stops it, or the gap.
2. In 2.2, can the entry relay distinguish an ACTIVATE for a destination route
   from ordinary route traffic in a way that lets it correlate a source's exit
   with a destination beyond what KI-1 already concedes?
3. Is signing the descriptor under `A'` sound given the Gate D linkability
   statement (unlinkable only against parties without `A`)? The connecting peer
   holds `A` by construction; the storage node does not.
4. Which of the six decisions are forced by existing invariants, and which are
   genuinely open?
5. Minimum falsifying test set for a first slice (the eleven-role gate plus the
   namespace capture oracle), in dependency order.

## Review lane — 2026-09-09

`omp/openai-codex/gpt-5.6-sol` (medium, read-only) reviewed the packet against
the tree and the approved documents. Verdict: **not ready to ratify**. Legacy
egress (§2.1) is coherent once decisions 1, 2, 5, 6 and 8 are taken;
private-to-private (§2.2) is not schedulable until the destination-entry trust
boundary (decision 7) is designed and approved, and it must carry the entry's
deterministic cross-circuit linkage as its own disclosure. Six claims in the
first draft were contradicted by the tree or the registry and are corrected
above: `DESTINATION_REF_V1` is a 164-byte body in a 172-byte object; the
8,270-byte outer reply is nine fragments (eight applies to the nested 8,062-byte
lookup response); STREAM cells are already sent and received in production;
the rendezvous messages are inner DATAGRAM over `ROUTE_PAYLOAD`, as the routed
DHT already is, not a separate outer context; 1,073 is
the whole logical route payload, not a per-message slice; and the 64-wide
datagram window is route/finalization semantics, not the adjacent-link
receiver. Question 1: no identity-substitution path at a malicious exit,
because Noise IK binds the responder static key (`lib/noise-wrap.js`,
`lib/connect.js`); the session capability only prevents cross-session
pairing. Question 3: an inner descriptor signature under `A'` is sound but
redundant with the Gate D mutable signature unless it carries a delegation
contract. Forced by existing invariants: decisions 1, 7 (in substance) and the
constraints inside 2, 5 and 8; open: 3, 4, 6, 9 and the choices inside 2, 5
and 8. The reviewer's minimum falsifying test set, in dependency order:
registry (unique IDs, old-version rejection, exact inventory, unknown
role/context rejection); authority (provenance-bound single-use egress
reference; cross-exit, cross-generation, replay, wrong-key and conflicting
capability rejection); routed duplex (ordering, segmentation, backpressure,
quota exhaustion, timeout, close, explicit half-close, capability erasure);
a real unchanged-peer blind-relay round trip with a mispairing exit failing
remote-key authentication; the Node and Bare eleven-role gates; synthetic
capture-oracle falsification (`test/private/route-oracles.js`) before any
live capture is trusted; namespace projection then live capture with the
oracle extended to endpoint→guard only, fixed cells, no plaintext on route
edges, hop-by-hop ciphertext change, and a positive plaintext control only at
the legacy-peer edge. The verdict is the seat's; JD ratifies the decisions.

## 6. Non-goals for the first slice

Mixing or cover traffic (Gate B), multiple concurrent streams per circuit,
relay-to-direct upgrade of any kind, mobile suspend semantics for open streams,
Hyperswarm integration, and any public required-mode exposure. Each is either
deferred by the gates index or blocked on the external cryptographic review.
