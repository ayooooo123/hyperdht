# Private Routing: Peer Streams — Design Review Record

**Date:** 2026-09-09
**Source baseline:** `06dc259c10d6270977d88e1bc12834d9051e1a77`
**Status:** not implementation-ready. No peer-stream wire or public API is enabled.

JD directed the seat to own the remaining work. The choices below are the
seat's design direction, not nine unanswered questions for JD. They do not
waive the existing reviewed-wire or external human cryptographic-review gates.
The earlier packet's claim that legacy egress was ready after a few choices
was wrong. This revision records the source constraints and the rejected parts
of that packet before any implementation relies on them.

## Design direction

| Concern              | Decision                                                                                                                                                                                                                                                       |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Wire version         | Use a new negotiated M3 version for peer streams. Do not add accepted stream IDs to protocol v1 or reuse the retired private-storage IDs. Exact layouts remain subject to review.                                                                              |
| Scope and order      | Preserve both original targets: legacy HyperDHT egress, then private-to-private streams. No generic VPN, clearnet proxy, or direct fallback.                                                                                                                   |
| Discovery            | Application supplies the expected legacy Noise key. Resolution stays inside the exit and returns single-use opaque authority, not direct send authority. Do not reopen public routed `findPeer`, `lookup`, or raw `query` under D11.                           |
| Descriptor           | Carry the full canonical entry advertisement if the complete descriptor fits Gate D's 814-byte limit. The live advertisement is 260–388 bytes, not the historical registry's 420–548-byte form. Do not approve a descriptor that omits usable entry discovery. |
| Descriptor signature | Reuse the verified Gate D record signature when the descriptor is consumed through that record. No redundant inner signature unless an independently transferable delegation requires it.                                                                      |
| Quotas               | Enforce a shared generation budget before deriving a smaller stream allowance. Count frames as well as bytes; byte-only credit permits a flood of tiny frames. Do not treat signed limits as existing runtime enforcement.                                     |
| API ownership        | Controller-owned, package-private peer connection/listener APIs. No root export, caller-supplied socket, or direct-authority raw-stream API.                                                                                                                   |
| Entry ownership      | Explicit authenticated terminal capability and route purpose. A peer entry is not implicitly authorized because a route terminates at a DHT exit. Do not invent a fourth physical role merely to rename the terminal service.                                  |
| Carrier              | Keep setup and data classes explicit. The current live route uses outer DATAGRAM cells; ordered stream delivery requires a reviewed transport change, not just a new decoder.                                                                                  |
| Lifetime             | Bind each stream to admitted route generations. Route expiry, loss, rotation, suspension, or network change closes the stream; no unreviewed cross-generation transfer.                                                                                        |
| Release              | Public required mode remains disabled. Internal model review is not external human cryptographic review.                                                                                                                                                       |

## Verified implementation constraints

### Three layers must not be confused

1. Adjacent links have CONTROL, STREAM, and DATAGRAM cryptographic contexts.
   STREAM is used by extension setup in `udx-cell-endpoint.js`.
2. The M3 context envelope registry maps its `ROUTE_PAYLOAD` context to STREAM.
   That mapping alone does not describe the live post-finalization transport.
3. The live `sendM3RouteFrame()` in `m3-adjacency-runtime.js` seals an exact
   1,100-byte frame in an outer **DATAGRAM** cell. Its receive pump rejects
   other outer classes. Inside that frame, `RoutePayloadCodec` has independent
   STREAM and DATAGRAM counters. Current DHT requests and replies use inner
   DATAGRAM.

`RoutePayloadCodec` accepts at most 1,073 payload bytes. That is the budget for
the complete inner object, including its header and any additional envelope;
it is not a stream data allowance. Fixed outer cells are 1,200 bytes.

The current route pump retains at most `MAX_FRAGMENTS` frames and discards
excess frames while continuing to process teardown and branch loss. That is
intentional DATAGRAM behavior. Reusing it unchanged for ordered streams would
lose bytes. Stopping the pump when the consumer is slow would instead restore
the previously fixed branch-loss starvation bug.

### Admission is not spending

`guard-link.js`, `link-parameters.js`, and `tail-control.js` encode, compare,
and authenticate `maxCells`, `maxBytes`, and `maxCommands`. The inspected live
M3 send/receive paths do not decrement those fields. `RelayService.trySend()`
bounds queued bytes; it is not a lifetime cell/byte/command ledger.

Therefore the earlier packet's promise to put streams inside already-enforced
route quotas was unsupported. A shared ledger needs defined ownership,
charging rules, failure behavior, and rotation behavior before that promise is
valid. The default request is 64 cells, 65,536 bytes, and ten commands. Under
a proposed 1,200-byte-per-cell charge, the byte limit would permit only 54
cells before setup, retries, and control reserves. Increasing defaults is not
a substitute for implementing accounting.

### Presence and entry discovery

`blinded-presence.js` permits at most 814 opaque descriptor bytes. Gate D
verifies the mutable-record signature under the blinded period key and binds
record revision before exposing the decrypted descriptor. The descriptor
codec and its live route owner do not yet exist.

A useful private-peer descriptor must authenticate the expected destination
Noise identity, the entry advertisement, the destination route key, route
parameters, generation/epoch, expiry, and the entry's bounded route-admission
material. Its byte table must include every envelope and authentication tag.
An identity hash without a means to obtain the corresponding authenticated
entry advertisement is not a complete discovery scheme.

## Legacy egress: required Noise order

The previous packet incorrectly put Noise after relay pairing. Existing
HyperDHT performs Noise IK first and starts SecretStream over the paired raw
transport afterward. `relayThrough` is inside the encrypted Noise payload;
the exit cannot create or edit it on the endpoint's behalf.

Required sequence for a future adapter:

1. Resolve the application-supplied Noise key inside the exit under bounded,
   live, route/generation-bound authority. Keep candidate addresses there.
2. Reserve a real framed UDX raw stream at the exit. Return only the opaque
   egress reference and the relay metadata needed to author the handshake.
3. The endpoint generates the session capability. Use that same value as the
   blind-relay token; do not introduce a second independent pairing key.
4. The endpoint's `NoiseWrap` creates IK message 1. Its payload names the exit
   relay and reserved UDX ID, disables reusable-socket behavior, includes no
   local addresses or hole-punch request, and does not advertise an open
   endpoint firewall.
5. The exit forwards the Noise ciphertext unchanged through the
   authority-bound DHT relay candidate. It does not call ordinary `connect()`
   to create an exit-owned application Noise handshake.
6. The legacy server returns its Noise reply and may register the pending
   responder half of blind-relay pairing.
7. The exit carries that reply unchanged to the endpoint. The endpoint calls
   `NoiseWrap.recv()`, checks the expected responder key, then calls `final()`.
8. An authenticated handshake-accept message tells the exit that the endpoint
   accepted the reply. It is a state-transition signal, not a cryptographic
   proof that a malicious endpoint executed particular local code.
9. Only then may the exit start its initiator-side blind-relay pairing with
   the reserved real UDX stream and the same session capability.
10. After successful pairing, the exit connects that raw stream to the returned
    relay stream ID and reports OPEN. The endpoint starts SecretStream over
    the routed duplex with its finalized handshake state.

Source: `lib/connect.js` `connectThroughNode` and `relayConnection`;
`lib/noise-wrap.js`; `lib/server.js` handshake handling and `_relayConnection`;
`node_modules/blind-relay/index.js` `BlindRelayRequest` and `BlindRelayLink`.

### Legacy adapter boundaries still requiring proof

- `blind-relay` exchanges real UDX stream IDs and calls `relayTo()`. A normal
  JavaScript duplex is not a replacement for that raw-stream endpoint.
- The exit relay must admit only live, authority-bound session tokens and
  permitted pairing roles. An unrestricted `blind-relay.Server` would expose
  a general relay service. Token lookup must happen before resource allocation.
- Direct peer-handshake handling can skip relay setup in `server.js`. The
  adapter must reject that path and accept raw traffic only through the
  authorized relay transport. Merely setting a `holepunch` option is not proof.
- The current `EXIT_LOCAL` enum has no live issuer/verifier for this operation;
  `verifyDhtExitRoutedDestination()` accepts `DHT_NODE_HANDLE`. A zero reference
  is not authority. Legacy resolution needs a reviewed activation-bound issuer.
- The unchanged peer's encrypted Noise reply can contain its addresses.
  The private controller can discard them and provide no direct send authority,
  but cannot promise that the endpoint process never decrypts address bytes.
  The security contract must distinguish address knowledge from send authority.

## Private-to-private: entry and transcript requirements

The entry would associate two separately authenticated route generations.
That is deterministic cross-circuit linkage at one relay, stronger than the
existing timing/volume limitation. It must be disclosed separately. The entry
must not receive either peer's Noise session keys or direct endpoint authority.

An entry admission must bind the destination's live route slot and expiry,
the authenticated source-side route, the exact descriptor, both ephemeral
route keys, nonces, and downward-only limits. Both route owners must retain
revocation authority. Closing either circuit must revoke the pairing before
asynchronous callbacks can reuse it.

ACTIVATE → READY → ACK → OPEN is the required semantic order. Each message
may authenticate only the context and messages that already exist. A transcript
that includes all four message digests in ACTIVATE or READY is cyclic and is
rejected. A cumulative transcript must be specified byte-for-byte, including
which authentication suffixes enter each digest.

Identical retries retain identical authenticated bodies under fresh datagram
counters. Changed bodies under a reused semantic ID are rejected. OPEN transfers
exactly one duplex at each endpoint. Bounded tombstones may answer delayed
messages but cannot restore send authority or transfer another duplex.

The entry's ownership of two endpoint–entry codecs does not make their
ciphertexts interchangeable. Opening/resealing at the entry requires an
explicit end-to-end authenticated setup construction. Simply copying one
circuit's frame into the other fails its keys, descriptor binding, circuit ID,
and direction. A proposed 284-byte descriptor and generic signed transcript
from the review did not settle these contracts and are not approved layouts.

## Transport and accounting acceptance

Before either flow can be implemented safely, settle and prove:

- One receive owner and class-aware dispatch per route. No competing DHT and
  stream readers; no starvation of teardown, loss, or credit messages.
- Bounded data and control residency. Overflow of authenticated ordered traffic
  fails the owning stream/route instead of silently discarding a frame.
- Cumulative frame and byte credits. Duplicate/stale credit cannot create
  capacity; a peer cannot gain extra frame slots by using tiny payloads.
- Credit reservations across both entry legs. A bridge cannot grant more than
  the destination's receive capacity or either leg's remaining budget.
- Shared generation accounting, including setup, retries, data, and close.
  Define control reserves and quota-driven rotation before selecting defaults.
- Exact offsets, segmentation, half-close, reset, idle deadline, queue erasure,
  and delayed-callback behavior. No application bytes before authenticated OPEN.

These are implementation prerequisites, not implemented properties.

## Review outcome and next acceptance boundary

Two read-only Sol reviews examined the source. The second lane first attempted
Orca GLM, which failed for insufficient credits; the replacement used the same
Sol model on separate context. This is not independent-model or external human
cryptographic approval. The seat rejects both the original packet and the
incomplete byte proposals as ready to build.

The next accepted artifact must supply complete canonical byte tables,
non-cyclic authentication/KDF inputs, role and capability admission, live
ownership transfers, and the quota/flow-control state machine together.
Approximate Noise sizes, unnamed issuers, generic duplex callbacks, and partial
OPENED/CLOSE layouts do not meet that boundary.

Verification must then exercise real production owners: unchanged-peer Noise
with malicious mispair rejection; private-to-private rendezvous; slow readers
and simultaneous half-close; expiry/rotation/suspend; Node and Bare processes;
and Linux capture with explicit negative controls for endpoint-to-guard-only
traffic, fixed cells, plaintext leaks, and hop-by-hop ciphertext changes.
Existing DHT capture evidence does not prove peer-stream privacy.

Public required mode remains blocked on the complete aggregate gate and a
named external human cryptographic review of the exact final source and native
dependency revisions. Mixing/cover traffic and anonymous admission remain out
of this work; consumer integration follows the public gate.
