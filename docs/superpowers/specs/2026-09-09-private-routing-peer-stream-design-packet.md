# Private Routing: Peer Streams — Implementation Prerequisite

**Date:** 2026-09-09
**Runtime baseline:** `02bce1422de05c271260b1f37344d69dbe9afe23`
**Original review baseline:** `06dc259c10d6270977d88e1bc12834d9051e1a77`
**Status:** internal implementation prerequisite ratified, including the reviewed delayed OFFER-replay clarification in transport §5.1/§9. No v2 runtime or public API is enabled; implementation, native privacy acceptance, and external human cryptographic/public-release gates remain separate.

The [ratification record](#prerequisite-ratification), [transport specification](#transport-specification), and [semantic specification](#semantic-specification) below form the current integrated specifications, subject to the status above. The intervening review record preserves rejected drafts and earlier proof boundaries as history.

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

Public required mode remains blocked on reviewed peer-stream wire, its
implementation and verification above, the complete aggregate gate, and a
named external human cryptographic review of the exact final source and native
dependency revisions. Mixing/cover traffic and anonymous admission remain out
of this work; consumer integration follows the public gate.

## Subsequent prerequisite experiments and advisory disposition

The published runtime baseline advanced to `87f0499`; this historical review
record does not authorize peer-stream implementation against it. Subsequent
native-gate success is not evidence that the peer-stream proposals are ready.
The current transport and semantic proposals remain unratified.

The revised candidate retains two explicit fragmentation layers. A semantic
Noise fragment contains at most 1,002 ciphertext bytes and has 71 bytes of
envelope/metadata overhead. Its 1,073-byte maximum wire object requires
HANDSHAKE payloads of 981 and 92 bytes. Under the candidate's explicit
4,096-byte legacy Noise-flight compatibility cap, the five semantic wires
are `[1073, 1073, 1073, 1073, 159]`, requiring nine reliable packets.
The old 66-fragment claim and one-object-per-ordered-frame assumption are
rejected. A larger otherwise valid legacy reply fails closed under this
proposed cap; it is not full compatibility with every possible reply size.

For confirmation transcripts, `completeIK1` and `completeIK2` are the raw
Noise ciphertext returned by the corresponding `NoiseWrap.send()` calls,
before fragmentation. Reconstruction concatenates validated ciphertext slices
by offset and verifies the whole-ciphertext commitment. These values contain
no semantic envelope, fragment metadata, transport wrapper, padding, length
prefix, or digest substituted for ciphertext. In the constrained private
profile they are exactly 101 and 53 bytes. In contrast, `completeACTIVATE`,
`completeREADY`, and `completeACK` include their complete canonical eight-byte
semantic envelopes and bodies, including the MAC fields within those bodies.
Ciphertext needed by a later confirmation survives `recv()` until its final
confirmation consumer; it is not erased prematurely.

Actual `NoiseWrap.final()` produces a 64-byte handshake hash and 32-byte
directional keys. Thus the confirmation context
`noiseHash64 | sessionId16 | sourcePurposeDigest32 |
destinationPurposeDigest32 | registrationCommitment32` is 176 bytes.
The draft's 144-byte assertion failed a native constructor probe.
Corrected Sodium/Python BLAKE2b vectors agree; READY, ACK, and ACCEPTED
transcript lengths are respectively 1,046, 1,339, and 1,361 bytes.
A throwaway nested-envelope reconstruction verified the 101/53-byte flights
and the synthetic 4,096-byte bound above. These are construction/arithmetic
checks, not production v2 decoder, state-machine, or privacy proofs.

The current candidate adds route-authenticated `PRIVATE_SOURCE_RECEIPT_V2`
(provisional ID `0x0364`, 120-byte body, 128-byte wire) after the source
verifies `PRIVATE_ACCEPTED`. Entry verifies the exact source route,
generation, session, accepted MAC, nonce, and receipt commitment before
`PRIVATE_OPEN_V2` (`0x0365`). An ARQ acknowledgement is not this semantic
receipt and does not prove endpoint MAC verification.

The current transport candidate also specifies a phase-0 query, cookie
challenge, phase-1 retry carrying the cookie, and only then the signed
capability response and active proof. All direct datagrams are padded to
1,200 bytes; the six-message exchange reserves 24 attempted cells in each
physical direction at eight attempts per message. Source contacts only its
pinned guard; guard and safety perform onward discovery. The earlier
unauthenticated short-query/large-response proposal is rejected. This
construction still needs production enforcement and reflection-negative
evidence; citing v1 cookie logic alone is not proof.

Native experiments now establish the legacy ownership boundary against an
unchanged HyperDHT server: actual relayed Noise, its stock remote relay client,
an admitted egress service using exported pair codecs, and a real
egress-owned UDX stream. The source owns Noise/SecretStream and no native
socket. Exact 65,536/12,345-byte transfer, closes, and either one-sided EOF
followed by opposite-direction data pass. Earlier simultaneous-end-event
timeouts remain recorded, not relabeled as success.

SecretStream's initial raw record is 59 bytes:
`uint24le(56) | streamIdentity32 | secretStreamHeader24`.
An application record has three prefix bytes and ciphertext of
`plaintextBytes + 17`; the inherited raw maximum is 16,777,218 bytes.
An actual 1 MiB record fragmented into 977-byte chunks produced no plaintext
after 24 chunks and first plaintext only at chunk 1,075. Therefore credits
replenished only by application plaintext consumption would deadlock the
proposed 24-slot window. Reserved record assembly and transport-slot release
must be distinct from application backpressure.

The interrupted transport revision has not settled per-session reset
isolation, reciprocal startup credits, complete record/native-buffer
ownership, noncyclic first-finalization associated data, and all control
traffic charges. Its earlier whole-route totals are not approved budgets.
In particular, `ceil(ciphertextBytes / 977)` is a best-packing lower bound,
not the worst-case frame spend: one-byte DATA frames are valid. Admission
must independently bound frames and bytes and charge credit traffic,
retransmissions, acknowledgements, startup headers, and per-stream closure
without terminating unrelated streams on a shared listener route.

These findings preserve the implementation and external-review gates above.

## Prerequisite ratification

Main accepts the integrated transport and semantic specifications below as the internal implementation prerequisite, superseding the historical rejected drafts above. Both review lanes report no blocking findings in their assigned scopes on corrected commit `af8e014c5f10b33c1c7038456813117509260339`, exact document SHA-256 `d05a264f499cad84b1277654bcb0cf3096d450d510bc24f4722ccea0c458f2cd`. [Native run34444531538](https://github.com/ayooooo123/hyperdht/actions/runs/34444531538) passed all three jobs. Main additionally adjudicated the final wording clarification in `f8771f9`, document SHA-256 `f2d13af91582d90e8594d60519cecf974464327a946f249327df00fea618a9ce`: the tail transcript digest is an input to the distinct routed-candidate commitment, not that commitment itself. This clarification changes no equation, wire layout, KDF input, or budget; synthetic commitment construction confirms the distinction. The reviewers' no-blocker reports apply to the earlier exact hash, not a falsely claimed rereview of this metadata/wording update. Ratification does **not** accept a v2 implementation, prove peer-stream privacy, enable public required mode, or substitute for named external human cryptographic review of the eventual exact source and native dependency revisions.

The fresh-context Sol findings were dispositioned by Main, not delegated as an approval verdict. Attempts to obtain another-model review encountered the recorded provider credit failures; same-model fresh contexts are not independent-model or external-human review. No such independence is claimed.

Delayed advisory reconciliation found that the earlier OFFER-replay sentence did not explicitly bind fresh class-5 sealing to the original response attempt limit. The corrected §5.1/§9 distinguishes canonical bytes, outer AEAD counters, and one shared eight-attempt budget. Sol reviewed exact commit `00def436785f87f8a145cdc730b1bdafa3a87d66`, document SHA-256 `d82555ba0dc9773d4f09704dc1bcd768d24d70cb3166224d1dd743b0f0c32fdf`, and returned no blocking findings in that assigned scope. Main ratifies that bounded replay contract; wire widths, purpose partitions, and physical cell/byte totals remain unchanged. The subsequent status/provenance update is Main-authored metadata, not a falsely claimed rereview. The earlier review hashes above remain historical provenance; neither this document review nor the synthetic replay model establishes v2 runtime behavior or external approval.

Frozen pre-review standalone input SHA-256 values follow. The integrated specifications below supersede those inputs where final review changed ordering, binding, or memory ownership; these hashes identify provenance, not the final reviewed artifact.

- Transport: `cce990bd6492ba0b7a3289d4e6589a1c45740b915a55410ca811a0f8cbc70c70`.
- Semantics: `f835e31b35b150e39de0769617c7a8a519b9b3c06a14f4821bc30844ee1eec48`.

### Accepted corrections

| Concern                          | Final disposition                                                                                                                                                                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reflection and bootstrap retries | One phase-0 response per received fixed cell; bounded cookie pool; first-valid requester phase freezes; SPENT committed before first ACTIVE send; spent rows retained through cookie expiry without publishing after challenge expiry.                                       |
| Wire/local expiry                | Explicit Unix-millisecond fields and one-time local projections. Exact hidden-bootstrap minimum is verified by the tail that owns those inputs; source checks its available authenticated bounds and commitment, not an unavailable proof.                                   |
| Reliable identity and replay     | Sequence key excludes digest; first binding is immutable. Checked receive horizons and issued-only ACKs; bounded full-wrapper digest history after delivery; stale history cannot allocate or generate ACK work.                                                             |
| Direction and OPEN causality     | Every common route ID matches its outer owner, including OPENED/CREDIT. Explicit direction exceptions; zero DATA flags; first HANDSHAKE waits for cumulative acknowledgement of installed OPEN, not a bitmap-only ACK.                                                       |
| Semantic admission               | Exact directional first objects and lifetime HANDSHAKE frame/byte profiles; canonical two-level fragmentation; lifetime stream caps and nonrefundable purpose partitions.                                                                                                    |
| Endpoint confirmation            | READY/ACK/ACCEPTED match retained fields; source receipt uses a fourth Noise-derived key; source and destination compare canonical remote bindings, while local owners compare object identity.                                                                              |
| Limits and capabilities          | Byte cap is bounded by `977*maxFrames`; service-wide token collision/lookup domains include unexpired tombstones and bounded resampling.                                                                                                                                     |
| Memory ownership                 | Complete pending reservations precede OFFER/ACCEPT and transfer at sentinels. Disjoint ARQ, receive, canonical cache, endpoint records, legacy Noise scratch, private confirmation arenas, and singleton legacy pre-OPEN ingress. No hidden lifetime OPEN/OPENED byte cache. |
| Close and loss                   | Leg-local FIN/EOF mapping; session-scoped reset preserves unrelated streams and listener ownership; explicit stream, route, and mutually exclusive physical closure reserves.                                                                                                |
| Tail transcript binding          | LINK_OFFER carries both exact directional partitions and the candidate commitment. The canonical136-byte framed digest binds all three into the exact290-byte tail transcript and all eight tail-control/finalize derivations.                                               |

Main's final integration additionally resolved stale formula copies, offered-versus-admitted queue calculation, cookie-tombstone retention after early challenge expiry, reverse first-object validation, and settled reliable-byte ownership. The final exact review additionally requires IK2-first private reply lists, a complete two-partition tail transcript binding, and reserved confirmation scratch. The binding adds58 bytes to the proposed v2 LINK_OFFER only; v1 and public APIs remain unchanged.

### Deliverable proof and its limits

- Existing native Noise profile: private IK1/IK2 **101/53 bytes**, handshake hash **64 bytes**, confirmation context **176 bytes**.
- Unchanged legacy server and real UDX/stock remote relay: exact **65,536/12,345-byte** transfer, both closes, and either one-sided EOF followed by opposite-direction data. This proves the ownership boundary, not an implemented M3 peer path.
- Actual SecretStream: header **59 bytes**, raw record maximum **16,777,218**, one MiB record requires **1,075** transported chunks; no plaintext after24 chunks. The design therefore distinguishes record assembly from application backpressure.
- Native Sodium/Python confirmation vectors agree. Actual Node24/Sodium incremental KDF and receipt MAC match using only the additional528-byte confirmation arena, reject the changed receipt nonce, and erase the arena after each operation. Its384-byte state,32-byte key,32-byte tag, and80-byte framing slots are disjoint. These are synthetic transcript construction checks, not production decoder/state/privacy tests.
- Independent arithmetic: fixed ARQ **157,200 bytes**, cookie pool **680,000**, per-endpoint record **33,554,439**, legacy pre-OPEN singleton **16,777,280**, and two contiguous legacy Noise slots **8,192 per lifetime stream**. Semantic caches are **726/2,049/1,921/9,620**; route admission floors are **820/1,396/1,636/2,164 cells** for the four named profiles. Full derivations are normative below.
- Native Sodium and independent Python agree on the canonical two-partition limits digest,290-byte tail transcript digest, and all eight tail KDF outputs. Changing either partition or the candidate commitment changes every derived key; appended LINK_OFFER fields are signed. The proposed432-byte signed offer still occupies one fixed cell, so physical packet budgets do not change.

Retained evidence includes `peer-stream-final-integration-proof.json`, `peer-stream-handshake-admission-proof.json`, `peer-stream-legacy-scratch-proof.json`, `peer-stream-incremental-confirmation-proof.txt`, `peer-stream-final-correction-proof.json`, `peer-stream-final-correction-python-proof.json`, `peer-stream-proof-manifest.json`, the confirmation vectors, and the native boundary results cited below. `local://` proof citations refer to the ownership session evidence directory:

`/Users/jd/.omp/agent/sessions/-.paseo-worktrees-12spyoi5-terrific-crocodile/2026-09-09T20-40-21-583Z_01a087e6-714f-71f9-825e-22a222e31292/local`

The runtime repair is separately published in [PR #54](https://github.com/ayooooo123/hyperdht/pull/54), merge `02bce1422de05c271260b1f37344d69dbe9afe23`. Accepted candidate, tested PR merge, and published merge share tree `c5aaa6c5b3b5fa1a85ff06d958c0602519787a46`. [Run34437120378](https://github.com/ayooooo123/hyperdht/actions/runs/34437120378) and the automatic [post-merge run34439259570](https://github.com/ayooooo123/hyperdht/actions/runs/34439259570) passed. The detailed119-file capture verification belongs to the former run, not to peer-stream privacy or a second downloaded bundle. Historical punch failure34435307484 remains unexplained; the cause-retention repair and later green runs do not waive it.

### Separate implementation and release gates

The specifications below describe future package-private implementation, not running v2 code. Its acceptance still requires real implemented owners, Node/Bare processes, malicious mispair rejection, private rendezvous, guarded record backpressure, simultaneous half-close convergence, expiry/rotation/suspend, quota/replay/cross-lane negative controls, and native Linux capture with endpoint-to-guard-only, fixed-cell, plaintext-leak, and hop-ciphertext checks. Existing DHT capture evidence is not a substitute. Public required mode remains disabled pending that implementation/aggregate acceptance and a named external human cryptographic review. No compatibility shim, direct fallback, or consumer release is authorized here.

## Transport specification

Section numbers in this part are local to this specification.

### 1. Frozen boundaries

1. Physical protocol remains version 0 and every UDP cell is exactly 1,200 bytes. A cell has the live 36-byte clear header, 1,148-byte ciphertext, and 16-byte AEAD tag. The decrypted cell payload ceiling is 1,146 bytes.
2. Route frames remain exactly 1,100 bytes: `counter u64 | ciphertext1092`. Opened plaintext is `class u8 | payloadLength u16 | payload<=1073 | random padding`, and the route AEAD tag is 16 bytes.
3. M3 v1 remains unchanged. V2 has a separate object registry, codecs, transcripts, keys, counters, contexts, dispatch owner, candidate directory, and selected-version owner. A v1 decoder rejects every v2 ID and context class; a v2 decoder rejects every v1 object.
4. Outer M3 route carriage remains DATAGRAM. It is not native reliable UDX STREAM carriage. Reliability is the bounded v2 ARQ in §7.
5. Purpose is exactly 1 `LEGACY_PEER_EGRESS`, 2 `PRIVATE_PEER_SOURCE`, or 3 `PRIVATE_PEER_DESTINATION`. V2 branch class is exactly2 `PEER`; v1 LOOKUP=0 and ANNOUNCE=1 remain unchanged and reject2. V2 link-role scalars remain source/client0, safety1, terminal2; guard is the first safety-role adjacency and there is no fourth hop.
6. A route consumes one of the source endpoint's existing four shared-guard transfer slots and one signed `maxConcurrentCircuits` slot. DHT lookup/announce pair leases are untouched.
7. V2 advertisement is exactly 260 bytes: body188, signature64, envelope8, `policyCount=0`, minimum/maximum version2/2, mask9 for guard/safety and mask11 for terminal. Bit4 and unknown bits reject.
8. Semantic IDs remain `0x0340..0x03bf`. Transport consumes the final semantic geometry in `#semantic-specification` without redefining it. Semantic Noise data is at most1,002 bytes; a maximum 1,073-byte canonical Noise object becomes HANDSHAKE fragments981+92. Legacy Noise ciphertext is deliberately capped at4,096 bytes per flight, yielding five semantic objects and nine transport HANDSHAKE packets, not 66 fragments.

Source anchors: `lib/private/protocol.js:9-20,32-58,141-152,383-430`; `lib/private/bootstrap-envelope.js:25-35,295-375`; `lib/private/route-payload.js:13-17,243-309,709-853`; `lib/private/m3-adjacency-runtime.js:895-971,1265-1280,1471-1539`; `lib/private/final-exit-handoff.js:15-28,64-137`; `lib/private/tail-control.js:1829-2209,2228-2302,3142-3362`; `lib/private/final-exit-activation.js:121-271,273-747,1821-1867,1902-1994`; `lib/private/final-exit.js:543-671`.
Hash notation is single-valued throughout: `H(D,X) = cryptoSuite.hash([u16be(UTF8(D).length) | UTF8(D), X])`, exactly32 bytes. This is the imported framing used by `lib/private/guard-link.js:474-480` and `#semantic-specification`; D is always a literal domain shown at the callsite and X is the exact concatenation inside that call. There is no bare or raw `H(bytes)` form and no additional X-length prefix.

### 2. Complete transport registry

Every object uses the canonical big-endian envelope `version u32=2 | id u16 | bodyBytes u16 | body | registered suffix`. Exact total length, known ID, body length, suffix length, reserved bytes, and state are checked before retention or allocation.

|         ID | Name                                |     Body | Suffix |     Wire | Accepted state/carriage                                                      |
| ---------: | ----------------------------------- | -------: | -----: | -------: | ---------------------------------------------------------------------------- |
|       0300 | `PEER_CAPABILITY_ADVERTISEMENT_V2`  |      188 |     64 |      260 | candidate validation only                                                    |
|       0301 | `PEER_CAPS_QUERY_V2`                |      110 |      0 |      118 | direct bootstrap phase0/1                                                    |
|       0302 | `PEER_CAPS_COOKIE_CHALLENGE_V2`     |       72 |      0 |       80 | direct response to phase0                                                    |
|       0303 | `PEER_CAPS_RESPONSE_V2`             |      335 |     64 |      407 | direct response to phase1; exactly one ad                                    |
|       0304 | `PEER_ACTIVE_CHALLENGE_V2`          |      176 |      0 |      184 | direct after response validation                                             |
|       0305 | `PEER_ACTIVE_CHALLENGE_RESPONSE_V2` |      240 |     64 |      312 | direct active proof                                                          |
|       0306 | `PEER_DISCOVER_REQUEST_V2`          | 79 or339 |      0 | 87 or347 | current tail-control ordered                                                 |
|       0307 | `PEER_DISCOVER_RESPONSE_V2`         |      436 |      0 |      444 | current tail-control ordered                                                 |
|       0308 | `PEER_LINK_OFFER_V2`                |      360 |     64 |      432 | physical adjacency setup; both partitions and candidate commitment           |
|       0309 | `PEER_LINK_ACCEPT_V2`               |      213 |     64 |      285 | physical adjacency setup                                                     |
|       030a | `PEER_REDACTED_RESPONDER_PROOF_V2`  |      306 |     64 |      378 | native link-reply member at index1/2; nested EXTENDED proof at source        |
|       030b | `PEER_EXTENDED_V2`                  |      486 |      0 |      494 | tail-control ordered                                                         |
|       030c | `PEER_TAIL_READY_V2`                |      210 |     64 |      282 | tail-control ordered                                                         |
|       030d | `PEER_EXTEND_REQUEST_V2`            |      516 |      0 |      524 | tail-control ordered; two limits plus candidate commitment                   |
|       030e | `PEER_BRANCH_DESTROY_V2`            |       42 |      0 |       50 | immediate route DATAGRAM                                                     |
|       030f | `PEER_BRANCH_TEARDOWN_V2`           |       58 |      0 |       66 | immediate route DATAGRAM                                                     |
|       0310 | `PEER_BRANCH_TEARDOWN_ACK_V2`       |       58 |      0 |       66 | immediate route DATAGRAM                                                     |
|       0311 | `PEER_ROUTE_OFFER_V2`               |      212 |     16 |      236 | tail-finalize DATAGRAM                                                       |
|       0312 | `PEER_ROUTE_ACCEPT_V2`              |      260 |     16 |      284 | tail-finalize DATAGRAM                                                       |
|       0313 | `PEER_ROUTE_REJECT_V2`              |       64 |     16 |       88 | tail-finalize DATAGRAM                                                       |
|       0314 | `PEER_RELIABLE_PACKET_V2`           | 29..1065 |      0 | 37..1073 | active purpose route                                                         |
|       0315 | `PEER_RELIABLE_ACK_V2`              |       64 |      0 |       72 | purpose confirmation or active ARQ                                           |
|       0316 | `PEER_OPEN_V2`                      |       88 |      0 |       96 | reliable control lane                                                        |
|       0317 | `PEER_OPENED_V2`                    |       64 |      0 |       72 | APPLICATION only, reliable control lane                                      |
|       0318 | `PEER_HANDSHAKE_V2`                 | 49..1029 |      0 | 57..1037 | REGISTRATION_CONTROL uses control lane; APPLICATION uses data lane; N=1..981 |
|       0319 | `PEER_DATA_V2`                      | 45..1021 |      0 | 53..1029 | APPLICATION/OPENED only; N=1..977                                            |
|       031a | `PEER_CREDIT_V2`                    |       60 |      0 |       68 | APPLICATION/OPENED control lane                                              |
|       031b | `PEER_FIN_V2`                       |       56 |      0 |       64 | APPLICATION/OPENED control lane                                              |
|       031c | `PEER_CLOSE_V2`                     |       56 |      0 |       64 | reliable forced-close control lane                                           |
|       031d | `PEER_RESET_V2`                     |       60 |      0 |       68 | reliable forced-close control lane                                           |
|       031e | `PEER_ROUTE_CLOSE_V2`               |       40 |      0 |       48 | unwrapped purpose-route DATAGRAM                                             |
|       031f | `PEER_ROUTE_CLOSE_ACK_V2`           |       40 |      0 |       48 | unwrapped purpose-route DATAGRAM reply                                       |
| 0320..033f | reserved                            |        — |      — |        — | always reject                                                                |

`PEER_CAPABILITY_ADVERTISEMENT_V2` body order is exactly `relayIdentity32 | currentDhtNodeId32 | reachableEndpoint19 | routeEncryptionPublicKey32 | capabilityMask u32 | minimumVersion u32 | maximumVersion u32 | cellSize u16 | maxCellPayload u16 | contextEnvelopeSize u16 | routeFrameSize u16 | maxRoutePayload u16 | datagramReplayWindow u16 | maxConcurrentCircuits u16 | capacityClass u8 | maxCells u32 | maxBytes u32 | maxCommands u32 | idleTimeoutMs u32 | maxQueuedBytes u32 | epoch u64 | issuedAt u64 | expiresAt u64 | policyCount u16=0` =188. Signature input is `u16be(labelLength) | "hyperdht-private-routes/m3/capability-advertisement/v2" | u32be(2) | u16be(0x0300) | u16be(188) | body`; digest domain is `hyperdht-private-routes/m3/capability-advertisement-digest/v2`.
`PEER_LINK_OFFER_V2` body360 is `advertisementDigest32 | initiatorIdentity32 | responderIdentity32 | initiatorRole u8 | responderRole u8 | branchClass u8=2 | branchId16 | circuitId16 | generation u64 | extensionIndex u8 (0..2) | initiatorLinkEphemeralPublicKey32 | clientTailEphemeralPublicKey32 | clientNonce32 | payloadParametersDigest32 | requestedLimits26 | offerDeadline u64 | initiatorForwardLimits26 | candidateAuthorityCommitment32`. The appended fields begin at body offsets302 and328. It is accepted only by the exact active candidate/locator owner in CIRCUIT_BUILDING, before an adjacency exists. `PEER_LINK_ACCEPT_V2` body213 is `offerDigest32 | advertisementDigest32 | responderIdentity32 | observedPredecessorEndpoint19 | responderLinkEphemeralPublicKey32 | admittedLimits26 | acceptedAt u64 | acceptNonce32`; it is accepted only against one pending byte-identical OFFER. V2 requires `admittedLimits26` byte-equal to `requestedLimits26`, not downward negotiation: inability to reserve the exact requested reverse partition rejects setup. The initiator reserves its exact appended forward partition before OFFER. The reverse partition must fit the responder advertisement and local reservation. The forward partition must fit the initiator reservation and its authenticated pinned-guard grant at index0 or current-tail advertisement at indices1/2; the source is not required to issue a relay advertisement. Both partitions remain within their applicable stored parent deadlines. Their64-byte signatures cover the complete bodies using the matching identities and link-offer/link-accept domains.
`PEER_REDACTED_RESPONDER_PROOF_V2` body306 is `responderAdvertisementDigest32 | initiatorIdentity32 | responderIdentity32 | branchClass u8=2 | branchId16 | circuitId16 | generation u64 | extensionIndex u8 | clientTailEphemeralPublicKey32 | clientNonce32 | advertisedRouteEncryptionPublicKey32 | admittedLimitsDigest32 | expiresAt u64 | responderProofNonce32`; it is accepted only as the second member of the matching index1/2 native link-reply vector or, at the source, nested in the matching EXTENDED. Its64-byte responder signature is verified before authenticated retention. `expiresAt` is byte-equal to the matching ACCEPT's admitted reverse partition expiry, and therefore to the retained OFFER/EXTEND_REQUEST reverse partition expiry. An expiry outside the advertisement or applicable stored parent bounds rejects admission; no silent clamp rewrites the accepted partition or proof. The proof never extends an existing forward/reverse, physical, or local deadline. A standalone proof has no carrier or authority. `PEER_EXTENDED_V2` body486 is `branchClass u8=2 | branchId16 | circuitId16 | generation u64 | extensionIndex u8 | responderAdvertisementDigest32 | proofLength u16=378 | completeProof378 | extensionNonce32`; only the source-side pending extension accepts it. `PEER_TAIL_READY_V2` body210 is `branchClass u8=2 | branchId16 | circuitId16 | generation u64 | extensionIndex u8 | tailControlTranscriptDigest32 | tailIdentity32 | tailAdvertisementDigest32 | clientNonce32 | readyNonce32 | expiresAt u64`; only the source that verified matching EXTENDED accepts its64-byte tail signature.
`PEER_BRANCH_DESTROY_V2` body42 is `branchClass u8=2 | branchId16 | circuitId16 | generation u64 | reason u8=1 downstreamPhysicalLoss`; it is accepted immediately on a matching live adjacency before ordinary route dispatch. Its byte-identical packet has at most eight attempts, including the first. DESTROY selects the physical-loss closure mode for that admitted branch. It is mutually exclusive with intentional TEARDOWN/ACK and spends the same ten-cell per-admitted-branch, per-adjacency-direction physical-teardown partition; it never adds cells beyond that partition. A shared physical link sums one such partition for every admitted branch, and DESTROY removes only the named branch owner, never a sibling route or branch authority. `PEER_BRANCH_TEARDOWN_V2` and ACK bodies58 are `branchClass u8=2 | branchId16 | circuitId16 | generation u64 | reason u8=2 intentionalSuspend | teardownId16`. A live/draining matching adjacency accepts TEARDOWN once, caches the exact ACK, and rejects changed reuse; only the initiator waiting on the same nonzero teardownId accepts ACK. TEARDOWN and its ACK share one ten-attempt counter in each direction through timer and duplicate triggers.

The nine core adjacency layouts `0308..0310` preserve the v1 field order except the two explicit v2 appendices: LINK_OFFER adds58 bytes and EXTEND_REQUEST adds58 bytes. V2 scalar changes are exact: branchClass=2 PEER; envelope version2; IDs above; transcript protocol scalar2; literal `/v2` domains; advertisement fixed260. `PEER_EXTEND_REQUEST_V2` uses the v1-shaped458-byte body, then appends `currentTailForwardLimits26` and `candidateAuthorityCommitment32`, making516. Its existing `requestedLimits26` is the successor's reverse-send partition. The current tail reserves its forward partition and consumes the one-use candidate authority before successor LINK_OFFER, copying the exact reverse partition, forward partition, and commitment into that OFFER. The successor adopts the exact requested reverse partition in LINK_ACCEPT. No v1 validator, enum, constant, or mask is widened.

### 3. Origin-safe candidate construction

#### 3.1 Locator authorities

No public caller supplies a host, port, socket, DHT ID, or destination reference.

- The source's guard locator is a non-exportable `PeerGuardLocatorAuthority` derived from a live pinned guard handle. It contains the expected guard identity, exact numeric endpoint, epoch, grant digest, run ID, operations, and local monotonic `localDeadline`. The source can send direct capability traffic only to that endpoint and identity.
- A current tail's directory-mode locator is a non-exportable local `PeerCandidateLocatorAuthority` returned by that tail's authenticated private candidate directory. It binds one exact numeric endpoint to one signed advertisement with Unix-millisecond `expiresAt` and one stored local monotonic `localDeadline`.
- A supplied-mode terminal locator comes only from the verified Gate D descriptor's exact 260-byte terminal advertisement. Source passes it inside encrypted tail control. The current safety tail validates the signature/epoch/mask and uses its reachable endpoint for the direct liveness exchange. Knowledge of the address never becomes source direct-send authority.
- Legacy terminal selection uses directory mode at the current safety tail. Private terminal selection uses supplied mode. Neither safety nor terminal receives the source address or source stable identity.

Active-candidate consumption explicitly requires the intended provenance kind: `guard` for pinned D0 or `candidate` for a relay's neighbor discovery. The complete expectation object is snapshotted through own-data descriptors before inspecting candidate state. Only `expectedKind`, `expectedIdentity32`, `expectedEndpoint19`, `expectedAdvertisement260`, `clockIdentity`, `expectedEpoch`, `expectedGrantDigest`, `expectedRunId`, and `expectedOperations` are allowed; accessors, unknown/string-or-symbol keys, and non-plain/non-null prototypes reject with INVALID_ROUTE without executing expectation getters. A kind mismatch rejects before one-shot consumption. Guard and neighbor link consumers supply `expectedAdvertisement260`; it must byte-match the internally retained canonical advertisement before consumption, so a same-identity replacement cannot burn the candidate. The consumer rechecks revocation, prior consumption, and the stored local deadline after the clock callback; an initially valid candidate cannot publish after being revoked or consumed reentrantly.

#### 3.2 Exact direct cookie and active-proof exchange

The direct exchange is the live capability-bootstrap shape with v2 IDs/domains, not the signed link bootstrap envelope. Each object is wrapped as `magic u16=0xd301 | objectLength u16 | complete object | zero padding` to exactly1,200 bytes. Length is 8..1,196 and every padding byte must be zero. The unchanged wrapper magic is grounded at `lib/private/caps-responder.js:18-19` and `lib/private/udx-cell-endpoint.js:91-92`.

`PEER_CAPS_QUERY_V2` body offsets are:

`requestedMask u32@0 | randomTarget32@4 | queryNonce32@36 | maximumResults u8=1@68 | phase u8@69 | cookieExpiresAt u64@70 | returnCookie32@78`.

Phase0 requires zero `cookieExpiresAt` and zero cookie. The responder observes the UDP source endpoint and returns `PEER_CAPS_COOKIE_CHALLENGE_V2`: `queryNonce32 | cookieExpiresAt u64 | returnCookie32` =72. `cookieExpiresAt` is exactly5,000ms after the paired local wall-clock sample. Cookie secret is32 bytes, rotates every300,000ms, and the immediately prior secret remains valid only through cookies issued before rotation. One valid1,200-byte phase0 packet permits exactly one1,200-byte COOKIE_CHALLENGE send attempt. That send has no timer retry, duplicate-triggered retry, allocation, or per-query state. The requester may transmit the same phase0 packet at most eight times, so at most eight challenge responses are charged.

`returnCookie = BLAKE2b-256(key=rotatingSecret32, input=u16be(labelLength) | "hyperdht-private-routes/m3/caps-return-cookie/v2" | u32be(2) | observedSourceEndpoint19 | requestedMask u32 | randomTarget32 | queryNonce32 | maximumResults u8 | cookieExpiresAt u64)`.
The requester is one bounded operation with states `PHASE0 -> COOKIE_FROZEN -> CAPS_FROZEN -> ACTIVE_FROZEN -> COMPLETE/FAILED`. In PHASE0 it owns one canonical phase0 packet, one eight-attempt counter, and one timer train. The first matching COOKIE_CHALLENGE whose query nonce and widths validate and whose `cookieExpiresAt` is future under one paired local wall/monotonic sample atomically stores that wire expiry and its once-projected local deadline, freezes one canonical phase1 packet and its fresh eight-attempt counter, moves to COOKIE_FROZEN, and cancels all phase0 work. Every later cookie is ignored without sampling a clock, replacing bytes, restarting a timer, or creating another counter.

Phase1 must repeat mask/target/nonce/count byte-for-byte and supply the live `cookieExpiresAt` and cookie. An invalid or elapsed `cookieExpiresAt` produces no response and no allocation. After reclaiming rows whose `cookieLocalDeadline` has elapsed, the responder admits phase1 only into a fixed startup pool of256 rows, with at most8 unexpired rows for one exact observedEndpoint19. It obtains the per-endpoint count by scanning the bounded pool; no auxiliary endpoint map exists. A full global or per-endpoint pool silently rejects. On first admission the responder takes one paired local wall/monotonic sample, requires `cookieExpiresAt > wallNow` under its existing clock guard, computes `cookieLocalDeadline = monotonicNow + (cookieExpiresAt-wallNow)` with checked arithmetic, and stores it. Replay never resamples or extends that deadline.

The row key is the canonical tuple `(observedEndpoint19,queryNonce32,cookieExpiresAt u64,returnCookie32)`. A digest may index the pool, but admission compares that complete tuple and the complete canonical phase1 body. Reuse of a nonce, tuple, or row key with changed query/body bytes conflicts and rejects. An exact phase1 retry finds the original row and cached padded CAPS_RESPONSE; it uses only that response object's remaining original eight-attempt counter and performs no allocation, RNG, signing, or timer creation.

Each responder row has fixed states `LIVE -> SPENT -> EXPIRED`. LIVE owns the canonical key/body, stored `cookieLocalDeadline`, fixed timer owner, cached exact1,200-byte CAPS_RESPONSE, its attempt counter, and the first accepted ACTIVE_CHALLENGE digest. On the first valid ACTIVE_CHALLENGE, the responder synchronously constructs the exact ACTIVE_RESPONSE and candidate facts, then atomically commits `LIVE -> SPENT`, the challenge digest, cached exact1,200-byte ACTIVE_RESPONSE, its original eight-attempt counter, `challengeLocalDeadline`, and `candidatePublished=false` before charging or sending attempt one. Send callbacks may only compare the same row owner/state and flip `candidatePublished` from false to true once; they cannot construct, replace, or republish a candidate. An exact challenge retry may only consume a remaining attempt from that cached response; it never creates another candidate. Changed challenge bytes conflict. LIVE and SPENT rows remain until their first stored deadline and are never evicted earlier; exact replay never renews either deadline.
Both LIVE and SPENT row keys remain reserved until the original `cookieLocalDeadline`, including when the active challenge expires earlier; otherwise an unexpired cookie could allocate another LIVE row. A SPENT row is an inert tombstone after `challengeLocalDeadline`: no ACTIVE send, candidate publication, or callback transfer is legal then. Every send callback rechecks the exact owner/state and both stored deadlines before publication. Expiry never resets either attempt counter.
At PHASE0 creation, the requester stores `operationLocalDeadline=min(locator.localDeadline,operationStartMonotonic+5000)` with checked arithmetic. Every later cookie/challenge projection is clamped to that immutable operation deadline as well as its named parents. Exhausting any eight-attempt train without a valid phase response fails the operation; a late response cannot revive it.

Listener startup pre-reserves exactly `256*(2*1200+256) + 2*32 = 256*2656+64 = 680,000` owned bytes. Every row owns two fixed1,200-byte response-cache slots and exactly256 metadata bytes: `observedEndpoint19 + canonicalPhase1Body110 + activeChallengeDigest32 + lookupDigest32 + cookieLocalDeadline8 + challengeLocalDeadline8 + state1 + capsAttempts1 + activeAttempts1 + candidatePublished1 + timerOwnerId8 + reserved35 =256`. The reserved tail is zeroed and cannot hold variable data. Both32-byte rotating cookie-secret slots are included. An implementation that needs any other row field rejects startup unless it first raises this explicit fixed reservation. This node-level startup pool is separate from every route ledger and allows no post-admission cache or metadata allocation.

`PEER_CAPS_RESPONSE_V2` body is exactly335:

`responderIdentity32 | queryNonce32 | responseTime u64 | count u8=1 | advertisementLength u16=260 | complete advertisement260`.

Its signature input is `u16be(labelLength) | "hyperdht-private-routes/m3/caps-response/v2" | u32be(2) | u16be(0x0303) | u16be(335) | body`. In COOKIE_FROZEN the requester checks expected responder identity, frozen query nonce, responseTime against the stored cookie window, advertisement version/mask/framing/epoch/`expiresAt`/signature, locator identity/endpoint equality, and response signature before retention. The first valid CAPS_RESPONSE atomically freezes that advertisement and one canonical ACTIVE_CHALLENGE with one eight-attempt counter, moves to CAPS_FROZEN, and cancels phase1 work. Every later response is ignored without replacing bytes or restarting a counter or timer.

`PEER_ACTIVE_CHALLENGE_V2` body is exactly176:

`advertisementDigest32 | responderIdentity32 | requesterEphemeralX25519PublicKey32 | challengeExpiresAt u64 | queryNonce32 | cookieExpiresAt u64 | returnCookie32`.
The requester fixes `challengeExpiresAt = min(cookieExpiresAt,verifiedAdvertisement.expiresAt)`. Before sealing the ACTIVE_CHALLENGE it takes one fresh paired wall/monotonic sample `(W,M)`, requires `W < challengeExpiresAt`, computes `M+(challengeExpiresAt-W)` with checked u64 arithmetic, and stores the resulting `challengeLocalDeadline` clamped to the frozen cookie and advertisement local deadlines. Exact retransmission reuses the same challenge bytes, expiry, projection, counter, and timer train.

The first occurrence is accepted only against the matching LIVE one-use cookie row and exact observed source endpoint. Before mutation the responder takes one paired `(wallNow,monotonicNow)` sample and requires exact query nonce, cookie, advertisement digest, current local advertisement, responder identity, and observed-endpoint binding plus `wallNow < challengeExpiresAt <= min(cookieExpiresAt,localAdvertisement.expiresAt)`. It computes the checked projection once and stores `challengeLocalDeadline = min(cookieLocalDeadline,localAdvertisement.localDeadline,monotonicNow+(challengeExpiresAt-wallNow))`. A SPENT row accepts only a byte-identical challenge occurrence whose complete digest matches the stored first challenge, solely to spend a remaining attempt from the cached response counter. `PEER_ACTIVE_CHALLENGE_RESPONSE_V2` body is exactly240:

`advertisementDigest32 | responderIdentity32 | requesterEphemeralPublicKey32 | responderNonce32 | challengeExpiresAt u64 | queryNonce32 | cookieExpiresAt u64 | returnCookie32 | routeKeyProof32`.

The fixed prefix before `routeKeyProof32` is `32+32+32+32+8+32+8+32 = 208` bytes. `routeKeyProof = BLAKE2b-256(key=X25519(responderRouteSecret,requesterEphemeralPublic), input=u16be(labelLength) | "hyperdht-private-routes/m3/active-challenge/route-key-proof/v2" | body[0..207])`. Low-order/all-zero agreement rejects. Signature input is `u16be(labelLength) | "hyperdht-private-routes/m3/active-challenge-response/v2" | u32be(2) | u16be(0x0305) | u16be(240) | body`. The canonical object is `8+240+64=312` bytes and remains padded to the fixed1,200-byte direct wrapper. Successful response follows the LIVE-to-SPENT ordering above and yields the candidate at most once.

#### 3.3 Who sends each discovery packet

Requester phase0, frozen phase1, and frozen ACTIVE_CHALLENGE objects each permit exactly eight byte-identical attempts at250ms intervals, including the first, bounded by their stored local deadlines. The first valid ACTIVE_RESPONSE in CAPS_FROZEN verifies every frozen binding and proof, atomically stores the exact response/candidate facts, moves to ACTIVE_FROZEN, and cancels ACTIVE work; transferring the candidate authority moves to COMPLETE exactly once. Any validation, deadline, or ownership failure moves to FAILED and cancels every remaining timer. COOKIE_CHALLENGE permits only the one response send caused by each received valid phase0 packet. Once phase1 creates a responder row, cached CAPS_RESPONSE and ACTIVE_RESPONSE each have one eight-attempt counter shared by timers and exact duplicate triggers; a duplicate trigger consumes the next unused ordinal and cannot start another retry train. Every physical attempt is charged before send; failed or uncertain sends remain charged.

1. Source physical owner sends phase0, phase1, and ACTIVE_CHALLENGE to the pinned guard; guard bootstrap owner sends cookie, CAPS_RESPONSE, and ACTIVE_RESPONSE. This is the only direct source discovery. The guard learns source IP; safety and terminal do not.
2. Source sends `PEER_DISCOVER_REQUEST_V2` through authenticated current-tail control to guard. Guard's physical owner performs the six-packet cookie/active exchange with safety from guard's address. Guard returns `PEER_DISCOVER_RESPONSE_V2` through tail control.
3. After extension1, source sends the second request through authenticated current-tail control to safety. Safety performs the same exchange with the selected legacy terminal or descriptor-supplied private terminal from safety's address and returns the response.

`PEER_DISCOVER_REQUEST_V2` body is `requestNonce32 | mode u8 (1 DIRECTORY,2 SUPPLIED) | requestedMask u32 | randomTarget32 | expiresAt u64 | suppliedAdvertisementLength u16 (0 or260) | suppliedAdvertisement`. Body79 or339. Mode1 requires length0; mode2 requires length260 and mask11. On first admission the current tail requires a nonzero nonce, exact mode/length/mask binding, and a paired sample proving `wallNow < expiresAt` within its authenticated wire bound; it stores the canonical request and once-projected local deadline. Exact replay reuses both, while changed bytes conflict without resampling or extending the operation.
`PEER_EXTEND_REQUEST_V2` retains `branchClass u8=2 | branchId16 | circuitId16 | generation u64 | extensionIndex u8 | advertisementLength u16=260 | advertisement260 | clientTailEphemeralPublicKey32 | clientNonce32 | payloadParametersDigest32 | successorReverseLimits26 | extensionNonce32`, then appends `currentTailForwardLimits26 | candidateAuthorityCommitment32`; body516. Each limits block is `cellSize u16=1200 | maxCells u32 | maxBytes u32 | maxCommands u32 | idleTimeoutMs u32 | expiresAt u64`. The commitment and both partitions are covered by tail-control AEAD/transcript. Before EXTENDED, current tail reserves its local forward row and successor reserves its reverse row; failure releases both.

`PEER_DISCOVER_RESPONSE_V2` body is `requestNonce32 | currentTailIdentity32 | completeAdvertisement260 | activeResponseDigest32 | candidateAuthorityNonce32 | verifiedAt u64 | expiresAt u64 | candidateAuthorityCommitment32` =436. The current tail—not source—verifies the direct ACTIVE_RESPONSE signature, exact frozen query/cookie/advertisement/local-identity bindings, X25519 proof, mask, role, and locator. It then takes one paired sample `(W,M)`, sets `verifiedAt=W`, and sets `expiresAt = min(discoverRequest.expiresAt,activeChallenge.challengeExpiresAt,advertisement.expiresAt,locator.wireExpiresAt)`. It requires `W < expiresAt`, computes `projected=M+(expiresAt-W)` with checked u64 arithmetic, and stores `discoverLocalDeadline=min(currentTail.localDeadline,projected)` with the canonical request, exact response fields, and one-use authority. Exact replay reuses `verifiedAt`, `expiresAt`, and `discoverLocalDeadline`; none is resampled or extended. `activeResponseDigest=H("hyperdht-private-routes/m3/active-challenge-response-digest/v2",complete ACTIVE_RESPONSE)`, `discoverRequestDigest=H("hyperdht-private-routes/m3/peer-discover-request-digest/v2",complete DISCOVER_REQUEST)`, and `advertisementDigest=H("hyperdht-private-routes/m3/capability-advertisement-digest/v2",completeAdvertisement)`. `candidateAuthorityCommitment=H("hyperdht-private-routes/m3/routed-candidate-authority/v2",tailControlTranscriptDigest32 | discoverRequestDigest32 | advertisementDigest32 | activeResponseDigest32 | candidateAuthorityNonce32 | verifiedAt u64 | expiresAt u64)`. Source verifies tail-control AEAD, request/tail binding, advertisement signature/digest/role/expiry, and commitment. It requires `verifiedAt < expiresAt <= min(originalRequest.expiresAt,advertisement.expiresAt,sourceParentWireExpiresAt)` and projects that expiry once under its own clock/parent deadline before retaining the response. The exact minimum involving hidden direct-bootstrap inputs is checked by the current tail; source does not claim to recompute that minimum or the X25519 proof from a digest. Source appends this commitment to EXTEND_REQUEST. Current tail requires matching LIVE authority, exact advertisement/request binding, unused nonce, and unexpired stored `discoverLocalDeadline`, then atomically consumes it before successor LINK_OFFER. The authority or commitment cannot authorize source UDP.

Each direct six-message exchange therefore reserves24 attempted cells in each physical direction. Forward/requester work is phase0+phase1+ACTIVE_CHALLENGE, each at most8. Reverse/responder work is at most8 one-shot COOKIE_CHALLENGE responses to the requester's eight phase0 attempts, plus at most8 cached CAPS_RESPONSE attempts and8 cached ACTIVE_RESPONSE attempts. D0 is source↔guard, D1 guard↔safety, D2 safety↔terminal. These charges belong to those local bootstrap send owners, not to an end-to-end route ledger. The responder's separate fixed680,000-byte startup pool owns all phase1/active binding state.

#### 3.4 Native relay-neighbor prerequisite and separate service accounting

A1/A2 use already-live authenticated relay-neighbor links, just as A0 uses its already-pinned guard link. Each relay owns a non-exportable bounded neighbor-link pool established through the existing v0 topology-grant, `LinkDirectory`, `UdxCellEndpoint.openLink`, and native link-bootstrap chain. Only locally configured, authenticated topology authority may provision that pool; a source request, decoded advertisement, direct ACTIVE proof, or caller-supplied address cannot mint a topology grant or native dial capability.

Provisioning transfers one caller-authorized opaque `LinkHandle`, not ownership of its `LinkDirectory` or topology grant. The caller constructs bootstrap options against that exact handle. Pre-consumption rejection preserves the handle; post-consumption cleanup owns only the resulting session and its reservations, never unrelated handles or the shared grant. Pool-owned clock identity, clock readers, and timer callbacks replace caller timing hooks. The bootstrap deadline is clamped to the stored parent deadline and any earlier operation deadline. Advertisement clocks must match the pool; established wire-to-monotonic projection occurs once, and later reads cannot extend it after wall-clock rollback. Long timers rearm against the original deadline using bounded host delays. Accept provisioning waits on the session's one-shot owned completion, not timer polling.

After D1/D2, the current tail must match the exact verified candidate identity, numeric endpoint, epoch, advertisement, and owned local clock to an existing live neighbor-link owner before consuming the candidate and reserving its branch slot. A missing, expired, mismatched, or full neighbor owner rejects the extension without a dial fallback. Supplied terminal selection has the same requirement. The pool supplies the real UDX endpoint and the same bounded four-entry physical transfer set; it cannot create a parallel v2 slot allowance. Native loss revokes all branches using that neighbor owner, while a single branch close leaves its surviving siblings owned.

Neighbor provisioning and maintenance have a separate finite node-level ledger and stored local deadline. It charges every native CREATE/CREATED, cancellation, PING/PONG, renewal, reconnection, and teardown attempt before send; failed or uncertain attempts remain spent. Neither unused circuit allowance nor another neighbor's reservation may fund this service traffic. Exhaustion/expiry revokes the neighbor owner and prevents new admission; close work must already have its own reserved allowance. The runtime must implement this accounting at the actual native send boundary, not merely annotate a fixture or subtract packets from capture afterward.

V2 LINK_OFFER/ACCEPT on these established links use outer-v0 DATAGRAM carriage and their existing eight-attempt owners. The v1 native STREAM setup exchange, its STREAM ACKs, and its context/installed-ACK messages are not reused. Direct `0xd301` remains exclusively CAPS/ACTIVE discovery; it never carries LINK_OFFER. The `532 + 48*N + 96*M` expression is the complete per-circuit v2 work bound, not a bound on separately accounted node bootstrap/neighbor service traffic. Native acceptance reports both categories and their sum, with every captured packet assigned to exactly one actual send owner.

The canonical native link reply is expectation-driven: the pending authenticated OFFER's `extensionIndex` determines its exact shape. Index0 accepts only complete ACCEPT285. Indices1/2 accept only `complete ACCEPT285 | complete REDACTED_RESPONDER_PROOF378`, exactly663 bytes, in that order, as one raw outer-v0 DATAGRAM payload. There is no extra wrapper, padding, optional member, trailing byte, standalone proof send, or separate proof retry train. Decode both canonical members and verify both signatures plus every shared OFFER/advertisement/branch/circuit/generation/index/client-tail-key/client-nonce/R/F/C/transcript binding before adjacency adoption or EXTENDED publication. The proof expiry matches the exact accepted reverse partition as §2 defines. Wrong shape or either invalid member rejects the whole reply; it cannot create a partially adopted branch.

The vector is one logical reply under the original eight-attempt owner: each attempt sends one1,200-byte cell; failures remain spent; retries reuse the byte-frozen vector and original physical reservation. All adjacency hashes and KDFs consume only complete OFFER432 and the ACCEPT285 member, never the663-byte vector or proof. The responder's bounded pending-OFFER cache owns663 bytes instead of285 at indices1/2, explicitly adding378 cache bytes per such row outside the bootstrap pool. On the initiator, the validated proof transfers once with the established-link owner into its adjacency runtime; `takePeerM3ExtensionProof` moves it once from a live index1/2 initiator runtime to the EXTENDED builder. Failure, expiry, or destruction erases untransferred proof bytes. The source receives proof bytes only inside EXTENDED; raw ACCEPT bytes, including the observed predecessor endpoint, never enter tail control. This changes neither the `LINK_ACCEPT8` partitions nor `532 + 48*N + 96*M`.

### 4. Dedicated circuit and complete finalization

#### 4.1 Circuit construction

The circuit is exactly A0 source↔guard, A1 guard↔safety, A2 safety↔terminal, with two EXTEND rounds.

1. Verify D0 and exchange `PEER_LINK_OFFER_V2/PEER_LINK_ACCEPT_V2` on A0. Install the v2 A0 runtime before any tail-control send.
2. Run D1 through guard authority. Source sends `DISCOVER_REQUEST1`, then `EXTEND_REQUEST1`. Guard creates A1 with LINK_OFFER and the canonical663-byte ACCEPT/proof reply. Before adoption, `completeTailExtend`-equivalent logic atomically validates both reply members and their complete retained tuple, then adopts the responder runtime, moves its verified proof once into EXTENDED, enqueues EXTENDED before publication, installs forwarding, and retains the old tail until source validates EXTENDED and signed TAIL_READY1.
3. Source validates READY1, atomically replaces tail-control secret/transcript with the successor material, and erases the old material. Publication remains owned by guard.
4. Run D2 through safety authority and repeat EXTEND_REQUEST2/EXTENDED2/TAIL_READY2 to create A2. Terminal forwarding is published before predecessor ownership release.
5. Completion of extension2 creates final material from the exact tail-control transcript, X25519 shared secret, Unix-millisecond `parentWireExpiresAt`, local monotonic `parentLocalDeadline`, `clockIdentity`, and finalize contexts. No peer route frame may be sent yet.

#### 4.2 One-time ownership chain before the first 1,100-byte frame

V2 mirrors the existing one-time source ownership chain, rather than treating labels as readiness:

`TAIL_READY2_VERIFIED -> FINAL_EXIT_READY -> FINAL_EXIT_HANDOFF -> FINAL_EXIT_ACTIVATION -> FINAL_EXIT_TRANSPORT_TAKING -> PURPOSE_CONFIRMING -> ACTIVE`.

- Final material contains exactly: `clockIdentity`; Unix-millisecond `parentWireExpiresAt`; local monotonic `parentLocalDeadline`; initiator flag; sharedSecret32; complete v2 tail-control transcript; finalize forward/reverse keys32 and nonce prefixes16; and the tail-control owner. These are parent bounds, not the child route clock tuple exported to semantics.
- `createFinalExitHandoff` moves that material once from tail-control state. `createFinalExitActivationClaim`, owner reservation, prepare, and commit perform the same compare-and-swap ownership checks as `tail-control.js:1929-2057` and `final-exit-activation.js:121-227`.
- `takeTailControlRouteTransport` requires empty tail-control receive/waiter queues, live runtime, matching owner/generation/`parentLocalDeadline`, and no install in progress. It calls the existing `takeM3RouteTransport` ownership boundary exactly once. Failure destroys the taken transport and material.
- Only after forwarding publication exists at A0/A1/A2, activation material is committed, finalize counters/keys are installed, and `takeM3RouteTransport` returns may source seal the first exact1,100-byte purpose OFFER frame.
- Purpose finalization uses context class5 `PEER_TAIL_FINALIZE_DATAGRAM`; its AD is exactly `contextClass u8 | version u32=2 | circuitId16 | generation u64 | direction u8 | counter u64` =38. Those fields are fixed by completed tail-control, so source can seal the first OFFER and terminal can open it without prior routeId/purpose publication. Active route traffic uses class6 `PEER_ROUTE_DATAGRAM`; only after authenticated OFFER/ACCEPT establishes routeId and purpose does its AD become `contextClass u8 | version u32=2 | routeId16 | circuitId16 | generation u64 | purpose u8 | direction u8 | counter u64` =55. Class5 and class6 have independent forward/reverse key labels, nonce-prefix labels, and counters; each counter begins0 and closes before `UINT64_MAX`, and each nonce is `prefix16 | counter u64`.
- Relays only transform their adjacency cell layer. Source and terminal alone open finalization and purpose-route payloads. The resulting active owner contains the route transport, purpose keys/counters, transcript digests, accepted directional ledgers, the accepted child clock tuple `{wireExpiresAt,localDeadline,clockIdentity,wallNow,monotonicNow}` derived in §5.2, stream table, and ARQ; it contains no endpoint Noise/SecretStream key.

#### 4.3 Literal v2 domains and derivations

Core domains:

- `hyperdht-private-routes/m3/link-offer/v2`
- `hyperdht-private-routes/m3/link-accept/v2`
- `hyperdht-private-routes/m3/link-offer-digest/v2`
- `hyperdht-private-routes/m3/link-accept-digest/v2`
- `hyperdht-private-routes/m3/cell-id/initiator/v2`
- `hyperdht-private-routes/m3/cell-id/responder/v2`
- `hyperdht-private-routes/tail-control/transcript/v2`
- `hyperdht-private-routes/tail-control/limits/v2`
- `hyperdht-private-routes/m3/redacted-responder-proof/v2`
- `hyperdht-private-routes/m3/tail-ready/v2`
- `hyperdht-private-routes/m3/tail-control/transcript-digest/v2`

Tail-control key labels:

- `hyperdht-private-routes/kdf/v2/tail-control/forward-key`
- `hyperdht-private-routes/kdf/v2/tail-control/reverse-key`
- `hyperdht-private-routes/kdf/v2/tail-control/forward-nonce`
- `hyperdht-private-routes/kdf/v2/tail-control/reverse-nonce`
- `hyperdht-private-routes/kdf/v2/tail-finalize/forward-key`
- `hyperdht-private-routes/kdf/v2/tail-finalize/reverse-key`
- `hyperdht-private-routes/kdf/v2/tail-finalize/forward-nonce`
- `hyperdht-private-routes/kdf/v2/tail-finalize/reverse-nonce`

Every KDF output is `sodium.crypto_generichash(out32, u16be(labelLength)|label|u32be(2)|u32be(transcriptLength)|transcript, key32)`. Nonce prefix is the first16 bytes of its independent nonce-label output. Keys and nonce labels never share output.

Adjacency key derivation is explicitly v2; the generic protocol0 `cryptoSuite.deriveKeys` construction is not inherited. Its nonzero X25519 shared secret is the agreement between LINK_OFFER `initiatorLinkEphemeralPublicKey` and LINK_ACCEPT `responderLinkEphemeralPublicKey`, using the corresponding local ephemeral secret. Both complete signed objects must already be authenticated and mutually bound before an adjacency owner is minted.

For each physical cell class `CONTROL=0` and `DATAGRAM=2`, define the exact104-byte transcript:

`UTF8("hyperdht-private-routes/link/created/v2") | H("hyperdht-private-routes/m3/link-offer-digest/v2",completeOffer432) | H("hyperdht-private-routes/m3/link-accept-digest/v2",completeAccept285) | cellClass u8`.

The39-byte leading literal has no additional prefix; each H uses the exact framed hash defined in §1. Derive four independent out32 values with the common v2 KDF and literal labels `hyperdht-private-routes/kdf/v2/forward-key`, `hyperdht-private-routes/kdf/v2/reverse-key`, `hyperdht-private-routes/kdf/v2/forward-nonce`, and `hyperdht-private-routes/kdf/v2/reverse-nonce`. Each nonce prefix is the first16 bytes of its own nonce output, whose full32 bytes are then erased. Initiator tx/rx map to forward/reverse; responder tx/rx map to reverse/forward. Each class/direction owns an independent counter beginning0 and nonce `prefix16 | counter u64be`; close before assigning `UINT64_MAX`, resetting, or wrapping under the same material. No STREAM adjacency key/context is allocated or admitted. Outer physical CellCodec remains version0.

Tail-control remains ordered-only, matching the registry. Its v2 context class is1 and its54-byte AD is `class1 u8 | version u32be=2 | branchId16 | circuitId16 | generation u64be | direction u8 | wireCounter u64be`. Preserve the explicit ordered counter encoding `wireCounter=logicalCounter<<1`: logical counters begin0 and close before `2^63`; the frame counter, AD counter, and nonce suffix are that same even wireCounter. Authenticate before requiring the low bit zero and passing `wireCounter>>1` to ordered replay state. The inner plaintext marker is STREAM=1; the fixed1,100-byte frame and1,101-byte context envelope travel inside physical DATAGRAM cells without native STREAM ACKs. Datagram tail-control/context2 under these keys rejects. This ordered-only rule does not alter class5/class6: their distinct-key counters remain the unmodified sequence0,1,... and are never low-bit packed.

#### 4.4 Canonical v2 tail transcript and partition binding

The v1 one-block limits digest is not imported into v2. Let `R26` be the exact admitted successor reverse-send limits (byte-equal to LINK_OFFER `requestedLimits26`), `F26` the exact LINK_OFFER `initiatorForwardLimits26`, and `C32` its exact candidate commitment. At extension1/2 these are byte-equal to the three corresponding retained EXTEND_REQUEST fields. At extension0, F is the source's reserved forward partition and R the guard's reserved reverse partition; C is exactly32 zero bytes because no routed discovery authority exists at index0. This explicit index0 constant is not a random identifier or capability and grants no send authority; pinned-guard locator and completed D0 active-candidate checks remain mandatory. Indices1/2 reject zero C and require the previously authenticated routed candidate commitment.

The exact limits input is `u32be(2)@0 | R26@4 | F26@30 | C32@56`, length88. Define `admittedLimitsDigest = H("hyperdht-private-routes/tail-control/limits/v2", that exact88-byte input)`. The H framing is `u16be(46) | domain46 | input88`, total136 bytes. No struct serialization, omitted field, extra length prefix, or raw v1 domain concatenation is allowed.

The complete v2 tail-control transcript T is exactly290 bytes:

| Offset | Bytes | Field                                                     |
| -----: | ----: | --------------------------------------------------------- |
|      0 |     2 | domain length u16be=50                                    |
|      2 |    50 | UTF8 `hyperdht-private-routes/tail-control/transcript/v2` |
|     52 |     4 | protocol u32be=2                                          |
|     56 |     1 | branchClass=2                                             |
|     57 |    16 | branchId                                                  |
|     73 |    16 | circuitId                                                 |
|     89 |     8 | generation u64be                                          |
|     97 |     1 | extensionIndex=0,1,2                                      |
|     98 |    32 | clientTailEphemeralPublicKey                              |
|    130 |    32 | advertisedTailRouteEncryptionPublicKey                    |
|    162 |    32 | candidateAdvertisementDigest                              |
|    194 |    32 | clientNonce                                               |
|    226 |    32 | tailIdentity                                              |
|    258 |    32 | admittedLimitsDigest defined above                        |

Each field comes from the matching authenticated LINK_OFFER/advertisement and the exact accepted tuple, never from a later callback or another extension. Successor signs the redacted proof's `admittedLimitsDigest` only after reserving R and authenticating the complete signed LINK_OFFER, including F and C. Current tail compares the proof against its retained accepted tuple; source independently reconstructs the same digest from its retained EXTEND_REQUEST tuple before accepting EXTENDED. A changed partition or commitment therefore fails before tail publication. Source and successor construct byte-identical T; no successor needs hidden direct-bootstrap proof bytes.

`tailControlTranscriptDigest = H("hyperdht-private-routes/m3/tail-control/transcript-digest/v2", T290)`. This digest is serialized in TAIL_READY and the purpose preTranscript. It is an input to the next routed-candidate commitment defined in §3.3, not the commitment itself; that distinct hash also binds the discovery request, advertisement, active response, authority nonce, and times. Every one of the eight tail-control/tail-finalize labels in §4.3 uses complete T290, not its digest, as the `transcript` in the KDF: `u16be(labelLength) | label | u32be(2) | u32be(290) | T290`, keyed by the matching source-tail X25519 shared secret32. Final-exit handoff moves the exact extension2 T290 and its derived material once. Subsequent purpose-specific KDFs use their explicitly named pre/final transcripts and are not silently substituted for T.

### 5. Purpose binding and both confirmations

#### 5.1 OFFER, ACCEPT, and MAC primitive

`PEER_ROUTE_OFFER_V2` body offsets:

`routeId16@0 | circuitId16@16 | generation u64@32 | purpose u8@40 | sourceDirection u8@41 | flags u16=0@42 | expiresAt u64@44 | terminalAdvertisementDigest32@52 | queryNonce32@84 | clientEphemeralPublicKey32@116 | forwardCells u32@148 | forwardBytes u64@152 | forwardCommands u32@160 | reverseCells u32@164 | reverseBytes u64@168 | reverseCommands u32@176 | maxStreams u16@180 | receiveFrames u16@182 | receiveBytes u32@184 | semanticOwnedBytes u32@188 | maxQueuedBytes u32@192 | offerNonce16@196` =212.

Pre-shared secret is exactly `X25519(clientEphemeralSecret, advertisedTerminalRoutePublicKey)` at source and `X25519(terminalEpochRouteSecret, clientEphemeralPublicKey)` at terminal. Null/low-order agreement rejects.

`sourceDirection` uses the protocol direction enum, FORWARD=0 and REVERSE=1. This architecture requires source/route-initiator to terminal direction FORWARD=0 in OFFER; purpose3 terminal-opened application streams later use physical REVERSE without changing the route binding.

`preTranscript` is:

`u16be(labelLength) | "hyperdht-private-routes/m3/peer-route-prepurpose/v2" | u32be(2) | tailControlTranscriptDigest32 | terminalAdvertisementDigest32 | queryNonce32 | clientEphemeralPublicKey32 | terminalRoutePublicKey32 | complete original OFFER body212`.

The terminal always derives from the original OFFER values. Downward ACCEPT values never replace OFFER values in `preTranscript`.

`preSourceMacKey16` and `preTerminalMacKey16` are the first16 bytes of two independent common-KDF `out32` results keyed by preShared. The full32-byte outputs use distinct literal labels below and are erased after truncation; they are never derived with BLAKE2b `out16`:

- `hyperdht-private-routes/kdf/v2/peer-route/pre/source-mac`
- `hyperdht-private-routes/kdf/v2/peer-route/pre/terminal-mac`

`MAC16(K16,M) = sodium.crypto_generichash(out16,M,K16)`. M is the complete eight-byte v2 header plus exact body. OFFER suffix is `MAC16(preSourceMacKey16,header|body)`; ACCEPT and REJECT use `preTerminalMacKey16`. Verification compares all16 bytes in constant time. The suffix contains the tag, never the KDF key.

`PEER_ROUTE_ACCEPT_V2` body offsets:

`routeId16@0 | circuitId16@16 | generation u64@32 | purpose u8@40 | sourceDirection u8@41 | flags u16=0@42 | expiresAt u64@44 | terminalAdvertisementDigest32@52 | queryNonce32@84 | clientEphemeralPublicKey32@116 | offerDigest32@148 | admittedForwardCells u32@180 | admittedForwardBytes u64@184 | admittedForwardCommands u32@192 | admittedReverseCells u32@196 | admittedReverseBytes u64@200 | admittedReverseCommands u32@208 | admittedMaxStreams u16@212 | admittedReceiveFrames u16@214 | admittedReceiveBytes u32@216 | admittedSemanticOwnedBytes u32@220 | admittedMaxQueuedBytes u32@224 | offerNonce16@228 | acceptNonce16@244` =260.

Every admitted value must be nonzero where used and no larger than OFFER, advertisement, local reservation, or authenticated `wireExpiresAt`/stored `localDeadline` bounds. `receiveFrames/receiveBytes` request symmetric per-owner maxima, and ACCEPT negotiates them downward once; they are not one shared physical pool. The source and terminal each reserve the accepted frame count and byte count for that local route owner's single inbound outer direction. The same rule applies independently on every bridge leg. `offerDigest=H("hyperdht-private-routes/m3/peer-route-offer-digest/v2",complete OFFER including MAC)`. ACCEPT suffix is `MAC16(preTerminalMacKey16,header|body)`.

Before sealing OFFER, source creates one source pending-purpose owner and reserves the offered fixed ARQ, `1073*M` reassembly, inbound receive-window, complete semantic-owned pool, directional cell/byte/command ledgers, cached OFFER, and pre-purpose crypto. After valid downward ACCEPT it atomically narrows that same owner to the accepted values and releases only the excess. After authenticating OFFER and choosing accepted values, terminal creates the corresponding terminal pending-purpose owner before sealing or caching ACCEPT; it exclusively owns the accepted copies of those same reservations, cached ACCEPT, and pre-purpose crypto. Neither pending owner borrows the peer's or another leg's storage. REJECT, local deadline, authentication failure, transport loss, or setup abort moves the affected pending owner once to RELEASED and releases every reservation exactly once.

REJECT body64 is `routeId16 | generation u64 | purpose u8 | reserved3=0 | offerNonce16 | reason u16 | reserved u16=0 | rejectNonce16`; suffix uses `preTerminalMacKey16`. Before valid OFFER authentication terminal sends nothing. First valid OFFER binds one canonical OFFER and exactly one cached canonical ACCEPT or REJECT. Timer retries and exact OFFER duplicates may consume only that cached response's remaining original eight-attempt budget, including its initial send; they never create a second response, counter, timer train, or reservation. Source OFFER likewise has one original eight-attempt budget. Each owner stores `finalizationLocalDeadline=min(parentLocalDeadline,firstAttemptMonotonic+2000ms)` once, uses the250ms retry schedule, and charges the next attempt and physical cell before sealing/sending, including failed sends. Exhaustion, deadline, or retirement of the original finalization owner permits no further response.

Canonical OFFER/ACCEPT/REJECT bytes and logical identity stay byte-identical on every retry. The class-5 outer wrapper is freshly sealed with the next unused monotonic finalize AEAD counter on each permitted attempt; this cryptographic counter is distinct from the single capped attempt counter and is never reset or reused. It does not mint another send allowance. Same routeId/offerNonce with changed canonical bytes destroys pending state. Captured outer-frame duplicates rejected by the AEAD replay window trigger no send; an authenticated fresh outer frame carrying an exact OFFER can trigger only the original cached response's remaining allowance.

#### 5.2 Purpose and final transcript digests

`purposeTranscript = preTranscript | complete OFFER including MAC | complete ACCEPT body excluding MAC`. It is constructed only after ACCEPT MAC and all downward limits verify.

Derive route forward/reverse keys32 and nonce prefixes16 from preShared and purposeTranscript with:

- `hyperdht-private-routes/kdf/v2/peer-route/forward-key`
- `hyperdht-private-routes/kdf/v2/peer-route/reverse-key`
- `hyperdht-private-routes/kdf/v2/peer-route/forward-nonce`
- `hyperdht-private-routes/kdf/v2/peer-route/reverse-nonce`

`acceptDigest = H("hyperdht-private-routes/m3/peer-route-accept-digest/v2",complete ACCEPT including MAC)`. `purposeDigest = H("hyperdht-private-routes/m3/peer-route-purpose-digest/v2", u32be(2) | tailControlTranscriptDigest32 | terminalAdvertisementDigest32 | routeId16 | circuitId16 | generation u64 | purpose u8 | sourceDirection u8 | offerDigest32 | acceptDigest32 | accepted six directional limits | admittedMaxStreams u16 | admittedReceiveFrames u16 | admittedReceiveBytes u32 | admittedSemanticOwnedBytes u32 | admittedMaxQueuedBytes u32 | offerNonce16 | acceptNonce16)`.

The accepted six limits are forward cells u32/bytes u64/commands u32 then reverse cells u32/bytes u64/commands u32. No field is implicit.

After ACCEPT MAC and every downward value verify, each side derives its immutable child route clock tuple before purpose-key use. The accepted body field `expiresAt` becomes child `wireExpiresAt` and must not exceed final material `parentWireExpiresAt`. Under final material `clockIdentity`, that side takes and stores one paired local `wallNow`/`monotonicNow` sample, requires `wireExpiresAt > wallNow`, computes `projectedRouteDeadline = monotonicNow + (wireExpiresAt-wallNow)` with checked arithmetic, and sets child `localDeadline = min(parentLocalDeadline,projectedRouteDeadline)`. It never resamples, imports a peer monotonic value, or compares monotonic clocks across hosts. Failure occurs before either sentinel.

#### 5.3 Sentinel confirmations and loss

The first purpose-key payload in each direction is `PEER_RELIABLE_ACK_V2` with both cumulative sequences `UINT64_MAX`, both bitmaps zero, `ackSnapshot=0`, and final `reservedZero=0`. Outer direction distinguishes confirmations.

1. Source sends its sentinel only after ACCEPT validation, purpose-key derivation, and successful narrowing of its pending-purpose owner.
2. Terminal derives purpose keys only from the same complete inputs, opens the source sentinel, and atomically transfers—not reacquires or recomputes—its complete pending-purpose owner into the active owner before sending its sentinel.
3. Source becomes ACTIVE only after opening the terminal sentinel and atomically transferring its complete pending-purpose owner into the active owner. Terminal may accept ordinary sequence0 only after sealing its sentinel and completing its transfer.
   Each direction has one global sentinel-attempt counter capped at eight, with nominal offsets0,250,500,750,1000,1250,1500,1750ms measured only by the owner's monotonic clock. At the first sentinel attempt the owner stores `operationStartMonotonic` and `sentinelLocalDeadline = min(localDeadline,operationStartMonotonic+2000ms)` using checked arithmetic. Every send—timer-driven or duplicate-triggered—must occur before that stored local deadline, consumes the next ordinal, uses identical ACK bytes with a fresh purpose-route counter, and charges one physical cell. A duplicate-triggered terminal send cancels the pending timer and consumes that same next ordinal; it is not an additional send. Source retries until terminal sentinel arrives. Terminal sends on first source sentinel, then uses duplicate source sentinels as early triggers for its remaining ordinals; its timers send only ordinals not already consumed. Neither direction can exceed eight sends. Loss of either sentinel cannot deadlock waiting for an ungenerated packet. Changed sentinel bytes or a non-sentinel first purpose packet fails authentication. No Unix wire time is compared directly with `operationStartMonotonic`.

Terminal erases preShared and both pre-MAC key16 values after source sentinel verification and ACCEPT/terminal-sentinel caches exist; retries need only purpose keys and cached bytes. Source erases them after terminal sentinel verification. Purpose keys live until route teardown. Terminal keeps the cached sentinel and duplicate-source-sentinel digest until `sentinelLocalDeadline`; source keeps its source sentinel cache until the same locally computed bound. Erasure never precedes bounded retry obligations.

`sourceConfirmDigest=H("hyperdht-private-routes/m3/peer-route/source-confirm/v2",source sentinel body64)` and `terminalConfirmDigest=H("hyperdht-private-routes/m3/peer-route/terminal-confirm/v2",terminal sentinel body64)`. `finalTranscriptDigest = H("hyperdht-private-routes/m3/peer-route-final-transcript-digest/v2", u32be(2) | tailControlTranscriptDigest32 | purposeDigest32 | offerDigest32 | acceptDigest32 | sourceConfirmDigest32 | terminalConfirmDigest32)`. Direction-specific domains distinguish the otherwise identical sentinel bodies.

After ACTIVE, transport exports exactly the accepted child tuple `{purposeDigest32,finalTranscriptDigest32,routeOwner,generation,purpose,wireExpiresAt,localDeadline,clockIdentity,wallNow,monotonicNow}` to semantic issuers. `wireExpiresAt` is authenticated ACCEPT `expiresAt`; `localDeadline` is the child projection stored in §5.2. Here `wallNow` and `monotonicNow` are the owned clock functions, not the numeric route-admission samples; those samples remain private projection evidence. It exports no parent deadline, preShared, route key, Noise key, mutable locator, or peer-supplied monotonic value.

Every serialized `expiresAt`, `deadline`, `cookieExpiresAt`, `challengeExpiresAt`, and `wireExpiresAt` value is an unsigned Unix-epoch millisecond value. Local monotonic deadlines are never serialized. For a later semantic wire deadline `T`, first admission takes one fresh paired sample `(W,M)` from those owned functions under the captured clock identity, requires `W<T<=wireExpiresAt`, computes `projected=M+(T-W)` with checked arithmetic, and stores `min(localDeadline,projected)`. A projection above the local parent deadline is clamped, not rejected; a wire expiry above the authenticated parent wire bound rejects. Exact replay reuses its stored projection and never samples again or extends it. Changed clock identity, rollback detected by existing guards, invalid width, overflow, or substitution of parent authority fails closed.

### 6. Stream classes, IDs, and physical directions

`common40 = routeId16 | streamId u64 | streamEpoch u32 | direction u8 | flags u8 | reserved u16 | position u64`. Reserved is zero. HANDSHAKE interprets position as semantic object sequence. DATA interprets it as continuous ciphertext offset. OPEN/OPENED/CREDIT/FIN/CLOSE/RESET require common position and common flags zero; their type-specific fields carry their state.
For every nested common object, including OPENED and CREDIT, `common.routeId` must equal the containing reliable wrapper routeId. For OPEN, HANDSHAKE, DATA, FIN, CLOSE, and RESET, `common.direction` must equal that wrapper's class-6 outer direction. OPENED travels opposite the saved OPEN direction while carrying that saved OPEN direction in `common.direction`. CREDIT travels opposite the granted DATA direction while naming that granted direction in `common.direction`. Any mismatch rejects before stream mutation or allocation.

`PEER_OPEN_V2` body remains88:

`common40 | semanticFirstId u16 | semanticClass u8 | reservedZero u8 | firstSemanticWireBytes u32 | requestedHandshakeFrames u32 | requestedHandshakeBytes u64 | requestedDataFrames u32 | requestedDataBytes u64 | openNonce16`.

Semantic classes are exact: 1 `REGISTRATION_CONTROL`, 2 `APPLICATION`. No other value is accepted.
The four handshake fields are an exact lifetime profile, not hints. `semanticFirstId/firstSemanticWireBytes` name the first canonical semantic envelope carried after OPEN. `requestedHandshakeFrames/requestedHandshakeBytes` cap HANDSHAKE packets and the sum of canonical semantic wire bytes in their fragment payloads in the opener→receiver outer direction. They include every profile object through delayed registration REVOKE where applicable; they never include OPEN, OPENED, DATA, CREDIT, FIN, padding, wrappers, or retransmissions.

| authenticated OPEN profile               | first ID/wire bytes |                                      opener→receiver HANDSHAKE frames/bytes |                      independently reserved receiver→opener frames/bytes |
| ---------------------------------------- | ------------------: | --------------------------------------------------------------------------: | -----------------------------------------------------------------------: |
| purpose3 registration control            |          `0349/486` |                                            `2/582` = REGISTER486 + REVOKE96 |                                                  `1/144` = REGISTERED144 |
| purpose2 private source application      |          `0360/757` |       `4/1297` = ACTIVATE757 + IK1 fragment172 + ACK240 + SOURCE_RECEIPT128 |     `4/752` = IK2 fragment124 + READY228 + ACCEPTED176 + PRIVATE_OPEN224 |
| purpose3 private destination application |          `0360/757` |         `4/1393` = ACTIVATE757 + IK1 fragment172 + ACK240 + PRIVATE_OPEN224 |                       `3/528` = IK2 fragment124 + READY228 + ACCEPTED176 |
| purpose1 legacy maximum application      |          `0341/112` | `12/4807` = RESOLVE112 + RESERVE104 + IK1 objects4451 + HANDSHAKE_ACCEPT140 | `12/4813` = RESOLVED114 + RESERVED140 + IK2 objects4451 + LEGACY_OPEN108 |

OPEN must match its fixed row exactly. Before acknowledging OPEN, the receiver reserves the row's fixed reverse profile independently. On the first HANDSHAKE FIRST fragment in the opener→receiver direction, and before any semantic allocation, it requires the envelope ID and derived canonical wire length to equal OPEN's `semanticFirstId/firstSemanticWireBytes`. The first reverse-direction object instead matches its profile: REGISTERED `034a/144`, IK2 NOISE_FRAGMENT `0345/124` for either private profile, or RESOLVED `0342/114` for legacy. Private IK2 precedes READY as semantic §7.2 requires. Each direction has independent fixed lifetime HANDSHAKE counters from its table column. Each sender charges one frame and that fragment's canonical semantic wire-byte contribution before first send; each receiver charges the same before first enqueue. Crossing either maximum rejects before semantic allocation and emits no over-budget ACK; an already allocated stream spends its reserved quota RESET. Exact retries never charge again, and unused profile capacity is not transferable.
The opener must receive a valid ARQ snapshot whose non-sentinel `controlCumulative` covers the original OPEN sequence before sending its first HANDSHAKE. A bitmap-only acknowledgement does not satisfy this barrier. Receiver control cumulative progress may pass OPEN only after OPEN is control-contiguous, all its reservations succeed, and its stream owner is installed. Thus an earlier control gap or cross-lane packet reordering cannot deliver a legitimate HANDSHAKE before stream admission. This barrier uses the existing OPEN/ACK attempt budgets and adds no wire object or retry train.

Stream IDs are collision-free without coordination: route initiator allocates odd IDs1,3,5...; route terminal allocates even IDs2,4,6.... Zero rejects. Each permitted allocator increments its next ID by2 with checked u64 arithmetic and closes before exhaustion. `(routeOwner,generation,streamId,streamEpoch)` is the transport identity; epoch starts1 and never wraps or reuses a tombstoned tuple. `admittedMaxStreams=M` is a lifetime cap, partitioned by authenticated route purpose with no shared race: purpose1 and purpose2 assign allM OPENs to the route initiator and zero to the terminal; purpose3 assigns exactly one initiator OPEN to registration-control stream1 and the remaining `M-1` terminal OPENs to even application streams. Purpose3 therefore requires `M>=1`. No other side/class combination may originate OPEN. A close, reset, FIN, or tombstone never refunds either partition; live concurrency and retained stream tombstones together remain bounded byM.

Before allocating a stream slot, reassembly, semantic state, or record memory, each local allocator and receiver checks the authenticated purpose partition, its nonrefundable accepted count, the required parity/class, and the strictly increasing stream ID. A locally originated OPEN atomically consumes one slot from that side's partition before its first send. A remotely originated OPEN atomically consumes one slot from the sender's matching partition when first admitted. Exact retransmission cannot consume again. A local request against an exhausted or forbidden partition fails locally without a packet. An authenticated OPEN from a forbidden side/class, wrong stream ID, or exhausted partition is a route protocol violation: it creates no stream, tombstone, semantic callback, or RESET, and fails the route through its already reserved route/physical teardown path. Fixed purpose partitions make simultaneous local and remote allocation unable to exceedM and leave no hidden response or unbudgeted close work.

Purpose3 direction mapping is explicit:

- The listener is route initiator. Its single registration-control stream is odd stream1 and opens in physical FORWARD direction listener→entry.
- Entry-originated incoming peer application streams are even and open in physical REVERSE direction entry→listener. All entry→listener HANDSHAKE/DATA/FIN packets are reverse; listener replies are forward on the same stream.
- Therefore the private-destination semantic profile maps destination→entry objects to physical FORWARD and entry→destination objects to physical REVERSE, matching semantic §9.3.

`REGISTRATION_CONTROL` transitions `IDLE -> CONTROL_OPEN -> CONTROL_ACTIVE -> CONTROL_CLOSING -> CLOSED`. It accepts only complete semantic IDs0349 REGISTER,034a REGISTERED,034b REVOKE in HANDSHAKE for the route lifetime. Those HANDSHAKE wrappers are CONTROL-lane packets and one of the route's eight sender control slots is reserved exclusively for this stream until it closes; application/control traffic cannot borrow it. It never emits OPENED, never accepts DATA/FIN/CREDIT, and pre-reserves its full lifetime HANDSHAKE frames/bytes in OPEN. CLOSE/RESET ends it. Later REVOKE is therefore legal after registration even when application data slots are full.

`APPLICATION` transitions `IDLE -> OPEN_RECEIVED -> AUTHENTICATING -> OPENED -> CREDIT_READY -> half-close states -> CLOSING -> CLOSED`. HANDSHAKE is legal before semantic success; after success transport emits OPENED and HANDSHAKE becomes illegal. DATA/CREDIT/FIN are legal only after OPENED, but neither endpoint may start SecretStream or emit its59-byte header until both directional initial CREDIT objects are authenticated as §7.2 requires.

HANDSHAKE body is `common40 | semanticObjectOffset u32 | fragmentBytes u16 | fragmentFlags u16 | bytesN`, N=1..981. FIRST=1, LAST=2. Offset resets per semantic object; common position increments once per complete object. REGISTRATION_CONTROL HANDSHAKE is legal only with reliable-wrapper CONTROL flag; APPLICATION HANDSHAKE is legal only without it on the data lane. Maximum semantic wire1,073 becomes exactly981+92.

Fragmentation is canonical, not sender-chosen: the FIRST fragment starts with the complete eight-byte semantic envelope header. Validate its registry ID/body length and fixed suffix before deriving total wire length `L<=1073`; for the first semantic object, L must also equal OPEN's `firstSemanticWireBytes`. Required offsets are `i*981`, payload length is exactly `min(981,L-offset)`, FIRST is set iff offset0, and LAST iff `offset+N=L`; all other flag bits are zero. Thus each object has exactly `ceil(L/981)` packets, at most two. Short non-final fragments, noncanonical offsets, overlaps, and changed envelope lengths are stream conflicts, never additional budgeted fragments. Duplicate metadata retains the ordered original reliable-packet identity vector indexed by semantic-object offset; interleaving other streams means those lane sequences need not be adjacent.

DATA body is `common40 | dataBytes u16 | dataFlags u16=0 | bytesN`, N=1..977. Every nonzero `dataFlags` rejects. Common position is the exact offset of the first ciphertext byte. Receiver requires it equal `nextCiphertextOffset` and advances with checked u64 addition.

`PEER_FIN_V2` body56 is `common40 | finalCiphertextOffset u64 | finalDataSequence u64`. It is CONTROL-lane and valid only for APPLICATION/OPENED. If that direction emitted no DATA, values must be `finalCiphertextOffset=0` and `finalDataSequence=UINT64_MAX`; otherwise finalDataSequence is the last DATA-lane sequence carrying that direction's ciphertext. FIN may be retained across a DATA gap but cannot become effective until it is control-lane contiguous and every DATA sequence through that value and every ciphertext byte below final offset is durably admitted. A stream reaches graceful CLOSED after both directional FIN conditions; no CLOSE packet is needed.
`PEER_CLOSE_V2` body56 is `common40 | finalCiphertextOffset u64 | finalDataSequence u64`. `PEER_RESET_V2` body60 appends `errorCode u16 | reserved u16=0`; codes are1 application,2 authentication,3 quota,4 idle,5 route-loss,6 revoked,7 conflict,8 internal, and unknown codes reject. CLOSE/RESET is accepted only on the CONTROL lane for one allocated stream after that stream's semantic owner has revoked its own authority. Once control-lane contiguous it closes only that stream, installs its tombstone, and consumes that stream's directional close/ACK reserve; it never enters route FAILED/DRAINING or invalidates another stream. A private session failure first revokes exactly that session's two bridge reservations and preserves listener registration plus every shared surviving route owner. Registration-control CLOSE/RESET is different only because semantic §5.3 revokes that registration and then its dependent sessions. Route loss directly revokes every session using the lost route, while independently owned counterpart routes survive. RESET need not wait for DATA; CLOSE records a last valid boundary but does not prove graceful FIN.

`PEER_ROUTE_CLOSE_V2` body40 is `routeId16 | generation u64 | closeNonce16`; every field is nonzero and no sentinel is allowed. It is unwrapped—never a RELIABLE_PACKET/control-lane member—and only route initiator may send it after every stream is CLOSED/tombstoned and both ARQ lanes have no non-route-close packet in flight. `PEER_ROUTE_CLOSE_ACK_V2` has the identical40-byte body, is also unwrapped, and is accepted only by the initiator in DRAINING as an exact echo. Each direction has one global eight-attempt counter shared by timers and duplicate triggers, exactly as sentinel counters are bounded; a duplicate route CLOSE can accelerate but never add an ACK ordinal. Neither object elicits ordinary ARQ ACK, so no ACK recursion or double charge exists. Changed nonce/binding fails. This8-cell-per-direction graceful route-close reserve is disjoint from every stream's forced-close reserve and from physical branch closure. Reaching stored `localDeadline` because authenticated `wireExpiresAt` elapsed, or losing the route earlier, is an out-of-band failure and never graceful proof.

### 7. ARQ, credits, and exact capacity semantics

#### 7.1 Independent data and control lanes

`PEER_RELIABLE_PACKET_V2` body is `routeId16 | laneSequence u64 | nestedLength u16 | flags u16 | completeNestedObjectN`, N=1..1,037. Flag bit0 is CONTROL; every other bit rejects. Data and control lanes have independent u64 sequences beginning0. The class-6 AD supplies the immutable `routeOwner`, `generation`, and `outerDirection`; wrapper `routeId` must equal AD `routeId`, and the AD circuit, generation, purpose, and direction must match that active owner before nested parsing. `nestedDigest=H("hyperdht-private-routes/m3/peer-reliable-nested-digest/v2",nestedBytes)`. Sequence identity is only `(routeOwner,generation,outerDirection,lane,laneSequence)`; digest is retained evidence, not part of the key.

Sender reservations are exactly24 data slots and8 control slots. Receiver windows are64 data and16 control. A sender assigns sequences from0 upward and closes the route before assigning `UINT64_MAX`; checked increment failure also closes it. A receiver admits a previously unseen DATA sequence only in its checked 64-entry horizon and a previously unseen CONTROL sequence only in its checked 16-entry horizon: when cumulative is `UINT64_MAX` the horizons are0..63 and0..15, otherwise they begin at checked `cumulative+1`. A new identity outside its lane horizon fails the route without retention or ACK. On a live purpose3 registration route, one control sender slot is exclusively reserved for its registration stream; other control objects use the remaining seven. Data never borrows control, and registration never borrows data. A DATA gap cannot block control-lane progress, but an earlier missing CONTROL sequence blocks the effect of later OPENED/CREDIT/FIN/CLOSE/RESET or registration REVOKE until that gap arrives or its bounded retry exhausts. Later in-horizon control objects may be authenticated, retained, and ACKed out of order; they do not mutate stream/semantic state before control contiguity. Prioritized control slots and retry reserves bound starvation but do not create a bypass. FIN still additionally waits for its asserted DATA sequence/offset.

`PEER_RELIABLE_ACK_V2` body64 is:

`routeId16 | generation u64 | dataCumulative u64 | dataBitmap u64 | controlCumulative u64 | controlBitmap u64 | ackSnapshot u32 | reservedZero u32`.

ACK `routeId/generation` must equal the class-6 AD and active owner before processing. `UINT64_MAX` means no contiguous packet in that lane; bitmap bit i then acknowledges sequence i. Otherwise bit i acknowledges checked `cumulative+1+i`. CONTROL bitmap bits16..63 are always zero. Decode old/new snapshots to absolute acknowledged sets only after proving every cumulative and set bitmap bit names an issued sequence no greater than that lane's retained highest-issued sequence; if no sequence was issued, the lane acknowledgement must be empty. An ACK that names an unissued/future sequence rejects and releases nothing. Cumulative may only advance, every old acknowledgement still within the new horizon must remain acknowledged after rebasing, and a retransmit slot is released only for its exact issued sequence identity. Raw bitmap integers may shift or clear. Same snapshot must be byte-identical; lower is stale. Snapshot wrap or checked absolute-sequence overflow closes the route.
Normal ARQ `ackSnapshot` starts1; zero is reserved exclusively for the two pre-ARQ purpose sentinels. The final ACK field is always zero.

ACK carries no free-capacity grant and no route-global credit epoch. CREDIT epoch is owned by one stream and one granted DATA direction as §7.2 defines. This prevents stale ACK snapshots or unrelated streams from minting capacity.

RTO is250ms, maximum eight sender attempts including first, no adaptive RTT. On the first admissible wrapper, the receiver atomically binds `(routeOwner,generation,outerDirection,lane,laneSequence)` to the exact wrapper bytes and retained nested digest before incrementing arrival count, enqueueing, or acknowledging it. An exact retry reuses that binding, cache entry, arrival/ACK bounds, and single eight-attempt sender counter. A changed wrapper under the same sequence key produces one scoped conflict outcome and no ACK, new cache, new budget, or counter reset: a safely identified stream spends its one pre-reserved conflict RESET; otherwise the route fails. ACK is immediate for an admitted gap, exact duplicate, control admission, or new contiguous state; otherwise coalesced no longer than25ms or8 packets. The receiver records only the first eight byte-identical physical arrivals for the bound key and emits at most one ACK attempt per recorded arrival; coalescing may reduce that count. Any further exact network duplicate is silently dropped with no ACK, route failure, counter change, cache change, or state mutation. A duplicate already durably admitted causes no second enqueue, credit, command, or semantic delivery.
Full reliable bytes live in sender slots until acknowledgement and in receiver reorder/ready slots until contiguous delivery; they are not retained forever. On delivery, the receiver records the full-wrapper digest `H("hyperdht-private-routes/m3/peer-reliable-wrapper-digest/v2",completeWrapper)` in its lane's fixed history row. Each 48-byte row is `laneSequence8 | wrapperDigest32 | arrivals1 | conflictRecorded1 | reserved6=0`; route owner, generation, direction, and lane are supplied by the row's owning fixed table. Keep the most recent64 contiguous DATA identities and16 contiguous CONTROL identities. While full bytes remain resident, compare them directly; after delivery, digest equality binds retries to those original complete bytes under the stated collision-resistance assumption. A digest mismatch never creates another identity or ACK allowance; if original stream scope is no longer retained, fail the route. Retained history preserves the original arrival count, including the eight-arrival ceiling. A sequence at or below cumulative but older than retained history is stale and is silently discarded without ACK, allocation, or state change; it is not a new out-of-horizon identity. Eviction occurs only when contiguous progress moves that sequence out of its fixed history range.

Reliable retry identity remains the sequence key above, its retained digest, and exact wrapper bytes. It may produce only the bounded current transport ACK and may resume a previously cached semantic response only while that original response remains unsettled and has an unused attempt. The response reuses its original packet and counter. Retry never invokes semantic allocation again and never creates a fresh reliable response sequence.

After a complete HANDSHAKE occurrence is first assigned its `common.position`, the transport retains the semantic duplicate key supplied by the semantic registry through stream tombstone or stored route `localDeadline`. The registry key includes its exact parent/stream identity and object-specific identity; canonical bytes are compared in full. Exactly one physical copy of each canonical semantic object is charged to the canonical-cache subledger of `admittedSemanticOwnedBytes` before acknowledgment. Authored response replay aliases that copy; duplicate-key, outcome, and response-reference fields are fixed scalar metadata and cannot hold another byte array. The same semantic occurrence at a new reliable lane sequence or later `common.position`, even with byte-identical canonical bytes, is a stream conflict. Transport invokes no semantic callback or response allocation and sends only the stream's pre-reserved conflict RESET. A changed duplicate follows the same bounded stream-conflict path when the stream is safely identifiable; an unscopable changed wrapper fails the route.

#### 7.2 Reciprocal lifetime cumulative credits

OPEN's `requestedDataFrames/requestedDataBytes` authenticate the ceiling only for the original OPEN sender's DATA direction. For every application direction, derive `Q_d` as the checked positive minimum of all named semantic, descriptor/registration, route-frame, and residual-ledger frame bounds, then derive `B_d = min(all named semantic, descriptor/registration, route-byte, storage-backed, and residual-ledger byte bounds, 977*Q_d)` with checked multiplication and require `B_d>=59`. The effective values must fit OPENED's existing u32 fields; widths do not change. An OPEN with positive data fields that cannot satisfy this relation rejects before stream allocation. OPENED body64 remains `common40 | openNonce16 | admittedDataFrames u32 | admittedDataBytes u32`; it is the one authenticated admission grant for the original OPEN sender's direction and never grants the OPEN receiver's reverse DATA. Before sending OPEN, the opener's semantic issuer creates a non-exportable reverse-receive admission bound to `(routeOwner,generation,purposeDigest,streamId,streamEpoch,openNonce,reverseDataDirection,wireExpiresAt,localDeadline)` and fixes reverse `Q_d/B_d` by the same minima. `wireExpiresAt` is the authenticated Unix-millisecond authority bound; `localDeadline` is the stored monotonic timer bound. Neither may be refreshed on replay. The peer cannot select or increase either limit and learns only cumulative spendable subsets through authenticated CREDIT. CONTROL_ACTIVE uses its exact OPEN handshake allowance and zero data fields.

CREDIT body60 is `common40 | cumulativeGrantedFrames u64 | cumulativeGrantedBytes u64 | creditEpoch u32`. `common.direction` names the DATA direction being granted, while the CREDIT object travels in the opposite physical direction from the receiver that owns that capacity. Credit state is keyed exactly by `(routeOwner,generation,streamId,streamEpoch,grantedDataDirection)`. Each of the two owners starts at epoch1 independently. The next accepted epoch must equal previous+1; lower is stale, a jump or wrap closes the stream, exact duplicate bytes are idempotent, and changed reuse resets only that stream. Cumulative frames/bytes never decrease and cannot exceed that direction's admitted `Q_d/B_d`. No ACK, OPENED replay, or opposite-direction CREDIT modifies this state.

OPENED alone therefore leaves reciprocal startup incomplete. The route pair must durably authenticate two distinct initial CREDIT objects: one granting FORWARD DATA and one granting REVERSE DATA. Each endpoint sends the CREDIT backed by its receive capacity, receives the opposite-direction CREDIT that authorizes its own sender, and waits for reliable acknowledgment of the CREDIT it sent; only then may either endpoint start SecretStream or emit its header. Each initial grant has epoch1, at least one frame, at least59 raw bytes, and no more than its independently admitted maximum. The grant for the original OPEN sender's direction must also be no larger than OPENED. The stream enters CREDIT_READY only after both obligations are retained.

For each application stream and DATA direction d, admission fixes the independent maxima `Q_d` and `B_d` above; both lifetime counters are checked before every DATA send and receive. For the local route owner receiving d, let initial frame window `W_d` satisfy `1 <= W_d <= min(24,Q_d,admittedReceiveFrames,floor(admittedReceiveBytes/977))`. Across all live streams in that one inbound outer direction, the owner also requires checked `sum(W_d)<=admittedReceiveFrames`, `977*sum(W_d)<=admittedReceiveBytes`, and `sum(W_d)<=24`; the accepted pair belongs only to that local owner and direction. The maximum number of CREDIT objects granting direction d is:

`G_d = 1 + (Q_d - W_d)`.

Before an initial or later CREDIT increase, the receiving local owner atomically reserves each newly granted full-frame slot in both its `admittedReceiveFrames` and `admittedReceiveBytes` subledgers. Before enqueueing any received DATA, it consumes one such frame slot and977 reserved bytes even for a short frame; lack of either reservation rejects before retention or ACK. A later CREDIT may be sent only after at least one complete DATA frame transfers out of that receive slot: into already reserved endpoint record capacity at an endpoint, or into the other leg's independently reserved sender slot at a bridge. It must increase cumulative frames by at least1, may aggregate several released frames, and may never exceed `Q_d/B_d`. The bridge never decrypts, owns an endpoint record buffer, or treats the opposite leg's receive window as reusable storage. No timer-only or byte-only CREDIT exists. Thus worst case is one replenishment per remaining frame, exactly bounded by `G_d`; all CREDIT retransmissions and ACK attempts are ordinary charged reliable traffic.

To avoid a byte-credit deadlock after all frame grants are issued, the grant rule is exact: `cumulativeGrantedBytes = min(B_d, 977*cumulativeGrantedFrames)` with checked arithmetic. Every outstanding frame reservation backs a full977-byte slot, including unused space in a short frame. The initial and every replenished `W_d` are bounded by that leg's accepted `admittedReceiveFrames` and `admittedReceiveBytes` as above. When a complete short frame transfers out of the reserved receive slot, its whole frame slot is released; unused bytes are not peer data and do not increment lifetime received-byte counters. Granting the final frame allowance therefore already grants the final byte allowance attainable under Q/B, without an unbudgeted byte-only CREDIT. If storage cannot back a complete additional slot, no replenishment is issued.

Sender eligibility is exactly:

`lifetimeSentFrames + nextFrameCount <= cumulativeGrantedFrames`

and

`lifetimeSentBytes + nextRawCiphertextBytes <= cumulativeGrantedBytes`.

ACK/retransmission does not change lifetime counters. Duplicate/stale CREDIT never grants twice. A private entry bridge reserves both route legs atomically in lexicographic `(routeId,streamId,direction)` order before either initial CREDIT. Each leg owns its accepted inbound receive-frame/byte reservation and its outbound sender reservation independently; neither can be reused by the other leg or direction. Endpoint record reservations remain owned only by source/destination controllers, never by entry. Each grant is bounded by registration/descriptor limits, authenticated route expiries, stored monotonic deadlines, and each leg's remaining frame/cell/byte ledger. Failure releases all partial reservations before any CREDIT.

#### 7.3 SecretStream framing and memory reservation

Existing SecretStream framing is preserved. The raw header is exactly59 bytes: a3-byte little-endian uint24 body length followed by32+24 header bytes. An application record body is `plaintextBytes+17`; raw length is `plaintextBytes+20`. The uint24 body ceiling remains16,777,215, so raw record maximum is16,777,218. V2 does not impose an arbitrary64KiB rejection because unchanged legacy compatibility uses the existing maximum.

Before reading or allocating a peer-sized record, an endpoint reserves a fixed3-byte prefix guard and reads exactly those3 bytes. Only then may it decode the little-endian uint24 length, validate header body56 or application body17..16,777,215, prove `body+3 <= 16,777,218`, and consume a pre-reserved record slot. No crypto parser receives bytes and no peer-sized allocation occurs before that check.

For every local endpoint/application stream, the semantic reservation accounts for two disjoint capacities: one pending outbound raw record up to16,777,218 bytes and one inbound assembly-or-retained-plaintext slot up to16,777,218, plus the3-byte prefix guard. The exact maximum is `2*16,777,218+3 = 33,554,439` bytes per local endpoint/application stream. The guarded adapter assembles a complete record and delivers it contiguously; SecretStream decrypts into a subarray of that same buffer. Inbound assembly and plaintext retention are exclusive phases of the same reservation, not simultaneous additional records. The adapter must not admit another inbound record while that slot's plaintext is retained. Any dependency path that copies instead must reserve that copy explicitly before use; this proposal does not silently count an unverified zero-copy path as implemented.

Facade destruction revokes pending work and releases its record/native references immediately. Its existing native error observer remains responsible until the owned SecretStream emits close, even when facade close happens first; native close then removes the remaining error/close observers. This preserves exactly-once failure reporting without a detached native error becoming unhandled. Publicly transferred plaintext backing is never reused or erased by this cleanup.

The framing evidence in `local://peer-stream-record-framing-check-results.txt` observed a1MiB application record,1,075 total977-byte chunks including the header, no plaintext at24 chunks, header raw59/body56, application raw1,048,596/body1,048,593, and raw maximum16,777,218. That proves dependency framing and pre-plaintext assembly/backpressure scope only; it is not a v2 ARQ/credit runtime proof.

Before route ACCEPT, reserve these byte-accounted transport buffers:

- sender retransmit: `32*1073 = 34,336`;
- data receive reorder: `64*1073 = 68,672`;
- control receive reorder: `16*1073 = 17,168`;
- lane tombstones: 80 entries ×48 =3,840;
- data-ready: `24*1037 = 24,888`;
- control-ready: `8*1037 = 8,296`.

Fixed ARQ buffer total is exactly157,200 bytes. Route admission also reserves `1073*M` bytes for one canonical semantic reassembly slot per lifetime stream, the local owner's accepted concurrent receive-window bytes, and the exact `admittedSemanticOwnedBytes`. The wire field at OFFER offset188 is `semanticOwnedBytes u32`; ACCEPT offset220 is `admittedSemanticOwnedBytes u32`. These names have no aliases and retain the existing widths and offsets.

`retainedCanonicalAndResponseCacheMaximum` retains one exact canonical semantic-wire copy of every object in the admitted lifetime profile through its stream tombstone or stored route deadline. An authored semantic response aliases that accounted canonical copy for replay; another response, transcript, or ciphertext copy must be named and added before OFFER. Reliable wrappers and transport OPEN/OPENED are excluded. The exact cache maxima are `C1(M)=9620*M`, `C2(M)=2049*M`, and `C3(M)=726+1921*(M-1)` for purpose3 `M>=1`: registration is486+144+96=726; private source is1297+752=2049; private destination is1393+528=1921; legacy is4807+4813=9620.

For each local route owner, define `localEndpointApplicationStreamCapacity` exactly: purpose1 source endpoint `M`, purpose1 legacy egress `0`; purpose2 source endpoint `M`, purpose2 entry `0`; purpose3 listener/destination endpoint `M-1`, purpose3 entry `0`. Define `localOwnerIsLegacyEgress` true only for the purpose1 terminal egress. Define `legacyNoiseScratchBytes = 8192*M` for every purpose1 local owner and zero otherwise, using checked arithmetic. Each purpose1 lifetime stream owns two disjoint4,096-byte contiguous raw-flight slots, one IK1 and one IK2, at both endpoint and egress. Buffers allocate lazily and erase after the final Noise consumer, but their reservation is not borrowed by canonical cache or another stream.
Define `privateConfirmationScratchBytes = 528*localEndpointApplicationStreamCapacity` for purpose2 source and purpose3 listener/destination owners, and zero for all other owners. Each private endpoint lifetime stream owns one disjoint528-byte arena with the exact layout and exclusive processing lifecycle specified in semantic §2.1. Entry has no endpoint confirmation keys and reserves no arena.

`requiredSemanticOwnedBytes = retainedCanonicalAndResponseCacheMaximum + 33554439*localEndpointApplicationStreamCapacity + (localOwnerIsLegacyEgress ? 16777280 : 0) + legacyNoiseScratchBytes + privateConfirmationScratchBytes`.

The exact owner floors are purpose1 source `33572251*M`, purpose1 egress `17812*M+16777280`, purpose2 source `33557016*M`, purpose2 entry `2049*M`, purpose3 listener `726+33556888*(M-1)`, and purpose3 entry `726+1921*(M-1)`. These endpoint-side floors still bound purpose1/2 to `M<=127` and purpose3 to `M<=128` before smaller advertisement, partition, or storage limits. The endpoint-record term owns one pending outbound maximum record, one inbound assembly-or-retained-plaintext maximum record, and its3-byte guard per endpoint application stream. Entry owns no endpoint record buffer.

Legacy canonical fragment caches contain envelope and fragment-metadata gaps, so neither contiguous4,096-byte raw flight may alias the9,620-byte canonical cache. Private IK1/IK2 raw flights are101/53-byte slices of their single canonical fragment payloads and alias those accounted bytes. Private confirmation, KDF, and MAC processing consumes canonical slices incrementally and may not allocate an uncharged concatenated transcript.

The legacy egress term is exactly one route-owner slot, never `M` slots. RESERVE must acquire it by exclusive atomic compare-and-swap before native contact; an occupied slot rejects with `quota=3`. Ownership moves from pre-OPEN ingress to accounted post-OPEN transfer without overlap, and successful transfer, rollback, timeout, RESET, or teardown releases it exactly once.

The accepted semantic-owned pool has disjoint non-borrowing subledgers for canonical/response caches, each endpoint record slot, each legacy stream's two-slot Noise scratch pair, each private endpoint's confirmation arena, and the one legacy pre-OPEN ingress slot. No byte may satisfy two subledgers, a receive window, ARQ, or reassembly. For the local owner, `admittedReceiveWindowBytes` is exactly its own accepted `admittedReceiveBytes`, charged once; the peer reserves a separate physical pool of the same negotiated maximum.

Transport OPEN96 and OPENED72 bytes are owned only by the fixed sender/reorder/ready ARQ slots. Sender bytes release on acknowledgement; receiver bytes release after contiguous delivery into installed stream state. Their full bytes are not retained in a lifetime cache: immutable parsed fields and digests remain in count-bounded scalar stream state, with settled retry recognition using the fixed48-byte history rows above. No replay may allocate or reconstruct another canonical copy. Thus the semantic pool deliberately remains726/2049/1921/9620 rather than mixed-pool822/2217/2089/9788.

With checked arithmetic for each local owner:

`requiredMaxQueuedBytes = 157200 + 1073*M + admittedReceiveBytes + admittedSemanticOwnedBytes`.

Before OFFER, evaluate the same formulas with the offered values: `M=maxStreams`, receive-window bytes=`receiveBytes`, and semantic-owned bytes=`semanticOwnedBytes`; require `semanticOwnedBytes>=requiredSemanticOwnedBytes` and `maxQueuedBytes>=157200+1073*maxStreams+receiveBytes+semanticOwnedBytes`. Before ACCEPT, terminal evaluates the admitted values against its own role-specific floors; after ACCEPT, source rechecks those admitted values against its own floors before its sentinel. Each side reserves the full accepted capacities in its pending-purpose owner even when its role-specific floor is smaller. Overflow, an admitted value below either local floor, or any result above OFFER/advertisement/local storage rejects before OPEN, CREDIT, DATA, semantic allocation, or crypto-parser allocation. Fixed metadata maps are pre-sized by admitted stream/window counts and hold no peer-sized byte arrays outside these equations.

### 8. Exact cells, bytes, commands, and profile totals

#### 8.1 Charge rules and disjoint reserves

Every physical send attempt charges one directional cell and1,200 bytes before send. Failed/uncertain sends remain charged. Receive counters never claim remote lost attempts.

One reliable packet permits eight attempts. Every attempt may elicit one ACK attempt in the opposite direction. If `F` reliable packets originate physical-forward and `R` physical-reverse, ordinary reliable work costs `8*(F+R)` cells in each physical direction. `F/R` include every admitted DATA, CREDIT, FIN, and semantic packet.

Each route direction separately adds:

- purpose OFFER forward or ACCEPT/REJECT reverse:8;
- source sentinel forward or terminal sentinel reverse:8;
- unwrapped route CLOSE forward or exact route CLOSE_ACK reverse:8;
- physical branch closure by DESTROY or TEARDOWN/ACK: one shared10-cell partition per admitted branch and adjacency direction;
- per admitted stream:8 attempts for a local CLOSE/RESET plus8 attempts to ACK an opposite-direction CLOSE/RESET, hence16 cells per direction per stream.

These partitions are disjoint. Route close is exactly8 cells per direction and is legal only after every lifetime-admitted stream is CLOSED/tombstoned and both ARQ lanes have no non-route-close packet in flight. Each admitted branch owns exactly10 physical-closure cells per adjacency direction. Physical-loss DESTROY uses at most8 of them; intentional TEARDOWN/ACK uses at most10. Selecting either mode excludes the other, unused cells are not borrowed, and shared links sum the partition per admitted branch. Each lifetime-admitted stream has at most one locally originated terminal CLOSE-or-RESET per endpoint; an exact opposing closure after the first stream tombstone is ACKed without another semantic revocation. Consequently all lifetime stream failures remain bounded by16 cells per physical direction per admitted stream. Successful streams use FIN and leave their forced-close reserve unused.

Each authenticated direction reserves `M+2` control commands for lifetime `M=admittedMaxStreams`: at most one first stream-close transition per lifetime-admitted stream, one route-close/tombstone transition, and one physical branch-closure/tombstone transition. Commands otherwise increment once on first authenticated state allocation. Exact replay, CREDIT update, or forwarding does not add a command. The semantic profile's `C_f/C_r` includes OPEN where applicable; transport adds purpose OFFER allocation at terminal, LINK/EXTEND allocations at their actual owner, and the `M+2` control term.

#### 8.2 Setup sends per adjacency

Every listed setup object reserves eight attempts. Routed discovery objects traverse every established predecessor adjacency.

| local directional sender |                                                                                                           Setup attempts S | Allocation commands at that owner |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------: | --------------------------------: |
| A0 source forward        |                        LINK_OFFER8 + DISCOVER_REQUEST1 8 + EXTEND_REQUEST1 8 + DISCOVER_REQUEST2 8 + EXTEND_REQUEST2 8 =40 |        one local link/route owner |
| A0 guard reverse         | LINK_ACCEPT8 + DISCOVER_RESPONSE1 8 + EXTENDED1 8 + TAIL_READY1 8 + DISCOVER_RESPONSE2 8 + EXTENDED2 8 + TAIL_READY2 8 =56 |          A0 link accept + EXTEND1 |
| A1 guard forward         |                                    successor LINK_OFFER8 + forwarded DISCOVER_REQUEST2 8 + forwarded EXTEND_REQUEST2 8 =24 |                     A1 link owner |
| A1 safety reverse        |                            LINK_ACCEPT8 + TAIL_READY1 8 + DISCOVER_RESPONSE2 8 + EXTENDED2 8 + forwarded TAIL_READY2 8 =40 |          A1 link accept + EXTEND2 |
| A2 safety forward        |                                                                                                   successor LINK_OFFER8 =8 |                     A2 link owner |
| A2 terminal reverse      |                                                                                           LINK_ACCEPT8 + TAIL_READY2 8 =16 |                    A2 link accept |

Direct discovery D0/D1/D2 adds24 sends in each direction of each direct bootstrap pair, as §3.3 specifies. Phase0 keeps no responder state and each received valid packet permits one COOKIE_CHALLENGE send. A candidate responder charges one bootstrap command only when a verified phase1 cookie creates a LIVE row in the pre-reserved256-row pool; LIVE-to-SPENT and candidate publication are not second allocations.

#### 8.3 Per-adjacency algebra

Let `P_f/P_r` be exact semantic/control reliable packets before post-OPEN DATA/CREDIT/FIN. For each admitted application stream s, let `Q_{s,f}/Q_{s,r}` be independent DATA-frame maxima and `G_{s,f}/G_{s,r}` the §7.2 maxima for CREDIT objects granting those DATA directions. A CREDIT granting forward DATA travels reverse, and vice versa:

`F = P_f + sum_s(Q_{s,f} + G_{s,r} + 1_FIN_f)`

`R = P_r + sum_s(Q_{s,r} + G_{s,f} + 1_FIN_r)`

`N = F+R`.

Registration control contributes no DATA, CREDIT, or FIN. `N` excludes per-stream CLOSE/RESET and their ACK attempts, both purpose sentinels, purpose OFFER/ACCEPT, unwrapped route close/ACK, and mutually exclusive physical DESTROY-or-TEARDOWN work because those have disjoint fixed reserves. For adjacency Ai with setup attempts `Sif/Sir` from §8.2 and lifetime `M=admittedMaxStreams`:

`Ai.forwardCells = Sif + 8*N + 16*M + 34`

`Ai.reverseCells = Sir + 8*N + 16*M + 34`.

The `8*N` term includes every reliable send's eight attempts plus the opposite direction's eight possible ACK attempts. `16*M` is the two-endpoint forced-close/ACK bound for every stream accepted during the route lifetime. `34=8 purpose +8 sentinel +8 route-close-or-ACK +10 mutually-exclusive physical DESTROY-or-TEARDOWN/ACK`. Bytes are exactly `1200*cells`; each local owner authenticates and reserves its own outgoing row.

Across all three adjacencies the route ledger is `184 setup + 204 fixed + 48*N reliable + 96*M lifetime-stream-close = 388 + 48*N + 96*M` cells. Adding D0/D1/D2 direct discovery gives `532 + 48*N + 96*M` total cells and exactly1,200 times that many bytes. The numeric totals do not change when physical-loss DESTROY replaces intentional TEARDOWN because both modes spend the same existing10-cell partition and cannot coexist.

This total includes circuit work and D0/D1/D2 only. Native guard bootstrap and relay-neighbor provisioning/maintenance are independently bounded and charged under §3.4; native evidence must report them separately and include them in total observed node traffic.

Directional commands are:

`directionCommands = setupAllocationsAtOwner + semanticAllocationsTerminatingHere + purposeOfferAllocationIfTerminal + lifetimeM + 2`.

A route rejects before OFFER/ACCEPT if any directional row's cells, bytes, commands, lifetime stream count, record reservation, or queue bytes exceeds its signed advertisement or local remaining reservation.

#### 8.4 Semantic profiles, DATA frames, CREDIT, and exact baselines

Authoritative semantic packet and cache inputs are semantic §§8.2 and9.1–9.4. Purpose3 physical direction matches that contract: destination→entry is FORWARD with four packets; entry→destination is REVERSE with five.

| Profile                                      | Semantic P_f | Semantic P_r | Semantic commands C_f/C_r | Notes                                                                                    |
| -------------------------------------------- | -----------: | -----------: | ------------------------: | ---------------------------------------------------------------------------------------- |
| purpose3 registration lifetime               |            3 |            1 |                       2/0 | OPEN+REGISTER+later REVOKE forward; REGISTERED reverse; no OPENED/FIN/DATA/CREDIT        |
| purpose2 private source leg                  |            5 |            5 |                       2/0 | OPEN and ACTIVATE allocate forward                                                       |
| purpose3 private destination application leg |            4 |            5 |                       0/2 | IK2,READY,ACCEPTED,OPENED forward; incoming OPEN,ACTIVATE,IK1,ACK,PRIVATE_OPEN reverse   |
| purpose1 legacy maximum                      |           13 |           13 |                       3/0 | OPEN, RESOLVE, RESERVE allocate forward; nine HANDSHAKE packets per maximum Noise flight |

An application admission floor is not a zero-wire operation. Even with zero application plaintext, existing SecretStream emits one59-byte header in each direction. Each header consumes one DATA frame/59 raw bytes; reciprocal startup consumes one initial CREDIT in each direction; graceful completion consumes one FIN in each direction. Thus a one-stream zero-application-byte baseline adds exactly three reliable packets per direction and six to N. It is only the minimum application envelope; a general admission must use the admitted `Q/G/B` maxima below.

The exact admission-budget floors, including worst-case retries/ACKs, both directional lifetime-stream forced-close reserves, route close, mutually exclusive physical branch closure, setup, and direct discovery, are:

| Admitted route profile                                                 |   N | Lifetime M | Route adjacency cells | Direct discovery cells | Total cells | Total bytes |
| ---------------------------------------------------------------------- | --: | ---------: | --------------------: | ---------------------: | ----------: | ----------: |
| purpose3 registration only                                             |   4 |          1 |                   676 |                    144 |         820 |     984,000 |
| purpose2 private source, one application, zero plaintext               |  16 |          1 |                 1,252 |                    144 |       1,396 |   1,675,200 |
| purpose3 registration plus one destination application, zero plaintext |  19 |          2 |                 1,492 |                    144 |       1,636 |   1,963,200 |
| purpose1 legacy maximum handshake plus one application, zero plaintext |  32 |          1 |                 2,020 |                    144 |       2,164 |   2,596,800 |

For the legacy row the local-owner distribution is source370, guard740, safety708, terminal346 cells; sum2,164. Direct D0/D1/D2 sends remain owned by their actual local senders.

For general admission, `Q_f/Q_r` are independent directional DATA-frame maxima. For each direction, compute `frameByteCeiling=977*Q_d` with checked arithmetic and set `B_d` to the exact minimum of every named semantic, descriptor/registration, route, storage-backed, and residual-ledger byte bound plus `frameByteCeiling`; require `Q_d>=1` and `B_d>=59`. Every nonempty DATA uses one frame and1..977 bytes, total frames never exceed Q, and total raw bytes never exceed B. `ceil(B_d/977)<=Q_d` is guaranteed but is only best-packing feasibility, never the worst-case frame demand; one-byte adversarial frames may consume all Q. No individual record may exceed16,777,218.

For a single application stream, add admitted DATA and bounded CREDIT traffic through:

`N = P_f+P_r + Q_f+Q_r + G_f+G_r + 2_FIN`,

where `G_d=1+(Q_d-W_d)` and CREDIT granting d travels opposite d. For multiple streams sum each stream's terms and count every accepted stream against lifetimeM, including streams already closed. Every DATA/CREDIT attempt and every ACK attempt is already charged by `8*N`; no dynamic control traffic exists outside this bound. A zero-plaintext baseline sets `Q_f=Q_r=W_f=W_r=1`, hence `G_f=G_r=1`.

OFFER must carry at least these exact directional rows and cannot infer one shared scalar is independently spendable in both directions. ACCEPT authenticates downward per-direction cells/bytes/commands/frame maxima plus symmetric per-owner receive and semantic-owned maxima; each physical owner separately reserves and checks its accepted values.

### 9. Failure, replay, and teardown

Route states are `CANDIDATE -> CIRCUIT_BUILDING -> FINAL_EXIT_READY -> PURPOSE_CONFIRMING -> ACTIVE -> DRAINING -> CLOSED`, or FAILED. Stream states are class-specific as §6 defines.

Exact reliable retry of OFFER, sentinel, OPEN, HANDSHAKE, DATA, CREDIT, FIN, CLOSE, RESET, or discovery request reuses its original bytes, identity, lane sequence where present, cache entry, and single attempt counter. It may trigger only the cached result's remaining original attempt or a bounded transport ACK; it never creates a fresh reliable packet, semantic occurrence, allocation, command, credit, or candidate. A semantic occurrence repeated at a new lane sequence or later semantic position is a bounded stream conflict and emits only that admitted stream's reserved conflict RESET. Reused identity with changed bytes fails the narrowest authenticated owner: a safely identified stream resets; invalid outer route authentication, an unknown stream that cannot be safely scoped, route counter failure, stream admission beyond lifetimeM, or route-ledger exhaustion fails the route. Stream tombstones persist no later than stored route `localDeadline` and are bounded by lifetime admittedMaxStreams; lane tombstones are fixed by receive windows.
For finalization, “original bytes” means the cached canonical object, not the class-5 ciphertext wrapper. The fresh outer AEAD counter rule in §5.1 never resets the original capped attempt counter or its stored deadline.

A private semantic authentication/session failure atomically revokes exactly that session's two bridge reservations before its stream CLOSE/RESET, then rejects that session's waiters and clears its queues/reassembly/caches/secrets. It never revokes listener registration or a shared surviving route. Registration revoke, reaching its stored registration `localDeadline`, or control reset follows semantic §5.3 and revokes the registration plus all sessions dependent on it. Reaching route `localDeadline`, route loss/rotation, guard loss, suspend/network change, route ARQ exhaustion, route-ledger failure, or route owner/generation mismatch revokes every session using that route and begins charged route teardown. A physical adjacency loss instead spends the affected branch's DESTROY mode before removing that branch. In both cases a counterpart route or sibling branch with its own live owner/generation survives.

Control is independent of DATA, not of itself. RESET, CLOSE, CREDIT, FIN, and REVOKE can progress despite a DATA gap, but an earlier missing CONTROL sequence delays their state effect until retransmission fills the gap or bounded exhaustion fails the route. Per-stream close traffic consumes only its admitted16-cell-per-direction reserve. Unwrapped route close consumes only its8-cell-per-direction reserve after all lifetime streams are tombstoned. Each admitted branch's mutually exclusive DESTROY-or-TEARDOWN physical closure consumes only its10-cell-per-adjacency-direction partition. Exhaustion destroys only the corresponding local owner; shared physical links preserve sibling branch and route authorities, no partition is borrowed, and no cross-generation transfer or fallback occurs.

### 10. Implementation contract and remaining runtime proof

1. Main must integrate a parallel v2 registry and contexts; v1 constants, masks, object decoders, bootstrap IDs, public APIs, and the existing16,777,218-byte raw SecretStream record maximum remain unchanged.
2. Direct wrappers use magic0xd301. ACTIVE_RESPONSE body/wire are240/312 with no duplicate identity field; its proof prefix is body bytes0..207 and its signature commits bodyBytes240.
3. The requester state machine is `PHASE0 -> COOKIE_FROZEN -> CAPS_FROZEN -> ACTIVE_FROZEN -> COMPLETE/FAILED`; first-valid transitions freeze one byte string, counter, expiry projection, and timer train, and later responses cannot restart them. The responder uses the fixed256-row,8-per-endpoint,680,000-byte startup pool and commits LIVE-to-SPENT, challenge digest, cached ACTIVE_RESPONSE, counter, deadline, and `candidatePublished=false` before attempt one.
4. Finalization class5 uses only the38-byte tail-known AD; active class6 uses the55-byte route/purpose AD after authenticated OFFER/ACCEPT. No hidden earlier routeId/purpose publication is permitted.
5. The common KDF always returns independent out32 label outputs. Each pre-MAC key is first16 of its own out32 result; `MAC16` remains keyed BLAKE2b out16.
6. Authenticated ACCEPT derives the child route clock tuple once: `wireExpiresAt=ACCEPT.expiresAt`, paired local `wallNow`/`monotonicNow`, and `localDeadline=min(parentLocalDeadline,projectedRouteDeadline)`. Active transport exports only that child tuple. No serialized field or peer input carries a monotonic time, and replay never refreshes either bound.
7. `admittedMaxStreams` is a lifetime accepted-stream cap with fixed purpose partitions: purpose1/2 initiatorM and terminal0; purpose3 initiator1 registration and terminal `M-1` applications. It is never refunded. Tombstones, semantic reassembly, `16*M`, `M+2`, and route profile totals all use that lifetimeM.
8. Registration control is semanticClass1, remains CONTROL_ACTIVE, emits no OPENED/DATA/CREDIT, accepts REGISTER/REGISTERED/REVOKE via HANDSHAKE for route lifetime, and closes only through stream-scoped transport CLOSE/RESET. Application is semanticClass2.
9. Purpose3 incoming streams use terminal-even IDs. Entry→destination OPEN/ACTIVATE/IK1/ACK/PRIVATE_OPEN and application traffic are physical REVERSE; destination→entry IK2/READY/ACCEPTED/OPENED and replies are physical FORWARD.
10. Every application startup authenticates initial CREDIT in both directions before either59-byte header. Each local owner reserves accepted `admittedReceiveFrames/admittedReceiveBytes` for its one inbound outer direction; a bridge owns separate non-borrowing windows per leg and no endpoint record buffer.
11. Admission derives `B_d=min(all named byte bounds,977*Q_d)` with checked arithmetic and requires `B_d>=59`. It independently bounds DATA frames, raw bytes, CREDIT messages, receive windows, semantic-owned memory, lifetime stream-close work, route close, and mutually exclusive DESTROY-or-TEARDOWN closure.
12. Reliable sequence identity excludes nested digest: first admission binds `(routeOwner,generation,outerDirection,lane,laneSequence)` to exact bytes and digest. DATA/CONTROL horizons are64/16, future or unissued ACK claims release nothing, changed bytes receive no ACK or rebudget, and an exact retry reuses its one counter.
13. Pending-purpose owners exist before source OFFER and terminal ACCEPT, hold complete accepted reservations, and transfer atomically on their respective sentinel success; no sentinel reacquires memory. Per-session semantic failure revokes only that session's two bridge reservations and stream. Registration loss cascades its sessions; route and branch loss preserve independently owned counterparts.
14. Main's independent arithmetic checks cover the OPEN rows `2/582+1/144`, `4/1297+4/752`, `4/1393+3/528`, and `12/4807+12/4813`; semantic caches726/2049/1921/9620; purpose1 scratch `8192*M`; owner floors and u32 limits in §7.3; fixed ARQ157,200; endpoint record33,554,439; legacy singleton16,777,280; route totals820/1396/1636/2164; and `B_d<=977*Q_d`. Actual Node24/Sodium incremental KDF and receipt-MAC results match the retained vector and reject its changed nonce. These are construction checks only. Runtime acceptance still requires requester freeze, responder pre-send SPENT, exact expiry reuse, sequence horizons/unsent-ACK rejection, OPEN causality, direction equality, pending-owner transfer, independent receive windows, and singleton legacy ingress in the implemented owners.
15. `local://peer-stream-record-framing-check-results.txt` proves only existing framing, a1MiB record split across1,075 chunks, no plaintext at24 chunks, and the16,777,218-byte raw maximum. It is scope evidence, not v2 runtime proof. Unchanged-server probes prove full-duplex data, both closes, and one-sided EOF with reverse continuation at the native legacy boundary, not M3 privacy, ARQ, credit, or simultaneous half-close convergence.
16. Semantic and transport reserve terminology remains aligned: stream forced-close/ACK is16 cells per direction per lifetime-admitted stream; unwrapped route close is a separate8 cells per direction; branch physical closure is one mutually exclusive10-cell DESTROY-or-TEARDOWN partition per adjacency direction. Whole-route totals are checked design budgets, not ratified runtime behavior; actual owner/ledger enforcement remains a separate acceptance gate.

The object IDs, purpose values, branch/role scalars, semanticClass values, and semantic ID range remain unchanged. Ratification and every runtime proof above remain Main's integration verdict.

## Semantic specification

Section numbers in this part are local to this specification.

### 1. Accepted transport boundary

This slice consumes the transport contract without redefining it:

- Semantic IDs are `0x0340..0x03bf` under the separate M3 v2 envelope `u32be version=2 | u16be id | u16be bodyBytes | body | registered suffix`.
- Advertisement is exactly `PEER_CAPABILITY_ADVERTISEMENT_V2`, 188-byte body, 64-byte signature, 260-byte wire, `policyCount=0`, version `2/2`, mask 9 for safety or 11 for terminal. No 388-byte form exists here.
- Purpose is exactly 1 `LEGACY_PEER_EGRESS`, 2 `PRIVATE_PEER_SOURCE`, or 3 `PRIVATE_PEER_DESTINATION`.
- Before application OPENED, canonical semantic objects use `PEER_HANDSHAKE_V2`, at most 981 semantic-object bytes per transport fragment. After OPENED, `PEER_DATA_V2` carries only raw SecretStream ciphertext, at most 977 bytes, with continuous per-direction `u64` offsets.
- A semantic Noise fragment carries at most 1,002 ciphertext bytes. Its largest canonical wire is 1,073 bytes and becomes exactly two HANDSHAKE fragments, 981 and 92.
- Transport owns disjoint reserves:16 cells per direction per admitted stream for forced CLOSE/RESET and opposite closure ACK work,8 cells per direction for unwrapped route close/ACK, and10 attempts per physical adjacency direction for teardown. Bootstrap, purpose OFFER/ACCEPT, two purpose-key sentinel confirmations, DATA/CREDIT/FIN, retransmissions, ACKs, and per-hop charges are also transport-owned. Section 9 supplies exact semantic ordered objects, packet counts, and semantic allocation commands for transport's algebra. Transport `admittedMaxStreams=M` is a lifetime accepted-stream cap, includes the purpose-3 registration stream, is never refunded on close/reset, and bounds both accepted stream identities and tombstones.
- Listener control remains distinct from application DATA as specified in §5. No DHT query-pair lease, public lookup/findPeer/raw query, caller socket, direct fallback, fourth role, or route-generation transfer is authorized.

Source geometry: `lib/private/protocol.js:383-430`; live route payload ceiling `lib/private/relay-capability.js:537-542`; route payload context `lib/private/live-route-authority.js:557-566`; route ownership `lib/private/live-route-authority.js:302-305` and `lib/private/route-manager.js:796-803`.

### 2. Common authentication and KDF

All scalars are unsigned fixed-width big-endian. Zero random identifiers/nonces/tokens reject. No optionals, implicit defaults, sentinels, or trailing bytes. Decoders copy retained fields before allocation.

`H(D,X) = cryptoSuite.hash([u16be(UTF8(D).length) || UTF8(D), X])`, exactly 32 bytes. This is the source pattern at `lib/private/guard-link.js:479-480`.

Every route-local semantic object has a zero-byte suffix. Its first authenticator is the containing purpose-bound route AEAD and reliable sequence. It is invalid off that exact route owner/generation/direction. Entry owns both route-leg AEAD contexts but never endpoint Noise or SecretStream keys.

#### 2.1 Private confirmation keys

`NoiseWrap.final()` returns `tx`, `rx`, and `hash`; initiator tx equals responder rx, responder tx equals initiator rx, and hash matches (`lib/noise-wrap.js:33-49`). Main measured the constrained existing payload `{error:0,firewall:0,secretStream:{}}`: IK1=101, IK2=53, no UDX/holepunch/address/relay fields, reciprocal keys/hash, and expected identities (`local://peer-stream-prerequisite-check-results.txt:1-5`). No new private payload codec or fake UDX ID is proposed.

For direction key `Kdir32`, literal label `L`, completed Noise hash `Nh64`, session ID `Sid16`, source purpose digest `Sp32`, destination purpose digest `Dp32`, and descriptor registration commitment `Rc32`: actual `NoiseWrap.final()` returns a 64-byte hash and 32-byte direction keys. Main's first constructor probe rejected the draft's incorrect 144-byte context; use the full hash, never an implicit truncation.

```text
context = Nh64 || Sid16 || Sp32 || Dp32 || Rc32              // 176 bytes
input   = u16be(len(L)) || UTF8(L) || u32be(2) ||
          u32be(176) || context
Kconfirm = sodium.crypto_generichash(out32, input, Kdir32)
```

`KCONF(Kdir,L,Nh,Sid,Sp,Dp,Rc)` is the function that returns `Kconfirm` from exactly that construction, with input widths 32, variable literal label, 64, 16, 32, 32, and 32 respectively. It performs no hash truncation, coercion, normalization, or implicit domain prefix.

This is the keyed BLAKE2b KDF shape used at `lib/private/crypto-suite.js:151-173`. Low/missing/wrong-length inputs reject. Native Sodium and independent Python `hashlib.blake2b` produced identical READY, ACK, and ACCEPTED keys/tags with the 176-byte context; the synthetic canonical transcript lengths were 1,046, 1,339, and 1,361 bytes (`local://peer-stream-confirmation-check-results.txt`; `local://peer-stream-confirmation-vectors.json`). Those vectors cover the first three confirmation steps only. The exact RECEIPT transcript below is 1,489 bytes and its `CONFIRM` hash input is 1,493 bytes including the u32 length. Literal labels:

- `hyperdht-private-routes/peer/private-ready-confirmation-key/v2`
- `hyperdht-private-routes/peer/private-ack-confirmation-key/v2`
- `hyperdht-private-routes/peer/private-accepted-confirmation-key/v2`
- `hyperdht-private-routes/peer/private-receipt-confirmation-key/v2`

READY and ACCEPTED use responder tx / initiator rx. ACK and RECEIPT use initiator tx / responder rx.

Main's fourth vector agrees between Python BLAKE2b and native Node24/Sodium for the RECEIPT key and MAC. Negative fixtures reject an unkeyed substitute, changed receipt nonce, and changed purpose digest (`local://peer-stream-receipt-vector.json`, `local://peer-stream-receipt-check-results.txt`). This uses synthetic canonical layout bytes with a directional key from the completed Noise experiment; it does not prove production decoding, state transitions, or privacy.

For cumulative canonical bytes `X`:

`CONFIRM(K,X) = sodium.crypto_generichash(out32, u32be(X.length) || X, K32)`.

`X.length` must equal the named concatenation and fit u32. Derive a confirmation key only after `NoiseWrap.final()` succeeds, use it for one canonical MAC or verification, then erase it. Retain canonical Noise ciphertext flights and semantic objects through their last confirmation consumer: RECEIPT creation at source and RECEIPT verification at destination. After authenticated OPEN, erase confirmation keys and redundant transcript-construction/plaintext scratch, but retain the already-budgeted full canonical retry/duplicate caches required by §8. Do not replace those caches with digest-only equality or allocate a second transcript copy for retention. Final Noise material transfers once to SecretStream; entry receives none.

Each private endpoint lifetime stream pre-reserves exactly528 bytes of additional confirmation scratch before its route OFFER/ACCEPT: `hashState384@0 | confirmationKey32@384 | computedTag32@416 | framing80@448`. The longest KCONF framing prefix is75 bytes (the65-byte ACCEPTED label plus ten scalar bytes); unused framing bytes are zero. CONFIRM reuses the first4 framing bytes for X.length. The state size must equal the pinned Sodium backend's384 bytes; a different backend size rejects integration until the explicit reservation is revised. Completed Noise tx/rx/hash remain in their existing endpoint Noise owner; canonical context fields and transcript parts are read-only views of already-owned bytes, not copies into another buffer.

The arena has one exclusive synchronous consumer per stream, acquired before any KCONF/CONFIRM processing. KCONF writes its result into confirmationKey32, then reinitializes the same hashState384 for CONFIRM, whose output goes to computedTag32. Verification compares that slot against the canonical received tag; authorship copies it into the already-reserved canonical response field. All four keys are derived just in time, never retained together. No asynchronous yield, user callback, second hash state, or reentrant use is permitted while the arena is held; exhaustion or reentrancy causes stream RESET `internal=8` without allocation. Success and every failure erase the entire arena before releasing its processing ownership. The reserved capacity remains exclusively charged to that lifetime stream until owner teardown and is never refunded by semantic replay or early completion. Different admitted streams may process concurrently only in their own arenas. Thus peak additional scratch is exactly528 bytes per private endpoint application capacity, zero at entry, with no uncharged concatenated KDF/MAC transcript.

#### 2.2 Wire expiry and local clocks

Every semantic issuer receives the transport-owned tuple `{wireExpiresAt,localDeadline,clockIdentity,wallNow,monotonicNow}`. Every serialized `expiresAtUnixMs` or `deadlineUnixMs` field is an unsigned u64 Unix epoch millisecond value. A local monotonic value is never serialized or compared with another host.

Here `parentWireExpiresAt=issuer.wireExpiresAt` and `parentLocalDeadline=issuer.localDeadline`; these are semantic-parent bounds from the accepted child route, not exports of the earlier tail-control parent.

On first admission of a wire expiry, take one fresh paired sample from the issuer's owned `wallNow` and `monotonicNow` functions under its `clockIdentity`. Require `sampledWall<wireExpiry<=parentWireExpiresAt`, compute `projected=sampledMonotonic+(wireExpiry-sampledWall)` with checked u64 arithmetic, and store `min(parentLocalDeadline,projected)`. A projection above the local parent deadline is clamped; a wire value above the authenticated parent wire bound rejects. Multiple authenticated bounds contribute the minimum of their first projections. Exact replay must match its stored wire value and reuse its stored projection, never sample again or refresh a timer. Clock identity mismatch, rollback under existing guards, overflow, expired wire time, or substituted parent authority fails closed.

All semantic timers, pair holds, idle checks, delayed callbacks, and tombstone retention use only stored local monotonic deadlines. Wire values remain in canonical commitments and are checked for downward equality or ordering where named. No host treats a peer's monotonic value as authority.

### 3. Canonical semantic registry

|         ID | Name                         | Sender -> receiver                  |     Body | Suffix |     Wire | HANDSHAKE fragments |
| ---------: | ---------------------------- | ----------------------------------- | -------: | -----: | -------: | ------------------: |
|       0340 | `PEER_DESCRIPTOR_V2`         | presence owner -> authorized reader |      511 |      0 |      519 |                   1 |
|       0341 | `LEGACY_RESOLVE_V2`          | endpoint -> egress                  |      104 |      0 |      112 |                   1 |
|       0342 | `LEGACY_RESOLVED_V2`         | egress -> endpoint                  |      106 |      0 |      114 |                   1 |
|       0343 | `LEGACY_RESERVE_V2`          | endpoint -> egress                  |       96 |      0 |      104 |                   1 |
|       0344 | `LEGACY_RESERVED_V2`         | egress -> endpoint                  |      132 |      0 |      140 |                   1 |
|       0345 | `PEER_NOISE_FRAGMENT_V2`     | endpoint/egress/entry forwarding    | 64..1065 |      0 | 72..1073 |              1 or 2 |
|       0346 | `LEGACY_HANDSHAKE_ACCEPT_V2` | endpoint -> egress                  |      132 |      0 |      140 |                   1 |
|       0347 | `LEGACY_OPEN_V2`             | egress -> endpoint                  |      100 |      0 |      108 |                   1 |
|       0348 | reserved                     | —                                   |        — |      — |        — |              reject |
|       0349 | `ENTRY_REGISTER_V2`          | listener -> entry                   |      478 |      0 |      486 |                   1 |
|       034a | `ENTRY_REGISTERED_V2`        | entry -> listener                   |      136 |      0 |      144 |                   1 |
|       034b | `ENTRY_REVOKE_V2`            | listener -> entry                   |       88 |      0 |       96 |                   1 |
|       0360 | `PRIVATE_ACTIVATE_V2`        | source -> entry -> destination      |      749 |      0 |      757 |                   1 |
|       0361 | `PRIVATE_READY_V2`           | destination -> entry -> source      |      220 |      0 |      228 |                   1 |
|       0362 | `PRIVATE_ACK_V2`             | source -> entry -> destination      |      232 |      0 |      240 |                   1 |
|       0363 | `PRIVATE_ACCEPTED_V2`        | destination -> entry -> source      |      168 |      0 |      176 |                   1 |
|       0364 | `PRIVATE_SOURCE_RECEIPT_V2`  | source -> entry                     |      120 |      0 |      128 |                   1 |
|       0365 | `PRIVATE_OPEN_V2`            | entry -> both endpoints             |      216 |      0 |      224 |                   1 |
| 0366..03bf | reserved                     | —                                   |        — |      — |        — |              reject |

Closure is exclusively transport `PEER_FIN_V2`, `PEER_CLOSE_V2`, and `PEER_RESET_V2`. Semantic ID 0348 is rejected. Semantic owner callbacks revoke token/bridge/UDX authority before transport closure callbacks run.

### 4. Noise fragment and compatibility bound

`PEER_NOISE_FRAGMENT_V2` body:

| Offset | Bytes | Field                                 |
| -----: | ----: | ------------------------------------- |
|      0 |    16 | sessionId                             |
|     16 |     1 | flight: 1 IK1, 2 IK2                  |
|     17 |    32 | `H(NOISE_DOMAIN,completeCiphertext)`  |
|     49 |     4 | total ciphertext bytes                |
|     53 |     2 | semantic fragment index               |
|     55 |     2 | count = `ceil(total/1002)`            |
|     57 |     4 | offset = `index*1002`                 |
|     61 |     2 | N, 1..1002; exactly 1002 except final |
|     63 |     N | ciphertext slice                      |

`NOISE_DOMAIN = hyperdht-private-routes/peer/noise-ciphertext/v2`.

`completeIK1` and `completeIK2` mean only the complete raw Noise ciphertext byte strings returned by the corresponding `NoiseWrap.send()` calls, before either fragmentation layer. Receive-side reconstruction concatenates ciphertext slices in increasing validated offsets and verifies the whole-ciphertext commitment before use. Neither value includes semantic envelopes, fragment metadata, transport wrappers, padding, a length prefix, or a digest in place of ciphertext. Private confirmation inputs contain exactly 101 IK1 bytes and 53 IK2 bytes. `H(IK1)` and `H(IK2)` are shorthand exclusively for `H(NOISE_DOMAIN, completeIK1)` and `H(NOISE_DOMAIN, completeIK2)`. `completeACTIVATE`, `completeREADY`, `completeACK`, and `completeACCEPTED` instead mean their entire canonical eight-byte semantic envelope plus body, including any MAC field inside that body and the registered zero-byte suffix. This distinction is deliberate: transport segmentation/retransmission never changes a confirmation transcript.

Legacy v2 deliberately supports at most 4,096 Noise ciphertext bytes per flight. This is a proposed profile compatibility bound, not a measured dependency maximum. It yields at most five semantic fragments: four data lengths 1,002 and one length 88. Their canonical wires are four 1,073-byte objects and one 159-byte object. Transport count is `4*2+1=9` HANDSHAKE packets per maximum flight. A larger unchanged reply is rejected and the logical stream resets; there is no direct fallback.

Private v2 requires the measured fixed profile: IK1 exactly 101 and IK2 exactly 53. Their fragment wires are 172 and 124, one HANDSHAKE packet each.

Before first fragment retention, reserve the exact complete ciphertext length, fragment count, semantic-object bytes, and transport frame/byte allowance. For each `(parent route owner,generation,streamId,streamEpoch,sessionId,flight)`, freeze exactly one `(wholeCiphertextCommitment,totalCiphertextBytes,fragmentCount)` before fragment-key lookup. A changed tuple, second concurrent commitment, overlap, gap, invalid offset/length, changed bytes for an occupied fragment index, or final commitment mismatch causes stream RESET `conflict=7` and erases the flight. An exact replay of the same original fragment occurrence is a no-op after reliable dedup and cannot create a new response sequence. Reassembled ciphertext transfers once into `NoiseWrap.recv()`; retain the owned canonical ciphertext required by §2.1 until its last confirmation consumer, then erase it.

### 5. Descriptor, registration, and listener control lifetime

#### 5.1 Descriptor

`PEER_DESCRIPTOR_V2` body, 511 bytes:

```text
kind u8 = 1
expectedDestinationNoiseKey32
entryIdentity32
advertisementLength u16 = 260
complete PEER_CAPABILITY_ADVERTISEMENT_V2[260]
destinationPurposeDigest32
destinationFinalTranscriptDigest32
destinationCircuitId16
destinationGeneration u64
entryEpoch u64
maxFrames u32
maxBytes u64
idleTimeoutMs u32
expiresAtUnixMs u64
admissionToken32
registrationCommitment32
```

Fixed before advertisement is 67; fixed after is 184; `67+260+184=511`, wire 519, below Gate D's 814-byte descriptor ceiling (`lib/private/blinded-presence.js:41-46`). Advertisement must be terminal mask 11, version 2/2, policy count zero, signer/epoch matching entry, unexpired, and otherwise pass the v2 validator. Its route-encryption setup key is not a generation key.

`registrationCommitment = H('hyperdht-private-routes/peer/entry-registration/v2', entryIdentity || expectedDestinationNoiseKey || destinationCircuitId || u64be(destinationGeneration) || destinationPurposeDigest || destinationFinalTranscriptDigest || u64be(entryEpoch) || u32be(maxFrames) || u64be(maxBytes) || u32be(idleTimeoutMs) || u64be(expiresAtUnixMs) || admissionToken || completeAdvertisement)`.

Gate D's mutable signature authenticates descriptor bytes only through verified resolution. `openPresenceRecord()` verifies before decrypt and binds revision (`lib/private/blinded-presence.js:542-618`); conflict/replay resolution is `:657-717`. Copied standalone bytes are unauthenticated. Reader compares `expectedDestinationNoiseKey` to its requested key before allocating a source route.

#### 5.2 Control stream

Purpose-3 route owns exactly one reserved registration-control stream. Its class is fixed `REGISTRATION_CONTROL=1` in `PEER_OPEN_V2.semanticClass`; application handshake class is 2. It transitions `IDLE -> CONTROL_OPEN -> CONTROL_ACTIVE -> CONTROL_CLOSING -> CLOSED`, never emits `PEER_OPENED_V2`, never grants DATA credit, and rejects DATA/FIN. It accepts only complete 0349/034a/034b objects inside reliable `PEER_HANDSHAKE_V2` for the route lifetime. Transport CLOSE/RESET ends it. Thus later REVOKE remains legal without creating an application duplex or abusing post-OPENED HANDSHAKE.

#### 5.3 Registration

Purpose-3 activation creates non-exportable `PrivateEntryRegistrationIssuer`, bound to route owner capability, routeId, circuitId, generation, purpose digest, final transcript digest, the §2.2 clock tuple and projected local route deadline, listener identity, entry identity/epoch, lifetime stream cap, and ledger.

`ENTRY_REGISTER_V2` body, 478 bytes:

`destinationNoiseKey32 | circuitId16 | generation8 | purposeDigest32 | finalTranscriptDigest32 | entryEpoch8 | maxFrames4 | maxBytes8 | idleMs4 | expiresAtUnixMs8 | adLength2=260 | advertisement260 | registerNonce32 | requestCommitment32`.

`requestCommitment = H('hyperdht-private-routes/peer/entry-register-request/v2', every preceding REGISTER body byte)`. Entry verifies exact purpose-3 route binding, advertisement, downward limits and wire expiry, nonce, commitment, lifetime stream capacity, ledger, and memory before token generation. It projects `expiresAtUnixMs` once under §2.2 and stores the resulting local registration deadline.

Entry samples a nonzero random 32-byte token. Within the authenticated entry service, `(entryIdentity,token)` must be absent from every LIVE registration row and every unexpired registration tombstone. After a colliding initial candidate it makes at most eight new samples; collision of the initial candidate and all eight resamples fails with RESET `internal=8`. It never replaces a row or tombstone. The unambiguous row key is `(entryIdentity,token,registrationCommitment)` and contains the exact descriptor fields, owner handle, register nonce, cached response, limits, expiry, and state LIVE; its service collision index retains `(entryIdentity,token)` through the same tombstone deadline.

`ENTRY_REGISTERED_V2` body, 136 bytes:

`registerNonce32 | token32 | registrationCommitment32 | circuitId16 | generation8 | expiresAtUnixMs8 | entryEpoch8`.

Listener verifies exact route/carrier, nonce, circuit/generation, wire expiry/epoch, and recomputed commitment before publishing. An exact replay at the original semantic position may only resume the cached original REGISTERED packet's remaining attempt counter. It never allocates a fresh reliable sequence or command. A repeated REGISTER at a later semantic position or the same nonce with changed canonical bytes causes bounded stream RESET `conflict=7`.

`ENTRY_REVOKE_V2` body, 88 bytes:

`token32 | registrationCommitment32 | circuitId16 | generation8`.

Only the bound listener issuer may submit a new REVOKE while the control stream is CONTROL_ACTIVE. The first valid occurrence records its complete canonical bytes, semantic position, reliable lane sequence, and terminal outcome before changing state. In CONTROL_CLOSING or CLOSED, the closing/tombstone cache may recognize only that exact original occurrence; it is a no-op that does not run revocation again, mint a response, renew a deadline, or alter the cached CLOSE attempt. A later-position/lane occurrence or changed duplicate causes RESET `conflict=7` while the transport stream remains live; after transport closure it is rejected as closed with no new packet. An unknown or mismatched token, commitment, or route binding on the authenticated live control stream causes generic RESET `authentication=2` without revealing token existence.

The first valid REVOKE atomically moves the control stream CONTROL_ACTIVE -> CONTROL_CLOSING and the registration LIVE -> REVOKING; removes registration lookup authority; installs TOMBSTONE; revokes every dependent bridge; then clears queues, waiters and token before callbacks or owner cleanup. Purpose-3 route loss/expiry/rotation, owner revocation, suspend/network change, entry advertisement expiry/epoch replacement, ledger failure, or registration-control reset enters the same registration teardown from its current live state. A valid listener REVOKE closes its registration-control stream without an error code and resets dependent application sessions with `revoked=6`. Registration expiry uses `idle=4` on the control stream and `revoked=6` on dependents; purpose-route loss uses `route-loss=5`. Tombstone key is `H('hyperdht-private-routes/peer/entry-registration-tombstone/v2',token||registrationCommitment)`. It retains that key, the service collision tuple `(entryIdentity,token)`, original route binding, original REVOKE bytes/position/lane when present, terminal result, cached CLOSE packet/counter, wire expiry, and stored local registration deadline through that deadline; it is bounded by the lifetime accepted-stream cap and never restores authority. A delayed REVOKE carries the fields needed to derive this key. A delayed REGISTER on a closed control owner is rejected, not answered from token lookup.

The entry deterministically links route generations and sees timing/volume. The authorized reader learns the signed entry address. Address knowledge, linkage, and direct-send authority are separate; no anonymity claim is made.

### 6. Unchanged legacy HyperDHT egress

#### 6.1 Proven compatible boundary

Main's network-isolated native probe used an unchanged HyperDHT Server with custom listen key, actual routed `_router.peerHandshake`, stock remote `blind-relay.Client`, exported pair/unpair codecs, real UDX, and source Noise/SecretStream with no source DHT/socket. IK1=175, IK2=125; 65,536 forward and 12,345 reverse bytes and both closes passed. The reply legitimately contained holepunch metadata and one address. Relay-control identity differed from application listen identity (`local://peer-stream-unchanged-legacy-check-results.txt:1-90`). The smaller boundary probe confirms the same single-egress pair exchange (`local://peer-stream-pair-boundary-check-results.txt:1-92`). Two further native runs proved one-sided EOF in each direction: the opposite side remained writable and delivered the exact remaining response after forward-first and reverse-first EOF (`local://peer-stream-legacy-half-close-check-results.txt:1-7`). These prove the unchanged legacy boundary and directional half-close behavior, not M3 transport, privacy, simultaneous end-event convergence, or ARQ behavior.

The egress service is not stock `BlindRelayServer`, does not use its private `_pairing` map, and does not need a new stock-server hook. It is a dedicated admitted single-egress Protomux service:

- Existing protocol literal `blind-relay`.
- Channel ID equals `controlSocket.remotePublicKey`, as exercised at proof lines 34-43.
- Existing exported `Relay.messages.pair` and `Relay.messages.unpair`; no new relay control codec.
- Egress pre-reserves one token row before returning LEGACY_RESERVED. No unreserved token can allocate.
- One real framed raw UDX stream owned by egress. Source owns only logical duplex and Noise/SecretStream.
- Incoming control connection is accepted only by the egress server listening under its authenticated advertised identity. The remote control identity is recorded for session binding but is not compared with expected application Noise identity: unchanged `server.js` may use its default DHT identity for `_relayConnection` even when application listen uses a custom key (`lib/server.js:646-666`; proof lines 67-68).

#### 6.2 Objects

`LEGACY_RESOLVE_V2` body, 104:

`sessionId16 | expectedNoiseKey32 | clientNonce32 | deadlineUnixMs8 | maxCandidates2 (1..8) | maxNoiseBytes2=4096 | requestedFrames4 | requestedBytes8`.

A purpose-1 `LegacyEgressAuthorityIssuer` is bound to route owner/purpose/final transcript, the §2.2 clock tuple and projected local route deadline, ledger, and the egress service's authenticated advertisement/listening identity. Egress first validates canonical widths, route owner/generation/purpose, nonzero session/nonce, future `deadlineUnixMs`, candidate bound, fixed Noise bound, and positive requested frame/byte limits. It projects the deadline once, then resolves the expected key through bounded existing DHT routing. It requires the router result later report `relayed=true` and returns no address/socket/referral authority.

`LEGACY_RESOLVED_V2` body, 106:

`sessionId16 | clientNonce32 | egressRef32 | candidateCount2 | expiresAtUnixMs8 | reservationNonce16`.

`candidateCount` must be `1..requestedMaxCandidates`. `expiresAtUnixMs` must be no later than the request deadline, route wire expiry, and service advertisement expiry. Source verifies exact session/client nonce, these bounds, and the nonzero reservation nonce before retaining the result. Egress samples a nonzero random `egressRef` bound to expected key, candidates, route owner/generation, request deadline, stored local deadline, and ledger. In the exact owner scope `(routeOwner,generation,purposeDigest)`, it checks the ref against all LIVE rows and unexpired tombstones. After a colliding initial candidate it makes at most eight new samples; collision of the initial candidate and all eight resamples fails with RESET `internal=8`. It never replaces a row or tombstone.

`LEGACY_RESERVE_V2` body, 96:

`sessionId16 | egressRef32 | reservationNonce16 | egressServiceIdentity32`.

Identity must equal the admitted terminal's authenticated advertisement/listening identity. Before native contact, egress validates the exact LIVE RESOLVED row, session/ref/reservation nonce/service identity, stored local deadline, lifetime stream capacity, ledger, and all record reservations. Expiry uses RESET `idle=4`; exhausted capacity within this admitted stream uses RESET `quota=3`; an authenticated changed binding uses RESET `conflict=7`; a wrong authenticated service or semantic binding uses RESET `authentication=2`. Invalid outer route authentication never reaches semantics and is handled by transport as route failure. The legacy egress route owner has one already-reserved 16,777,280-byte pre-OPEN ingress slot, partitioned as header59 + application record16,777,218 + next-prefix/surplus guard3. RESERVE must atomically acquire that slot from FREE to OWNED_BY_THIS_ROW before native contact; if another row owns it, this occurrence fails with RESET `quota=3` while the RESOLVED row and every native resource remain unconsumed. Only after acquisition does egress atomically consume RESOLVED -> RESERVED, transfer exclusive slot ownership to the row, admit raw-stream ownership, and create one real `dht.createRawStream({framed:true})`. Exact replay observes the same row ownership and never reacquires the slot. The row releases the slot exactly once after its held bytes transfer into accounted post-OPEN capacity or on any teardown; no other row may borrow any partition while it is owned. Egress requires the resulting UDX ID be a nonzero u32. It samples a nonzero random 32-byte `sessionCapability`. The lookup and collision domain is the authenticated egress service: `(egressServiceIdentity,sessionCapability)` must be absent from every LIVE token row and every unexpired token tombstone for that service. After a colliding initial candidate it makes at most eight new samples; collision of the initial candidate and all eight resamples fails with RESET `internal=8`. It never replaces a row or tombstone. It inserts the complete row under that service-and-token key before returning RESERVED. Any failure rolls back every partial row and native resource and releases an acquired pre-OPEN slot exactly once before a response or callback.

`LEGACY_RESERVED_V2` body, 132:

`sessionId16 | egressRef32 | reservationNonce16 | sessionCapability32 | egressRawUdxId4 | egressServiceIdentity32`.

Source accepts RESERVED only in the matching pending state and only after exact equality of `sessionId`, `egressRef`, `reservationNonce`, and admitted `egressServiceIdentity`; a nonzero `sessionCapability`; a nonzero u32 `egressRawUdxId`; and the previously checked `candidateCount` range. Malformed fields reject before Noise allocation. No RESERVED field supplies new address, socket, or referral authority.

Source authors IK1 with existing legacy codec: `error=NONE`, `firewall=UNKNOWN`, no source addresses, no holepunch, `udx={id:egressRawUdxId,seq:0,reusableSocket:false}`, `secretStream={}`, and `relayThrough={publicKey:egressServiceIdentity,token:sessionCapability}`. Existing order/codecs: `lib/connect.js:431-467`, `lib/messages.js:130-188`.

#### 6.3 Exact relay-control state

After egress forwards IK1 through `_router.peerHandshake`, it requires the returned router result have `relayed=true`; false/missing rejects. The unchanged server authors IK2 and starts its stock relay client early (`lib/server.js:395-412,646-670`). Its connection reaches the egress service. Egress opens the blind-relay channel and decodes only exported pair/unpair.

On pair message, before any new allocation:

1. Obtain `egressServiceIdentity` from the authenticated dedicated egress service that accepted this control connection, then require exactly one live row by `(egressServiceIdentity,sessionCapability)` lookup; `isInitiator=false`; `seq=0`; `id` is a nonzero u32 UDX ID; row state WAIT_REMOTE_HALF or ENDPOINT_ACCEPTED; no pending pair. The pair carries no owner, generation, purpose digest, or service field and therefore never performs token-only lookup.
2. Record `pending={completePairBytes,remoteUdxId,controlSocket,authenticatedRemoteControlIdentity}` inside the reserved row. If endpoint acceptance is absent, move to REMOTE_HALF_HELD.
3. Without endpoint acceptance, do not call `raw.connect`, send a pair response, or create another UDX stream. If acceptance was already retained, compare its verified responder ID and commitments and perform the single CONNECTING transition below.

Wrong/unknown token, initiator=true, seq change, duplicate, changed pair, second connection, or unpair before acceptance closes that control channel and revokes only the matching row when one exists. Unknown-token rejection creates no row and reveals no token detail. Exact duplicate while held is rejected, not treated as a second half. On first pair admission, the egress stores `pairHoldDeadline = min(routeLocalDeadline,projectedLegacyDeadline,operationStartMonotonic+15000)` with checked local monotonic arithmetic. Replay reuses this stored deadline and never renews it.

Endpoint decrypts IK2. It requires Noise ciphertext <=4096, payload version 1, error NONE, valid nonzero `payload.udx.id`, `payload.udx.seq=0`, compatible SecretStream metadata, and `NoiseWrap.remotePublicKey == expectedNoiseKey`; then `final()` succeeds. Ordinary bounded reply firewall, addresses, holepunch, and relay-address metadata are ignored as routing authority because source has no native socket/direct-upgrade path. They are not rejected. A reply `relayThrough` is accepted only if absent or names the same egress service identity/token; a different server-selected relay authority rejects. Source never contacts reply addresses.

`LEGACY_HANDSHAKE_ACCEPT_V2` body, 132:

`sessionId16 | egressRef32 | reservationNonce16 | H(IK1)32 | H(IK2)32 | validatedResponderUdxId4`.

Endpoint sends it only after those checks. Egress authenticates purpose-1 carrier and exact session/commitments, then retains one endpoint acceptance in the existing row. If no remote half exists, enter ENDPOINT_ACCEPTED and wait within the stored local pair deadline. If a half exists, require `validatedResponderUdxId == pending.remoteUdxId`. An exact acceptance replay at its original occurrence cannot connect again or mint a response; a later-position occurrence or changed acceptance causes RESET `conflict=7`. Egress learns no Noise keys or reply metadata.

Only when both validated facts exist, egress atomically enters CONNECTING and connects its pre-created raw stream exactly as proven:

`egressRaw.connect(controlSocket.rawStream.socket, pending.remoteUdxId, controlSocket.rawStream.remotePort, controlSocket.rawStream.remoteHost)`.

Then it sends exported pair response:

`{isInitiator:false, token:sessionCapability, id:egressRaw.id, seq:0}`.

The unchanged stock client consumes this response and connects its raw stream. Egress then moves CONNECTED and sends `LEGACY_OPEN_V2` body, 100:

`sessionId16 | egressRef32 | reservationNonce16 | pendingRemoteUdxId4 | H(IK2)32`.

Endpoint accepts exact state/commitment once and marks finalized Noise eligible for its controller-owned logical duplex. It does not construct/start SecretStream or release ciphertext until the §8.1 reservations, semantic OPEN success, transport OPENED, and authenticated directional DATA credit exist. Connecting the unchanged remote can make its 59-byte header and one full application record arrive before local OPENED. Egress's guarded pre-OPEN adapter admits exactly the initial 59-byte record, then at most one raw application record through 16,777,218 bytes, plus at most the next 3-byte prefix; it never forwards any of them before source acceptance and startup credit. It copies admitted bytes into those reserved slots without retaining the native callback buffer, pauses raw ingress when capacity is occupied, and resets on any additional pre-OPEN byte rather than pinning unaccounted surplus. Post-startup egress bridges guarded raw SecretStream ciphertext between route DATA and real UDX. No plaintext/key crosses.

States: `NEW -> RESOLVED -> RESERVED/WAIT_REMOTE_HALF -> REMOTE_HALF_HELD -> ENDPOINT_ACCEPTED -> CONNECTING -> CONNECTED -> OPEN -> CLOSING -> TOMBSTONE`. Pair-before-ACCEPT is valid and held. ACCEPT-before-pair stays ENDPOINT_ACCEPTED for the same stored local deadline; later exact pair triggers connect. Every exit from LIVE authority first enters CLOSING, removes token and ref lookup authority, and installs a service-scoped `(egressServiceIdentity,sessionCapability)` token tombstone plus the owner-scoped ref tombstone before callbacks or cleanup. Tombstones retain the one-use keys, original owner/session binding, terminal result, wire expiry, and projected local session/route deadline through that local deadline; expired tombstones are reclaimed before collision checks. Then egress destroys pending/raw/control/bridge state and invokes the §8.3 leg-local transport closure from its reserve. Timeout uses RESET `idle=4`; route or native UDX/control loss uses `route-loss=5`; owner/token revoke uses `revoked=6`; changed duplicate uses `conflict=7`; authentication failure uses `authentication=2`; capacity failure uses `quota=3`; an adapter/state invariant uses `internal=8`.

### 7. Private rendezvous without source identity disclosure

#### 7.1 ACTIVATE and Noise

`PRIVATE_ACTIVATE_V2` body, 749:

`sessionId16 | sourceCircuitId16 | sourceGeneration8 | sourceFinalTranscriptDigest32 | sourcePurposeDigest32 | sourceNonce32 | descriptorLength2=519 | completeDescriptor519 | sourceMaxFrames4 | sourceMaxBytes8 | sourceIdleMs4 | expiresAtUnixMs8 | H(IK1)32 | ik1Bytes4=101 | activateCommitment32`.

Fixed excluding descriptor is 230. `activateCommitment = H('hyperdht-private-routes/peer/private-activate/v2', every preceding body byte)`. No source stable identity appears. Destination learns/authenticates it only inside `NoiseWrap.recv(IK1)`.

Entry verifies the exact registered token/commitment, descriptor bytes, both owner handles, purpose/final transcript/circuit/generation/expiry, limits, and IK1 commitment before bridge allocation. Destination receives IK1, checks the 101-byte ciphertext length, calls `recv`, and requires the known decoded private profile: version1, error0, firewall0, SecretStream version1, no UDX/holepunch/relay fields and empty address lists. It then sends the 53-byte private IK2 profile and completes Noise. Source applies the same known-field checks to IK2. The ciphertext remains opaque dependency-owned Noise encoding; no claim is made that NoiseWrap rejects unknown flags its existing decoder ignores.

#### 7.2 READY

`PRIVATE_READY_V2` body, 220:

`sessionId16 | activateCommitment32 | destinationCircuitId16 | destinationGeneration8 | destinationNonce32 | H(IK1)32 | H(IK2)32 | expiresAtUnixMs8 | maxFrames4 | maxBytes8 | readyMac32`.

`Kready = KCONF(responderTx,READY_LABEL,noiseHash,sessionId,sourcePurposeDigest,destinationPurposeDigest,registrationCommitment)`.

`readyMac = CONFIRM(Kready, completeACTIVATE || completeIK1 || every READY body byte before readyMac)`.

Entry forwards IK2 then READY only after first-occurrence binding checks succeed: READY `sessionId`, `activateCommitment`, and `H(IK1)` equal retained ACTIVATE and reconstructed IK1; `destinationCircuitId` and `destinationGeneration` equal the registered descriptor and the authenticated destination route owner; `H(IK2)` equals the reconstructed complete IK2; and READY expiry, `maxFrames`, and `maxBytes` are no greater than every retained destination advertisement, descriptor, registration, route, and residual-ledger bound. Source repeats every equality against its retained ACTIVATE, descriptor, route, and reconstructed flights before it calls `final()`, verifies the expected destination key and readyMac with initiator rx, erases Kready, or emits ACK.

#### 7.3 ACK and destination acceptance

`PRIVATE_ACK_V2` body, 232:

`sessionId16 | activateCommitment32 | readyMac32 | sourceCircuitId16 | sourceGeneration8 | sourceNonce32 | destinationNonce32 | H(IK2)32 | ackMac32`.

`Kack = KCONF(initiatorTx,ACK_LABEL,noiseHash,sessionId,sourcePurposeDigest,destinationPurposeDigest,registrationCommitment)`.

`ackMac = CONFIRM(Kack, completeACTIVATE || completeREADY || completeIK1 || completeIK2 || every ACK body byte before ackMac)`.

Entry forwards ACK and destination changes state only after ACK `sessionId`, `activateCommitment`, `sourceCircuitId`, `sourceGeneration`, and `sourceNonce` equal retained ACTIVATE and its authenticated source route owner; `destinationNonce` and `readyMac` equal retained READY; and `H(IK2)` equals the reconstructed complete IK2. Destination then derives Kack from responder rx, verifies, erases, and only then emits acceptance.

`PRIVATE_ACCEPTED_V2` body, 168:

`sessionId16 | activateCommitment32 | readyMac32 | ackMac32 | destinationCircuitId16 | destinationGeneration8 | acceptedMac32`.

`Kaccepted = KCONF(responderTx,ACCEPTED_LABEL,noiseHash,sessionId,sourcePurposeDigest,destinationPurposeDigest,registrationCommitment)`.

`acceptedMac = CONFIRM(Kaccepted, completeACTIVATE || completeREADY || completeACK || every ACCEPTED body byte before acceptedMac)`.

Destination sends ACCEPTED on its authenticated purpose-3 route. Before that send and before entry changes to DESTINATION_ACCEPTED or forwards bytes, ACCEPTED `sessionId` and `activateCommitment` must equal retained ACTIVATE, `readyMac` must equal retained READY, `ackMac` must equal retained ACK, and `destinationCircuitId` and `destinationGeneration` must equal retained READY and the authenticated destination route owner. Entry cannot verify the endpoint-secret MAC but enforces those carried-field and carrier equalities before forwarding exact bytes. Source repeats the retained-field equalities, verifies acceptedMac with initiator rx, and erases Kaccepted. For READY, ACK, and ACCEPTED, an authenticated first occurrence with any carried-field, reconstructed-hash, route-owner, expiry, or limit mismatch uses RESET `authentication=2`; after a valid original occurrence is frozen, changed bytes, position, lane identity, or binding use RESET `conflict=7` and never forward or change state.

Object-identical owner-handle checks are local: entry checks the source and destination legs it owns. A remote endpoint checks the canonical circuit, generation, and purpose bindings retained in ACTIVATE and the descriptor, authenticated by the endpoint confirmation transcript; it never imports or compares a remote process's local owner handle.

#### 7.4 Source receipt, exact limits, and OPEN

`PRIVATE_SOURCE_RECEIPT_V2` body remains 120 bytes and wire 128:

`sessionId16 | acceptedMac32 | sourceCircuitId16 | sourceGeneration8 | receiptNonce16 | receiptMac32`.

`Kreceipt = KCONF(initiatorTx,RECEIPT_LABEL,noiseHash,sessionId,sourcePurposeDigest,destinationPurposeDigest,registrationCommitment)`.

`receiptMac = CONFIRM(Kreceipt, completeACTIVATE || completeREADY || completeACK || completeACCEPTED || every RECEIPT body byte before receiptMac)`.

The canonical `X` above is `757+228+240+176+88 = 1,489` bytes; the keyed BLAKE2b input is 1,493 bytes after its u32 length. Source derives Kreceipt only after accepted-MAC verification, samples a nonzero receipt nonce, emits the MAC, erases Kreceipt, and retains the exact receipt until OPEN. Entry accepts the receipt only from the exact purpose-2 owner/generation in DESTINATION_ACCEPTED, requires its session/source binding and acceptedMac equal the forwarded ACCEPTED, cannot verify the endpoint-secret MAC, and caches the complete canonical receipt. Exact replay follows §8; changed binding, nonce, or bytes uses RESET `conflict=7`.

`PRIVATE_OPEN_V2` body is 216 bytes, wire 224:

`sessionId16 | activateCommitment32 | readyMac32 | ackMac32 | bridgeId16 | sourceGeneration8 | destinationGeneration8 | expiresAtUnixMs8 | maxFrames4 | maxBytes8 | idleMs4 | receiptNonce16 | receiptMac32`.

The one `maxFrames` and one `maxBytes` value apply independently to each ciphertext direction. They are two separate lifetime counters with the same cap, never one shared pool. `maxFrames` is the checked positive minimum of descriptor and registration frame limits, ACTIVATE `sourceMaxFrames`, READY `maxFrames`, all four corresponding source/destination route-leg DATA-frame quotas, and residual registration/session frame ledgers. Compute `frameByteCeiling=977*maxFrames` with checked u64 arithmetic. `maxBytes` is exactly the checked minimum of every matching descriptor, registration, ACTIVATE, READY, route-leg, and residual-ledger byte constraint and `frameByteCeiling`. Because one scalar is carried for each kind, the entry takes the minimum across both ciphertext directions and both legs; it may lower but never raise either cap.

`idleMs` is the checked positive minimum of descriptor idle, registration idle, ACTIVATE `sourceIdleMs`, and both route idle bounds. READY has no idle field and creates none. `expiresAtUnixMs` is the minimum of descriptor expiry, registration expiry, ACTIVATE expiry, READY expiry, both route wire expiries, and residual registration/session ledger expiry. Each endpoint projects that exact wire value once under §2.2 and clamps it to its own parent local deadline. Each endpoint rejects an OPEN value above any authenticated constraint it knows.

Admission requires `maxFrames>=1`, the exactly computed `maxBytes>=59`, both endpoint record reservations inside their local semantic-owned pools, both route-leg quotas, and the bridge reservations before OPEN. A byte constraint above `977*maxFrames` cannot make the excess grantable; a result below 59 rejects rather than raising it. The 16,777,218-byte atomic raw-record parser ceiling remains unchanged; the lifetime byte cap is not a hidden per-record parser limit. `M` is the transport lifetime accepted-stream cap: it includes the registration stream on purpose3, is not refunded, and must have room on both legs before application stream allocation. If a leg has no lifetime stream or tombstone slot, its new OPEN is rejected before stream allocation and no unreserved CLOSE/RESET is sent on that unallocated leg. If the counterpart stream was already admitted, that existing stream fails with RESET `quota=3` from its own reserved closure counter before any bridge or semantic OPEN.

Only after destination ACCEPTED and the exact source receipt does entry activate both bridge reservations and construct one canonical OPEN body. It sends that byte-identical body on both route AEAD contexts and caches 224 bytes per leg, 16 more than the prior draft. Source requires prior accepted verification and exact equality of its cached `receiptNonce/receiptMac`. Destination reconstructs the canonical 120-byte RECEIPT from retained ACTIVATE/READY/ACK/ACCEPTED state plus OPEN's receipt fields, derives Kreceipt from responder rx, verifies receiptMac, erases Kreceipt and transcript scratch, and only then accepts semantic success. Duplicate OPEN cannot transfer a controller twice. Semantic success authorizes transport OPENED; each direction then requires its own authenticated CREDIT before its immediate 59-byte SecretStream header may enter DATA.

Cumulative order is noncyclic: ACTIVATE -> READY -> ACK -> ACCEPTED -> SOURCE_RECEIPT -> OPEN -> destination RECEIPT verification. Route/descriptor inputs precede Noise confirmations. Transport never consumes Noise outputs.

States: `NEW -> ACTIVATE_REASSEMBLY -> DESTINATION_NOISE_AUTHENTICATED -> READY -> SOURCE_NOISE_AUTHENTICATED -> ACK_FORWARDED -> DESTINATION_ACCEPTED -> SOURCE_ACCEPTED -> OPEN -> CLOSING -> TOMBSTONE`. A connection failure, conflict, Noise/MAC failure or stream reset revokes only that session's two bridge reservations before clearing its bytes/waiters/callbacks. It must not revoke the listener registration or destroy a shared surviving route owner. Route loss revokes every session using the lost route; its surviving counterpart routes remain owned independently. Listener registration revoke/expiry invokes §5.3 and revokes all sessions using that registration. No cross-generation move.

### 8. Duplicate, allocation, and ownership rules

- `registryId` means the fixed semantic registry ID in §3, never a reliable lane sequence or arbitrary message number. The route-local parent tuple is `(routeOwnerCapability,generation,streamId,streamEpoch)`.
- A Noise-fragment duplicate key is `(parent,sessionId,flight,wholeCiphertextCommitment,fragmentIndex)`. Before this lookup, §4 freezes one `(commitment,totalCiphertextBytes,fragmentCount)` per `(parent,sessionId,flight)`; any changed flight tuple conflicts before it can form another key.
- A session-singleton key is `(parent,sessionId,registryId)` for LEGACY_RESOLVE/RESOLVED/RESERVE/RESERVED/HANDSHAKE_ACCEPT/OPEN and PRIVATE_ACTIVATE/READY/ACK/ACCEPTED/SOURCE_RECEIPT/OPEN.
- Registration-control keys cover objects without session IDs. Before key lookup the control owner freezes its one REGISTER `registerNonce` and the resulting `(token,registrationCommitment)` binding; any changed nonce or binding at that phase causes RESET `conflict=7`. With that freeze, REGISTER is `(parent,0x0349,registerNonce)`; REGISTERED is `(parent,0x034a,registerNonce,token,registrationCommitment)`; REVOKE is `(parent,0x034b,token,registrationCommitment)`. Descriptor identity is exactly `(verifiedPresenceIdentity,descriptorDigest)`: the first component is the opaque identity returned by verified presence resolution, and the second is computed from the verified complete descriptor bytes.
- Every row stores the full canonical semantic bytes, original semantic position, and the ordered original reliable-packet identity vector indexed by canonical object offset, plus the original response packet-vector/attempt state. Transport canonically fragments at981 bytes, so one semantic object spans at most two packet identities; their lane sequences need not be adjacent when streams interleave. Compare full canonical bytes and each fragment's original `(lane,laneSequence,nestedDigest)` identity. Only the same key, bytes, semantic position, and complete packet vector is the same occurrence. It may resume only original cached response packets with remaining shared eight-attempt counters. A changed position, packet identity, or canonical bytes causes bounded stream RESET `conflict=7`, never a new semantic allocation, callback, response sequence, or retry train.
- Allocate exact reassembly, cached objects, clock projection, timers, row/tombstone, lifetime stream slot, and both bridge-leg queue/ledger reservations before acknowledgment. The semantic-owned reservation and its pending-owner transfer obey §8.2. Failure rejects before token, UDX stream, bridge or OPEN authority. Transport retries keep the original packet bytes, lane sequence, and one eight-attempt counter.
- Delayed callbacks capture owner capability, generation, state epoch, clock identity, and stored local deadline; mismatch or expiry erases the result without mutation.
- Legacy session tokens are one-use capabilities. A private registration token is reusable only for distinct admitted session IDs within its live generation, remaining limits, and remaining lifetime stream cap. Purpose3 `M` includes its registration stream; every accepted application stream consumes another lifetime slot, and close/reset never refunds it. Admission checks `acceptedLifetimeStreams<M` and tombstone capacity before allocation. No cap failure may allocate a hidden RESET response outside the reserved stream-close work.
- Entry owns pair record/leg contexts only. Egress owns token/ref rows, control socket, native UDX and ciphertext bridge. Endpoint controller owns logical duplex and Noise/SecretStream. Every transfer is a one-time atomic compare-and-swap.
- Transport FIN/CLOSE/RESET is authoritative for continuous ciphertext offsets and leg closure. Semantic teardown follows §8.3 and revokes authority before transport closure callbacks. Native unchanged-server probes establish full-duplex equality, both full closes, forward EOF followed by reverse data/EOF, and reverse EOF followed by forward data/EOF. They do not establish simultaneous end-event convergence, M3 transport behavior, or ARQ behavior.

#### 8.1 SecretStream framing, guarded ownership, and startup

The inherited unchanged-peer profile keeps SecretStream's full atomic record maximum; narrowing it would silently break legacy compatibility. The exact raw format is:

- Every raw item is `uint24le bodyBytes || body`.
- Initial body is exactly `streamIdentity32 || secretStreamHeader24` = 56 bytes; initial raw item is exactly 59 bytes. This order matches `_setupSecretStream()` and `_incoming()`.
- Every later body is authenticated ciphertext, not plaintext followed by a clear tag. Its length is `plaintextBytes + ABYTES17`, so `bodyBytes` is 17..16,777,215 and raw length is 20..16,777,218. Maximum plaintext is 16,777,198 bytes.
- Initial header and application ciphertext count as DATA bytes and frames. The 59-byte header is one DATA frame in each direction; it is not free handshake material.

`@hyperswarm/secret-stream` writes its 59-byte initial record immediately in `_setupSecretStream()` and accepts the uint24 length before allocating a fragmented body (`node_modules/@hyperswarm/secret-stream/index.js:373-397,226-276`). Therefore every endpoint/session reserves, before native contact or OPEN:

1. one pending-outbound-record slot of 16,777,218 bytes;
2. one inbound-assembly-or-plaintext-retention slot of 16,777,218 bytes; and
3. a separate 3-byte inbound prefix guard.

These endpoint record capacities are charged to the endpoint-record subledger of the route owner's semantic-owned pool. They are disjoint from transport queues, reliable caches, canonical/response cache bytes, confirmation transcript scratch, and legacy egress's separate 16,777,280-byte pre-OPEN ingress subledger: header59 + application record16,777,218 + next-prefix/surplus guard3. Actual buffers allocate lazily to validated lengths. The endpoint inbound slot changes ownership in place from ciphertext assembly to SecretStream input to retained plaintext; current SecretStream decrypts into a plaintext subarray of the same complete message (`index.js:328-348`), so those phases do not each earn another maximum-sized reservation.

An unavoidable bounded-record adapter sits between DATA reassembly and `SecretStream.rawStream`. It first accumulates exactly three prefix bytes, decodes uint24 little-endian without passing them to SecretStream, and validates by state: first length must equal 56; every later length must be 17..16,777,215. It then acquires the already admitted inbound slot, lazily allocates exactly `3+bodyBytes`, assembles one complete contiguous record, and passes that complete record in one write. Complete delivery follows SecretStream's no-extra-fragment-allocation path; passing unguarded fragments would permit its parser to allocate the declared length before the setup check. If the dependency/API cannot preserve this complete-buffer ownership path, integration requires a small dependency adapter/change or an additional explicitly admitted copy; it must not claim the stock API itself enforces the bound.

Each direction has independent authenticated byte and frame credit. After semantic success and OPENED, the receiver issues CREDIT only for storage already reserved in that direction; the peer may then instantiate/start SecretStream and transmit its immediate 59-byte header. Source must not start until it can retain its pending header and transmit it under received credit. For legacy, the unchanged remote may emit its header and one application record immediately after the relay pair response; egress holds them only in the separately admitted bounded pre-OPEN slots, with the next three bytes owned by the surplus guard, and forwards them only after source acceptance, OPENED, and source-side receive credit. No new remote confirmation message is introduced.

Transport queue/frame slots and encrypted-byte charges release when contiguous ciphertext transfers into the already reserved record slot, not when application plaintext is consumed. The record reservation remains charged while assembling and, after in-place decrypt, while plaintext is retained under application backpressure. This separates transport ciphertext flow control from application plaintext backpressure without double-freeing either ledger. A record may therefore consume more than the physical frame window while its fragments cycle through reserved storage.

The native framing proof sent 1 MiB plaintext through actual SecretStream over 977-byte fragmented chunks: initial raw/body 59/56; application raw/body 1,048,596/1,048,593; 1,075 accepted chunks; no plaintext after 24 chunks; first plaintext only at chunk 1,075 (`local://peer-stream-record-framing-check-results.txt:1-45`). It proves built-in framing and that application-consumption-only replenishment deadlocks a 24-slot frame window. It does not prove the v2 guard, CREDIT, ARQ, or transport implementation.

#### 8.2 Semantic-owned memory and exact profile cache maxima

The transport wire field at OFFER offset188 is `semanticOwnedBytes u32`; the field at ACCEPT offset220 is `admittedSemanticOwnedBytes u32`. These names replace `cachedSemanticBytes` and `admittedCachedSemanticBytes` at the same widths and offsets. There are no aliases. For each local route owner, checked arithmetic must prove:

```text
requiredSemanticOwnedBytes =
  retainedCanonicalAndResponseCacheMaximum
  + legacyNoiseScratchBytes
  + privateConfirmationScratchBytes
  + 33,554,439 * localEndpointApplicationStreamCapacity
  + (localOwnerIsLegacyEgress ? 16,777,280 : 0)
```

Transport separately proves, with checked arithmetic for the same local owner:

```text
requiredMaxQueuedBytes =
  157,200
  + 1,073*M
  + admittedReceiveWindowBytes
  + admittedSemanticOwnedBytes
```

Here `admittedReceiveWindowBytes` is that owner's actual reserved inbound outer-direction storage corresponding to accepted `admittedReceiveBytes`; it is not endpoint record memory or a shared cross-direction pool. Either required value exceeding its u32 field, advertisement, or local reservation rejects before OFFER/ACCEPT.

`retainedCanonicalAndResponseCacheMaximum` retains one exact canonical semantic-wire copy of every object in the admitted lifetime profile through its stream tombstone or stored route deadline. An authored semantic response reuses that one canonical copy for exact response replay; it is not counted a second time. Reliable wrapper/retransmit bytes and transport `PEER_OPEN_V2`/`PEER_OPENED_V2` bytes stay in transport-owned reservations and are not counted here. Consequently the cache figures below deliberately exclude the extra transport 96-byte OPEN and 72-byte OPENED; adding them would produce 822/2,217/2,089/9,788 mixed-pool figures rather than semantic-owned cache bytes. If an implementation retains another semantic response, transcript, or ciphertext copy rather than aliasing the accounted canonical bytes, it must name and add that copy before OFFER.
Transport OPEN/OPENED full bytes release on sender acknowledgement or receiver contiguous delivery; settled replay uses transport's fixed48-byte digest-history rows, not another canonical cache. Before sending the first semantic HANDSHAKE, the opener waits for a non-sentinel control cumulative acknowledgement covering OPEN; a bitmap-only acknowledgement is insufficient. Transport installs the admitted owner before that cumulative progress. OPEN's first-ID/length fields constrain only the opener direction; each reverse direction starts with its own fixed profile object (REGISTERED, private IK2 fragment, or LEGACY_RESOLVED).

For purpose1, `legacyNoiseScratchBytes=8192*M` at both source endpoint and egress: two disjoint 4,096-byte contiguous raw-flight slots per lifetime-admitted stream, separate from the 9,620-byte canonical semantic cache. Canonical fragments contain envelope gaps and cannot stand in for contiguous Noise input. Slots allocate lazily to validated flight lengths, retain raw bytes through their final reconstruction/hash/handshake consumer, then erase and release exactly once; release cannot refund lifetime stream admission. The other purposes use zero for this legacy term. Their 101/53-byte raw flights use views into their single canonical fragment payloads after construction. Confirmation and KDF/MAC processing consumes the framed length/domain prefix and canonical slices incrementally; no concatenated transcript copy is retained or allocated outside its reservation. An implementation requiring an additional copy must reject its admission until that copy is explicitly included.

For purpose2 source and purpose3 listener/destination, `privateConfirmationScratchBytes=528*localEndpointApplicationStreamCapacity`; all other local owners use zero. Semantic §2.1 defines the exact arena, acquire-before-processing rule, concurrency bound, erasure, and exhaustion behavior. This term is additional to canonical caches, endpoint Noise-owned final keys/hash, and the record slots; none may lend bytes to the arena.

The exact per-profile canonical maxima and OPEN handshake bindings are:

| Profile                                  | `semanticFirstId/wire` |                                    opener -> receiver HANDSHAKE frames/bytes |                             receiver -> opener fixed reserve frames/bytes | canonical bytes per lifetime stream |
| ---------------------------------------- | ---------------------: | ---------------------------------------------------------------------------: | ------------------------------------------------------------------------: | ----------------------------------: |
| purpose3 registration control            |             `0349/486` |                                             `2/582` = REGISTER486 + REVOKE96 |                                                   `1/144` = REGISTERED144 |                               `726` |
| purpose2 private source                  |             `0360/757` |                       `4/1297` = ACTIVATE757 + IK1 172 + ACK240 + RECEIPT128 |              `4/752` = IK2 124 + READY228 + ACCEPTED176 + PRIVATE_OPEN224 |                             `2,049` |
| purpose3 private destination application |             `0360/757` |                  `4/1393` = ACTIVATE757 + IK1 172 + ACK240 + PRIVATE_OPEN224 |                                `3/528` = IK2 124 + READY228 + ACCEPTED176 |                             `1,921` |
| purpose1 legacy maximum                  |             `0341/112` | `12/4807` = RESOLVE112 + RESERVE104 + maximum IK1 4451 + HANDSHAKE_ACCEPT140 | `12/4813` = RESOLVED114 + RESERVED140 + maximum IK2 4451 + LEGACY_OPEN108 |                             `9,620` |

These are semantic wire payload bytes carried by physical canonical HANDSHAKE packets; frames include the canonical 981-byte split. They exclude transport OPEN/OPENED, ACK wrappers, CREDIT, DATA, FIN, and forced closure. For purpose3 application, the opener is entry, so opener -> receiver is physical REVERSE entry -> destination and the fixed reverse reserve is physical FORWARD destination -> entry.

Therefore the route-owner cache maxima are `C1(M)=9620*M`, `C2(M)=2049*M`, and `C3(M)=726+1921*(M-1)` for purpose3 `M>=1`. Registration-only purpose3 at `M=1` is exactly726 bytes. Endpoint-bearing purpose1 and purpose2 owners use `localEndpointApplicationStreamCapacity=M`; the purpose3 listener/destination owner uses `M-1`. A private entry bridge owns no endpoint record buffer on either leg, and legacy egress owns no SecretStream endpoint record buffer; each uses capacity zero in this term. Legacy egress instead owns the one 16,777,280-byte pre-OPEN ingress subledger and serializes occupancy so a second pre-OPEN remote cannot borrow it.

The resulting exact local minima are: purpose1 source endpoint `(33,554,439+9,620+8,192)*M = 33,572,251*M`; purpose1 legacy egress `(9,620+8,192)*M+16,777,280 = 17,812*M+16,777,280`; purpose2 source endpoint `(33,554,439+2,049+528)*M = 33,557,016*M`; purpose2 private entry bridge `2,049*M`; purpose3 listener/destination `726+(33,554,439+1,921+528)*(M-1) = 726+33,556,888*(M-1)`; and purpose3 entry bridge `726+1,921*(M-1)`. The u32 field and checked arithmetic reject overflow before OFFER/ACCEPT. In particular, the endpoint-side formulas bound purpose1 and purpose2 to `M<=127` and purpose3 to `M<=128`; a smaller advertisement, local reservation, or authenticated partition still wins.

The semantic-owned pool has disjoint, non-borrowing subledgers for canonical/response caches, legacy contiguous-Noise scratch, private confirmation arenas, each endpoint record slot, and the legacy pre-OPEN ingress slot. Transport receive/reorder windows and reliable buffers never spend this pool. Conversely, both local route owners reserve their accepted inbound outer-direction `admittedReceiveFrames` and `admittedReceiveBytes` in transport memory even though the negotiated fields are symmetric maxima; they are two physical reservations, not one shared pool. A private entry bridge reserves the accepted inbound window independently for each leg and cannot reuse either window for its other leg or direction.

Before sealing OFFER, source creates a pending-purpose owner holding the offered directional ledgers, fixed ARQ/reassembly, its own inbound receive window, and the full offered `semanticOwnedBytes`. Before sealing ACCEPT, terminal creates its corresponding pending-purpose owner with the admitted values. Terminal may admit downward only while `admittedSemanticOwnedBytes` is at least its local formula; source accepts only while it remains at least source's local formula. ACCEPT shrinkage releases only the excess from source's already-held reservation. Source-sentinel and terminal-sentinel success atomically transfer each pending owner and every subledger into the active owner; neither side reacquires or recomputes memory. REJECT, deadline, authentication failure, or transport loss releases the pending owner exactly once.

#### 8.3 Leg-local FIN, CLOSE, and RESET mapping

Each application leg owns independent DATA sequences, continuous ciphertext offsets, FIN state, and closure cache. A local SecretStream/raw outbound end first forbids new writes, drains every accepted raw ciphertext byte into that leg's DATA lane, then emits one `PEER_FIN_V2` with that leg's exact final ciphertext offset and last DATA sequence. An effective remote FIN is delivered once as inbound raw EOF (`push(null)` or the dependency's read-side equivalent); it never calls `.end()` on the local outbound raw side and never prevents opposite-direction writes.

A private entry bridge never copies a FIN object between legs. After an ingress FIN becomes effective, entry forwards all preceding ciphertext into the other leg, waits until those bytes are durably admitted there, then creates a new FIN from the other leg's own offset and DATA sequence. The two route legs may therefore have equal byte offsets but different DATA sequences. Each direction stays writable until its own FIN or forced closure.

At legacy egress, native UDX inbound EOF follows the same rule: after all preceding native bytes have entered route DATA, egress emits a new route FIN with that route leg's fields. An effective route FIN in the opposite direction first drains its preceding route DATA into native UDX, then ends only the native writable half for that direction. It does not destroy the native stream or synthesize EOF for the surviving direction.

Graceful completion uses FIN in both directions and no CLOSE. `PEER_CLOSE_V2` is only a non-error owner-requested early close with a valid last-byte boundary. It revokes the session and both bridge-leg admissions, then destroys both logical halves; it never synthesizes FIN. Every error uses `PEER_RESET_V2` with the existing exact registry: application-requested abort or surfaced application failure `application=1`; Noise, MAC, SecretStream authentication, profile, or invalid carrier failure `authentication=2`; stream/frame/byte/memory/lifetime-cap exhaustion `quota=3`; idle or stored local deadline expiry `idle=4`; purpose-route loss or native UDX/control connection loss `route-loss=5`; registration/token/owner revocation `revoked=6`; changed duplicate, reused identity, or binding conflict `conflict=7`; impossible adapter, callback, entropy, or state invariant `internal=8`. No other code is defined.

Forced closure ordering is exact: atomically move the semantic session LIVE/OPEN -> CLOSING; remove session, token, ref, UDX and bridge lookup authority; install bounded tombstones; revoke both leg reservations and reject waiters; erase queued bytes and endpoint secrets; then ask each still-live transport leg to send its own cached CLOSE or RESET from that leg's reserved counter. A lost leg sends nothing; a surviving counterpart receives a fresh leg-local RESET `route-loss=5`. Incoming CLOSE/RESET becomes effective only under transport control contiguity; its semantic callback performs the same revoke-first sequence before controller/raw destruction. Exact closure replay uses the original cached packet and counter. No closure packet, FIN, offset, sequence, or authority moves across a route generation.

### 9. Exact semantic phase counts and physical startup additions

Semantic-only counts below are canonical semantic/control objects converted to reliable packets with `ceil(wire/981)`. They exclude transport route bootstrap, LINK/EXTEND, purpose OFFER/ACCEPT, two sentinel confirmations, normal ACK packets, reciprocal CREDIT, DATA, and disjoint stream/route/physical closure reserves. Each application-leg table then names startup additions: one authenticated CREDIT and one59-byte-header DATA frame in each direction. Exact replay never adds a semantic packet or fresh reliable sequence. Transport owns retransmission/ACK, byte/frame-credit, per-hop, and physical cell accounting. A receiver count never includes a remote attempt that did not arrive.

#### 9.1 Listener registration control

Semantic-only:

- listener -> entry: `PEER_OPEN`, REGISTER = 2 reliable packets.
- entry -> listener: REGISTERED = 1.
- semantic allocation commands: OPEN + REGISTER = 2.

Lifetime revocation reserves one later listener -> entry REVOKE packet. Full lifetime semantic maximum is forward 3, reverse 1, and two allocation commands. REGISTERED replay can only spend its original packet's remaining attempt counter, so it does not increase these counts. This control stream never OPENED or carries DATA, so reciprocal CREDIT and SecretStream headers are not applicable.

#### 9.2 Private source leg

Direction orientation is forward source -> entry and reverse entry -> source.

- Semantic-only forward: `PEER_OPEN`, ACTIVATE, IK1 fragment, ACK, SOURCE_RECEIPT = 5.
- Semantic-only reverse: IK2 fragment, READY, ACCEPTED, PRIVATE_OPEN, `PEER_OPENED` = 5.
- Semantic allocation commands: OPEN + private ACTIVATE admission = 2.
- Physical startup forward: one `PEER_CREDIT_V2` granting reverse capacity, plus one `PEER_DATA_V2` carrying the source's 59-byte raw header after reverse CREDIT arrives.
- Physical startup reverse: one `PEER_CREDIT_V2` granting forward capacity, plus one `PEER_DATA_V2` carrying the destination's 59-byte raw header after forward CREDIT arrives.

Thus pre-DATA semantic counts remain 5/5; startup adds exactly two physical packets and 59 DATA bytes in each direction. PRIVATE_OPEN is now wire224 but remains one HANDSHAKE packet; its bytes are included in the exact 2,049-byte source-leg profile cache in §8.2.

#### 9.3 Private destination leg

Direction orientation is forward destination -> entry and reverse entry -> destination. This preserves Main's corrected physical orientation.

- Semantic-only forward: IK2 fragment, READY, ACCEPTED, `PEER_OPENED` = 4.
- Semantic-only reverse: `PEER_OPEN`, ACTIVATE, IK1 fragment, ACK, PRIVATE_OPEN = 5.
- Semantic allocation commands: OPEN + private ACTIVATE admission = 2.
- Physical startup forward: one `PEER_CREDIT_V2` granting reverse capacity, plus one `PEER_DATA_V2` carrying the destination's 59-byte raw header after reverse CREDIT arrives.
- Physical startup reverse: one `PEER_CREDIT_V2` granting forward capacity, plus one `PEER_DATA_V2` carrying the source's 59-byte raw header after forward CREDIT arrives.

Thus pre-DATA semantic counts are forward 4/reverse 5; startup adds exactly two physical packets and 59 DATA bytes in each direction. Across both private legs the semantic-only total remains 19 reliable packets and four semantic allocation commands; physical startup adds eight packets and four transported 59-byte header instances because each endpoint header crosses both legs. The two byte-identical OPEN instances each require a 224-byte per-leg cache, 32 aggregate bytes above the prior two 208-byte instances.

#### 9.4 Legacy maximum profile

At the proposed 4,096-byte Noise cap, each flight is five semantic Noise objects and nine HANDSHAKE packets. Direction orientation is forward endpoint -> egress and reverse egress -> endpoint.

- Semantic-only forward: `PEER_OPEN`, RESOLVE, RESERVE, nine IK1 HANDSHAKE packets, HANDSHAKE_ACCEPT = 13.
- Semantic-only reverse: RESOLVED, RESERVED, nine IK2 HANDSHAKE packets, LEGACY_OPEN, `PEER_OPENED` = 13.
- Semantic allocation commands: OPEN + RESOLVE admission + RESERVE = 3.
- Physical startup forward: one `PEER_CREDIT_V2` granting reverse capacity, plus one `PEER_DATA_V2` carrying the source's 59-byte header after reverse CREDIT arrives.
- Physical startup reverse: one `PEER_CREDIT_V2` granting forward capacity, plus one `PEER_DATA_V2` forwarding the held unchanged-remote59-byte header after forward CREDIT arrives.

The observed unchanged-server sample (175/125) used one Noise object and one HANDSHAKE packet per flight, but admission uses the supported4,096 bound. Semantic-only `P_f=P_r=13`; startup contributes two additional reliable packets and59 DATA bytes per direction. The five Noise fragment identities are distinct by flight, commitment, and fragment index, while all share registryId0345. Transport adds retry/ACK, setup, purpose confirmation, lifetime CREDIT, FIN, per-stream forced closure, separate route close, and physical teardown terms. No semantic whole-route cell total is asserted.

### 10. Cross-layer implementation requirements

1. Transport registry uses the fixed 260-byte advertisement, semantic classes `REGISTRATION_CONTROL=1` and `APPLICATION=2`, and unchanged semantic IDs. PRIVATE_OPEN is body216/wire224; every other §3 size is unchanged.
2. Transport exports `{purposeDigest32,finalTranscriptDigest32,routeOwner,generation,purpose,wireExpiresAt,localDeadline,clockIdentity,wallNow,monotonicNow}` to semantic issuers. Section2.2 performs one local projection; replay never renews it. Advertisement setup keys are never generation keys.
3. Exact semantic replay reuses the original packet identity, lane sequence, bytes, and shared eight-attempt counter. A later-position occurrence causes bounded stream conflict and no semantic response allocation.
4. Duplicate identity uses registryId plus the exact class keys in §8. Noise fragments first freeze one flight tuple, then key by flight/commitment/index. All comparisons retain full canonical bytes.
5. Private source identity appears only inside Noise IK1. KCONF consumes the 64-byte Noise hash and 176-byte context. RECEIPT adds the initiator-tx/responder-rx label, a 1,489-byte canonical transcript, and a 1,493-byte keyed hash input. Destination verifies the reconstructed receipt before semantic success.
6. PRIVATE_OPEN carries one frame and byte cap applied independently to both ciphertext directions. `maxFrames` is the checked minimum of every named frame bound; `maxBytes` is the checked minimum of every named byte bound and checked `977*maxFrames`; both route legs receive the same complete OPEN, and admission requires `maxFrames>=1` and `maxBytes>=59`. Purpose3 `M` is a lifetime cap including registration and is never refunded.
7. Dedicated legacy egress uses only exported blind-relay pair/unpair codecs on protocol `blind-relay`. Its ref keeps bounded owner-scoped collision resampling. Its session capability uses bounded initial-plus-eight resampling and service-wide `(egressServiceIdentity,sessionCapability)` LIVE/tombstone collision and lookup scope. Registration tokens likewise use initial-plus-eight service-wide collision resampling and reject unexpired tombstones. RESERVED performs the exact session/ref/nonce/service/candidate/UDX checks in §6.
8. Legacy source has no native socket/direct upgrade. Ordinary reply addresses/holepunch/firewall metadata are decoded then ignored as authority. Router `relayed=true`, bounded valid UDX metadata, compatible relay authority, and expected application Noise key are required. The 4,096-byte legacy Noise cap remains an explicit compatibility restriction.
9. Current SecretStream accepts a fragmented uint24 length before allocation. Integration needs the §8.1 guarded complete-record ownership path or an explicitly admitted copy. Legacy egress also needs the 16,777,280-byte pre-OPEN ingress reservation and copy/pause discipline; overflow resets without retained unaccounted bytes.
10. Section8.3 maps local raw end, remote FIN, private bridge FIN, native UDX EOF, CLOSE, and every existing RESET reason to leg-local offsets/sequences and revoke-first owner order. No cross-generation closure transfer exists.
11. Semantic packet counts remain registration4, private source10, private destination9, combined private19, and legacy26 before startup additions. Exact canonical cache maxima are registration726, private source2,049, private destination application1,921, and legacy9,620 bytes per lifetime profile; §8.2 lifts them to lifetime `M`.
12. Runtime proof still must cover guarded raw pause/copy behavior, simultaneous end-event convergence, v2 ARQ/retransmission, first clock projection and replay stability, lifetime stream exhaustion, session-isolated reset, private M3 transport, and privacy. Native proof establishes only unchanged-boundary bytes, both closes, and one-sided EOF continuation.
