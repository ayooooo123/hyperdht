# Private Routing: DATAGRAM SURB Reply Path (Gate C)

**Status:** implemented package-private behind an explicit experimental flag.
The Gate C wire is owner-approved for experimentation, not externally
cryptographically reviewed or wire-stable. See the
[construction and ownership amendments](./2026-08-10-private-routing-surb-construction-design.md)
and [current implementation](../../private-routing-migration.md#current-implementation).
**Date:** 2026-08-10
**Relates to:** [v1 design](../../private-routing-v1.md) and
[Logos lessons, Gate C](../../private-routing-logos-lessons.md).
**Prior art:** Sphinx single-use reply blocks (SURBs); Nym / Loopix reply mechanics.

## Summary

The initiator supplies a bounded batch of single-use reply blocks inside an
authenticated routed request. The exit seals each reply fragment to a different
SURB, and the route's middle and guard peel locally before the endpoint opens it.
Physical carriage is link-sealed in fixed 1,200-byte cells.

This implementation uses the existing reverse relays and operation lifetime.
It is not an independently routed or mixed return path and does not permit
replies after arbitrary forward-route teardown.

## What already exists (do not re-solve)

- **Correlated DHT replies** remain the default and follow the established route.
  The queried DHT node sees the exit, not the endpoint.
- **Required SURB replies** are available for immutable/mutable get and put,
  including presence publication, resolution, and revocation. They require
  `experimentalSurbReplies: true` and explicit `replyMode: 'SURB_REQUIRED'`.
  Failure never falls back to a correlated reply.
- **Peer streams and private-peer DATAGRAMs** are not implemented by this gate.
  Opaque destination references and tail-extension authority are not a completed
  peer rendezvous or `privateConnect` API.

SURBs add one-use reply authority and a separate reply envelope, not timing
anonymity. They share the route/query deadline, and their timing and cell-count
signatures remain visible. Mixing/cover traffic stays deferred.

## SURB mechanics (target)

- The initiator builds independent SURBs for the bounded reply-fragment batch,
  retains their one-use open authorities, and supplies opaque terminal handles.
  No endpoint network address is embedded as the terminal destination.
- The descriptors travel inside the forward request's source-to-exit AEAD.
  Intermediate forward relays cannot read them; the terminating DHT exit is the
  intended recipient and can consume the descriptors, not the open authorities.
- The exit emits the sealed first-hop cell onto its reverse link. Each return
  relay authenticates and peels locally, admits replay state atomically, wraps
  only ciphertext, and forwards through its own link authority.
- The endpoint admits the terminal handle and consumes its open authority.
  Authorities are bound to the signed capability window and operation lifetime;
  a fragment never reuses another fragment's SURB.

## Enforcement / integration points

- `lib/private/surb.js` owns construction, sealing, relay peeling, replay
  admission, and one-use open/forward authorities. The original buffer API is
  superseded by the construction note's ownership amendment.
- `surb-batch.js`, `routed-dht.js`, and `fragments.js` implement the authenticated
  V2 batch and bounded reply-fragment profile.
- `dht-exit-io.js`, relay-local `processRelaySurbHop`, and the routed IO/live
  authority connect the production reply path. No exit-side local peel is used.
- The controller's counted required-mode hold covers query construction,
  retries, and put commit, with cleanup even if query construction throws.
  Mutable-get refresh remains restricted to correlated reply mode.

## Security invariants (must hold)

1. A SURB is single-use: a second use of the same SURB nullifier within its epoch is
   rejected as replay; the reply is delivered at most once.
2. No SURB descriptor grants the exit the endpoint's network address or open
   authority. Return-path handles do not grant arbitrary dial authority.
3. Each return relay learns only its own next hop (same guarantee as the forward path);
   no relay can read the reply payload (inner AEAD to the initiator).
4. SURB secrets and open authorities are fresh per fragment, bound to the
   capability/operation lifetime, and erased on consume, expiry, or teardown.
5. Intermediate forward relays cannot read the source-to-exit inner request or
   substitute its authenticated reply mode and descriptors across contexts.
6. `required` mode: if a reply requires a SURB and none is present or it is invalid/expired,
   the reply is dropped — never a fallback that reveals the initiator, never a downgrade
   of the pinned guard.
7. A correlated-mode request retains the existing correlated reply behavior.
   That is not a fallback from a failed required-mode request.

## Resolved integration decisions and open gates

- **Wire budget:** `ROUTED_REQUEST_V2` (`0x0103`) wraps an unchanged V1 request
  and up to eight 436-byte descriptors. The generic envelope ceiling is
  4,910 bytes; a maximum legal immutable-put body with eight descriptors is
  4,839 bytes. Multi-cell request carriage is implemented; no RLN proof is added.
- **Large replies:** each fragment gets an independent SURB. The
  `SURB_REPLY_FRAGMENT_PROFILE` carries 492 bytes per fragment, at most eight
  fragments / 3,936 reply-message bytes. Larger replies fail closed.
- **Mode selection:** correlated is the default; required mode is explicit and
  experimental, with no correlated fallback. Reads and writes are proven on the
  live gate, including presence revocation and authenticated tombstone resolution.
- **Return path:** the current integration uses the route's own reverse relays;
  independent path selection or lifetime is not implemented.
- **Open:** external cryptographic review, public required mode, peer-stream
  design, and any future mixing/lifetime amendment remain separate gates.

## Non-goals

The correlated V1 wire and default behavior are unchanged. No economic layer,
public constructor, peer-stream implementation, or mixing scheduler is added.
Guard pinning and forward-path selection remain intact. This gate does not
defeat a global passive observer or guard/exit timing correlation and makes no
production anonymity claim.
