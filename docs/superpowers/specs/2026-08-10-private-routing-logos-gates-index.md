# Private Routing: Logos-Lessons Gate Set — Index

**Date:** 2026-08-10
**Source analysis:** [`../../private-routing-logos-lessons.md`](../../private-routing-logos-lessons.md)

Four candidate hardening ideas were derived from the Logos/Nym/Loopix/Tor-v3 prior art and
mapped onto v1's `Out of scope` list. **Important scope correction:** this protocol keeps
everything inside the hyperdht peer network — there is **no exit from the DHT** (that would
be a separate VPN-service protocol, not this one). That closed-world reality prunes the set
substantially. None is owner-approved; anything that survives is gated behind the existing
testnet + external-review bar.

| Gate | Property | Status | Notes |
|---|---|---|---|
| **A** | Anonymous admission (Sybil/abuse control) | **DROPPED — not this protocol** | No exit ⇒ only abuse is relay resource exhaustion, already bounded by `relay-service.js` quotas. [analysis/decision record](./2026-08-10-private-routing-admission-analysis-note.md) |
| **C** | DATAGRAM SURB reply path | OPTIONAL — optimization | STREAM circuits already carry bidirectional replies; SURBs add connectionless / timing-decoupled / private-peer request-response. Not required for a closed peer network. [datagram-surb](./2026-08-10-private-routing-datagram-surb-design.md) |
| **D** | Blinded, epoch-rotating presence-record keys | FORWARD NOTE — requirement | Still relevant: private presence records stored on DHT nodes need enumeration resistance. Fold into the future presence-record gate. [blinded-presence-keys](./2026-08-10-private-routing-blinded-presence-keys-note.md) |
| **B** | Scoped mixing + cover traffic | FORWARD NOTE — research-grade | Still the only thing addressing timing correlation / passive observers inside the network. Later gate. [scoped-mixing](./2026-08-10-private-routing-scoped-mixing-note.md) |

## What actually applies to a closed peer network

The core private-routing design (guards, 3-hop circuits, fixed padded cells, per-context
AEAD) already provides the privacy this protocol needs. Of the imported extras:

1. **A is out** — admission control protects an exit; there is no exit. Relay resource
   limits are the existing quotas.
2. **C is optional** — an optimization for connectionless / mix-compatible replies and
   lightweight private-peer request/response; not needed while STREAM circuits handle
   replies.
3. **D** remains a real requirement for whenever address-free presence records
   (`lookup`/`announce`) are built — storage nodes must not enumerate/link private services.
4. **B** remains the only route to timing-correlation / passive-observer resistance; hard,
   research-grade, and it must stay off the STREAM fast path (mix the signaling, not the
   payload).

## Not borrowed from Logos

Blockchain / consensus / token layer; mix-everything-by-default; libp2p/nim-libp2p
transport; **zk-RLN and any anonymous-admission scheme** (no exit to protect, and RLN needs
a proving-system dependency + a poorly-scaling replicated membership set). hyperdht stays
native on UDX/dht-rpc, no new dependencies.
