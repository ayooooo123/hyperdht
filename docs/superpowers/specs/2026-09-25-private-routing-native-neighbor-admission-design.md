# Private Routing: Native Relay-Neighbor Admission (per-node admission owner)

**Status:** DRAFT for owner review. JD chose option A (two-party grants) on
2026-09-25. This draft fits option A inside the peer-stream design packet §3.4
contract; see "Trust model" for where the two differ. No code has been written.
**Date:** 2026-09-25
**Relates to:** [peer-stream design packet §3.4](2026-09-09-private-routing-peer-stream-design-packet.md#34-native-relay-neighbor-prerequisite-and-separate-service-accounting),
[migration record, open gates](../../private-routing-migration.md#current-implementation).
**Review gate:** the grant format below is new signed data, and its digest
crosses the wire inside NAT punch plans. It must be part of the named external
cryptographic review before public exposure.

## Problem

The dormant native peer-tail stack (A0 source↔guard, A1 guard↔safety, A2
safety↔terminal) only runs inside `setupFourNodeNativeFixture`
(`test/private/peer-native-fixture.js:838`). A0 already has an authority-free
production path (dynamic bootstrap link handles,
`lib/private/udx-cell-endpoint.js:1153`). A1 and A2 do not. For those links the
fixture supplies things no production component provides:

| Fixture input                                                            | Where                                          | Production owner needed                                          |
| ------------------------------------------------------------------------ | ---------------------------------------------- | ---------------------------------------------------------------- |
| One `grantAuthority` key signs every relay↔relay topology grant          | `peer-native-fixture.js:886`, `:1179`, `:1395` | Per-node configured authority and a grant source                 |
| One `LinkDirectory` per node and role, fixed epoch `7n`, fixed `runId32` | `:1153`–`:1177`, `:1369`–`:1393`               | Admission owner builds directories from config                   |
| Hand-paired `provisionPeerNativeNeighbor` calls on both ends at once     | `:1252`, `:1458`                               | Admission owner dials and accepts on its own                     |
| Shared static key pair and seeded circuit/local IDs for link setup       | `:1217`–`:1240`, `buildSessionOptions` `:1663` | Fresh random IDs; responder static key from an authorized source |
| Advertisements built in place (`issuedAt: 1000n`, fixed `expiresAt`)     | `:938`–`:1083`                                 | Relay owner publishes and refreshes                              |
| Fake clock                                                               | `:869`                                         | Real clock; the modules already take clocks as input             |
| Fixed service budgets (`nodeServiceCells`, `serviceCells`)               | `:996`–`:1011`                                 | Config with checked defaults                                     |

Nothing in `lib/` constructs a `LinkDirectory` today (only the class in
`lib/private/topology-grant.js:714` exists), and nothing calls
`createDynamicResponderSetup` (`lib/private/link-bootstrap-session.js:74`).

## Contract this design must keep (packet §3.4)

1. Each relay owns a non-exportable, bounded neighbor-link pool built through
   the existing topology-grant → `LinkDirectory` → `UdxCellEndpoint.openLink` →
   native link-bootstrap chain.
2. **Only locally configured, authenticated topology authority may provision
   that pool.** A source request, decoded advertisement, direct ACTIVE proof, or
   caller-supplied address cannot mint a topology grant or native dial
   capability.
3. After D1/D2, extension needs an existing live neighbor owner matching the
   exact verified advertisement; a missing owner rejects with no dial fallback
   (`lib/private/peer-native-neighbors.js:858`–`:874`).
4. Neighbor provisioning and maintenance charge a separate finite node-level
   ledger at the real native send boundary. Circuit allowances cannot fund it.

## Trust model

**The fixture's single shared key is one configuration, not a requirement.**
§3.4 asks for a locally configured authority on each node, not one signer for
the whole network.

**Option A, fitted to §3.4:**

- Each node is configured with a set of trusted authority public keys. By
  default this set holds exactly one key: the relay's own identity key, so
  each relay operator is their own authority. Operators who run several relays
  can put one operator key there instead.
- A relay↔relay link needs one grant carrying two signatures: one by an
  authority trusted by endpoint A, one by an authority trusted by endpoint B.
- Each node checks both signatures, but **only its own side's signature
  admits the link locally.** The peer's signature proves the peer consented
  and makes the grant one shared object, so both ends compute the same
  `digest32`. That shared digest is required: NAT punch plans carry
  `topologyGrantDigest32` (`udx-cell-endpoint.js:6491`), so two different
  one-sided grants could not punch.
- **A node signs a grant only because local operator policy says so.**
  Seeing a valid advertisement on the DHT never causes signing. That is the
  §3.4 line. A mode that countersigns automatically for any advertisement that
  passes checks would let an advertisement mint dial capability. It is out of
  scope here and would need a packet amendment.

**What this changes, stated plainly:** the network becomes a graph of
operator-agreed relay pairs. Because of rule 3 (no dial fallback), a source's
guard→safety→terminal path must follow existing edges. A sparse graph shrinks
the set of possible paths and lets an observer who knows the graph narrow the
guess. This limit belongs next to KI-1 and KI-5 in the known-issues list.

## Grant format 1

Format 0 (`TOPOLOGY_GRANT_FORMAT = 0`, one signature) stays for the routed-DHT
stack and its process harness, which use a single topology owner. Format 1 is
used only by the peer native path.

Unsigned body = format 0 body with `format = 1`, plus per endpoint:

- `authority32`: the authority key that signs for this endpoint;
- `linkStaticKey32`: the X25519 static key this endpoint uses when it
  responds to a link setup.

Signed encoding = unsigned body `| signatureA64 | signatureB64`. Both
signatures cover `hash(DOMAIN.TOPOLOGY_GRANT_V1, unsigned)` under a new
domain label `hyperdht-private-routes/topology-grant/v1`. Endpoint ordering
keeps the format 0 rule (sorted by identity, `topology-grant.js:278`), so
signature order is fixed.

Why the grant carries `linkStaticKey32`: link setup requires the initiator to
hold the responder's 32-byte X25519 static public key before it sends
`LINK_CREATE`. The initiator seals the setup challenge to that key, and the
responder proves it owns the key (`lib/private/link-setup.js:742`, `:765`,
`:859`, `:983`). Nothing in production supplies this key today. The fixture
hands both sides one shared pair (`peer-native-fixture.js:1217`). The 260-byte
advertisement carries `routeEncryptionPublicKey32`, but that key already
serves the §3.2 ACTIVE route-key proof (packet line 541).

§3.4 does not force this choice. It forbids an advertisement from minting
authorization. It does not forbid an authenticated advertisement from
supplying a setup key after a locally authorized grant exists. The choices
are:

- **Key in the grant (this draft's default).** One X25519 key serves one
  protocol. The key is fixed for the life of the grant, and both authorities
  sign it. Cost: rotating the key needs a new grant, and new grants are
  swapped out of band.
- **Reuse `routeEncryptionPublicKey32`.** No new field, and the key rotates
  whenever the advertisement is refreshed. Cost: one X25519 key is used in two
  protocols, so the reviewer must check both uses together. Reconnects after a
  refresh also need the peer's current advertisement.
- **New advertisement field.** The key rotates with the advertisement and is
  used for one purpose only. Cost: it changes the fixed 260-byte advertisement
  and every check tied to that size.

`LinkDirectory` gains an `authorityPublicKeys` set for format 1. `add()`
requires `local.authority32 ∈ authorityPublicKeys` and both signatures valid,
then keeps every existing check: epoch, `runId32`, role, expiry, bounds and
tombstones.

## Per-node admission owner

New package-private module `lib/private/peer-neighbor-admission.js`. One per
relay node. It owns:

- **Config:** trusted authority keys, the node's format 1 grants, the service
  budget, and the relay owner and endpoint. Clocks come from the real clock.
- **Directories:** one `LinkDirectory` per `(localRole, epoch, runId32)`. A
  directory binds one local role (`topology-grant.js:785`), and a safety relay
  is `SAFETY_FINAL` toward its guard but `SAFETY_GUARD` toward its terminal
  (fixture `:1166`, `:1369`).
- **Dialing:** the endpoint with `INITIATE` in the grant dials, using fresh
  random `circuitId` and local IDs and the peer's `linkStaticKey32` from the
  grant.
- **Accepting:** the responder uses `createDynamicResponderSetup` with its own
  static secret and identity secret, and learns IDs from `LINK_CREATE`
  (`link-bootstrap-session.js:116`–`:140`).
- **Neighbor pools:** `createPeerNativeNeighborPool` and
  `provisionPeerNativeNeighbor`, with the pool's `nodeServiceBudget` as the
  §3.4 separate ledger. No other budget funds service traffic.
- **Upkeep:**
  - renew a link before its grant expires;
  - reconnect after native loss, charged to the service ledger;
  - re-provision when the peer refreshes its advertisement, because neighbor
    matching compares the exact 260 advertisement bytes
    (`peer-native-neighbors.js:863`);
  - revoke a neighbor when its ledger runs out or it expires.
- **Teardown:** destroys pools, directories and pending setups, and erases key
  material, in the same way as the fixture's `closeFixtureResources`.

The owner exposes no dial method that takes an address or advertisement.
Callers can only read neighbor state and let the tail control look up a
matching neighbor.

## Grant exchange (v1: out of band)

No new network message. An operator tool (subcommand of `bin.js`):

1. `grant draft`: reads local config plus the peer's shared line (identity,
   role, host, port, operations, authority key, link static key). It writes the
   unsigned format 1 body.
2. `grant sign`: signs one side with the local authority key.
3. The operators swap the half-signed grant; the second side signs.
4. `grant add`: installs the fully signed grant into the node's config.

Signing grants online over the network is not in scope. It would be a new
wire protocol, and it would need rules proving that no advertisement or remote
request can trigger a signature.

## Public surface

Nothing new on `dht.privateRouting` in this step. The admission owner is
package-private and runs only under tests until the external review covers
format 1. The public alpha stays on the current four-relay peer stream.

## Open questions (with the default this draft uses)

1. **Epoch meaning.** The grant epoch must match on both ends (`LINK_CREATE`
   check, `link-bootstrap-session.js:125`). Default: one deployment-wide
   constant, configured, like the fixture's `7n`. Rotation is later work.
2. **D1 DIRECTORY choice.** Mode 1 lets the guard pick a safety by random
   target. Under rule 3, a pick that is not a live neighbor fails with
   `ERR_PRIVACY_UNAVAILABLE`. Default: the guard picks only from its live
   neighbors whose role and mask match. This needs a packet note, because the
   current text does not say so.
3. **Supplied terminals.** A destination's supplied private terminal must be
   a neighbor of the source's safety relay. Default: fail closed and report
   it; do not dial.
4. **Format 0 and 1 side by side.** Default: keep both, each used by a
   different stack. The other choice is to move the routed-DHT harness to
   format 1 as well, which touches the reviewed Gate 3B1 path.
5. **Where the link static key lives.** Default: in the grant (see "Grant
   format 1"). Pick this before step 1, because it decides whether format 1
   has the `linkStaticKey32` field.

## Plan outline

1. Grant format 1: encode, decode, verify, domain label, and `LinkDirectory`
   authority set, with vectors and hostile-shape tests. Node and Bare.
2. Admission owner: config, directories, dynamic accept, dial with fresh
   randomness, and pool wiring.
3. Upkeep: renewal, reconnect, advertisement refresh, ledger exhaustion. Every
   send is charged at the native send boundary.
4. Rebuild the four-node setup on the admission owner with a real clock and
   out-of-band grants. Run the existing `peer-tail-control` suite against it.
5. Packet capture: each captured service packet is assigned to exactly one
   send owner, and service totals are reported apart from circuit work (§3.4
   final paragraph).
6. Operator tool for the grant commands.
7. Update the migration record, the README alpha section and the review
   packet, and add the path-graph limit to known issues.
