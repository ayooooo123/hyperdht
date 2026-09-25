# Private Routing: Native Relay-Neighbor Admission (per-node admission owner)

**Status:** APPROVED by JD on 2026-09-25 (option A, two-party grants), fitted
to the peer-stream design packet §3.4 contract; see "Trust model". Step 1
(grant format 1) is implemented. JD deferred external cryptographic review
on 2026-09-25; work proceeds on internal review only.
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

Unsigned body = format 0 body with `format = 1`, plus `authority32` per
endpoint: the authority key that signs for that endpoint.

Signed encoding = unsigned body `| signatureA64 | signatureB64`. Both
signatures cover `hash(DOMAIN.TOPOLOGY_GRANT_V1, unsigned)` under a new
domain label `hyperdht-private-routes/topology-grant/v1`. Endpoint ordering
keeps the format 0 rule (sorted by identity, `topology-grant.js:278`), so
signature order is fixed.

**Link setup key.** Link setup requires the initiator to hold the responder's
32-byte X25519 static public key before it sends `LINK_CREATE`: the initiator
seals the setup challenge to that key and the responder proves it owns it
(`lib/private/link-setup.js:742`, `:765`, `:859`, `:983`). §3.4 forbids an
advertisement from minting authorization, not from supplying a setup key after
a locally admitted grant exists. The routed-DHT link owners already use the
responder's advertised route key for this (initiator
`test/private/process/wire-services.js:813`; dynamic responder `:365`,
`:1861`). The native neighbor path follows that convention: the responder
static key is the `routeEncryptionPublicKey32` of the peer advertisement the
admission owner fetched from the granted identity and address. An earlier
draft put a separate `linkStaticKey32` in the grant; it was removed before any
runtime used it, because it duplicated the fetched key and would have tied key
rotation to out-of-band grant reissue. Cost of reuse: one X25519 key serves
the §3.2 ACTIVE route-key proof and link setup, each under its own
domain-separated derivation.

`LinkDirectory` gains an `authorityPublicKeys` set for format 1. `add()`
requires `local.authority32 ∈ authorityPublicKeys` and both signatures valid,
then keeps every existing check: epoch, `runId32`, role, expiry, bounds and
tombstones.

## Per-node admission owner

New package-private module `lib/private/peer-neighbor-admission.js`. One per
relay node. It owns:

- **Config:** trusted authority keys, the node's format 1 grants, the service
  budget, and the relay owner and endpoint. Clocks come from the real clock.
- **One `(epoch, runId32)` per endpoint.** The NAT traversal authority is one
  per endpoint (`udx-cell-endpoint.js:6002`) and holds one epoch and run ID.
  `readAuthorizedLink` rejects any handle with a different pair
  (`:6285`–`:6287`), and a punch counter-offer requires the offer's grant
  digest, epoch and run ID to equal its own link's (`:6580`–`:6582`). So every
  grant used on one endpoint carries the same pair. A grant carries one pair
  for both ends, so linked relays share it, and so does every relay reachable
  through links. The pair is therefore one deployment-wide config value. The
  admission owner takes it once and rejects any grant with a different pair.
  Changing it is a coordinated restart; rolling rotation would need NAT
  authority scoping per pair and is out of scope.
- **Directories:** one `LinkDirectory` per link attempt, holding exactly one
  grant, with the node's single `(epoch, runId32)`. A link handle is consumed
  by `openLink` (`udx-cell-endpoint.js:2332`), and a directory returns the
  same handle for a grant it already holds, so a retry or reconnect needs a
  fresh directory. The directory lives as long as its neighbor: destroying it
  closes the handle, and the pool's link-close subscription tears the neighbor
  down.
- **Advertisement fetch:** before provisioning, the owner runs the existing
  CAPS/ACTIVE exchange toward the granted peer through
  `createPeerGrantDirectTransport`, the grant-pinned (`'guard'`) discovery
  kind. Identity, address, epoch, grant digest and run ID come from the link
  handle; the advertisement is learned. The exchange's 24-cell reservation
  comes from the pool's node service ledger
  (`reservePeerNativeNeighborService`). Discovery already requires the
  advertised epoch to equal the grant epoch (`peer-direct-bootstrap.js:1298`),
  so every relay advertises the deployment epoch.
- **Dialing:** the side whose grant endpoint may `INITIATE` dials; if both may,
  the lower identity dials. It uses fresh random `circuitId` and local IDs, the
  grant expiry as the signed setup expiry, and the fetched advertisement's
  route key as the responder static key.
- **Accepting:** the responder uses `createDynamicResponderSetup` with its
  route secret and identity secret, and learns IDs from `LINK_CREATE`
  (`link-bootstrap-session.js:116`–`:140`). It waits up to the grant expiry.
  If a branch responder is configured, it is registered on the accepted link
  so the node answers LINK_OFFER extensions from its dialer.
- **Neighbor pools:** `createPeerNativeNeighborPool` and
  `provisionPeerNativeNeighbor`, with the pool's `nodeServiceBudget` as the
  §3.4 separate ledger. No other budget funds service traffic.
- **Upkeep:** the pool reports every published neighbor that ends (native
  loss, link close, or expiry at the earlier of grant and peer advertisement
  expiry) through `onNeighborClosed`. The owner then releases that attempt's
  directory and, after one second, provisions again, which refetches the
  peer's current advertisement. So a peer that refreshes its advertisement is
  picked up when the old one expires.
  - **Renewal:** `addPeerNeighborGrant` installs a newer grant for a known
    peer. The pool holds one neighbor per identity, so the live neighbor keeps
    its current grant; the newer one takes over at the next provisioning.
    There is a short gap at the old grant's expiry. A grant for a new peer
    starts provisioning at once.
  - **Stop:** a slot whose grant has expired with no replacement ends in
    `expired` and does not redial. Three failed attempts in a row end in
    `failed`; a new grant restarts it. Every attempt draws on the finite node
    service ledger, so exhaustion also stops redialing.
- **Teardown:** destroys pools, directories and pending setups, and erases key
  material, in the same way as the fixture's `closeFixtureResources`.

The owner exposes no dial method that takes an address or advertisement.
Callers can only read neighbor state and let the tail control look up a
matching neighbor.

## Grant exchange (v1: out of band)

No new network message. The experimental `hyperdht grant` subcommand
(`lib/private/grant-tool.js`) covers the exchange:

1. `grant draft`: builds the unsigned format 1 body from both endpoints'
   identity, role, host, port, operations and authority key, plus epoch, run
   ID and validity window. Prints hex.
2. `grant sign`: each operator signs the same draft with their own authority
   key file (64-byte secret key or 32-byte seed). Prints the signature.
3. `grant assemble`: joins the two signatures in either order, matching each
   to the endpoint whose authority it verifies under.
4. `grant inspect`: prints the decoded grant and whether both signatures hold.

The fully signed hex is what `createPeerNeighborAdmission` (`grants`) and
`addPeerNeighborGrant` take. There is no node config file yet, so there is no
`grant add`; a relay runtime that loads grants from config is later work.

Signing grants online over the network is not in scope. It would be a new
wire protocol, and it would need rules proving that no advertisement or remote
request can trigger a signature.

## Public surface

Nothing new on `dht.privateRouting` in this step. The admission owner is
package-private and runs only under tests until the external review covers
format 1. The public alpha stays on the current four-relay peer stream.

## Open questions (with the default this draft uses)

1. **Epoch and run ID.** Settled: one deployment-wide `(epoch, runId32)`,
   configured (see "Per-node admission owner"). Rotation is later work.
2. **D1 DIRECTORY choice.** Settled by existing code: directory discovery
   selects only live, published neighbors whose mask matches
   (`peer-native-neighbors.js:1428`–`:1459`).
3. **Supplied terminals.** A destination's supplied private terminal must be
   a neighbor of the source's safety relay. Default: fail closed and report
   it; do not dial.
4. **Format 0 and 1 side by side.** Default: keep both, each used by a
   different stack. The other choice is to move the routed-DHT harness to
   format 1 as well, which touches the reviewed Gate 3B1 path.
5. **Where the link static key lives.** Settled: the peer's advertised route
   key, following the routed-DHT link owners (see "Grant format 1").

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
