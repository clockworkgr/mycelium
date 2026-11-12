# ADR-021: Local Transport Authentication

## Status

Accepted (2026-11-12). **Implementation pending — ROADMAP T-34.**

## Context

The BLE Node ID characteristic (`…7891`) serves a bare 32-byte NodeId and the
Identity characteristic (`…7894`) takes one; Wi-Fi Direct's `Hello` exchanges
the same. No identity key is carried, nothing proves possession of one, and
nothing binds the claim to the connection, so `mycelium_ble_on_peer_discovered`
installs whatever id the platform layer reports. An attacker in radio range can
claim any node's id: `TransportManager` installs a route for it, AODV prefers
the fake neighbour, and that node's traffic is delivered to the attacker and
dropped.

ADR-011 fixed the same defect for the internet transport: carry the identity
key, prove possession against something fresh and connection-bound, and
*derive* the NodeId instead of accepting one.

## Decision

### The local transports run the internet handshake

ADR-011's authenticated-channel handshake runs over the existing fragmentation
layer on BLE and Wi-Fi Direct, rather than a second, BLE-shaped proof in the
Identity characteristic. One proof format and one implementation across all
three transports: the alternative was a challenge written to `…7894` and a
signature read back, which is smaller on the wire but means two authentication
protocols to specify, test and keep in agreement — and the mistakes in this
area are exactly the ones that come from a second path nobody looks at.

The NodeId is derived from the proved key. Nothing in the system installs a
peer from an asserted id, and `…7891` stops being an input.

The cost is on the link: a 20-byte-MTU connection carries a handshake before
it carries anything else, and the platform layers must relay opaque frames
before any peer exists to attribute them to. That reshapes the Kotlin and Swift
bridges, which currently report a discovered peer *by id*.

### Rust and both bridges land together

One task across three languages. There is no build in which a peer is
installed from an asserted id, and no flag anyone has to remember to flip.

The alternatives were a config switch defaulting to today's behaviour — which
ships an insecure default and relies on memory — and landing the Rust side
fail-closed, which leaves BLE and Wi-Fi Direct installing no peers at all
between two commits. A single larger change is the honest cost of not having
either.

## Consequences

**Easier:**

- A peer's identity on every transport is proved, and route poisoning by id
  claim stops being possible rather than being merely bounded.
- One handshake to audit. A change to the proof format applies everywhere at
  once instead of to whichever transport was remembered.

**Harder:**

- A big change in three languages that cannot land incrementally, and cannot
  be verified on real radios until T-15. Until then the spec marker stays
  "Implemented, untested on hardware".
- Connection setup gets slower on BLE, where it is already slow, and the
  handshake has to survive the fragmentation layer's reassembly and the
  reconnection churn that a phone's radio produces.
- The platform bridges stop knowing who they are talking to until the
  handshake completes, so their own bookkeeping — which device address maps to
  which peer — has to be rebuilt around that.
- Wi-Fi Direct's `Hello` becomes redundant and must be removed rather than left
  as a second, weaker path.

## Alternatives Considered

1. **Challenge and signature in the Identity characteristic.** BLE-native and
   cheap on the wire; a second authentication protocol to maintain beside
   ADR-011's.
2. **Install the asserted id but deny it routing privileges.** No wire change;
   an attacker still occupies the id at the transport layer, and "installed but
   untrusted" is a state every later feature has to remember to check.
3. **Rust first behind a flag, bridges later.** Reviewable in pieces, with an
   insecure default in the meantime.
4. **Rust first, fail closed.** No insecure window, and the local transports
   are dead between the two commits.
