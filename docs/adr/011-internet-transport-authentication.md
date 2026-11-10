# ADR-011: Keyed Internet Channels and Signed DHT Records

## Status

Accepted (2026-11-10)

## Context

The internet transport (spec §8.4) is the only transport that carries traffic
between nodes with no physical proximity, and the only one whose peers are
reached by address rather than by being in radio range. Three defects made it
the weakest link in the system (ROADMAP T-09):

1. **The `Hello` was a bare assertion.** `Hello { node_id, listen_port }`
   carried a NodeId and nothing else. A node that claimed an id was believed,
   and `TransportManager` then installed a route for that id, so any internet
   peer could take delivery of any node's traffic by naming it. Every other
   ingress path in the codebase enforces `NodeId = SHA-256(identity key)`
   (spec §14.3); this one had no key to check it against.

2. **`max_connections` was configuration only.** Nothing read it. Connections
   were accepted until the process ran out of file descriptors.

3. **Framing was JSON.** `serde_json` writes `Vec<u8>` as a list of decimal
   numbers, expanding a mesh payload about 5×. `mtu()` advertised 1 MiB and the
   receiver's frame cap was also 1 MiB, so a send at the advertised MTU was
   always rejected and the real ceiling was around 210 KB.

The DHT underneath had its own gaps: records were a bare `NodeId → SocketAddr`
map that any peer could write to for any id, with no expiry, no cap, and no
lookup beyond "ask whoever is already connected".

### Why a signature over nonces is not enough

The first attempt at (1) was a signature over two exchanged nonces, with the
signer's own nonce placed first on the theory that the fixed order prevents a
relay. **It does not,** and the reasoning is worth recording because it looks
sound:

An attacker A wants to authenticate to S as the victim V. A connects to S and
learns `s_nonce`, then connects to V and offers `s_nonce` as *its* challenge.
V replies with `v_nonce` and signs `(v_nonce, s_nonce, V_key, V_port)`. A now
sends `v_nonce` to S as its own challenge — it has not sent one yet, and
nothing obliges it to — and forwards V's signed hello. S checks the signature
against `(peer_nonce = v_nonce, my_nonce = s_nonce)`: exactly what V signed.
A is authenticated as V.

Reordering the fields does not help, because the attacker always gets to choose
its own nonce *last* on each connection. Nor do role or identity binding: A can
be the client on one connection and the server on the other, and can claim S's
identity to V without ever having to prove it, because a responder sends its
hello after receiving the initiator's.

The property actually needed is **channel binding**: authentication has to
attach to something only the real peer can continue to use, not to a transcript
that can be replayed into another connection. That also answers a second
problem the nonce design ignored — TCP has no integrity, so even a perfect
handshake authenticates only the first frame.

## Decision

### Signed ephemeral keys and sealed frames

Each side generates a fresh X25519 ephemeral keypair and signs the **public
key** with its identity key:

```
→ Hello { identity_key, ephemeral_public, listen_port, signature }   (cleartext)
← Hello { identity_key, ephemeral_public, listen_port, signature }

signature = Ed25519( b"mycelium-internet-hello-v2:"
                   ‖ ephemeral_public(32) ‖ identity_key(32)
                   ‖ listen_port(2 LE) )
```

Both sides verify, then derive the channel:

```
shared     = X25519(my_ephemeral_secret, peer_ephemeral_public)
transcript = SHA-256( b"mycelium-internet-channel-v1:"
                    ‖ min(eph)‖max(eph) ‖ min(id)‖max(id) )
prk        = HKDF-Extract(salt = transcript, ikm = shared)
k_send     = HKDF-Expand(prk, b"frame:" ‖ my_ephemeral_public)
k_recv     = HKDF-Expand(prk, b"frame:" ‖ peer_ephemeral_public)
```

and prove possession of it before anything is installed:

```
→ Confirm { transcript }   sealed under k_send, counter 0
← Confirm { transcript }
```

Every frame after the two `Hello`s is AES-256-GCM under the sending
direction's key, with the frame counter as the nonce. Counters are per
direction and advance **only on success**, so a forged frame cannot
desynchronise the channel, and a replayed or reordered frame simply fails to
open — TCP already guarantees ordering, so strictness costs nothing.

Keying each side's send key with *its own* ephemeral public key makes the
derivation symmetric: the peer's receive key matches without either side
needing to know who dialled. The transcript sorts both pairs for the same
reason.

Why this closes the relay: A can forward V's signed `Hello`, and S will accept
the signature. But S derives its keys from V's ephemeral public key, and A has
no ephemeral secret for it. A cannot produce the `Confirm` frame, so the
handshake fails and nothing is installed; and even if confirmation were
skipped, A could not send or read a single frame. A full forwarding relay is
still possible, but that is not impersonation — it is being a transparent TCP
hop between two nodes whose channel is keyed end to end.

Additional checks: a peer that echoes our own ephemeral key is refused (both
directions would share a key stream), and so is one whose key yields an
all-zero shared secret, which only a low-order or zero point does.

The NodeId is **derived** from the `identity_key` in the `Hello` and never
carried, so §14.3's binding cannot be violated by construction. The
`listen_port` is signed because it becomes the peer's dialable address in the
DHT; unsigned, a man in the middle could redirect every future dial for that
node. An inbound peer's dialable address is its socket IP with that signed
port, not the socket's ephemeral source port, which was never usable for
dialling back.

The inbound and outbound paths run the *same* `establish` function; the
previous code had two copies of this logic, which is how they came to differ.

### Connection slots are a semaphore

`max_connections` becomes `Semaphore` permits. A permit is taken **before** the
handshake and held for the connection's lifetime, inbound and outbound alike,
so connections that never finish a handshake still count. With no permit the
socket is dropped immediately; the peer sees EOF rather than a hello.

Taking the permit before the handshake rather than after is the point: an
attacker who opens sockets and stalls is exactly the case the limit exists for.

`stop()` cancels, waits for the accept task to drop the listener, and then
waits for every permit to come back. Connection tasks are deliberately *not*
joined — one of them can itself dial out through `DhtRpc`, so joining them from
`stop()` would deadlock — and their permits are the observable proof that they
are gone, stalled handshakes included.

### Binary framing

4-byte little-endian body length, then a 1-byte tag and fixed-width fields,
little-endian throughout to match §4:

```
0x01 MeshData   sender(32) len(4) bytes
0x02 Dht        request_id(8) <body>
0x03 DhtReply   request_id(8) <body>
0x05 Hello      identity_key(32) ephemeral(32) listen_port(2) signature(64)
0x06 Confirm    transcript(32)
```

`MAX_WIRE_MESSAGE` (1 MiB) caps the frame body as it appears on the wire —
ciphertext, tag included. A cleartext handshake frame is capped far lower
(`MAX_HANDSHAKE_FRAME`, 1 KiB) so a peer cannot make us allocate a megabyte
before it has proved anything. `mtu()` is the frame cap minus the 16-byte AEAD
tag and the 37 bytes `MeshData` framing costs, so a send at the advertised MTU
is exactly one frame the receiver accepts; `send()` refuses anything larger up
front with `ExceedsMtu` instead of writing a frame the peer will discard.

The decoder is a bounds-checked cursor whose every length check subtracts on
the trusted side (`len - pos`), rejects trailing bytes, caps a `FoundNodes`
list at 64 entries, and refuses unknown tags. A declared payload length is
checked against the bytes actually present before anything is allocated.

### DHT records are signed, dated, capped and expiring

A stored record is a node's signed claim about its own address:

```rust
struct DhtRecord { public_key: [u8; 32], addr: SocketAddr,
                   published_at: u64, signature: [u8; 64] }
```

signed over `b"mycelium-dht-record-v1:" ‖ public_key ‖ addr ‖ published_at`,
and keyed under `SHA-256(public_key)`. `store_record` refuses, in order: a bad
signature; a timestamp more than 300 s in the future; a record already past
`RECORD_TTL_SECS` (3600); a record no newer than the one held; and finally a
full store. The "no newer" rule is what stops a captured older record being
replayed to roll an address back to one the attacker still controls.

The store is capped (`max_records`, default 4096) and swept of expired entries
before every insert. At capacity the entry closest to expiry is evicted rather
than the new record refused, because refusing would let whoever fills the store
first lock everyone else out of it.

**A record found over the network goes through the same `store_record`**, and
is returned to the caller only if it was accepted. Checking the signature alone
would have handed callers addresses the node itself considers expired or
future-dated.

A DHT request carries **no sender identity**. The sender is whoever completed
the handshake on the connection it arrived over, so a self-asserted sender in
the body would only ever be a way to put an address you do not own into
someone's routing table. For the same reason, in-flight requests are tracked
**per connection**: with one shared map, any authenticated peer could answer a
request addressed to another by guessing its id, suppressing the real reply or
injecting referrals. A pending entry is cleared by a drop guard, so a lookup
that is cancelled or times out cannot leave it behind.

We offer our own record to every peer we authenticate, and re-sign and re-offer
it every `RECORD_TTL_SECS / 3`. Publishing only at connection setup would make
a node with a long-lived connection unresolvable once its record expired.

### Lookups terminate on bounds, not on luck

`iterative_find_value` drives α-parallel `FindValue` rounds over a `DhtRpc`
trait the transport implements, correlating replies by `request_id`. It stops
at the first of: the record found; every one of the k closest known nodes
queried with nothing closer turning up; `MAX_LOOKUP_ROUNDS` (16); or
`LOOKUP_TIMEOUT` (10 s), with `REQUEST_TIMEOUT` (2 s) per request. The deadline
bounds the requests *in flight*, not merely the gap between rounds, so a round
starting just before it cannot run on for another two seconds. A visited set
means a referral cycle costs each peer exactly one query.

A `FoundValue` is accepted only if its derived NodeId is the target and the
record passes `store_record`, so a peer cannot answer a lookup with a validly
signed record belonging to someone else, nor get such a record cached under the
target's id.

## Consequences

**Easier:**

- An internet peer is now as well identified as a BLE one: the same
  `NodeId = SHA-256(identity key)` rule, proved rather than asserted, and bound
  to a channel it has to keep using.
- Frame-level integrity. Injecting, altering, replaying or reordering a frame
  on an established connection all fail, which previously nothing detected.
- A send at the advertised MTU works, and a mesh payload costs 37 bytes of
  framing plus a 16-byte tag instead of 5× its own size.
- The DHT can be made to actually resolve addresses, because lookups now
  terminate and records cannot be forged by the peer relaying them.

**Harder:**

- **Breaking wire change.** The handshake, the framing and the DHT messages all
  change at once. The protocol is `0.1-draft` with no deployed nodes, so no
  shim is provided; a pre-change node fails to parse the first frame.
  Precedent: ADR-005, ADR-009, ADR-010.
- `InternetTransport::new` now takes `Arc<Identity>` rather than a `NodeId`,
  because it has to sign. Callers reach it through `Node::identity_handle()`.
- Two round trips and an X25519 exchange before any data flows, then an AEAD
  seal and open per frame. For a TCP overlay carrying already-encrypted mesh
  payloads that is a small cost on top of the Double Ratchet's.
- **No forward secrecy claim is made for the channel.** The ephemeral keys are
  per connection, so a later identity-key compromise does not decrypt captured
  frames — but the payloads inside are already end-to-end encrypted (§5.3), and
  the channel key exists for authentication and integrity, not confidentiality.
- A peer that sends a well-formed but unverifiable `Hello` still costs us a
  socket and a slot for up to `HANDSHAKE_TIMEOUT` (10 s). The slot accounting
  bounds that; it does not eliminate it.
- **A record for a wildcard listen address is neither stored nor published.**
  The default `0.0.0.0:9736` cannot be published usefully, and signing
  `0.0.0.0` would produce a valid, useless record that `FindValue` would then
  serve. Learning our externally reachable address is ROADMAP T-31, and until
  it exists the DHT only holds records for nodes configured with a concrete
  address.
- **DHT contacts are kept after a disconnect**, because the stored address is
  the thing that lets a peer be dialled again. Nothing prunes a contact that
  has gone for good, so a k-bucket can fill with dead entries and refuse live
  ones; that needs bucket liveness checks (ROADMAP T-32).

## Alternatives Considered

1. **Sign exchanged nonces, with the signer's own nonce first.** Implemented
   first and discarded: see "Why a signature over nonces is not enough" above.
   The attacker chooses its nonce last, so field ordering, role binding and
   peer-identity binding are all relayable. Recorded here because the flaw is
   not visible from the signed payload alone.
2. **TLS, or the full Noise framework.** Both solve this properly and bring a
   dependency, a certificate or key-pinning story, and a second identity system
   alongside the Ed25519 one the rest of the protocol uses. What is implemented
   here is a signed-ephemeral pattern in the same shape as Noise `IK`, built
   from primitives the project already depends on (X25519, HKDF, AES-GCM,
   Ed25519) and reviewed as about 200 lines rather than trusted as a black box.
   Revisit if the channel ever needs rekeying, 0-RTT or padding.
3. **Authenticate the handshake and leave later frames in the clear.** Half the
   work and it leaves TCP's lack of integrity exposed on the one transport that
   crosses untrusted networks. Once a key exists, sealing frames with it is
   nearly free.
4. **Carry the NodeId in the `Hello` alongside the key and check they match.**
   Equivalent when implemented correctly and one more field that can be got
   wrong. Deriving it is the same check with nothing to forget.
5. **Refuse new records when the store is full.** Simpler than eviction, and it
   hands the store to whoever fills it first. Evicting the entry closest to
   expiry keeps the table churning.
6. **Protobuf or Cap'n Proto for framing.** The project already hand-writes its
   binary codec for the mesh envelope (§4) because the Cap'n Proto toolchain is
   not available in this environment; a second encoding scheme for one transport
   is not worth the inconsistency.
