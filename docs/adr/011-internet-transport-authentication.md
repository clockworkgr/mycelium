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
   peer could take delivery of any node's traffic by naming it. The *message*
   ingress paths enforce `NodeId = SHA-256(identity key)` — a `SessionInit` or
   `PrekeyResponse` whose key does not hash to the envelope source is dropped
   (spec §14.3) — but this path had no key to check at all.
   The local transports are no better: BLE and Wi-Fi Direct both exchange a
   bare NodeId with no key and no proof of possession (ROADMAP T-34). This
   ADR does not fix those; it is the first transport to prove identity at the
   transport layer, not the last to do so.

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
node. An **inbound** peer's dialable address is its socket IP with that
signed port, because the socket's source port is ephemeral and was never
usable for dialling back. An **outbound** connection keeps the address it
dialled, which has just been proved to work: substituting the signed port there
would break any peer behind a port forward, turning a working `public:443` into
an unreachable `public:9736`.

The inbound and outbound paths run the *same* `establish` function; the
previous code had two copies of this logic, which is how they came to differ.

### One writer task per connection

Sealing a frame advances the direction's counter, so sealing and writing have
to happen together or not at all. A caller cancelled between them — a DHT
lookup hitting its deadline, for instance — would leave a truncated frame on
the wire and every later frame mis-numbered, and the sender would not find out
until some unrelated read failed.

So each connection owns a writer task holding the sealed write half, fed by a
bounded outbox. `enqueue` is **synchronous**: it has no await to be cancelled,
and a full outbox is a failed send rather than a wait, which matches the
bounded-outbox shape the other transports use (§8.4) and lets the node's DTN
layer take over. A write that fails or outlives `FRAME_WRITE_TIMEOUT` shuts
the write half down, so the peer sees EOF instead of trying to parse a partial
frame, and both ends tear the connection down.

This also keeps the read loop's own work inside its cancellation select: it
queues DHT replies instead of writing them, so a peer that stops reading
cannot hold its connection slot past `stop()`.

The write itself *is* inside the writer task's own cancellation select, which
looks like a contradiction and is not: abandoning a half-written frame is safe
exactly there, because the task then cancels the connection and closes the
socket, so nothing more is ever sealed for that channel. Without it, a peer
that stopped reading kept a live socket for the full write timeout after
`stop()` had returned — and the slot had already come back, so the dead socket
escaped `max_connections` altogether.

Each connection therefore has its **own cancellation token**, a child of the
transport's. Either task cancels it on the way out, so a failed writer takes
the read loop with it rather than leaving an entry that can never be written to
and blocks a reconnect, and the permit is shared between both tasks so the slot
returns only when both are gone.

The transport's own token is **replaced, not just cancelled**, by `stop()`:
everything alive is a child or clone of whatever the token was when it was
created, and a later `start()` needs an uncancelled parent. `start()` used to
install a fresh token instead, which silently orphaned any connection made by
`connect_to` before it — a supported case — so a later `stop()` never reached
those sockets or their permits.

`start()` holds the `started` lock until every background task is registered.
Releasing it right after the bind let a `stop()` run to completion in the gap:
it cancelled the token `start()` had already captured, joined a task set the
accept task was not in yet, drained the permits and returned —
while `start()` still held a bound listener it was about to hand to a task
attached to that cancelled token. `stop()` takes the same lock first, so it
now waits for a `start()` in progress.

`started` is set at the **end** of `start()`, once the tasks exist. Set before
the awaits in between, a caller that stopped awaiting mid-startup — the
listener is a local, so it is dropped with the future — left the transport
marked started with no accept task and no way back: every later `start()`
returned `AlreadyStarted`.

The replacement token is published only **after** the drain, and dials are
refused while a `stop()` is in progress. Publishing it first left a window in
which a concurrent dial attached to the new token, survived the cancellation,
had its map entry cleared by the shutdown, and then held its socket and permit
for good.

A dial takes its token **before** it reads the shutdown flag, and both before
it takes a slot. The flag alone is not enough: a dial can read it, be
descheduled, and resume after an entire `stop()` has set the flag, cancelled
the token, drained the permits, published a replacement and cleared the flag
again — at which point nothing it could consult says a shutdown happened, and
taking the token then would attach it to the replacement and install a live
connection on a transport whose `stop()` had already returned, with nothing
left to cancel it. Taking the token first puts every dial on one side or the
other: its token is the one `stop()` cancels, or it is a dial after that stop,
which is a supported `connect_to` on a stopped transport.

### Connection slots are a semaphore

`max_connections` becomes `Semaphore` permits. A permit is taken **before** the
handshake and held for the connection's lifetime, inbound and outbound alike,
so connections that never finish a handshake still count. With no permit the
socket is dropped immediately; the peer sees EOF rather than a hello.

Taking the permit before the handshake rather than after is the point: an
attacker who opens sockets and stalls is exactly the case the limit exists for.
The permit count is clamped to what a single `acquire_many` can request *and*
to `Semaphore::MAX_PERMITS`, which is below `u32::MAX` on the 32-bit Android
targets — a larger configured value used to panic at construction — and the
same effective value is what `stop()` drains.

A dial is cancellable and timed out, and captures the cancellation token
*before* connecting. Both matter: an unreachable host would otherwise hold a
permit for the OS connect timeout and outlive `stop()`, and a dial that
completed after a restart would read the *new* token and install itself on the
restarted transport.

Two connections to one peer exist whenever both ends dial at once, or two
lookups dial the same peer. Both ends have to keep the *same* one: if they
choose differently, each closes the one the other kept and both are lost.

The ordering value is the **channel transcript**: identical at both ends of a
given connection, different between connections, and known to both without any
extra exchange. The lower transcript wins, and the loser's per-connection token
is cancelled. Two weaker rules were tried and are wrong — local arrival order
can differ at the two ends, and "the lower NodeId's connection wins" does not
distinguish two connections opened by the *same* node, which is exactly what
concurrent lookups produce.

A displaced connection closing must emit **no** `NeighborLost`. It is no longer
the entry in the map, and reporting a loss for a peer that is still connected
makes the routing layer drop that peer and its routes while the replacement is
live. The event is therefore tied to actually removing the current entry, and
is emitted **under the connection-map lock**, as `NeighborDiscovered` is. Both
events have to be ordered with the map mutation they describe: emitted after
unlocking, a reconnect could insert and announce itself in between, and the
stale loss would still strip the live peer's routes.

A peer's address becomes a DHT **contact** when it is either proved or
admitted, and the two are not the same moment. Recorded in `establish` for
every connection alike, a contact was written before the duplicate was
resolved, so a connection that lost the tie-break and was closed immediately
still rewrote the contact of the peer whose other channel we kept.

A contact also carries **where its address came from** (`AddrSource`) and
**when that was established** (`addr_proved_at`): `Dialled` for an address we
reached ourselves, `Claimed` for an inbound connection's (its socket IP with
the signed listen port) or a referral from a third node. A claim never
displaces a dialled address — the `public:443` → `public:9736` regression,
reached through the contact table instead of through `dialable_addr` — and
within a level the fresher evidence wins. A claim replacing an older claim is
how a peer that moved is re-learned, since what we hold is no better evidence
than what it now says; a dialled address that has gone stale is for bucket
liveness to remove (T-32), not for a claim to overwrite.

`addr_proved_at` is **not** `last_seen`, and the difference is the whole
point: a connection refreshes its contact on every DHT request it answers,
and those refreshes carry the address *that* connection was made to. Dated
`now`, a long-lived channel's refresh kept reinstating its own endpoint over
one a later dial had proved — so a contact could revert to an address that no
longer reaches the peer. A connection's refreshes therefore carry the instant
its own handshake completed, which is what makes them lose to newer
evidence.

The rule lives in the bucket insert rather than at the call sites, because
there are more of those than is obvious: the first attempt put it in the
transport and `handle_request` — which refreshes the contact of whoever asks —
undid it on the next DHT frame.

A **dialled** contact is recorded as soon as the handshake completes, before
the duplicate is resolved, because a dial that completed proves its endpoint
whatever becomes of that channel. Recorded only in the read loop, the proof
was thrown away whenever the dial lost the tie-break, leaving the inbound
channel's unreachable claim cached for a peer we had just reached at a working
address. A *claim* still waits for admission: recording one early is what put
a closed channel's address in the table to begin with.

A dial made to reach a *particular* node carries that expectation, and a peer
that proves a different identity is refused before anything is installed. The
identity is legitimate, but the connection is not the one that was asked for,
and a stale or dishonest DHT referral should not leave an unrelated peer
holding a slot.

Whatever `stop()` leaves behind is restored by a drop guard rather than by
the tail of the function, because everything after the cancellation can be
abandoned by a caller that stops awaiting mid-drain. Left to the tail, such a
call published no replacement token and never cleared the shutdown flag, so
every later dial was refused for good and `start()` could not run at all.
Abandoning the drains themselves is safe — the connections have already been
cancelled, their read loops remove their own entries and their permits come
back with nobody waiting on them — but the flag and the token are state no
later call would repair.

`stop()` cancels, waits for the accept task to drop the listener, and then
waits for every permit to come back. Connection tasks are deliberately *not*
joined — one of them can itself dial out through `DhtRpc`, so joining them from
`stop()` would deadlock — and their permits are the observable proof that they
are gone, stalled handshakes included. Both waits are bounded by
`STOP_DRAIN_TIMEOUT` and log on expiry, and the bootstrap dial is cancellable
and timed out, so a task that ignores cancellation cannot make `stop()` hang.

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

The DHT bodies follow the 8-byte `request_id`:

```
request  0x01 Ping        —
         0x02 FindNode    target(32)
         0x03 FindValue   key(32)
         0x04 Store       <record>
reply    0x01 Pong        —
         0x02 FoundNodes  count(2) then count × [ node(32) <addr> ]
         0x03 FoundValue  <record>
         0x04 Stored      —
         0x05 Rejected    —

<addr>   family(1): 4 → octets(4) | 6 → octets(16), then port(2)
<record> public_key(32) <addr> published_at(8) signature(64)
```

`<addr>` is the one canonical address encoding, used on the wire *and* inside
the record's signed payload, so a signature can only verify against the same
address bytes the signer meant. `FoundNodes` carries at most
`MAX_FOUND_NODES` (64) entries and the encoder truncates to that, so it can
never produce a frame its own decoder would reject.

The AEAD nonce is the frame counter and nothing else: 12 bytes, the first four
zero, the counter little-endian in the last eight. No associated data is
passed, because a frame's only context is the key (one per direction) and that
counter. The counter is refused rather than wrapped when it would overflow
(`CounterExhausted`), so a (key, nonce) pair is never reused.

`MAX_WIRE_MESSAGE` (1 MiB) caps the frame body as it appears on the wire —
ciphertext, tag included. A cleartext handshake frame is capped far lower
(`MAX_HANDSHAKE_FRAME`, 1 KiB) so a peer cannot make us allocate a megabyte
before it has proved anything, and the sealed `Confirm` frame — read *before*
the peer has proved the channel key — is capped at its exact 49-byte size.
`mtu()` is the frame cap minus the 16-byte AEAD tag and the 37 bytes
`MeshData` framing costs, so a send at the advertised MTU is exactly one frame
the receiver accepts; `send()` refuses anything larger up front with
`ExceedsMtu` instead of writing a frame the peer will discard.

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
target's id. One exception is deliberate: when `store_record` says the answer
is no newer than what we hold, the lookup returns the **cached** record rather
than nothing, because that is what a second lookup racing the first looks like
and reporting "not found" there would make concurrent resolution fail at
random. For the same reason, a lookup whose own dial was refused as a duplicate
re-reads the connection map before giving up: another lookup may have dialled
the same peer and won, and that connection is perfectly usable.

## Consequences

**Easier:**

- An internet peer is now *better* identified than a local-mesh one:
  `NodeId = SHA-256(identity key)` is proved rather than asserted, and bound to
  a channel the peer has to keep using. BLE and Wi-Fi Direct still install the
  id their platform layer reports (ROADMAP T-34), so this is the only
  transport where a peer's id is proved where the connection is made.
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
- **Resolution exists but nothing calls it.** `InternetTransport::resolve`
  will find a peer's address through the DHT, and no send path asks it to: a
  `send` to an unconnected peer still fails with `PeerNotConnected`. Dialling
  through the DHT is ROADMAP T-33, kept separate because it changes when the
  transport opens connections, not how it authenticates them.
- **A connection opened only to ask a DHT question is never closed.**
  `DhtRpc::request` dials the peer it needs and installs an ordinary
  connection, so a node running many lookups would hold a slot for each one
  and then refuse the dials that follow fresh referrals. Nothing reaches that
  path yet — `resolve()` is its only caller and nothing calls `resolve()` — so
  it becomes real exactly when T-33 wires resolution into the send path, and
  it is an acceptance criterion there: lookup connections need a lease or idle
  eviction.
- A cancelled send can now lose a queued frame instead of corrupting the
  channel. That is the right trade for a transport under a protocol with its
  own retry and DTN fallback, but it does mean `send` returning `Ok` means
  "queued", not "written".

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
   Ed25519) and reviewed as under 300 lines rather than trusted as a black
   box.
   Revisit if the channel ever needs rekeying, 0-RTT or padding.
3. **Authenticate the handshake and leave later frames in the clear.** Half the
   work and it leaves TCP's lack of integrity exposed on the one transport that
   crosses untrusted networks. Once a key exists, sealing frames with it is
   nearly free.
4. **A shared writer behind a mutex, with callers sealing and writing.** What
   was implemented first. It puts a cancellation point between the seal and the
   write, which silently corrupts the channel; and it puts an unbounded wait
   inside the read loop's reply path. A writer task removes both by
   construction rather than by careful call sites.
5. **Carry the NodeId in the `Hello` alongside the key and check they match.**
   Equivalent when implemented correctly and one more field that can be got
   wrong. Deriving it is the same check with nothing to forget.
6. **Refuse new records when the store is full.** Simpler than eviction, and it
   hands the store to whoever fills it first. Evicting the entry closest to
   expiry keeps the table churning.
7. **Protobuf or Cap'n Proto for framing.** The project already hand-writes its
   binary codec for the mesh envelope (§4) because the Cap'n Proto toolchain is
   not available in this environment; a second encoding scheme for one transport
   is not worth the inconsistency.
