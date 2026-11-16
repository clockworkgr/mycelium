# ADR-021: Local Transport Authentication

## Status

Accepted (2026-11-12). **Implemented 2026-11-16 — ROADMAP T-34.** See the
implementation note at the end: it records what this decision left open, one
place where ADR-011's reasoning does not survive the move to a radio link, and
five residuals.

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

## Implementation note (2026-11-16, T-34)

What the decision above left open, and what implementing it settled.

### Links, not peers, and the bridges got smaller

The bridges name a link by an address they already hold — a BLE device
address, a CoreBluetooth peripheral or central id, a Wi-Fi socket endpoint —
prefixed by the role that carries it (`c:` where we are the GATT central,
`s:` where we are the server). Rust keeps `address → link` and, once proved,
`NodeId → address`; the bridges keep no identity at all.

The prefix is load-bearing on Android, where both GATT roles can be live with
the same device and both report the same address: one name for both would
merge two channels, each with its own key and counters, into one link.

Both characteristics that carried a bare id are **gone from the GATT service**,
not merely unused: Node ID (`…7891`) and Identity (`…7894`). Wi-Fi Direct's
`Hello` is gone with them, and its mDNS TXT record no longer advertises a node
id prefix. The Identity characteristic existed to map a BLE Random Private
Address to a NodeId; the problem dissolves rather than moving, because a link
is keyed by whatever address the platform reports for it and identity is
proved over that link, so an address nobody can correlate is exactly as usable
as one anybody can.

A link is announced only when it can carry frames in **both** directions:
after the central's subscription to the data characteristic completes, and on
the server side when a central subscribes. Announcing a link that can only be
written to leaves a handshake waiting for a reply that cannot arrive, and the
reaper takes it ten seconds later.

### Sealed frames carry their counter

ADR-011's `FrameCipher` keeps the frame counter implicit, on the stated
ground that "TCP already guarantees ordering, so strictness costs nothing".
That ground does not hold on a radio link. A sealed frame crossing BLE is
split into 512-byte fragments (ADR-022) that nothing above the ATT layer
retries, and the write queue drops the remainder of a message whose write
fails. One lost fragment means the frame never reassembles, so the receiver
never opens it and its implicit counter stays a frame behind the sender's for
good: every later frame would fail under the wrong nonce. A single dropped
notification would kill the link.

So a local link's data frames carry the counter in the clear ahead of the
ciphertext (8 bytes, little-endian), and the receiver keeps a floor rather
than an exact position: a counter at or above the floor is opened and moves
the floor past itself. Loss is survivable; replay and reordering are refused;
the counter is still the nonce and nothing else, so altering it in flight only
picks a nonce the frame cannot open under. The internet transport keeps
implicit counters, where a loss is the connection's death anyway and the eight
bytes buy nothing.

The two cleartext `Hello`s and the sealed `Confirm` are byte-identical to the
internet transport's and carry no counter: the handshake's own state says what
the next frame must be, and the `Confirm` is always frame 0.

### The counter is taken as the frame leaves, not as it is queued

Sealing at `send` looked obviously right and is wrong. The outbox puts an
emergency ahead of ordinary traffic (§9.5, ADR-014), so the peer would receive
counters in a different order from the frames, and everything the alert
overtook would be refused as stale — a test of the alert's priority is what
caught it. The counter is therefore assigned where the transmission order is
decided: the outbox holds the message, and the frame is sealed on its way out.
Handshake frames do not share that queue at all — they have their own, drained
first and never evicted, for the reason under "Bounds" below — and the
fragments of one frame are drained before the next frame is taken, because two
frames interleaved on one link would be reassembled in whichever order they
completed and the loser refused.

### One handshake, two drivers

`ChannelHandshakeDriver` (`transport/channel.rs`) is the proof; the transports
differ only in how frames reach it. `internet::handshake` is now four framed
reads and writes around it, and the local link layer feeds it reassembled
frames as they arrive. A local hello signs `listen_port = 0`: there is no port
to dial on a radio, the field is covered by the signature either way, and the
ephemeral key is what makes a captured hello useless, so no transport can
reinterpret another's.

The wire codec is shared too, which means a local link can *decode* a DHT
request. It refuses one explicitly rather than relying on nobody sending it.

### A peer may hold several links

BLE runs both roles, so two devices connect to each other in both directions
and both handshakes complete. The most recently established link carries what
we send; earlier ones stay readable; a peer is reported lost only when its
last link goes. The internet transport resolves its duplicates by comparing
transcripts, which is right where a connection is a scarce dialable thing and
wrong here, where both links are real and the routing layer must not see a
peer flap because one role dropped.

### Bounds, and what the bridge is told

No background task: nothing in the link layer awaits, and the table is swept
on every call, so an unfinished handshake is reaped by the next event — in
practice the app's 50 ms outbox poll. A link has 10 seconds to become
established, the same bound the internet transport puts on its handshake.
Links are capped (32 BLE, 16 Wi-Fi Direct) and a newcomer past the cap is
**refused rather than admitted by eviction**, so nothing in radio range can
drop a peer that has already proved itself by opening links.

Handshake frames have their own queue, drained before the outbox and never
evicted, bounded at two per link — a hello and a confirmation. They cannot
share the outbox: a full outbox makes room for an alert by dropping the oldest
frame of its own class, so a flood of emergencies on one link would silently
discard another link's confirmation, after which our data frames would reach a
peer still waiting for it and it would close a link we think is good. A
handshake that cannot be queued fails its link immediately instead.

Authentication outcomes are decided in Rust, and closing sockets is the
bridge's job, so the bridge polls a directive queue beside the outbox:
`established` (stop retrying) and `close` (drop it and leave that link alone
for 30 seconds — the handshake failed, timed out, named us, or there was no
room). Without it a refused link would hold one of BLE's seven connection
slots indefinitely. One directive per link, newest kept. When the queue is full, what
goes is an entry for an address this layer **no longer holds** — a close for a
socket it has forgotten, and the only kind that is not bounded by
`max_links`. An entry for a live link is never the victim: a `close` for one
would leak a socket counted against nothing, and an `established` is what
stops the bridge's own stale-link sweep from closing a peer that has proved
itself. (The first version of this note had it the other way round, before
the bridges needed `established` for their own liveness.)

The bridge does not *depend* on that queue for liveness, because a queue it
polls is the wrong place to keep a socket's lifetime. Each bridge closes a
link of its own accord once it has been announced for twenty seconds without
becoming established — longer than the handshake deadline, so the directive
normally arrives first and this is the backstop.

A frame on a link the bridge never announced is dropped and answered with
`close`: letting a frame open a link would let one we had just closed reopen
itself with whatever was still in flight. The one exception is on the bridge
side, where the peer's first frame can beat our own subscription callback: a
frame for a connection the bridge already holds announces its link rather than
being dropped, unless that link has just been refused.

A link that proves **our own** identity key is closed. That replaces the
id comparison the bridges used to make, which an attacker could satisfy by
claiming our id and which nothing now reports.

### What the bridges own, and what they are told

A socket's lifetime belongs to the layer holding the socket. The directive
queue tells a bridge what *authentication* decided; it is not how a bridge
learns that a connection is dead, because a queue it polls cannot be trusted
for that. So each bridge also, on its own five-second sweep:

- closes a link announced for twenty seconds without becoming established;
- closes a connection that never became announceable at all — a central that
  connects and never subscribes, a discovery that stalls — which nothing
  above the bridge knows exists;
- expires a partial frame after ten seconds, and refuses one longer than a
  Rust frame (512 bytes on BLE), because the bounded reassembler above never
  sees an incomplete frame and so cannot bound this one;
- forgets expired refusals, which a BLE address rotation would otherwise
  leave in the map for good.

Two things about the write queue below the fragmenter are not obvious.

A completion names **the link** — the device, plus the role from which
callback fired — and nothing more. The platform supplies no operation token,
so a late completion cannot be told apart from the current one by inspecting
it, and two attempts at detecting one are recorded here because both were
wrong. Counting the completions we *expect* stalls the queue whenever one
never arrives, which is the normal case: Android unregisters a GATT's
callbacks when it is closed. Tagging each operation with a generation compares
the operation in flight against the current generation, and the operation in
flight always *is* the current generation, so the check never fires. What
works is removing the ambiguity rather than detecting it: a purge that leaves
the connection alive — an unsubscribe, or a server-side cancellation, the only
cases where a completion can still arrive — **quarantines** that link for five
seconds. No write of its own is started in that window, so the next completion
for it can only be the abandoned one, and other links carry on. A callback
that never comes costs that link one write window; where the connection is
gone, no quarantine is needed, because its callbacks went with it.

A handshake fragment is queued **ahead of ordinary traffic** and is never the
one evicted from a full queue, or the handshake priority inside Rust would be
undone one layer down. Which fragments those are is **told to the bridge**, as
an out-parameter of the dequeue: the bridge cannot work it out, because a link
counts as established in Rust the moment the peer's confirmation arrives,
which can be before *our* confirmation has left — so "is this link
established" is the wrong question by exactly the margin that matters, and
answering it that way would let a full queue drop the confirmation a peer is
waiting for. A handshake fragment also goes after every *other* queued
handshake rather than at the front, because a link's hello and confirmation
must stay in that order; delivered the other way round, the peer reads the
confirmation as the hello it is waiting for and closes the link.

What no layer here bounds is time: a platform write that neither completes nor
fails leaves a bridge's queue stopped, because the platform offers no deadline
and this layer adds none. See residual 6.

The native queues are bounded in their own right — 128 operations on BLE, 32
queued writes per Wi-Fi Direct socket — and a handshake fragment is never
what a full queue sacrifices. The Rust outbox's bound does **not** carry over
to them: the poll frees Rust capacity the moment a frame is handed across, so
behind a slow peer the backlog would simply move down a layer and grow there.
That is a bound the first version of this note claimed and did not have.

*Which* ordinary frame is lost differs by transport, and the reason is what
each queue can see. BLE holds its own operations, so it drops the **oldest**
ordinary one, as the outbox above it does. Wi-Fi Direct's backlog is a thread
pool's queue of opaque tasks, which cannot be inspected to tell a handshake
write from a data write, so there the **newest** ordinary frame is refused
instead — the only choice that cannot throw away a handshake. A handshake
frame does make room for itself there, by dropping the oldest queued write.

### Removed rather than ported

`mycelium_ble_set_send_callback` and `mycelium_wifi_set_send_callback`, and the
callback paths inside both transports, are gone. Nothing registered them —
Dart cannot hand out a synchronous C callback, so both platforms use the
outbox poll — and porting an unused second send path to links would have been
the "second path nobody looks at" this ADR was written to avoid. The FFI
surface stays at 64 functions: the six link-event functions and two directive
polls replace the six peer-event functions and the two callbacks.

### What a frame costs

A message's ceiling drops by the sealed frame's own overhead — the counter,
the `MeshData` header and the AEAD tag, 61 bytes in all — so BLE carries 4035
bytes per message rather than 4096 and Wi-Fi Direct 65474 rather than 65535.
The reassembly bound is unchanged; what changed is how much of it is payload.

### Residuals

1. **The outbox is bounded in messages, not bytes.** 128 queued messages on
   BLE and 64 on Wi-Fi Direct, so a queue full of maximum-sized messages is
   512 KB and 4 MB respectively. Real traffic is envelopes of a few hundred
   bytes; a byte bound would be tighter and needs its own refusal path.
2. **One outbox serves every link**, so one link's traffic can crowd out
   another's: past the bound the oldest ordinary message is dropped, as on
   every transport's outbox (ADR-014), and the sender is not told. Nothing
   has been sealed at that point, so no counter is spent and the peer sees no
   gap — a dropped message, not a damaged channel. Handshakes are **not**
   exposed to this: they have their own queue, which refuses a new link
   rather than evicting an existing one's hello, so a link that cannot be
   handshaked fails visibly instead of appearing to work and dying at the
   reaper. Refusing ordinary traffic instead of evicting it would let the DTN
   layer take over the message that did not fit, which is the better rule and
   a change to an outbox four transports share.
3. **The quarantine is a five-second heuristic.** If an abandoned
   completion arrives after it expires and a new write of that link has
   started, it is taken for that write's: one fragment is skipped, the frame
   fails to open and one message is lost. The alternative — closing a link
   that may be perfectly healthy — costs a reconnection every time to avoid a
   rare lost message.
4. **Frames are attributed to a link by the address the bridge reports.** The
   handshake makes that attribution safe — a frame that does not open is
   dropped — but a platform layer that mixed up two links' frames would
   simply break both channels rather than cross them.
5. **iOS cannot disconnect a central.** `CBPeripheralManager` has no
   counterpart to Android's `BluetoothGattServer.cancelConnection`, so a
   refused link in our peripheral role is forgotten and stops being written
   to, but the central's connection survives until it gives up. A peer that
   keeps failing handshakes can therefore hold a slot in the peripheral role
   on iOS, where on Android the same peer is disconnected. Nothing at this
   layer can do better; what it costs is local capacity, not safety.
6. **Never run on a radio.** The handshake, the counter rule and the
   bridges' bookkeeping are covered by the Rust tests, and everything that a
   toolchain can check has been checked: the debug APK builds with the FFI
   library packaged for all three ABIs and the link functions exported from
   it, and the whole iOS `Runner` module typechecks against the iPhoneOS SDK.
   That caught two defects five rounds of review had not — an
   `ExecutorService` has no `queue`, and `os.Logger`'s message is an
   autoclosure needing an explicit `self`. What nothing here exercises is a
   radio: MTU negotiation, notification loss, reconnection churn, the
   twenty-second sweeps and the five-second quarantine all have their timings
   from reasoning rather than measurement, and no two devices have ever
   handshaked. The spec marker is "Implemented, untested on hardware" and
   T-15 owns the report.
7. **No deadline on a platform write.** A GATT write or notification that
   neither completes nor fails stops that bridge's write queue; nothing here
   times one out, because nothing did before either. The links above it are
   reaped on their own deadlines and the Rust side is unaffected, so what it
   costs is one radio's sends until the connection drops and the queue is
   purged. See residual 3 for the related ambiguity this leaves.
8. **A link's name is not unique across its incarnations.** A reconnection
   reuses the same name — `c:<address>`, or a Wi-Fi endpoint — and by then
   some of the previous incarnation's work has already been dispatched
   through the app: a frame, a `close`, an `established`. Rust's own queues
   are purged when a link goes, but nothing can retract what has left. The
   consequences are bounded and recoverable, but one is a liveness hole and
   not a lost frame: a stale frame on a live link fails to open and is
   dropped, a stale `close` costs a healthy link a reconnection and 30
   seconds, and a stale `established` *is* accepted by a replacement of the
   same name — the bridge checks only that it still holds the link, which it
   does — which exempts that replacement's unfinished handshake from the
   bridge's own stale-link sweep and leaves the Rust side's ten-second
   deadline as the only thing that closes it. Closing the class properly
   means carrying a
   connection instance in the link name end to end — Rust, app and bridge —
   with the device-and-role backoff keyed separately, because that must
   outlive an incarnation. ROADMAP T-48.
9. **iOS state restoration cannot keep a link, in either role.**
   CoreBluetooth restores a central's connections *and* a peripheral
   manager's services with their subscribed centrals, but the channel keys
   behind all of them were in the process that went away — and the remote
   still believes its link is established, so a fresh hello over it arrives
   where a sealed frame is expected. The bridge therefore drops restored
   connections and removes restored services, letting scanning and
   re-advertising rebuild both, which gives up what state restoration was
   for on exactly those links.
10. **BT Classic and LoRa still install an asserted id.** The same defect, one
    in the same shape and one that needs a different design, recorded as
    ROADMAP T-47.
