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

## Note (2026-11-17, from T-04's review): the link bound is not kept

This record has Rust decide authentication and the bridges own their sockets,
with concurrent native links bounded in the bridge. The Android Wi-Fi Direct
bridge does not keep that bound, in two ways that pull in opposite directions.

A slot counted at the accept is never released when the address is one Rust
recently refused: `handleClient` returns before its `try`, so the `finally`
that would release it does not run (`WifiDirectService.kt:510`). Sixteen
attempts from a refused address exhaust the bound for the life of the service,
and every later socket from any peer is closed on arrival.

The other way, `stop()` sets the counter to zero while reader threads are
still unwinding (`WifiDirectService.kt:236`); their `finally` then decrements
past zero, so a restarted service admits more than sixteen. Neither cancels
the other reliably.

The refusal window and the bound both arrived with this ADR, so these are its
defects rather than later ones. ROADMAP T-56 carries both; nothing in this
record's reasoning changes, only the claim that the bridge honours it.

## Note (2026-11-18, T-56): the link bound is kept now

The note above recorded that the Android Wi-Fi Direct bridge did not hold the
sixteen-socket bound this record gives it. It does now. What the fix took is
worth setting down, because the two defects that note named were symptoms of
one mistake, and finding them all took four rounds of review.

The bound was an `AtomicInteger`, incremented when a socket was accepted or
dialled and decremented in the reader's `finally`. A count like that is only
as good as the pairing of its two halves, and nothing in the code made that
pairing visible — so it was wrong in both directions at once: a path that
returned before the `finally` spent a slot for the life of the service, and
`stop()` zeroing the counter while readers were still unwinding let their
decrements take it below zero.

A socket's slot has to answer three questions, and a number answers only the
first:

**Is it still counted?** A slot is now a **token**, and the count is the
number of tokens outstanding — so releasing one twice frees one slot,
releasing a token that was never issued does nothing, and the count cannot go
below zero because a set has no negative size. `stop()` drops every token
instead of zeroing a count, so a reader unwinding afterwards releases
something that is already gone. Tokens are never reused, which is what lets a
handler delayed across a stop *and* a start ask whether its own slot survived:
a restart cannot change that answer, where the `running` flag is true again
and says nothing.

**What is it holding?** A slot carries the socket it counts, so dropping a
slot closes it. `stop()` closed only the links in its table, which left every
socket that had been accepted but not yet registered open — each would have
closed itself on reaching its first check, so this was a race rather than a
leak, but it meant a stopped service still owned sockets while its replacement
was admitting sixteen more.

**Whose service accepted it?** A slot carries the **generation** it was taken
in, which `stop()` bumps. This is the one that took three rounds, because it
is not enough to have the generation: it has to be read where the work was
*justified*, not where it runs.

- A socket accepted or dialled before a stop can have its slot taken after the
  restart, from the new service's own budget. The token is legitimate then, so
  no token check can catch it; a generation stamped before the blocking accept
  or the five-second connect does.
- `stop()` cleared the budget inside `lifecycleLock` but closed the listening
  socket after that block, so an accept loop resuming in between read the
  *new* generation and accepted a connection belonging to the group being torn
  down. `stop()` now closes the listener first, which is the right order in
  any case: stop accepting before tearing down what has been accepted.
- The accept loop read the `serverSocket` field on every accept, so a loop
  whose service had been stopped could accept on the *replacement* listener
  and then refuse that connection as stale — taking a healthy peer's socket
  away from the service that should have had it. A loop is now bound to one
  listener and one generation, both fixed before it starts.
- A **group disconnect** ends the group's work as surely as a stop does, and
  did not touch the generation: a queued `startServer` still passed its check
  and left the device listening on 9740 even when the next group made it a
  client, which is not a role this design gives a group client, and a queued
  dial still dialled. The disconnect path now clears the budget, which both
  begins a new generation and closes the sockets — every one of which lived
  inside the group that has gone.
- `requestConnectionInfo` answers asynchronously, so its callback can arrive
  after a stop and a start and stamp the old group's role and dial with the
  new generation. The stamp is taken where the connection event is observed
  and carried through the callback into the listener and the dial. On Wi-Fi
  Direct the group owner's address is the same on both sides of a restart, so
  a stale dial reaches whatever now answers on it — including this node's own
  server, which Rust refuses as a link naming us, at the cost of a socket and
  the handshake deadline.

Two more, in the same work. `stop()` was changing the link table without
`lifecycleLock` — the lock every other change to it takes — so a handler
already past its own checks could install a link after the teardown loop had
walked past it; it now holds the lock, so a registration either finishes first
and is torn down or starts afterwards and finds its slot gone. And the accept
loop gives its slot back if there is no thread to read the socket, which is
unreachable today, since nothing shuts that pool down, but the accounting
should not rest on that.

**The listener needed the same discipline, and for the same reason.** Deciding
to listen, binding, publishing the socket, closing it and clearing the field
were separate steps on a plain `var` written from three threads: the accept
task, the connection-info callback and `stop()`. A listener could bind and be
descheduled before publishing, escaping a teardown while still holding port
9740 — so the replacement's bind failed and, because the escaped task then
exited on its stale generation, there was no listener at all and nothing to
retry. A thread checking that the field was still its own and then clearing it
could erase a replacement installed in between, with the same result. Every
**mutation** of that field, and every check a decision rests on, is now under
`lifecycleLock`: the decision,
the bind and the publish as one critical section — which is also why a bind can
never be in flight during a teardown — and the two teardowns that read it in
order to close it.

An accept loop closes the listener it owns inside that same critical section
as it unpublishes it, which is not where the first version of this note put it.
Closing first and unpublishing after left the field pointing at a dead listener
for that moment, and `startServer` returns early whenever the field is set, so
a connection-info callback arriving in the window scheduled nothing and left
the group owner with no listener.

One read stays outside the lock: `startServer`'s early-out, which is why the
field is `@Volatile`. It is worth being exact about what that read can and
cannot be told. Nobody can observe a *closed* listener, because closing and
unpublishing are one critical section. But a listener that has just failed its
accept stays published until its `finally` runs, so the field means "published
and not yet cleaned up" rather than "healthy", and a callback in that instant
schedules nothing. Since that callback is the only caller, what follows is a
group owner waiting for the next connection event or the next group — recorded
as **ROADMAP T-58**, because closing it means the bridge restoring its own
listener rather than anything about this record's bound. The liveness half of
this belongs to ADR-003, whose claim that a group owner accepts connections is
the one that was not kept, and it has a note there.

One behaviour change beyond the leaks: a slot is refused by comparing before
taking rather than by incrementing and rolling back, so the count never rises
above the bound even momentarily, and a concurrent accept cannot be refused a
slot that was free.

**A pre-existing defect fixed on the way, named because it is not this one.**
The accept loop breaks out on any accept error, and left `serverSocket`
pointing at the dead listener; `startServer` returns early while that field is
set, so a single accept error stopped a group owner listening for the rest of
that group's life — recovery needed the group to drop, because the disconnect
path is the only other thing that cleared the field. The loop now closes its
own listener and clears the field if it is still its own. This became visible
only once the loop owned its socket, and it is unrelated to the bound. ADR-003
has the fuller note, since it is that record's claim about a listening group
owner that was not kept.

### The sweep list, against what the bridges do

That list is described as every bridge's, and on Wi-Fi Direct one of its two
frame duties was wrong and the other is absent.

**"Refuses one longer than a Rust frame"** was true of the shape and wrong by
a factor of four. The bridge's `MAX_FRAME` was 65535 — the transport's
`WIFI_MAX_MESSAGE`, which bounds a *message* — while what crosses this layer
since ADR-022 gave the transport a fragmentation layer is a *fragment*,
bounded by `WIFI_FRAME_MTU` at 16 KB. A peer's length prefix could therefore
claim four times what Rust can emit, for a frame the reassembler above would
never see. `MAX_FRAME` is now 16384, which is exactly a 6-byte fragment header
plus `frame_mtu - 6` of payload, so it cannot refuse anything legitimate. The
limits are per transport and not interchangeable: 512 bytes on BLE, 16384 on
Wi-Fi Direct.

**"Expires a partial frame after ten seconds"** is simply absent here. BLE does
that — it reassembles GATT writes into a frame, so a partial frame is a buffer
with a start time (`REASSEMBLY_TTL_MS`), and the sweep ages it out. The Wi-Fi
Direct bridge has
no such buffer: it reads a length-prefixed frame off a TCP stream with
`readFully`, so a "partial frame" is not a data structure but a blocked read,
and no socket timeout is set anywhere in that bridge. A peer that sends a
header announcing a frame and then stops holds the reader thread for as long as
the TCP connection survives. The sweep cannot help, because it closes links
that never became *established*, and this one did.

The gap is wider than the duty, and it matters to this note rather than only to
the sweep. Between frames, `readByte` blocks the same way, so an established
link whose peer vanished silently — out of range, or killed — is held until TCP
gives up, and since T-56 it is held *with its slot*. Sixteen of those and the
bound is exhausted again, by a route the token accounting cannot see, because
the slot is legitimately held by a reader that has not finished.

Nothing closes such a link at the application level, on either side of the FFI.
The bridge's sweep closes a link announced but never *established*. The Rust
link sweep expires only `Stage::Handshaking` past `HANDSHAKE_DEADLINE`, and
every other `Close` it issues answers an event — not accepting, the link bound,
a failed handshake queue, a frame on a link nobody announced, our own identity
on the far end — never silence on a link that is already proved; `link.rs` says
as much where it handles `Outcome::Close`: "a proved one does not reach here,
because a bad frame is dropped". So recovery needs TCP itself
to give up, which with no keepalive set can take hours, or the group to tear
down, or the service to stop. Since this change a group teardown does release
them, because the disconnect path clears the budget and closes what it was
counting.

A peer whose process *dies* is not the case: the OS closes its descriptors, and
the EOF or reset reaches the reader, which releases its slot on the way out.
What holds a slot is a peer that is alive and has stopped reading or writing —
a hung or frozen process — or a path that fails without a FIN or an RST, in
either case with the group still up.

It is left as **ROADMAP T-57** rather than fixed here. A read deadline is a
change to the frame reader rather than to the accounting, and the obvious
implementation — a blanket `soTimeout` — would also close a healthy link that
simply has nothing to say, so it needs the mid-frame case distinguished from
the between-frames case, or a keepalive instead. There is no harness here to
test either.

And a third thing about this list, which applies to every deadline on it rather
than to one duty: the bridges measure them on a **wall clock**.
`System.currentTimeMillis()` in both Kotlin bridges, `Date()` in the Swift one.
That is not a monotonic clock — NTP corrects it when a phone attaches to a
network, and the user can set it — so a backward correction holds a link past
its deadline and a forward one expires a link, or a partial frame, that is
making progress. It is worth naming here because the other side of this same
FFI gets it right: `link.rs` measures from `Instant`, and its `sweep` takes
`now` as a parameter, which is why it has tests. The bridges' sweeps read the
clock themselves, which is why they do not.

This is pre-existing — the deadlines came in with T-34, the change this note's
record is about — and it is left as **ROADMAP T-59** rather than fixed here,
because it spans three bridge files and two platforms, and because which clock
is right is a decision per deadline rather than a substitution: on Android
`elapsedRealtime()` counts time asleep and `uptimeMillis()` does not, and a
radio that was suspended is not a peer that went silent. The severity is
bounded by what still works: an unproved link's real deadline is Rust's
`HANDSHAKE_DEADLINE`, which is monotonic, so a clock jump mis-times a backstop
rather than leaving an unproved socket open for good.

### What this is verified by

`LinkBudget` touches no Android framework class, which is the point of its
being its own file: it has 16 JVM unit tests, the first the Kotlin bridges have
had, run by `make android-test` and counted apart from the Rust workspace's.
Eight of the sixteen fail against the old accounting, reimplemented behind the
same API to check: the capacity after a double release, after a release of a
token never issued, and after a stop with readers still unwinding; token
reuse; both generation tests; and the two that ask whether a dropped slot
closed its socket and a released one did not.

The call sites are **not** covered by those tests, and most of what is
described above is a call site. They need `WifiP2pManager`,
`android.util.Log`, a real `ServerSocket` and the broadcast receiver's
threading, and there is no instrumentation harness in this repository: what
each call site does with a slot is verified by `:app:compileDebugKotlin`, by
the debug APK build, and by reading the control flow. Nothing here has run on
a radio — ROADMAP T-15.
