package com.mycelium.mycelium_mesh

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.NetworkInfo
import android.net.wifi.p2p.*
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest
import android.os.Build
import android.util.Log
import java.io.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wi-Fi Direct transport service using Android WifiP2pManager.
 *
 * - Service discovery via Bonjour/mDNS (`_mycelium._tcp`)
 * - Group Owner runs a TCP server on port 9740
 * - Group Clients connect to the GO's IP
 * - TCP wire protocol: 1-byte type + 4-byte BE length + payload
 *   - Frame (0x02): one opaque frame for the Rust transport
 *
 * The `Hello` that used to carry a bare 32-byte NodeId is gone. Identity is
 * proved by a handshake in Rust carried over these frames, and the NodeId is
 * derived from the key it verifies (ADR-021, ROADMAP T-34); a second,
 * weaker path here would have been a way around it. This layer reports
 * **links**, named by the remote socket endpoint, and relays frames.
 */
@SuppressLint("MissingPermission")
class WifiDirectService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumWiFiDirect"
        private const val SERVICE_TYPE = "_mycelium._tcp"
        private const val SERVICE_NAME = "Mycelium"
        private const val TCP_PORT = 9740

        /** One opaque frame for the Rust transport. */
        private const val MSG_FRAME: Byte = 0x02

        /** Largest frame accepted in either direction. */
        /**
         * Largest frame this layer will read or write.
         *
         * It carries *fragments*, so this is the Rust transport's
         * `WIFI_FRAME_MTU` (16 KB), not its `WIFI_MAX_MESSAGE` (65535). It
         * held the message limit until T-56 — a leftover from before ADR-022
         * gave this transport a fragmentation layer — which let a peer's
         * length prefix claim four times what Rust can emit, and the
         * reassembler above never sees a frame that long.
         *
         * Paired with `WIFI_FRAME_MTU` in `transport/wifi_direct.rs`: a
         * fragment is a 6-byte header plus `frame_mtu - 6` bytes of payload,
         * so exactly this many bytes at most.
         */
        private const val MAX_FRAME = 16_384

        /**
         * How long a link may stay announced without being established
         * before this layer closes it itself.
         *
         * Longer than the Rust side's ten-second handshake deadline, so its
         * own `close` normally arrives first. This is the backstop for the
         * case where that directive never arrives: a silent socket and its
         * reader thread would otherwise live as long as the group does.
         */
        private const val STALE_LINK_MS = 20_000L

        /** How often the stale-link sweep runs. */
        private const val LINK_SWEEP_MS = 5_000L

        /** How long a refused peer is left alone before we redial it. */
        private const val REFUSED_BACKOFF_MS = 30_000L

        /** Writes queued for one link while its socket is not draining. */
        private const val MAX_PENDING_WRITES = 32

        /**
         * Sockets this layer will hold at once.
         *
         * Matches the Rust transport's own link bound, and exists because
         * that bound is only applied *after* an accepted socket has been
         * announced through Dart: a burst of connections would otherwise
         * have a reader thread each before anything decided to refuse them.
         */
        private const val MAX_NATIVE_LINKS = 16
    }

    interface EventListener {
        fun onLinkUp(linkId: String)
        fun onLinkDown(linkId: String)
        fun onLinkData(linkId: String, data: ByteArray)
    }

    var listener: EventListener? = null

    private val running = AtomicBoolean(false)

    private var manager: WifiP2pManager? = null
    private var channel: WifiP2pManager.Channel? = null
    private var receiver: BroadcastReceiver? = null

    // TCP I/O thread pool
    private val executor = Executors.newCachedThreadPool()

    // Group Owner server. Installed, closed and cleared under
    // `lifecycleLock`; volatile because `startServer`'s early-out reads it
    // without the lock, and a stale read there would decide whether to listen.
    @Volatile
    private var serverSocket: ServerSocket? = null

    // Live links: link id -> socket
    private val links = ConcurrentHashMap<String, LinkConnection>()

    // When each link was announced, and which have been established: a link
    // that never completes its handshake is closed here rather than waited on.
    private val linkOpenedAt = ConcurrentHashMap<String, Long>()
    private val establishedLinks = ConcurrentHashMap<String, Boolean>()

    // Peers whose handshake was refused, by remote address, with the time
    // they may be dialled again. By address rather than endpoint: the port is
    // ephemeral and changes on every reconnection, so an endpoint-keyed entry
    // would never match the socket it is meant to hold off.
    private val refusedUntil = ConcurrentHashMap<String, Long>()

    // Native sockets held, bounded at MAX_NATIVE_LINKS. Why they are
    // counted from the accept rather than from registration, and why a slot
    // is a token rather than a number, is in LinkBudget.
    private val linkBudget = LinkBudget(MAX_NATIVE_LINKS)

    // Sweep timer
    private var sweeper: ScheduledExecutorService? = null

    /// Serialises a link's registration, its cleanup and the lifecycle
    /// events either sends. Without it, removing the old socket publishes a
    /// vacant name before the old cleanup has finished, so a replacement can
    /// register and announce itself and then have its own bookkeeping
    /// deleted — and its Rust link torn down — by the cleanup that was
    /// already running.
    private val lifecycleLock = Any()

    // Track whether we are Group Owner
    @Volatile private var isGroupOwner = false

    private class LinkConnection(
        val socket: Socket,
        val output: DataOutputStream,
        /// One thread per link, so frames leave in the order they were
        /// queued. A shared pool keeps whole frames intact but not their
        /// order, and a frame overtaken on a link is refused by the
        /// receiver's counter floor (ADR-021).
        ///
        /// Typed as the concrete executor because its backlog is inspected:
        /// `ExecutorService` exposes no queue.
        val writer: ThreadPoolExecutor
    )

    // --- Public API ---

    fun start() {
        if (running.getAndSet(true)) return
        Log.i(TAG, "Starting Wi-Fi Direct service")

        manager = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
        channel = manager?.initialize(context, context.mainLooper, null)

        if (manager == null || channel == null) {
            Log.e(TAG, "Wi-Fi P2P not available")
            running.set(false)
            return
        }

        registerReceiver()
        registerService()
        discoverServices()

        sweeper = Executors.newSingleThreadScheduledExecutor().also {
            it.scheduleWithFixedDelay(
                { sweepStaleLinks() }, LINK_SWEEP_MS, LINK_SWEEP_MS, TimeUnit.MILLISECONDS
            )
        }
    }

    /**
     * Close links that never finished their handshake, and forget expired
     * refusals.
     *
     * The Rust side reaps a stalled handshake at its own deadline and asks us
     * to close the link, but that directive is polled; a queue that overflows
     * or an app that stops polling would leave a socket and its reader thread
     * alive for the life of the group. This layer owns the socket, so it does
     * not depend on being told.
     */
    private fun sweepStaleLinks() {
        if (!running.get()) return
        val now = System.currentTimeMillis()
        refusedUntil.entries.removeAll { now >= it.value }
        for (linkId in linkOpenedAt.keys.toList()) {
            // Read and acted on under the lifecycle lock, with the
            // connection identified: between a check outside the lock and
            // the close, a reconnection can take over the endpoint, and it
            // would be the replacement that was closed.
            synchronized(lifecycleLock) {
                val openedAt = linkOpenedAt[linkId] ?: return@synchronized
                if (establishedLinks.containsKey(linkId)) return@synchronized
                if (now - openedAt < STALE_LINK_MS) return@synchronized
                val held = links[linkId] ?: return@synchronized
                Log.w(
                    TAG,
                    "Closing $linkId: announced ${now - openedAt} ms ago, never established"
                )
                dropLink(linkId, held)
            }
        }
    }

    private fun refused(address: String?): Boolean {
        val until = refusedUntil[address ?: return false] ?: return false
        if (System.currentTimeMillis() >= until) {
            refusedUntil.remove(address)
            return false
        }
        return true
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        Log.i(TAG, "Stopping Wi-Fi Direct service")

        sweeper?.shutdownNow()
        sweeper = null

        // Under the lifecycle lock, like every other change to the link
        // table: a handler that has passed its own checks is mid-registration
        // and would otherwise install a link after this loop walked past it,
        // leaving a socket in a table the next service generation keeps. With
        // the lock held, a registration either finishes first and is torn
        // down here, or starts afterwards and finds its slot gone — and a
        // listener cannot be mid-bind, because binding and publishing happen
        // under this same lock.
        synchronized(lifecycleLock) {
            // The listener first: an accept loop blocked on a live server
            // socket can return a connection at any moment, and nothing
            // should arrive after this point (ROADMAP T-56).
            try { serverSocket?.close() } catch (_: Exception) {}
            serverSocket = null

            for ((linkId, link) in links) {
                closeQuietly(link)
                listener?.onLinkDown(linkId)
            }
            links.clear()
            // The link table's two companions, cleared with it rather than
            // after it: `dropLink` only ever changes them under this lock.
            linkOpenedAt.clear()
            establishedLinks.clear()
            // Dropped rather than zeroed, which does three things a count
            // could not: the reader threads still unwinding release tokens
            // that are already gone, so nothing drives the count negative;
            // a socket accepted but not yet registered is closed here rather
            // than being left to a handler that has not run; and the new
            // generation keeps a socket that arrived before this stop out of
            // the next service (ROADMAP T-56).
            linkBudget.clear()
        }
        // Address-keyed backoff, not link state, and maintained outside the
        // lock by the sweep.
        refusedUntil.clear()

        // Unregister service and receiver
        manager?.let { mgr ->
            channel?.let { ch ->
                mgr.clearLocalServices(ch, null)
                mgr.clearServiceRequests(ch, null)
            }
        }

        try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        receiver = null

        // Remove the Wi-Fi Direct group
        manager?.let { mgr ->
            channel?.let { ch ->
                mgr.removeGroup(ch, null)
            }
        }

        Log.i(TAG, "Wi-Fi Direct service stopped")
    }

    /**
     * Write one frame on a link.
     *
     * `isHandshake` comes from the Rust side, which is the only layer that
     * knows: a link counts as established there as soon as the peer's
     * confirmation arrives, which can be before our own has left. A
     * handshake frame makes room for itself in a full queue rather than
     * being the frame that is dropped.
     */
    fun sendData(linkId: String, data: ByteArray, isHandshake: Boolean): Boolean {
        val link = links[linkId] ?: run {
            Log.w(TAG, "sendData: no link $linkId")
            return false
        }
        if (data.size > MAX_FRAME) {
            Log.w(TAG, "sendData: frame of ${data.size} bytes exceeds $MAX_FRAME")
            return false
        }

        val backlog = link.writer.queue
        if (backlog.remainingCapacity() == 0) {
            if (!isHandshake) {
                Log.w(TAG, "sendData: $linkId has $MAX_PENDING_WRITES writes waiting, dropping a frame")
                return false
            }
            // The oldest ordinary write goes instead: a handshake frame that
            // is dropped costs the link its whole authentication.
            backlog.poll()
            Log.w(TAG, "sendData: made room on $linkId for a handshake frame")
        }

        try {
            link.writer.execute {
                try {
                    writeFrame(link.output, MSG_FRAME, data)
                } catch (e: Exception) {
                    Log.w(TAG, "sendData failed on $linkId: ${e.message}")
                    dropLink(linkId, link)
                }
            }
        } catch (e: RejectedExecutionException) {
            Log.w(TAG, "sendData on a closed link $linkId")
            return false
        }
        return true
    }

    /**
     * Close a link Rust refused: its handshake failed, timed out, named us,
     * or there was no room for it. Nothing was installed for it.
     */
    fun closeLink(linkId: String) {
        Log.i(TAG, "Closing refused link $linkId")
        // Held off by address: the group's own callbacks will otherwise
        // redial the same peer as soon as the socket drops, and its handshake
        // will fail again for whatever reason it failed the first time.
        links[linkId]?.socket?.inetAddress?.hostAddress?.let { address ->
            refusedUntil[address] = System.currentTimeMillis() + REFUSED_BACKOFF_MS
        }
        dropLink(linkId)
    }

    /** A link became established: stop sweeping it, and forget the backoff. */
    fun onLinkEstablished(linkId: String) {
        // The directive is polled, so it can arrive after the socket has
        // gone; marking a link we no longer hold would let a replacement of
        // the same name inherit the mark and skip the stale-link sweep.
        if (!linkOpenedAt.containsKey(linkId)) {
            Log.d(TAG, "Ignoring an establishment for a link we no longer hold: $linkId")
            return
        }
        establishedLinks[linkId] = true
        links[linkId]?.socket?.inetAddress?.hostAddress?.let { refusedUntil.remove(it) }
        Log.i(TAG, "Link $linkId established")
    }

    // --- Service Registration ---

    private fun registerService() {
        // The record carries no node id: nothing unproved identifies a node
        // any more, and the service type is what discovery needs.
        val serviceInfo = WifiP2pDnsSdServiceInfo.newInstance(
            SERVICE_NAME, SERVICE_TYPE, emptyMap()
        )

        manager?.addLocalService(channel, serviceInfo, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.i(TAG, "Local service registered")
            }
            override fun onFailure(reason: Int) {
                Log.e(TAG, "Failed to register service: $reason")
            }
        })
    }

    // --- Service Discovery ---

    private fun discoverServices() {
        // Set up DNS-SD response listeners
        manager?.setDnsSdResponseListeners(channel,
            { instanceName, registrationType, srcDevice ->
                Log.d(TAG, "Service found: $instanceName ($registrationType) from ${srcDevice.deviceName}")
                if (registrationType.contains(SERVICE_TYPE)) {
                    connectToPeer(srcDevice)
                }
            },
            { fullDomain, record, srcDevice ->
                Log.d(TAG, "TXT record: $fullDomain -> $record from ${srcDevice.deviceName}")
            }
        )

        val serviceRequest = WifiP2pDnsSdServiceRequest.newInstance()
        manager?.addServiceRequest(channel, serviceRequest, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.d(TAG, "Service request added")
                startDiscovery()
            }
            override fun onFailure(reason: Int) {
                Log.e(TAG, "Failed to add service request: $reason")
            }
        })
    }

    private fun startDiscovery() {
        if (!running.get()) return
        manager?.discoverServices(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.i(TAG, "Service discovery started")
            }
            override fun onFailure(reason: Int) {
                Log.w(TAG, "Service discovery failed: $reason")
            }
        })
    }

    // --- Peer Connection ---

    private fun connectToPeer(device: WifiP2pDevice) {
        if (!running.get()) return

        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
        }

        manager?.connect(channel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.i(TAG, "Connection initiated to ${device.deviceName}")
            }
            override fun onFailure(reason: Int) {
                Log.w(TAG, "Connection failed to ${device.deviceName}: $reason")
            }
        })
    }

    // --- Group Connection Handling ---

    private fun onConnectionInfoAvailable(info: WifiP2pInfo, generation: Int) {
        if (!info.groupFormed) return

        // `requestConnectionInfo` answers asynchronously, so this callback can
        // arrive after the service that asked has been stopped and another
        // started. Everything below belongs to the group that was current when
        // the connection event was seen: the role, the listener and the dial
        // (ROADMAP T-56).
        if (generation != linkBudget.currentGeneration()) {
            Log.d(TAG, "Ignoring connection info: the service that asked has been stopped")
            return
        }

        isGroupOwner = info.isGroupOwner
        Log.i(TAG, "Group formed. isGroupOwner=$isGroupOwner, GO address=${info.groupOwnerAddress}")

        if (isGroupOwner) {
            startServer(generation)
        } else {
            val goAddress = info.groupOwnerAddress
            if (goAddress != null) {
                executor.execute {
                    connectToGroupOwner(goAddress.hostAddress ?: return@execute, generation)
                }
            }
        }
    }

    // --- TCP Server (Group Owner) ---

    /**
     * Listen for group clients.
     *
     * The loop belongs to **one** listener and **one** service generation,
     * both fixed before it starts. Reading the `serverSocket` field on each
     * accept instead let a loop whose service had been stopped accept on the
     * *replacement* listener, and then refuse that connection as stale —
     * taking a healthy peer's socket away from the service that was supposed
     * to have it (ROADMAP T-56).
     */
    private fun startServer(generation: Int) {
        // Unlocked. What the field says is that a listener is published and
        // has not been cleaned up — not that it is healthy: no one can
        // observe a *closed* listener here, because closing and unpublishing
        // happen in one critical section, but a listener that has just failed
        // its accept is still published until its `finally` runs. A callback
        // landing in that instant schedules nothing, and since this is the
        // only caller, the group owner then waits for the next connection
        // event or the next group (ROADMAP T-58). The authoritative check is
        // taken again under the lock below.
        if (serverSocket != null) return

        executor.execute {
            // Deciding, binding and publishing are one step, under the lock
            // `stop()` closes the listener with. Separately, a task scheduled
            // by a service that has since stopped would bind, pause before
            // publishing, and escape the teardown entirely — still holding
            // port $TCP_PORT, so the replacement's own bind fails, while this
            // task goes on to exit on its stale generation and leave no
            // listener at all. Nothing retries: `startServer` is only called
            // from the connection-info callback (ROADMAP T-56).
            var bound: ServerSocket? = null
            synchronized(lifecycleLock) {
                if (generation != linkBudget.currentGeneration()) {
                    Log.d(TAG, "Not listening: the service that asked has been stopped")
                } else if (serverSocket != null) {
                    Log.d(TAG, "Not listening: this service already has a listener")
                } else {
                    try {
                        bound = ServerSocket(TCP_PORT).also { serverSocket = it }
                    } catch (e: Exception) {
                        Log.e(TAG, "Server start error: ${e.message}")
                    }
                }
            }
            val server = bound ?: return@execute

            try {
                Log.i(TAG, "TCP server listening on port $TCP_PORT")

                while (running.get() && generation == linkBudget.currentGeneration()) {
                    try {
                        val client = server.accept()
                        val slot = linkBudget.take(generation, client)
                        if (slot == null) {
                            Log.w(
                                TAG,
                                "Closing a socket: $MAX_NATIVE_LINKS already held, " +
                                    "or the service stopped as it arrived"
                            )
                            try { client.close() } catch (_: Exception) {}
                            continue
                        }
                        try {
                            executor.execute { handleClient(client, slot) }
                        } catch (e: RejectedExecutionException) {
                            // No reader means no `finally`, so the slot is
                            // given back here instead.
                            Log.w(TAG, "No thread to read an accepted socket: ${e.message}")
                            linkBudget.release(slot)
                            try { client.close() } catch (_: Exception) {}
                        }
                    } catch (e: Exception) {
                        if (running.get()) {
                            Log.w(TAG, "Server accept error: ${e.message}")
                        }
                        break
                    }
                }
            } finally {
                // Closed *and* unpublished in one critical section, under the
                // lock that installs a listener and the lock both teardowns
                // take. Two reasons it is not a bare check and assignment:
                //
                // A loop that passed the identity check and then paused while
                // a restart installed a replacement would erase the
                // replacement's reference, after which no `stop()` can close
                // it and every later bind fails on the port it still holds.
                //
                // And closing before unpublishing leaves the field pointing at
                // a dead listener for that moment. `startServer` returns early
                // whenever the field is set, so a connection-info callback
                // arriving in that window would schedule nothing at all and
                // leave the group owner with no listener until the next event
                // — which is the window the early-out's safety depends on not
                // existing.
                //
                // Unpublishing at all is what stops one accept error from
                // ending the group owner's listening for the rest of that
                // group's life: the loop breaks out, and `startServer`
                // returns early for as long as this field is set. That part
                // is a pre-existing defect, visible once the loop owned its
                // socket.
                synchronized(lifecycleLock) {
                    if (serverSocket === server) serverSocket = null
                    try { server.close() } catch (_: Exception) {}
                }
            }
        }
    }

    // --- TCP Client (Group Client) ---

    private fun connectToGroupOwner(goIp: String, generation: Int) {
        // Checked before the socket is opened: the group's own callbacks
        // fire on every reconnection, and dialling a peer we just refused
        // only to close its socket in `handleClient` is not the holdoff the
        // backoff promises.
        if (refused(goIp)) {
            Log.d(TAG, "Not dialling $goIp: refused recently")
            return
        }
        val socket = Socket()
        // The slot is taken before the connect, not after it: the connect
        // waits up to five seconds, and a socket that exists without a slot
        // is one the bound does not count and `stop()` cannot close. Repeated
        // connection-info callbacks each schedule a dial, so several such
        // sockets can be in flight at once. Taking the slot first also means
        // a stop closes this socket out from under the connect, which ends it
        // rather than leaving five seconds of dialling for a service that is
        // gone (ROADMAP T-56).
        //
        // `generation` was taken when the connection event was seen, not
        // here: this task may already have waited for a thread.
        val slot = linkBudget.take(generation, socket)
        if (slot == null) {
            Log.w(
                TAG,
                "Not dialling the GO: $MAX_NATIVE_LINKS already held, " +
                    "or the service stopped before this dial began"
            )
            try { socket.close() } catch (_: Exception) {}
            return
        }

        // `handleClient` owns the slot once it has been handed over, and
        // releases it in its own `finally`.
        var handedOver = false
        try {
            Log.i(TAG, "Connecting to Group Owner at $goIp:$TCP_PORT")
            socket.connect(InetSocketAddress(goIp, TCP_PORT), 5000)
            handedOver = true
            handleClient(socket, slot)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect to GO: ${e.message}")
        } finally {
            if (!handedOver) {
                linkBudget.release(slot)
                try { socket.close() } catch (_: Exception) {}
            }
        }
    }

    // --- Shared Client Handler ---

    /** The remote endpoint names the link; it is unique while the socket is. */
    private fun linkIdFor(socket: Socket): String =
        "${socket.inetAddress?.hostAddress ?: "?"}:${socket.port}"

    private fun handleClient(socket: Socket, slot: Long) {
        val linkId = linkIdFor(socket)
        var announced = false
        // This reader's own connection, so its cleanup cannot remove a
        // replacement that reused the name.
        var mine: LinkConnection? = null
        // Nothing between the slot being taken and this `try` may return:
        // the `finally` is the only thing that gives it back, so a return
        // before the `try` leaves the socket counted for the life of the
        // service (ROADMAP T-56). The refusal check therefore sits inside
        // it, and leaves closing the socket to the unannounced branch of
        // the `finally`, which is what it did by hand.
        try {
            if (refused(socket.inetAddress?.hostAddress)) {
                Log.d(TAG, "Dropping a socket from a peer we just refused: $linkId")
                return
            }
            val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))

            // One thread per link so frames leave in order, with a bounded
            // backlog: the Rust outbox frees its own capacity as soon as a
            // frame is handed over, so an unbounded queue here would grow
            // without limit behind a stalled socket. The oldest queued write
            // is what goes.
            // Bounded, and rejecting rather than discarding: a
            // discard policy decides *for* us which write goes, and it
            // would throw away a handshake frame as readily as a data
            // frame. `sendData` makes that choice instead.
            val writer = ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS,
                ArrayBlockingQueue(MAX_PENDING_WRITES)
            )
            val connection = LinkConnection(socket, output, writer)
            synchronized(lifecycleLock) {
                // Two windows, both of which would leave a link from a
                // stopped service in the table a restarted one keeps,
                // holding a socket that counts against nothing. `running`
                // catches a stop already under way; the slot catches one
                // that has finished, including a stop *and* start that both
                // happened while this handler waited for a thread — after
                // which `running` is true again and only the dropped slot
                // still says so (ROADMAP T-56).
                if (!running.get() || !linkBudget.holds(slot)) {
                    writer.shutdownNow()
                    Log.d(TAG, "Dropping $linkId: its slot did not outlive a stop")
                    return
                }
                val existing = links.putIfAbsent(linkId, connection)
                if (existing != null) {
                    // The previous socket of the same name may already be
                    // dead with its reader not yet finished cleaning up;
                    // replace it then. Otherwise this is a real duplicate.
                    if (existing.socket.isClosed) {
                        links.remove(linkId, existing)
                        closeQuietly(existing)
                    }
                    if (links.putIfAbsent(linkId, connection) != null) {
                        writer.shutdownNow()
                        Log.w(TAG, "A link named $linkId already exists; closing the duplicate")
                        try { socket.close() } catch (_: Exception) {}
                        return
                    }
                }
                mine = connection
                announced = true
                linkOpenedAt[linkId] = System.currentTimeMillis()
                // Rust answers with its handshake; nothing identifies the
                // peer until that completes.
                listener?.onLinkUp(linkId)
            }

            while (running.get() && !socket.isClosed) {
                val (msgType, data) = readFrame(input)
                when (msgType) {
                    MSG_FRAME -> synchronized(lifecycleLock) {
                        // Only while this reader still owns the link: an
                        // endpoint is reused on reconnection, and a frame
                        // read from the old socket would otherwise be fed
                        // into the replacement's handshake and close it.
                        if (links[linkId] === connection) {
                            listener?.onLinkData(linkId, data)
                        } else {
                            Log.d(TAG, "Dropping a frame from a superseded link $linkId")
                        }
                    }
                    else -> Log.w(TAG, "Unknown message type: $msgType")
                }
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.d(TAG, "Link $linkId ended: ${e.message}")
            }
        } finally {
            if (announced) {
                dropLink(linkId, mine)
            } else {
                try { socket.close() } catch (_: Exception) {}
            }
            linkBudget.release(slot)
        }
    }

    // --- TCP Wire Protocol ---

    private fun writeFrame(output: DataOutputStream, type: Byte, data: ByteArray) {
        synchronized(output) {
            output.writeByte(type.toInt())
            output.writeInt(data.size)
            output.write(data)
            output.flush()
        }
    }

    private fun readFrame(input: DataInputStream): Pair<Byte, ByteArray> {
        val type = input.readByte()
        val length = input.readInt()
        if (length < 0 || length > MAX_FRAME) {
            throw IOException("Invalid frame length: $length")
        }
        val data = ByteArray(length)
        input.readFully(data)
        return Pair(type, data)
    }

    // --- BroadcastReceiver ---

    private fun registerReceiver() {
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }

        receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(
                            WifiP2pManager.EXTRA_WIFI_STATE,
                            WifiP2pManager.WIFI_P2P_STATE_DISABLED
                        )
                        if (state != WifiP2pManager.WIFI_P2P_STATE_ENABLED) {
                            Log.w(TAG, "Wi-Fi P2P is not enabled")
                        }
                    }
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        @Suppress("DEPRECATION")
                        val networkInfo = intent.getParcelableExtra<NetworkInfo>(
                            WifiP2pManager.EXTRA_NETWORK_INFO
                        )
                        if (networkInfo?.isConnected == true) {
                            // Stamped where the event is observed. The
                            // callback below may not run until after a stop
                            // and a start, and by then the only thing that
                            // still says which service asked is this value.
                            val generation = linkBudget.currentGeneration()
                            manager?.requestConnectionInfo(channel) { info ->
                                onConnectionInfoAvailable(info, generation)
                            }
                        } else {
                            handleGroupDisconnected()
                        }
                    }
                }
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    // --- Disconnect Handling ---

    /**
     * The group went away, which ends every piece of work the group justified.
     *
     * All of it under the lifecycle lock, for the reason `stop()` holds it: a
     * close followed by a clear is two steps, and a queued `startServer`
     * publishing between them would have its live listener's reference erased,
     * after which nothing can close it and every later bind fails on the port
     * it still holds.
     */
    private fun handleGroupDisconnected() {
        Log.i(TAG, "Wi-Fi Direct group disconnected")
        synchronized(lifecycleLock) {
            // The listener first, so nothing new arrives during the teardown.
            try { serverSocket?.close() } catch (_: Exception) {}
            serverSocket = null

            for (linkId in links.keys.toList()) {
                dropLink(linkId)
            }

            // Every socket this bridge holds lived inside the group that has
            // just gone, so there is nothing left for them to count, and a
            // reader still blocked on one would otherwise hold its slot until
            // TCP gave up (ROADMAP T-57). Clearing also begins a new
            // generation, which is what keeps work the *old* group justified
            // out of the next one: a queued `startServer` would otherwise
            // still pass its check and leave this device listening on 9740
            // even when the next group makes it a client, and a queued dial
            // would still dial (ROADMAP T-56).
            linkBudget.clear()
        }
    }

    /**
     * Forget a link, optionally only if it is still the connection expected.
     *
     * A group client always dials `goIp:9740`, so a reconnection reuses the
     * link's name. Without the identity check, an old reader's cleanup — or a
     * queued write failing on its closed socket — would remove the
     * replacement that had just registered under that name and report *it*
     * down.
     */
    private fun dropLink(linkId: String, expected: LinkConnection? = null) {
        synchronized(lifecycleLock) {
            val held = links[linkId] ?: return
            if (expected != null && held !== expected) {
                Log.d(TAG, "Not dropping $linkId: it is a newer connection")
                return
            }
            if (!links.remove(linkId, held)) {
                Log.d(TAG, "Not dropping $linkId: it changed under us")
                return
            }
            linkOpenedAt.remove(linkId)
            establishedLinks.remove(linkId)
            closeQuietly(held)
            Log.i(TAG, "Link down: $linkId")
            listener?.onLinkDown(linkId)
        }
    }

    private fun closeQuietly(link: LinkConnection) {
        try { link.socket.close() } catch (_: Exception) {}
        // Cancelled rather than drained: a queued write would only fail
        // against a closed socket and report the link down again.
        link.writer.shutdownNow()
    }
}
