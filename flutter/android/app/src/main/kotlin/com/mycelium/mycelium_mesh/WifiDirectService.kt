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
import java.util.concurrent.atomic.AtomicInteger

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
        private const val MAX_FRAME = 65535

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

    // Group Owner server
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

    // Accepted sockets, counted from the accept rather than from
    // registration: a handler is scheduled asynchronously, so a burst would
    // otherwise see an empty table and give every socket a reader thread
    // before anything refused it.
    private val nativeSockets = AtomicInteger(0)

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

        for ((linkId, link) in links) {
            closeQuietly(link)
            listener?.onLinkDown(linkId)
        }
        links.clear()
        nativeSockets.set(0)
        linkOpenedAt.clear()
        establishedLinks.clear()
        refusedUntil.clear()

        // Close server socket
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null

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

    private fun onConnectionInfoAvailable(info: WifiP2pInfo) {
        if (!info.groupFormed) return

        isGroupOwner = info.isGroupOwner
        Log.i(TAG, "Group formed. isGroupOwner=$isGroupOwner, GO address=${info.groupOwnerAddress}")

        if (isGroupOwner) {
            startServer()
        } else {
            val goAddress = info.groupOwnerAddress
            if (goAddress != null) {
                executor.execute { connectToGroupOwner(goAddress.hostAddress ?: return@execute) }
            }
        }
    }

    // --- TCP Server (Group Owner) ---

    private fun startServer() {
        if (serverSocket != null) return

        executor.execute {
            try {
                serverSocket = ServerSocket(TCP_PORT)
                Log.i(TAG, "TCP server listening on port $TCP_PORT")

                while (running.get()) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        if (nativeSockets.incrementAndGet() > MAX_NATIVE_LINKS) {
                            nativeSockets.decrementAndGet()
                            Log.w(TAG, "Refusing a socket: $MAX_NATIVE_LINKS already held")
                            try { client.close() } catch (_: Exception) {}
                            continue
                        }
                        executor.execute { handleClient(client, counted = true) }
                    } catch (e: Exception) {
                        if (running.get()) {
                            Log.w(TAG, "Server accept error: ${e.message}")
                        }
                        break
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server start error: ${e.message}")
            }
        }
    }

    // --- TCP Client (Group Client) ---

    private fun connectToGroupOwner(goIp: String) {
        // Checked before the socket is opened: the group's own callbacks
        // fire on every reconnection, and dialling a peer we just refused
        // only to close its socket in `handleClient` is not the holdoff the
        // backoff promises.
        if (refused(goIp)) {
            Log.d(TAG, "Not dialling $goIp: refused recently")
            return
        }
        try {
            Log.i(TAG, "Connecting to Group Owner at $goIp:$TCP_PORT")
            val socket = Socket()
            socket.connect(InetSocketAddress(goIp, TCP_PORT), 5000)
            if (nativeSockets.incrementAndGet() > MAX_NATIVE_LINKS) {
                nativeSockets.decrementAndGet()
                Log.w(TAG, "Not keeping the GO socket: $MAX_NATIVE_LINKS already held")
                try { socket.close() } catch (_: Exception) {}
                return
            }
            handleClient(socket, counted = true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect to GO: ${e.message}")
        }
    }

    // --- Shared Client Handler ---

    /** The remote endpoint names the link; it is unique while the socket is. */
    private fun linkIdFor(socket: Socket): String =
        "${socket.inetAddress?.hostAddress ?: "?"}:${socket.port}"

    private fun handleClient(socket: Socket, counted: Boolean) {
        val linkId = linkIdFor(socket)
        var announced = false
        // This reader's own connection, so its cleanup cannot remove a
        // replacement that reused the name.
        var mine: LinkConnection? = null
        if (refused(socket.inetAddress?.hostAddress)) {
            Log.d(TAG, "Dropping a socket from a peer we just refused: $linkId")
            try { socket.close() } catch (_: Exception) {}
            return
        }
        try {
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
            if (counted) {
                nativeSockets.decrementAndGet()
            }
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
                            manager?.requestConnectionInfo(channel) { info ->
                                onConnectionInfoAvailable(info)
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

    private fun handleGroupDisconnected() {
        Log.i(TAG, "Wi-Fi Direct group disconnected")
        for (linkId in links.keys) {
            dropLink(linkId)
        }

        // Close server socket so it can be restarted on next group formation
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
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
