package com.mycelium.mycelium_mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * BLE transport service implementing both peripheral (GATT server) and
 * central (scanner/client) roles simultaneously.
 *
 * This layer carries frames and nothing else. It does not know, and no
 * longer reports, which node is on the other end of a connection: identity
 * is proved by a handshake in Rust over these frames, and the NodeId is
 * derived from the key that handshake verifies (ADR-021, ROADMAP T-34). The
 * Node ID and Identity characteristics that used to exchange a bare,
 * unprovable 32-byte id are gone with it.
 *
 * GATT service layout:
 *   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef1234567890
 *   Data TX char:   ...7892  (Write)  — central writes frames to peripheral
 *   Data RX char:   ...7893  (Notify) — peripheral notifies central with frames
 *
 * Links are named `c:<device address>` where we are the central and
 * `s:<device address>` where we are the server. Both roles can be connected
 * to the same device at once, and they are two links with two handshakes, so
 * one name for both would merge two channels into one.
 *
 * Fragmentation header (1 byte), below Rust's own:
 *   0x01 = first fragment
 *   0x02 = last fragment
 *   0x03 = first+last (single packet)
 */
@SuppressLint("MissingPermission")
class BleService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumBLE"

        val SERVICE_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        val DATA_TX_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567892")
        val DATA_RX_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567893")
        val CCCD_UUID: UUID         = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val FLAG_FIRST: Byte = 0x01
        const val FLAG_LAST: Byte  = 0x02
        const val FLAG_SINGLE: Byte = 0x03

        /** Our role in a link, and the prefix its name carries. */
        const val ROLE_CENTRAL = "c:"
        const val ROLE_SERVER = "s:"

        /**
         * Payload bytes in one GATT write at the 23-byte default ATT MTU.
         *
         * An ATT MTU of 23 carries 20 bytes of attribute value (3 go to the
         * ATT header), and one of those 20 is our own fragment flag, so 19
         * are payload. The old floor of 20 produced a 21-byte value that the
         * link cannot carry.
         */
        const val DEFAULT_FRAGMENT_SIZE = 19

        // Connection retry settings
        const val MAX_CONNECT_RETRIES = 3
        const val BASE_RETRY_DELAY_MS = 1000L

        // Scan cycling: Android kills LOW_LATENCY scans after ~30s.
        // Restart periodically to stay under the limit.
        const val SCAN_CYCLE_MS = 25_000L

        // Auto-reconnect delay after a link we had drops
        const val RECONNECT_DELAY_MS = 2000L

        /** How long an address refused by the Rust side is left alone. */
        const val REFUSED_BACKOFF_MS = 30_000L

        /**
         * How long a link may stay announced without being established
         * before this layer closes it itself.
         *
         * Longer than the Rust side's ten-second handshake deadline, so its
         * own `close` normally arrives first. This is the backstop for the
         * case where that directive never arrives — a connection holds one
         * of the radio's few slots, and nothing else would ever free it.
         */
        const val STALE_LINK_MS = 20_000L

        /** How often the stale-link sweep runs. */
        const val LINK_SWEEP_MS = 5_000L

        /**
         * Largest frame this layer will reassemble from GATT writes.
         *
         * The Rust side fragments to its BLE frame MTU, so anything longer
         * than that is not a frame it sent. Without this, an established
         * peer could send a first fragment and then continuation fragments
         * for ever: the bounded reassembler in Rust would never see them,
         * because they would never be handed over.
         */
        const val MAX_FRAME_BYTES = 512

        /**
         * Largest GATT attribute value Android will write.
         *
         * A negotiated ATT MTU of 517 would otherwise allow a 513-byte
         * value — a 512-byte Rust fragment plus this layer's flag byte —
         * which the framework rejects outright, so every full fragment of a
         * multi-fragment frame would be refused and no large message would
         * ever cross.
         */
        const val MAX_ATT_VALUE = 512

        /** How long a partial frame waits for the rest of itself. */
        const val REASSEMBLY_TTL_MS = 10_000L

        /**
         * How long a connection has to become announceable — subscribed, in
         * either role — before this layer closes it.
         */
        const val SETUP_DEADLINE_MS = 20_000L

        /**
         * How long a link waits for the completion of a write it abandoned
         * before writing again.
         *
         * The platform supplies no operation token, so this is what makes a
         * late completion unambiguous: while the link is quarantined nothing
         * of its own is in flight, so the next completion for it can only be
         * the one it is waiting for. Well inside the handshake deadline, so
         * a link that has to wait this out still has time to prove itself.
         */
        const val WRITE_QUARANTINE_MS = 5_000L

        /**
         * Operations held for the radio at once.
         *
         * The Rust outbox is bounded, but polling frees its capacity as soon
         * as a frame is handed over, so without a bound here a slow peer
         * accumulates writes without limit. Past this, the oldest operation
         * of an *established* link is dropped — ordinary traffic, as in the
         * outbox one layer up (ADR-014) — and a handshake is never the one
         * sacrificed.
         */
        const val MAX_WRITE_QUEUE = 128
    }

    interface EventListener {
        fun onLinkUp(linkId: String)
        fun onLinkDown(linkId: String)
        fun onLinkData(linkId: String, data: ByteArray)
    }

    var listener: EventListener? = null

    private var running = false
    private val handler = Handler(Looper.getMainLooper())

    // Bluetooth
    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null

    // Peripheral role
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private val subscribedDevices = ConcurrentHashMap<String, BluetoothDevice>()

    // Central role
    private var scanner: BluetoothLeScanner? = null
    private val connectedGatts = ConcurrentHashMap<String, BluetoothGatt>()

    // Connection management: track retry counts and pending connection attempts
    private val connectRetryCounts = ConcurrentHashMap<String, Int>()
    private val pendingConnections = ConcurrentHashMap<String, Boolean>()
    // Track devices connected to our GATT server (inbound connections)
    private val serverConnectedDevices = ConcurrentHashMap<String, Boolean>()

    // Links we have announced to Rust, by link id, with when we announced
    // them: a link that never becomes established is swept.
    private val openLinks = ConcurrentHashMap<String, Long>()
    // Links the Rust side has told us completed their handshake
    private val establishedLinks = ConcurrentHashMap<String, Boolean>()
    // Links Rust has refused, by link id, with the time they may be retried.
    // By link, not by device: both GATT roles report the same address, and a
    // handshake that failed in one role says nothing about the other.
    private val refusedUntil = ConcurrentHashMap<String, Long>()

    // Per-device negotiated MTU (default 23)
    private val deviceMtus = ConcurrentHashMap<String, Int>()

    // Addresses of devices whose link dropped — eligible for auto-reconnect
    private val disconnectedPeers = ConcurrentHashMap<String, BluetoothDevice>()

    // Fragment reassembly: link id -> partial buffer, and when it started
    private val reassemblyBuffers = ConcurrentHashMap<String, ByteArray>()
    private val reassemblyStartedAt = ConcurrentHashMap<String, Long>()

    // Connections that exist at the radio level but are not announceable
    // yet, by link id, with when they connected. A central that never
    // subscribes, or a connection that stalls in discovery, is never
    // announced and so would never be swept.
    private val pendingSetup = ConcurrentHashMap<String, Long>()

    // --- Sequential Write Queue ---
    // Android BLE allows only one outstanding GATT operation per connection.
    // This queue ensures writes are serialized properly.
    data class WriteOperation(
        val linkId: String,
        val address: String,
        val fragments: List<ByteArray>,
        var currentIndex: Int = 0,
        val isClientWrite: Boolean,  // true = GATT client write, false = GATT server notify
        /// Told to us by the Rust side, which is the only layer that knows:
        /// a link counts as established there as soon as the peer's
        /// confirmation arrives, which can be before our own has left, so
        /// "is this link established" is the wrong question by exactly the
        /// margin that matters. A handshake operation is never delayed
        /// behind traffic and never evicted.
        val isHandshake: Boolean
    )

    private val writeQueue = ArrayDeque<WriteOperation>()
    @Volatile private var writeInProgress = false
    private val writeLock = Any()

    // Links whose next completion belongs to an operation we abandoned,
    // with the time we stop waiting for it.
    //
    // The platform callbacks name the device and the role and nothing else:
    // no operation token, so a late completion cannot be told apart from the
    // current one by inspecting it. Two things were tried and are wrong. A
    // count of completions *owed* stalls the queue whenever the callback
    // never comes — which is the normal case, since Android unregisters a
    // GATT's callbacks when it is closed. A generation on each operation
    // compares the operation in flight against the current generation, and
    // the operation in flight always *is* the current generation, so the
    // check never fires.
    //
    // What works is to remove the ambiguity instead of detecting it: while a
    // link is quarantined no new operation of its own is started, so the
    // next completion for it can only be the abandoned one. The quarantine
    // is time-bounded, so a callback that never comes costs that link one
    // write window and nothing else. It is needed only where the connection
    // outlives the purge — an unsubscribe, or a server-side cancellation —
    // because callbacks cannot arrive from a closed GATT.
    private val writeQuarantine = ConcurrentHashMap<String, Long>()

    // --- Public API ---

    fun start() {
        if (running) return
        running = true

        bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.w(TAG, "Bluetooth not available or not enabled")
            return
        }

        startPeripheral()
        startCentral()
        handler.postDelayed(linkSweepRunnable, LINK_SWEEP_MS)
        Log.i(TAG, "BLE service started")
    }

    fun stop() {
        if (!running) return
        running = false

        handler.removeCallbacks(linkSweepRunnable)
        stopCentral()
        stopPeripheral()

        // Clear write queue
        synchronized(writeLock) {
            writeQueue.clear()
            writeInProgress = false
        }

        // Report every link down, so Rust drops the peers behind them.
        for (linkId in openLinks.keys) {
            listener?.onLinkDown(linkId)
        }
        openLinks.clear()
        establishedLinks.clear()
        refusedUntil.clear()
        writeQuarantine.clear()
        pendingSetup.clear()
        reassemblyStartedAt.clear()
        connectedGatts.clear()
        subscribedDevices.clear()
        serverConnectedDevices.clear()
        reassemblyBuffers.clear()
        connectRetryCounts.clear()
        pendingConnections.clear()
        deviceMtus.clear()
        disconnectedPeers.clear()

        Log.i(TAG, "BLE service stopped")
    }

    /**
     * Write one frame on a link. The link id says which role carries it, so
     * the two directions of a dual-role pair cannot be confused.
     */
    fun sendData(linkId: String, data: ByteArray, isHandshake: Boolean): Boolean {
        val address = addressOf(linkId) ?: run {
            Log.w(TAG, "sendData: malformed link id $linkId")
            return false
        }

        if (linkId.startsWith(ROLE_CENTRAL)) {
            if (connectedGatts[address] == null) {
                Log.w(TAG, "sendData: no GATT client link to $address")
                return false
            }
            val fragments = fragmentForDevice(address, data)
            enqueueWrite(
                WriteOperation(
                    linkId, address, fragments, 0,
                    isClientWrite = true, isHandshake = isHandshake
                )
            )
            return true
        }

        if (subscribedDevices[address] == null) {
            Log.w(TAG, "sendData: central $address is not subscribed")
            return false
        }
        val fragments = fragmentForDevice(address, data)
        enqueueWrite(
            WriteOperation(
                linkId, address, fragments, 0,
                isClientWrite = false, isHandshake = isHandshake
            )
        )
        return true
    }

    /**
     * Close a link Rust refused: its handshake failed, timed out, named us,
     * or there was no room for it. Nothing was installed for it, so the
     * connection is of no use; the address is left alone for a while rather
     * than redialled at once.
     */
    fun closeLink(linkId: String) {
        val address = addressOf(linkId) ?: return
        Log.i(TAG, "Closing refused link $linkId")
        refusedUntil[linkId] = System.currentTimeMillis() + REFUSED_BACKOFF_MS
        disconnectedPeers.remove(address)
        reportLinkDown(linkId)

        if (linkId.startsWith(ROLE_CENTRAL)) {
            connectedGatts.remove(address)?.let {
                purgeWritesFor(linkId)
                try { it.disconnect() } catch (_: Exception) {}
                try { it.close() } catch (_: Exception) {}
            }
        } else {
            // Disconnected, not merely forgotten: a central that keeps its
            // connection holds one of the radio's few slots, and this layer
            // is the only thing that can take it back.
            val device = subscribedDevices.remove(address)
                ?: runCatching { bluetoothAdapter?.getRemoteDevice(address) }.getOrNull()
            // The server callback is the GATT server's, not this
            // connection's, so a notification in flight can still report.
            purgeWritesFor(linkId, connectionAlive = true)
            if (device != null) {
                runCatching { gattServer?.cancelConnection(device) }
                    .onFailure { Log.w(TAG, "cancelConnection failed for $address: ${it.message}") }
            }
            serverConnectedDevices.remove(address)
        }
    }

    /** A link became established: stop retrying, and stop sweeping it. */
    fun onLinkEstablished(linkId: String) {
        val address = addressOf(linkId) ?: return
        // The directive is polled, so it can arrive after the link it
        // describes has gone. Marking a link we no longer hold would let a
        // replacement of the same name inherit the mark and slip past the
        // stale-link sweep.
        if (!openLinks.containsKey(linkId)) {
            Log.d(TAG, "Ignoring an establishment for a link we no longer hold: $linkId")
            return
        }
        connectRetryCounts.remove(address)
        refusedUntil.remove(linkId)
        establishedLinks[linkId] = true
        Log.i(TAG, "Link $linkId established")
    }

    private val linkSweepRunnable = object : Runnable {
        override fun run() {
            if (!running) return
            sweepStaleLinks()
            handler.postDelayed(this, LINK_SWEEP_MS)
        }
    }

    /**
     * Close links that never finished their handshake.
     *
     * The Rust side reaps them at its own deadline and asks us to close
     * them, but that directive is polled, and a queue that overflows or an
     * app that stops polling would leave a connection holding a radio slot
     * with nothing left to free it. This layer owns its sockets, so it does
     * not depend on being told.
     */
    private fun sweepStaleLinks() {
        val now = System.currentTimeMillis()
        // Addresses rotate — a BLE Random Private Address is new on every
        // reconnection — so an entry only reached when the same link comes
        // back is an entry that never goes.
        refusedUntil.entries.removeAll { now >= it.value }

        // A write window we were holding open for a completion that never
        // came. Retired under the write lock, and the queue is kicked after
        // it: a link whose quarantine expires has writes waiting, and
        // nothing else would start them until the next frame arrived.
        var retired = false
        synchronized(writeLock) {
            retired = writeQuarantine.entries.removeAll { now >= it.value }
        }
        if (retired) {
            processNextWrite()
        }

        // A partial frame whose rest never came.
        for ((linkId, startedAt) in reassemblyStartedAt) {
            if (now - startedAt < REASSEMBLY_TTL_MS) continue
            reassemblyBuffers.remove(linkId)
            reassemblyStartedAt.remove(linkId)
        }

        // A connection that never became announceable. Nothing above this
        // layer knows it exists, so nothing above it can free the slot.
        for ((linkId, connectedAt) in pendingSetup) {
            if (openLinks.containsKey(linkId)) {
                pendingSetup.remove(linkId)
                continue
            }
            if (now - connectedAt < SETUP_DEADLINE_MS) continue
            Log.w(TAG, "Dropping $linkId: connected ${now - connectedAt} ms ago, never subscribed")
            pendingSetup.remove(linkId)
            dropUnannounced(linkId)
        }

        for ((linkId, openedAt) in openLinks) {
            if (establishedLinks.containsKey(linkId)) continue
            if (now - openedAt < STALE_LINK_MS) continue
            Log.w(TAG, "Closing $linkId: announced ${now - openedAt} ms ago, never established")
            closeLink(linkId)
        }
    }

    /** Drop a connection that was never announced, in either role. */
    private fun dropUnannounced(linkId: String) {
        val address = addressOf(linkId) ?: return
        if (linkId.startsWith(ROLE_CENTRAL)) {
            connectedGatts.remove(address)?.let {
                try { it.disconnect() } catch (_: Exception) {}
                try { it.close() } catch (_: Exception) {}
            }
            return
        }
        val device = subscribedDevices.remove(address)
            ?: runCatching { bluetoothAdapter?.getRemoteDevice(address) }.getOrNull()
        serverConnectedDevices.remove(address)
        if (device != null) {
            runCatching { gattServer?.cancelConnection(device) }
        }
    }

    // --- Link bookkeeping ---

    private fun addressOf(linkId: String): String? =
        when {
            linkId.startsWith(ROLE_CENTRAL) || linkId.startsWith(ROLE_SERVER) ->
                linkId.substring(2).takeIf { it.isNotEmpty() }
            else -> null
        }

    private fun reportLinkUp(linkId: String) {
        pendingSetup.remove(linkId)
        if (openLinks.putIfAbsent(linkId, System.currentTimeMillis()) == null) {
            Log.i(TAG, "Link up: $linkId")
            listener?.onLinkUp(linkId)
        }
    }

    private fun reportLinkDown(linkId: String) {
        reassemblyBuffers.remove(linkId)
        reassemblyStartedAt.remove(linkId)
        pendingSetup.remove(linkId)
        establishedLinks.remove(linkId)
        if (openLinks.remove(linkId) != null) {
            Log.i(TAG, "Link down: $linkId")
            listener?.onLinkDown(linkId)
        }
    }

    private fun refused(linkId: String): Boolean {
        val until = refusedUntil[linkId] ?: return false
        if (System.currentTimeMillis() >= until) {
            refusedUntil.remove(linkId)
            return false
        }
        return true
    }

    // --- Write Queue Management ---

    /**
     * Queue an operation. Frames for a link that has not been established
     * yet go ahead of ordinary traffic.
     *
     * The Rust side puts a handshake frame first in its own queue, and this
     * one is what would undo that: a FIFO native queue can hold seconds of
     * data writes, and a hello behind them times out before it is written.
     * A link that is not established can only be carrying its handshake, so
     * no inspection of the frame is needed. Per-link order is kept either
     * way, because a link's two handshake frames are queued in order and a
     * link has no traffic until it is established.
     */
    private fun enqueueWrite(op: WriteOperation) {
        synchronized(writeLock) {
            if (writeQueue.size >= MAX_WRITE_QUEUE) {
                // Drop the oldest ordinary operation, never a handshake,
                // and never the one in flight.
                val floorIndex = if (writeInProgress) 1 else 0
                val victim = (floorIndex until writeQueue.size).firstOrNull {
                    !writeQueue[it].isHandshake
                }
                if (victim == null) {
                    Log.w(TAG, "writeQueue: full of handshakes, refusing ${op.linkId}")
                    return
                }
                Log.w(TAG, "writeQueue: full, dropping an operation for ${writeQueue[victim].linkId}")
                writeQueue.removeAt(victim)
            }
            if (!op.isHandshake) {
                writeQueue.addLast(op)
            } else {
                // After *every* queued handshake, not after the first one:
                // inserting between a link's own hello and confirmation
                // would deliver them in the wrong order and the peer would
                // read the confirmation as the hello it is waiting for. The
                // operation in flight is never displaced either.
                val floorIndex = if (writeInProgress) 1 else 0
                var insertAt = writeQueue.size
                for (index in floorIndex until writeQueue.size) {
                    if (!writeQueue[index].isHandshake) {
                        insertAt = index
                        break
                    }
                }
                writeQueue.add(insertAt.coerceAtLeast(floorIndex), op)
            }
        }
        processNextWrite()
    }

    /**
     * Drop queued writes for a link that just went away. Android never
     * delivers onCharacteristicWrite/onNotificationSent for a dropped link, so
     * without this the global writeInProgress flag would stay set forever and
     * stall BLE sends to every peer.
     */
    /**
     * Drop queued writes for a link that just went away.
     *
     * `connectionAlive` says whether a completion can still arrive for the
     * operation in flight: after an unsubscribe or a server-side
     * cancellation it can, and the link is quarantined so that completion
     * cannot be mistaken for a later operation's. After a GATT is closed it
     * cannot, because Android unregisters that GATT's callbacks.
     */
    private fun purgeWritesFor(linkId: String, connectionAlive: Boolean = false) {
        synchronized(writeLock) {
            val head = writeQueue.firstOrNull()
            writeQueue.removeAll { it.linkId == linkId }
            if (writeInProgress && head != null && head.linkId == linkId) {
                if (connectionAlive) {
                    writeQuarantine[linkId] = System.currentTimeMillis() + WRITE_QUARANTINE_MS
                }
                writeInProgress = false
            }
        }
        processNextWrite()
    }

    private fun processNextWrite() {
        synchronized(writeLock) {
            if (writeInProgress) return

            // A quarantined link has an abandoned completion outstanding;
            // starting another of its writes is what would make the two
            // indistinguishable. Other links carry on.
            //
            // An expired entry is retired here, under this lock, in the same
            // step that makes the link eligible. Leaving it to the sweep
            // would let a write start while the entry still stood, and its
            // genuine completion would then be swallowed as the abandoned
            // one — stalling the queue for every link.
            val now = System.currentTimeMillis()
            val op = writeQueue.firstOrNull { candidate ->
                val until = writeQuarantine[candidate.linkId] ?: return@firstOrNull true
                if (now >= until) {
                    writeQuarantine.remove(candidate.linkId)
                    true
                } else {
                    false
                }
            } ?: return
            if (writeQueue.firstOrNull() !== op) {
                writeQueue.remove(op)
                writeQueue.addFirst(op)
            }

            if (op.currentIndex >= op.fragments.size) {
                // Current operation complete, move to next
                writeQueue.removeFirst()
                processNextWrite()
                return
            }

            writeInProgress = true
            val frag = op.fragments[op.currentIndex]
            op.currentIndex++

            if (op.isClientWrite) {
                val gatt = connectedGatts[op.address]
                if (gatt == null) {
                    Log.w(TAG, "writeQueue: GATT client gone for ${op.linkId}")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                    return
                }
                val service = gatt.getService(SERVICE_UUID)
                val txChar = service?.getCharacteristic(DATA_TX_UUID)
                if (txChar == null) {
                    Log.w(TAG, "writeQueue: TX characteristic not found")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                    return
                }

                @Suppress("DEPRECATION")
                val ok = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeCharacteristic(
                        txChar, frag,
                        BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    ) == BluetoothStatusCodes.SUCCESS
                } else {
                    txChar.value = frag
                    txChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    gatt.writeCharacteristic(txChar)
                }

                if (!ok) {
                    Log.w(TAG, "writeQueue: GATT client write enqueue failed")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                }
                // else: wait for onCharacteristicWrite callback
            } else {
                // Server notify
                val server = gattServer
                val device = subscribedDevices[op.address]
                if (server == null || device == null) {
                    Log.w(TAG, "writeQueue: GATT server or device gone for ${op.linkId}")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                    return
                }
                val service = server.getService(SERVICE_UUID)
                val rxChar = service?.getCharacteristic(DATA_RX_UUID)
                if (rxChar == null) {
                    Log.w(TAG, "writeQueue: RX characteristic not found")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                    return
                }

                @Suppress("DEPRECATION")
                val ok = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    server.notifyCharacteristicChanged(device, rxChar, false, frag) ==
                        BluetoothStatusCodes.SUCCESS
                } else {
                    rxChar.value = frag
                    server.notifyCharacteristicChanged(device, rxChar, false)
                }

                if (!ok) {
                    Log.w(TAG, "writeQueue: GATT server notify enqueue failed")
                    writeQueue.removeFirst()
                    writeInProgress = false
                    processNextWrite()
                }
                // else: wait for onNotificationSent callback
            }
        }
    }

    /**
     * A write or notification completed on `linkId`.
     *
     * The platform callbacks carry the device, and which callback fired says
     * the role, so between them they name the link. They do not say which
     * *operation* finished, so a completion owed to an operation we abandoned
     * is swallowed rather than applied to the one in flight.
     */
    private fun onWriteCompleted(linkId: String, success: Boolean) {
        var proceed = false
        synchronized(writeLock) {
            val quarantined = writeQuarantine.remove(linkId) != null
            if (quarantined) {
                // The abandoned operation reporting back. Nothing of this
                // link's has been started since, so it can be nothing else,
                // and whatever is in flight belongs to another link. Its
                // writes are eligible again, so the queue is kicked below.
                Log.d(TAG, "writeQueue: retired an abandoned operation on $linkId")
                proceed = true
            } else {
                val op = writeQueue.firstOrNull()
                if (op == null || op.linkId != linkId) {
                    // The same device in the other GATT role, or a
                    // completion for something no longer queued.
                    Log.d(TAG, "writeQueue: ignoring a completion for $linkId")
                } else {
                    if (!success) {
                        // Drop remaining fragments of current operation
                        writeQueue.removeFirst()
                        Log.w(
                            TAG,
                            "writeQueue: write failed, dropping " +
                                "${op.fragments.size - op.currentIndex} remaining fragments"
                        )
                    }
                    writeInProgress = false
                    proceed = true
                }
            }
        }
        if (proceed) processNextWrite()
    }

    // --- Peripheral Role ---

    private fun startPeripheral() {
        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.w(TAG, "BLE advertising not supported")
            return
        }

        // Create GATT server
        gattServer = bluetoothManager?.openGattServer(context, gattServerCallback)
        if (gattServer == null) {
            Log.e(TAG, "Failed to open GATT server")
            return
        }

        val service = BluetoothGattService(
            SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // Data TX characteristic (write with response)
        val dataTxChar = BluetoothGattCharacteristic(
            DATA_TX_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        // Data RX characteristic (notify)
        val dataRxChar = BluetoothGattCharacteristic(
            DATA_RX_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val cccd = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        dataRxChar.addDescriptor(cccd)

        service.addCharacteristic(dataTxChar)
        service.addCharacteristic(dataRxChar)

        gattServer?.addService(service)

        // Start advertising
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        advertiser?.startAdvertising(settings, advertiseData, advertiseCallback)
    }

    private fun stopPeripheral() {
        advertiser?.stopAdvertising(advertiseCallback)
        gattServer?.close()
        gattServer = null
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.i(TAG, "BLE advertising started")
        }
        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE advertising failed: $errorCode")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val address = device.address
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.d(TAG, "GATT server: device connected $address")
                serverConnectedDevices[address] = true
                // The link is announced when the central subscribes: until
                // then we cannot notify, so a handshake frame would have
                // nowhere to go. The clock starts here all the same, or a
                // central that never subscribes would hold a slot unseen.
                pendingSetup[ROLE_SERVER + address] = System.currentTimeMillis()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "GATT server: device disconnected $address")
                serverConnectedDevices.remove(address)
                subscribedDevices.remove(address)
                val linkId = ROLE_SERVER + address
                purgeWritesFor(linkId)
                reportLinkDown(linkId)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray?
        ) {
            when (characteristic.uuid) {
                DATA_TX_UUID -> {
                    if (value != null && value.isNotEmpty()) {
                        handleFragment(ROLE_SERVER + device.address, value)
                        if (responseNeeded) {
                            gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                        }
                    } else {
                        if (responseNeeded) {
                            gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                        }
                    }
                }
                else -> {
                    if (responseNeeded) {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    }
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray?
        ) {
            if (descriptor.uuid == CCCD_UUID) {
                val address = device.address
                if (value?.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == true) {
                    subscribedDevices[address] = device
                    Log.d(TAG, "Device $address subscribed to notifications")
                    if (responseNeeded) {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    }
                    // Now that we can notify, the link can carry a handshake.
                    if (!refused(ROLE_SERVER + address)) {
                        reportLinkUp(ROLE_SERVER + address)
                    }
                    return
                }
                subscribedDevices.remove(address)
                // Purged before the link is reported down: a central that
                // resubscribes at once would otherwise be handed frames
                // sealed under the channel its replacement is not using.
                // The connection survives an unsubscribe, so a notification
                // in flight can still report back.
                purgeWritesFor(ROLE_SERVER + address, connectionAlive = true)
                reportLinkDown(ROLE_SERVER + address)
                // Still connected, and no longer announced, so neither sweep
                // would cover it: an unauthenticated central would keep a
                // radio slot for as long as it liked. The setup deadline
                // starts again, and closes it unless it resubscribes.
                if (serverConnectedDevices.containsKey(address)) {
                    pendingSetup[ROLE_SERVER + address] = System.currentTimeMillis()
                }
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            Log.d(TAG, "GATT server: MTU changed to $mtu for ${device.address}")
            deviceMtus[device.address] = mtu
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            // The server role, so this is the `s:` link for that device.
            onWriteCompleted(ROLE_SERVER + device.address, status == BluetoothGatt.GATT_SUCCESS)
        }
    }

    // --- Central Role ---

    private val scanCycleRunnable = Runnable { restartScan() }

    private fun startCentral() {
        scanner = bluetoothAdapter?.bluetoothLeScanner
        if (scanner == null) {
            Log.w(TAG, "BLE scanning not supported")
            return
        }
        doStartScan()
    }

    private fun doStartScan() {
        if (!running) return

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        try {
            scanner?.startScan(listOf(filter), settings, scanCallback)
            Log.i(TAG, "BLE scanning started")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start scan: ${e.message}")
        }

        // Schedule scan restart before Android kills it (~30s limit)
        handler.removeCallbacks(scanCycleRunnable)
        handler.postDelayed(scanCycleRunnable, SCAN_CYCLE_MS)
    }

    private fun restartScan() {
        if (!running) return
        try {
            scanner?.stopScan(scanCallback)
        } catch (_: Exception) {}

        // Brief pause then restart
        handler.postDelayed({
            if (running) {
                doStartScan()
                // Also retry any dropped links
                retryDisconnectedPeers()
            }
        }, 500)
    }

    private fun retryDisconnectedPeers() {
        val toRetry = ArrayList(disconnectedPeers.entries)
        for ((address, device) in toRetry) {
            if (connectedGatts.containsKey(address) || pendingConnections.containsKey(address) ||
                refused(ROLE_CENTRAL + address)
            ) {
                disconnectedPeers.remove(address)
                continue
            }
            Log.d(TAG, "Auto-reconnecting to $address")
            disconnectedPeers.remove(address)
            pendingConnections[address] = true
            connectToDevice(device, 0)
        }
    }

    private fun stopCentral() {
        handler.removeCallbacks(scanCycleRunnable)
        try {
            scanner?.stopScan(scanCallback)
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping scan: ${e.message}")
        }

        for ((_, gatt) in connectedGatts) {
            gatt.close()
        }
        connectedGatts.clear()
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val address = device.address

            // Skip if already connected or connection pending
            if (connectedGatts.containsKey(address)) return
            if (pendingConnections.containsKey(address)) return
            // Skip an address whose central-role handshake Rust just refused.
            if (refused(ROLE_CENTRAL + address)) return

            // If this device is currently connected to our GATT server,
            // add a delay before connecting as client to avoid conflicts
            val delay = if (serverConnectedDevices.containsKey(address)) {
                Random.nextLong(500, 1500)
            } else {
                // Add small random jitter to avoid both devices connecting simultaneously
                Random.nextLong(0, 300)
            }

            Log.d(TAG, "Discovered Mycelium device: $address (connecting in ${delay}ms)")
            pendingConnections[address] = true

            handler.postDelayed({
                if (!running) {
                    pendingConnections.remove(address)
                    return@postDelayed
                }
                // Re-check: skip if already connected while we waited
                if (connectedGatts.containsKey(address) || refused(ROLE_CENTRAL + address)) {
                    pendingConnections.remove(address)
                    return@postDelayed
                }
                connectToDevice(device, 0)
            }, delay)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: $errorCode")
        }
    }

    private fun connectToDevice(device: BluetoothDevice, attempt: Int) {
        val address = device.address
        if (!running) {
            pendingConnections.remove(address)
            return
        }

        Log.d(TAG, "GATT client connecting to $address (attempt ${attempt + 1})")
        val gatt = device.connectGatt(context, false, gattClientCallback, BluetoothDevice.TRANSPORT_LE)
        if (gatt != null) {
            connectedGatts[address] = gatt
            connectRetryCounts[address] = attempt
        } else {
            pendingConnections.remove(address)
        }
    }

    private val gattClientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val address = gatt.device.address
            if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                Log.d(TAG, "GATT client connected to $address")
                pendingConnections.remove(address)
                // Announceable only once discovery and subscription finish;
                // if they stall, this is what notices.
                pendingSetup[ROLE_CENTRAL + address] = System.currentTimeMillis()
                gatt.requestMtu(512)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "GATT client disconnected from $address (status=$status)")
                gatt.close()
                connectedGatts.remove(address)
                deviceMtus.remove(address)
                val linkId = ROLE_CENTRAL + address
                purgeWritesFor(linkId)
                val wasOpen = openLinks.containsKey(linkId)
                reportLinkDown(linkId)
                pendingConnections.remove(address)

                if (refused(linkId)) {
                    connectRetryCounts.remove(address)
                    return
                }

                // A link we had announced is worth getting back: schedule a
                // reconnect. One that never got that far is retried with
                // backoff, because the failure is in the connection itself.
                if (wasOpen) {
                    scheduleReconnect(gatt.device)
                    connectRetryCounts.remove(address)
                    return
                }

                if (status != BluetoothGatt.GATT_SUCCESS) {
                    val attempt = (connectRetryCounts[address] ?: 0)
                    if (attempt < MAX_CONNECT_RETRIES) {
                        val delay = BASE_RETRY_DELAY_MS * (attempt + 1) + Random.nextLong(0, 500)
                        Log.d(TAG, "Retrying connection to $address in ${delay}ms (attempt ${attempt + 2})")
                        handler.postDelayed({
                            if (running && !connectedGatts.containsKey(address) &&
                                !refused(ROLE_CENTRAL + address)
                            ) {
                                connectToDevice(gatt.device, attempt + 1)
                            } else {
                                pendingConnections.remove(address)
                            }
                        }, delay)
                    } else {
                        Log.w(TAG, "Giving up connection to $address after ${attempt + 1} attempts")
                        connectRetryCounts.remove(address)
                    }
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            Log.d(TAG, "MTU changed to $mtu for ${gatt.device.address} (status=$status)")
            if (status == BluetoothGatt.GATT_SUCCESS) {
                deviceMtus[gatt.device.address] = mtu
            }
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.w(TAG, "Service discovery failed for ${gatt.device.address}: status=$status")
                return
            }

            val service = gatt.getService(SERVICE_UUID) ?: run {
                Log.w(TAG, "Mycelium service not found on ${gatt.device.address}")
                return
            }

            // Subscribe to RX notifications. The link is announced once that
            // completes: before it, frames could leave but none could arrive,
            // so a handshake would stall and be reaped.
            val rxChar = service.getCharacteristic(DATA_RX_UUID)
            if (rxChar == null) {
                Log.w(TAG, "No RX characteristic on ${gatt.device.address}, nothing can arrive")
                gatt.disconnect()
                return
            }
            gatt.setCharacteristicNotification(rxChar, true)
            val cccd = rxChar.getDescriptor(CCCD_UUID)
            if (cccd == null) {
                Log.w(TAG, "No CCCD on ${gatt.device.address}, cannot subscribe")
                gatt.disconnect()
                return
            }
            @Suppress("DEPRECATION")
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            @Suppress("DEPRECATION")
            gatt.writeDescriptor(cccd)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            // The central role, so this is the `c:` link for that device.
            onWriteCompleted(ROLE_CENTRAL + gatt.device.address, status == BluetoothGatt.GATT_SUCCESS)
        }

        @Suppress("DEPRECATION")
        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            if (descriptor.uuid != CCCD_UUID) return
            val address = gatt.device.address
            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (!refused(ROLE_CENTRAL + address)) {
                    reportLinkUp(ROLE_CENTRAL + address)
                }
            } else {
                Log.w(TAG, "CCCD write failed (status=$status) for $address; nothing could arrive")
                gatt.disconnect()
            }
        }

        // API 33+ callback
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid == DATA_RX_UUID) {
                handleFragment(ROLE_CENTRAL + gatt.device.address, value)
            }
        }

        // Pre-API 33 callback
        @Suppress("DEPRECATION")
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            val value = characteristic.value ?: return
            if (characteristic.uuid == DATA_RX_UUID) {
                handleFragment(ROLE_CENTRAL + gatt.device.address, value)
            }
        }
    }

    private fun scheduleReconnect(device: BluetoothDevice) {
        val address = device.address
        if (!running) return
        disconnectedPeers[address] = device
        handler.postDelayed({
            if (running && disconnectedPeers.containsKey(address) &&
                !connectedGatts.containsKey(address) &&
                !pendingConnections.containsKey(address) && !refused(ROLE_CENTRAL + address)
            ) {
                Log.d(TAG, "Auto-reconnecting to $address")
                disconnectedPeers.remove(address)
                pendingConnections[address] = true
                connectToDevice(device, 0)
            }
        }, RECONNECT_DELAY_MS)
    }

    // --- Fragmentation ---

    private fun handleFragment(linkId: String, raw: ByteArray) {
        if (raw.isEmpty() || raw.size > MAX_FRAME_BYTES + 1) return
        // The peer's first frame can beat our own subscription callback, so
        // a frame for a connection we already hold announces its link rather
        // than being dropped — otherwise that handshake only recovers through
        // the reaper and the backoff. A link Rust has just refused is not
        // reopened by what was still in flight.
        if (!openLinks.containsKey(linkId)) {
            val address = addressOf(linkId)
            val connected = address != null &&
                (connectedGatts.containsKey(address) || subscribedDevices.containsKey(address))
            if (!connected || refused(linkId)) {
                Log.d(TAG, "Dropping a frame on unannounced link $linkId")
                return
            }
            Log.d(TAG, "First frame on $linkId arrived before our own callback")
            reportLinkUp(linkId)
        }
        val flags = raw[0]
        val payload = if (raw.size > 1) raw.copyOfRange(1, raw.size) else ByteArray(0)

        val isFirst = (flags.toInt() and 0x01) != 0
        val isLast  = (flags.toInt() and 0x02) != 0

        if (isFirst) {
            reassemblyBuffers[linkId] = payload
            reassemblyStartedAt[linkId] = System.currentTimeMillis()
        } else {
            val existing = reassemblyBuffers[linkId] ?: return
            if (existing.size + payload.size > MAX_FRAME_BYTES) {
                // Longer than any frame the Rust side sends, so this is not
                // one. Dropped here, because the bounded reassembler above
                // would never see it.
                Log.w(TAG, "Dropping an over-long reassembly on $linkId")
                reassemblyBuffers.remove(linkId)
                reassemblyStartedAt.remove(linkId)
                return
            }
            reassemblyBuffers[linkId] = existing + payload
        }

        if (isLast) {
            reassemblyStartedAt.remove(linkId)
            val complete = reassemblyBuffers.remove(linkId) ?: return
            Log.d(TAG, "Reassembled ${complete.size} bytes on $linkId")
            listener?.onLinkData(linkId, complete)
        }
    }

    // --- Fragment sizing based on negotiated MTU ---

    private fun fragmentForDevice(address: String, data: ByteArray): List<ByteArray> {
        val mtu = deviceMtus[address] ?: 23
        // ATT header: 3 bytes, our fragmentation header: 1 byte, and never
        // a value the framework itself will refuse.
        val fragSize = maxOf(mtu - 4, DEFAULT_FRAGMENT_SIZE)
            .coerceAtMost(MAX_ATT_VALUE - 1)
        return fragment(data, fragSize)
    }

    private fun fragment(data: ByteArray, fragSize: Int): List<ByteArray> {
        if (data.size <= fragSize) {
            return listOf(byteArrayOf(FLAG_SINGLE) + data)
        }

        val fragments = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + fragSize, data.size)
            val chunk = data.copyOfRange(offset, end)

            val flags: Byte = when {
                offset == 0 && end == data.size -> FLAG_SINGLE
                offset == 0 -> FLAG_FIRST
                end == data.size -> FLAG_LAST
                else -> 0x00
            }

            fragments.add(byteArrayOf(flags) + chunk)
            offset = end
        }
        return fragments
    }
}
