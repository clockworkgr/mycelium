package com.mycelium.mycelium_mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bluetooth Classic SPP (Serial Port Profile) transport service.
 *
 * Provides higher throughput than BLE (~2 Mbps) via RFCOMM sockets.
 * Runs both a listening server socket (accepting incoming connections)
 * and initiates outgoing connections to discovered peers.
 *
 * Wire protocol: [4-byte BE length][1-byte type][payload]
 *   Type 0x01 = Hello (32-byte node ID exchange)
 *   Type 0x02 = MeshData (variable-length mesh payload)
 *
 * SPP UUID: a1b2c3d4-e5f6-7890-abcd-ef12345678b0
 */
@SuppressLint("MissingPermission")
class BtClassicService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumBTClassic"

        /** SPP service UUID — distinct from BLE service UUID. */
        val SPP_UUID: UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678b0")
        private const val SERVICE_NAME = "MyceliumMesh"

        private const val MSG_HELLO: Byte = 0x01
        private const val MSG_MESH_DATA: Byte = 0x02

        private const val DISCOVERY_INTERVAL_MS = 30_000L
    }

    interface EventListener {
        fun onPeerConnected(peerId: ByteArray)
        fun onPeerDisconnected(peerId: ByteArray)
        fun onDataReceived(peerId: ByteArray, data: ByteArray)
    }

    var listener: EventListener? = null

    private var localNodeId: ByteArray = ByteArray(32)
    private val running = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newCachedThreadPool()

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var serverSocket: BluetoothServerSocket? = null

    // Connected peers: node ID hex -> PeerConnection
    private val peers = ConcurrentHashMap<String, PeerConnection>()
    // MAC address -> node ID (for discovery matching)
    private val addressToNodeId = ConcurrentHashMap<String, ByteArray>()

    private class PeerConnection(
        val nodeId: ByteArray,
        val socket: BluetoothSocket,
        val input: DataInputStream,
        val output: DataOutputStream
    )

    // --- Public API ---

    fun start(nodeId: ByteArray) {
        if (running.getAndSet(true)) return
        localNodeId = nodeId.copyOf()

        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = manager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e(TAG, "Bluetooth not available or disabled")
            running.set(false)
            return
        }

        // Register for discovery events
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(discoveryReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(discoveryReceiver, filter)
        }

        // Start listening for incoming connections
        startServer()

        // Start periodic discovery
        scheduleDiscovery()

        Log.i(TAG, "BT Classic service started")
    }

    fun stop() {
        if (!running.getAndSet(false)) return

        handler.removeCallbacksAndMessages(null)
        bluetoothAdapter?.cancelDiscovery()

        try {
            context.unregisterReceiver(discoveryReceiver)
        } catch (_: Exception) {}

        // Close server
        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        serverSocket = null

        // Disconnect all peers
        for ((hex, conn) in peers) {
            try {
                conn.socket.close()
            } catch (_: Exception) {}
            listener?.onPeerDisconnected(conn.nodeId)
        }
        peers.clear()
        addressToNodeId.clear()

        Log.i(TAG, "BT Classic service stopped")
    }

    /** Send mesh data to a specific peer. */
    fun sendData(peerId: ByteArray, data: ByteArray): Boolean {
        val hex = peerId.toHex()
        val conn = peers[hex] ?: return false

        return try {
            synchronized(conn.output) {
                val frameLen = 1 + data.size
                conn.output.writeInt(frameLen)
                conn.output.writeByte(MSG_MESH_DATA.toInt())
                conn.output.write(data)
                conn.output.flush()
            }
            true
        } catch (e: Exception) {
            Log.w(TAG, "Send failed to ${hex.take(16)}: ${e.message}")
            handlePeerDisconnect(hex)
            false
        }
    }

    // --- Server ---

    private fun startServer() {
        executor.submit {
            try {
                serverSocket = bluetoothAdapter?.listenUsingRfcommWithServiceRecord(
                    SERVICE_NAME, SPP_UUID
                )
                Log.d(TAG, "SPP server listening")

                while (running.get()) {
                    val socket = try {
                        serverSocket?.accept()
                    } catch (_: Exception) {
                        null
                    } ?: break

                    Log.d(TAG, "Incoming SPP connection from ${socket.remoteDevice.address}")
                    executor.submit { handleConnection(socket, isOutgoing = false) }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server socket error: ${e.message}")
            }
        }
    }

    // --- Connection Handling ---

    private fun handleConnection(socket: BluetoothSocket, isOutgoing: Boolean) {
        try {
            val input = DataInputStream(BufferedInputStream(socket.inputStream))
            val output = DataOutputStream(BufferedOutputStream(socket.outputStream))

            // Send Hello with our node ID
            val helloLen = 1 + localNodeId.size
            output.writeInt(helloLen)
            output.writeByte(MSG_HELLO.toInt())
            output.write(localNodeId)
            output.flush()

            // Read peer's Hello
            val peerHelloLen = input.readInt()
            val type = input.readByte()
            if (type != MSG_HELLO || peerHelloLen != 33) {
                Log.w(TAG, "Invalid hello from ${socket.remoteDevice.address}")
                socket.close()
                return
            }
            val peerId = ByteArray(32)
            input.readFully(peerId)

            val hex = peerId.toHex()
            if (peers.containsKey(hex)) {
                Log.d(TAG, "Already connected to ${hex.take(16)}, closing duplicate")
                socket.close()
                return
            }

            val conn = PeerConnection(peerId, socket, input, output)
            peers[hex] = conn
            addressToNodeId[socket.remoteDevice.address] = peerId

            Log.i(TAG, "BT Classic peer connected: ${hex.take(16)} (${if (isOutgoing) "outgoing" else "incoming"})")
            handler.post { listener?.onPeerConnected(peerId) }

            // Read loop
            while (running.get() && socket.isConnected) {
                val frameLen = input.readInt()
                if (frameLen <= 0 || frameLen > 65536) {
                    Log.w(TAG, "Invalid frame length $frameLen, disconnecting")
                    break
                }
                val msgType = input.readByte()
                val payload = ByteArray(frameLen - 1)
                input.readFully(payload)

                if (msgType == MSG_MESH_DATA) {
                    handler.post { listener?.onDataReceived(peerId, payload) }
                }
            }
        } catch (e: Exception) {
            // Connection closed or error
            Log.d(TAG, "Connection ended: ${e.message}")
        } finally {
            try { socket.close() } catch (_: Exception) {}
            val peerId = addressToNodeId.remove(socket.remoteDevice.address)
            if (peerId != null) {
                handlePeerDisconnect(peerId.toHex())
            }
        }
    }

    private fun handlePeerDisconnect(hex: String) {
        val conn = peers.remove(hex) ?: return
        try { conn.socket.close() } catch (_: Exception) {}
        Log.i(TAG, "BT Classic peer disconnected: ${hex.take(16)}")
        handler.post { listener?.onPeerDisconnected(conn.nodeId) }
    }

    // --- Discovery ---

    private fun scheduleDiscovery() {
        if (!running.get()) return
        handler.postDelayed({
            if (running.get()) {
                startDiscovery()
                scheduleDiscovery()
            }
        }, DISCOVERY_INTERVAL_MS)
    }

    private fun startDiscovery() {
        try {
            bluetoothAdapter?.startDiscovery()
            Log.d(TAG, "Started BT Classic discovery")
        } catch (e: Exception) {
            Log.w(TAG, "Discovery start failed: ${e.message}")
        }
    }

    private val discoveryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    }

                    device?.let {
                        // Check if device supports our SPP UUID
                        val uuids = it.uuids
                        if (uuids != null && uuids.any { u -> u.uuid == SPP_UUID }) {
                            val addr = it.address
                            if (!addressToNodeId.containsKey(addr)) {
                                Log.i(TAG, "Discovered Mycelium peer: $addr")
                                connectToPeer(it)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun connectToPeer(device: BluetoothDevice) {
        executor.submit {
            try {
                bluetoothAdapter?.cancelDiscovery()
                val socket = device.createRfcommSocketToServiceRecord(SPP_UUID)
                socket.connect()
                handleConnection(socket, isOutgoing = true)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to connect to ${device.address}: ${e.message}")
            }
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
