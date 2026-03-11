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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wi-Fi Direct transport service using Android WifiP2pManager.
 *
 * - Service discovery via Bonjour/mDNS (`_mycelium._tcp`)
 * - Group Owner runs a TCP server on port 9740
 * - Group Clients connect to the GO's IP
 * - TCP wire protocol: 1-byte type + 4-byte BE length + payload
 *   - Hello (0x01): 32-byte node ID exchange
 *   - MeshData (0x02): variable-length mesh payload
 */
@SuppressLint("MissingPermission")
class WifiDirectService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumWiFiDirect"
        private const val SERVICE_TYPE = "_mycelium._tcp"
        private const val SERVICE_NAME = "Mycelium"
        private const val TCP_PORT = 9740

        private const val MSG_HELLO: Byte = 0x01
        private const val MSG_MESH_DATA: Byte = 0x02
    }

    interface EventListener {
        fun onPeerConnected(peerId: ByteArray)
        fun onPeerDisconnected(peerId: ByteArray)
        fun onDataReceived(peerId: ByteArray, data: ByteArray)
    }

    var listener: EventListener? = null

    private var localNodeId: ByteArray = ByteArray(32)
    private val running = AtomicBoolean(false)

    private var manager: WifiP2pManager? = null
    private var channel: WifiP2pManager.Channel? = null
    private var receiver: BroadcastReceiver? = null

    // TCP I/O thread pool
    private val executor = Executors.newCachedThreadPool()

    // Group Owner server
    private var serverSocket: ServerSocket? = null

    // Connected peers: node ID hex -> PeerConnection
    private val peers = ConcurrentHashMap<String, PeerConnection>()

    // Track whether we are Group Owner
    @Volatile private var isGroupOwner = false

    private class PeerConnection(
        val nodeId: ByteArray,
        val socket: Socket,
        val output: DataOutputStream
    )

    // --- Public API ---

    fun start(nodeId: ByteArray) {
        if (running.getAndSet(true)) return
        localNodeId = nodeId
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
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        Log.i(TAG, "Stopping Wi-Fi Direct service")

        // Fire peer disconnected for all connected peers
        for ((_, peer) in peers) {
            closePeerQuietly(peer)
            listener?.onPeerDisconnected(peer.nodeId)
        }
        peers.clear()

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

    fun sendData(peerId: ByteArray, data: ByteArray): Boolean {
        val peerHex = peerId.toHex()
        val peer = peers[peerHex] ?: run {
            Log.w(TAG, "sendData: no connection for peer ${peerHex.take(16)}")
            return false
        }

        executor.execute {
            try {
                writeFrame(peer.output, MSG_MESH_DATA, data)
            } catch (e: Exception) {
                Log.w(TAG, "sendData failed for ${peerHex.take(16)}: ${e.message}")
                handlePeerDisconnected(peerHex, peer)
            }
        }
        return true
    }

    // --- Service Registration ---

    private fun registerService() {
        val nodePrefix = localNodeId.toHex().take(16)
        val record = mapOf("node" to nodePrefix)
        val serviceInfo = WifiP2pDnsSdServiceInfo.newInstance(
            SERVICE_NAME, SERVICE_TYPE, record
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
                        executor.execute { handleClient(client) }
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
        try {
            Log.i(TAG, "Connecting to Group Owner at $goIp:$TCP_PORT")
            val socket = Socket()
            socket.connect(InetSocketAddress(goIp, TCP_PORT), 5000)
            handleClient(socket)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect to GO: ${e.message}")
        }
    }

    // --- Shared Client Handler ---

    private fun handleClient(socket: Socket) {
        var peerHex: String? = null
        try {
            val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))

            // Send Hello with our node ID
            writeFrame(output, MSG_HELLO, localNodeId)

            // Read Hello from peer
            val (type, payload) = readFrame(input)
            if (type != MSG_HELLO || payload.size != 32) {
                Log.w(TAG, "Invalid Hello from peer")
                socket.close()
                return
            }

            val peerId = payload
            peerHex = peerId.toHex()

            // Don't connect to ourselves
            if (peerId.contentEquals(localNodeId)) {
                Log.d(TAG, "Connected to self, closing")
                socket.close()
                return
            }

            // Already connected?
            if (peers.containsKey(peerHex)) {
                Log.d(TAG, "Already connected to ${peerHex.take(16)}, closing duplicate")
                socket.close()
                return
            }

            val conn = PeerConnection(peerId, socket, output)
            peers[peerHex] = conn
            Log.i(TAG, "Peer connected: ${peerHex.take(16)}")
            listener?.onPeerConnected(peerId)

            // Read loop
            while (running.get() && !socket.isClosed) {
                val (msgType, data) = readFrame(input)
                when (msgType) {
                    MSG_MESH_DATA -> {
                        Log.d(TAG, "Received ${data.size} bytes from ${peerHex.take(16)}")
                        listener?.onDataReceived(peerId, data)
                    }
                    else -> {
                        Log.w(TAG, "Unknown message type: $msgType")
                    }
                }
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.d(TAG, "Peer connection ended: ${e.message}")
            }
        } finally {
            if (peerHex != null) {
                val peer = peers.remove(peerHex)
                if (peer != null) {
                    closePeerQuietly(peer)
                    Log.i(TAG, "Peer disconnected: ${peerHex.take(16)}")
                    listener?.onPeerDisconnected(peer.nodeId)
                }
            } else {
                try { socket.close() } catch (_: Exception) {}
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
        if (length < 0 || length > 65535) {
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
        for ((hex, peer) in peers) {
            closePeerQuietly(peer)
            listener?.onPeerDisconnected(peer.nodeId)
        }
        peers.clear()

        // Close server socket so it can be restarted on next group formation
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
    }

    private fun handlePeerDisconnected(peerHex: String, peer: PeerConnection) {
        if (peers.remove(peerHex) != null) {
            closePeerQuietly(peer)
            listener?.onPeerDisconnected(peer.nodeId)
        }
    }

    private fun closePeerQuietly(peer: PeerConnection) {
        try { peer.socket.close() } catch (_: Exception) {}
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
