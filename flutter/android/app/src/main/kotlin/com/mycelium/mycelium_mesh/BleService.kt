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
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.random.Random

/**
 * BLE transport service implementing both peripheral (GATT server) and
 * central (scanner/client) roles simultaneously.
 *
 * GATT service layout:
 *   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef1234567890
 *   Node ID char:   ...7891  (Read)   — 32-byte Ed25519 public key
 *   Data TX char:   ...7892  (Write)  — central writes data to peripheral
 *   Data RX char:   ...7893  (Notify) — peripheral notifies central with data
 *
 * Fragmentation header (1 byte):
 *   0x01 = first fragment
 *   0x02 = last fragment
 *   0x03 = first+last (single packet)
 */
@SuppressLint("MissingPermission")
class BleService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumBLE"

        val SERVICE_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        val NODE_ID_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567891")
        val DATA_TX_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567892")
        val DATA_RX_UUID: UUID      = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567893")
        val IDENTITY_UUID: UUID     = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567894")
        val CCCD_UUID: UUID         = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val FLAG_FIRST: Byte = 0x01
        const val FLAG_LAST: Byte  = 0x02
        const val FLAG_SINGLE: Byte = 0x03

        // Default fragment size (conservative, for 23-byte default MTU)
        const val DEFAULT_FRAGMENT_SIZE = 20

        // Connection retry settings
        const val MAX_CONNECT_RETRIES = 3
        const val BASE_RETRY_DELAY_MS = 1000L

        // Scan cycling: Android kills LOW_LATENCY scans after ~30s.
        // Restart periodically to stay under the limit.
        const val SCAN_CYCLE_MS = 25_000L

        // Auto-reconnect delay after a known peer disconnects
        const val RECONNECT_DELAY_MS = 2000L
    }

    interface EventListener {
        fun onPeerDiscovered(peerId: ByteArray)
        fun onPeerLost(peerId: ByteArray)
        fun onDataReceived(peerId: ByteArray, data: ByteArray)
    }

    var listener: EventListener? = null

    private var localNodeId: ByteArray = ByteArray(32)
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
    private val peerNodeIds = ConcurrentHashMap<String, ByteArray>()  // device address -> node ID
    private val nodeIdToAddress = ConcurrentHashMap<String, String>()  // hex node ID -> device address

    // Connection management: track retry counts and pending connection attempts
    private val connectRetryCounts = ConcurrentHashMap<String, Int>()
    private val pendingConnections = ConcurrentHashMap<String, Boolean>()
    // Track devices connected to our GATT server (inbound connections)
    private val serverConnectedDevices = ConcurrentHashMap<String, Boolean>()

    // Per-device negotiated MTU (default 23)
    private val deviceMtus = ConcurrentHashMap<String, Int>()

    // Addresses of known peers that disconnected — eligible for auto-reconnect
    private val disconnectedPeers = ConcurrentHashMap<String, BluetoothDevice>()

    // Fragment reassembly: device address -> partial buffer
    private val reassemblyBuffers = ConcurrentHashMap<String, ByteArray>()

    // --- Sequential Write Queue ---
    // Android BLE allows only one outstanding GATT operation per connection.
    // This queue ensures writes are serialized properly.
    data class WriteOperation(
        val address: String,
        val fragments: List<ByteArray>,
        var currentIndex: Int = 0,
        val isClientWrite: Boolean  // true = GATT client write, false = GATT server notify
    )

    private val writeQueue = ConcurrentLinkedQueue<WriteOperation>()
    @Volatile private var writeInProgress = false
    private val writeLock = Any()

    // --- Public API ---

    fun start(nodeId: ByteArray) {
        if (running) return
        localNodeId = nodeId
        running = true

        bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.w(TAG, "Bluetooth not available or not enabled")
            return
        }

        startPeripheral()
        startCentral()
        Log.i(TAG, "BLE service started")
    }

    fun stop() {
        if (!running) return
        running = false

        stopCentral()
        stopPeripheral()

        // Clear write queue
        synchronized(writeLock) {
            writeQueue.clear()
            writeInProgress = false
        }

        // Notify peer lost for all known peers
        for ((_, nodeId) in peerNodeIds) {
            listener?.onPeerLost(nodeId)
        }
        peerNodeIds.clear()
        nodeIdToAddress.clear()
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

    fun sendData(peerId: ByteArray, data: ByteArray): Boolean {
        val peerHex = peerId.toHex()
        val address = nodeIdToAddress[peerHex] ?: run {
            Log.w(TAG, "sendData: no address for peer ${peerHex.take(16)}")
            return false
        }

        // Try GATT client write first (we are central, peer is peripheral)
        val gatt = connectedGatts[address]
        if (gatt != null) {
            val fragments = fragmentForDevice(address, data)
            Log.d(TAG, "sendData: ${data.size} bytes -> ${fragments.size} fragments via GATT client to ${peerHex.take(16)}")
            enqueueWrite(WriteOperation(address, fragments, 0, isClientWrite = true))
            return true
        }

        // Try GATT server notify (we are peripheral, peer is central)
        val device = subscribedDevices[address]
        if (device != null) {
            val fragments = fragmentForDevice(address, data)
            Log.d(TAG, "sendData: ${data.size} bytes -> ${fragments.size} fragments via GATT server to ${peerHex.take(16)}")
            enqueueWrite(WriteOperation(address, fragments, 0, isClientWrite = false))
            return true
        }

        Log.w(TAG, "sendData: no connection to peer ${peerHex.take(16)}")
        return false
    }

    // --- Write Queue Management ---

    private fun enqueueWrite(op: WriteOperation) {
        writeQueue.add(op)
        processNextWrite()
    }

    private fun processNextWrite() {
        synchronized(writeLock) {
            if (writeInProgress) return

            val op = writeQueue.peek() ?: return

            if (op.currentIndex >= op.fragments.size) {
                // Current operation complete, move to next
                writeQueue.poll()
                processNextWrite()
                return
            }

            writeInProgress = true
            val frag = op.fragments[op.currentIndex]
            op.currentIndex++

            if (op.isClientWrite) {
                val gatt = connectedGatts[op.address]
                if (gatt == null) {
                    Log.w(TAG, "writeQueue: GATT client gone for ${op.address}")
                    writeQueue.poll()
                    writeInProgress = false
                    processNextWrite()
                    return
                }
                val service = gatt.getService(SERVICE_UUID)
                val txChar = service?.getCharacteristic(DATA_TX_UUID)
                if (txChar == null) {
                    Log.w(TAG, "writeQueue: TX characteristic not found")
                    writeQueue.poll()
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
                    writeQueue.poll()
                    writeInProgress = false
                    processNextWrite()
                }
                // else: wait for onCharacteristicWrite callback
            } else {
                // Server notify
                val server = gattServer
                val device = subscribedDevices[op.address]
                if (server == null || device == null) {
                    Log.w(TAG, "writeQueue: GATT server or device gone for ${op.address}")
                    writeQueue.poll()
                    writeInProgress = false
                    processNextWrite()
                    return
                }
                val service = server.getService(SERVICE_UUID)
                val rxChar = service?.getCharacteristic(DATA_RX_UUID)
                if (rxChar == null) {
                    Log.w(TAG, "writeQueue: RX characteristic not found")
                    writeQueue.poll()
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
                    writeQueue.poll()
                    writeInProgress = false
                    processNextWrite()
                }
                // else: wait for onNotificationSent callback
            }
        }
    }

    private fun onWriteCompleted(success: Boolean) {
        synchronized(writeLock) {
            if (!success) {
                // Drop remaining fragments of current operation
                val op = writeQueue.poll()
                if (op != null) {
                    Log.w(TAG, "writeQueue: write failed, dropping ${op.fragments.size - op.currentIndex} remaining fragments")
                }
            }
            writeInProgress = false
        }
        processNextWrite()
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

        // Node ID characteristic (read)
        val nodeIdChar = BluetoothGattCharacteristic(
            NODE_ID_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        // Identity characteristic (write) — client writes its 32-byte node ID
        // so the server can associate the client's BLE address with a node ID.
        // Needed because BLE RPA gives different addresses per connection.
        val identityChar = BluetoothGattCharacteristic(
            IDENTITY_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
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

        service.addCharacteristic(nodeIdChar)
        service.addCharacteristic(identityChar)
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
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "GATT server: device disconnected $address")
                serverConnectedDevices.remove(address)
                subscribedDevices.remove(address)
                handlePeerDisconnected(address)
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            when (characteristic.uuid) {
                NODE_ID_UUID -> {
                    Log.d(TAG, "Node ID read by ${device.address}")
                    val data = if (offset < localNodeId.size) {
                        localNodeId.copyOfRange(offset, localNodeId.size)
                    } else {
                        ByteArray(0)
                    }
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data)
                }
                else -> {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, 0, null)
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray?
        ) {
            when (characteristic.uuid) {
                IDENTITY_UUID -> {
                    // Client is identifying itself with its 32-byte node ID
                    if (value != null && value.size == 32) {
                        val address = device.address
                        peerNodeIds[address] = value
                        nodeIdToAddress[value.toHex()] = address
                        Log.i(TAG, "GATT server: client identified as ${value.toHex().take(16)}... at $address")
                    }
                    if (responseNeeded) {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    }
                }
                DATA_TX_UUID -> {
                    if (value != null && value.isNotEmpty()) {
                        Log.d(TAG, "GATT server: received ${value.size} bytes from ${device.address}")
                        handleFragment(device.address, value)
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
                if (value?.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == true) {
                    subscribedDevices[device.address] = device
                    Log.d(TAG, "Device ${device.address} subscribed to notifications")
                } else {
                    subscribedDevices.remove(device.address)
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
            onWriteCompleted(status == BluetoothGatt.GATT_SUCCESS)
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
                // Also retry any disconnected peers
                retryDisconnectedPeers()
            }
        }, 500)
    }

    private fun retryDisconnectedPeers() {
        val toRetry = ArrayList(disconnectedPeers.entries)
        for ((address, device) in toRetry) {
            if (connectedGatts.containsKey(address) || pendingConnections.containsKey(address)) {
                disconnectedPeers.remove(address)
                continue
            }
            Log.d(TAG, "Auto-reconnecting to previously known peer at $address")
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

            // Skip if we already know this peer (connected via server side)
            if (peerNodeIds.containsKey(address)) return

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
                if (connectedGatts.containsKey(address) || peerNodeIds.containsKey(address)) {
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
                connectRetryCounts.remove(address)
                gatt.requestMtu(512)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d(TAG, "GATT client disconnected from $address (status=$status)")
                gatt.close()
                connectedGatts.remove(address)
                deviceMtus.remove(address)

                // If the peer was already discovered, notify disconnect
                if (peerNodeIds.containsKey(address)) {
                    handlePeerDisconnected(address)
                    pendingConnections.remove(address)
                    return
                }

                // Retry on connection failure (status != 0 means error during connect)
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    val attempt = (connectRetryCounts[address] ?: 0)
                    if (attempt < MAX_CONNECT_RETRIES) {
                        val delay = BASE_RETRY_DELAY_MS * (attempt + 1) + Random.nextLong(0, 500)
                        Log.d(TAG, "Retrying connection to $address in ${delay}ms (attempt ${attempt + 2})")
                        handler.postDelayed({
                            if (running && !connectedGatts.containsKey(address) && !peerNodeIds.containsKey(address)) {
                                connectToDevice(gatt.device, attempt + 1)
                            } else {
                                pendingConnections.remove(address)
                            }
                        }, delay)
                    } else {
                        Log.w(TAG, "Giving up connection to $address after ${attempt + 1} attempts")
                        pendingConnections.remove(address)
                        connectRetryCounts.remove(address)
                    }
                } else {
                    pendingConnections.remove(address)
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

            // Read the Node ID characteristic
            val nodeIdChar = service.getCharacteristic(NODE_ID_UUID)
            if (nodeIdChar != null) {
                Log.d(TAG, "Reading Node ID from ${gatt.device.address}")
                gatt.readCharacteristic(nodeIdChar)
            }
        }

        // API 33+ callback
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            handleNodeIdRead(gatt, characteristic, value, status)
        }

        // Pre-API 33 callback
        @Suppress("DEPRECATION")
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            handleNodeIdRead(gatt, characteristic, characteristic.value ?: return, status)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (characteristic.uuid == IDENTITY_UUID) {
                Log.d(TAG, "Identity write completed: status=$status for ${gatt.device.address}")
                // Identity handshake done — NOW emit peerDiscovered so Rust
                // can safely send data without conflicting with our setup writes.
                val nodeId = peerNodeIds[gatt.device.address]
                if (nodeId != null) {
                    listener?.onPeerDiscovered(nodeId)
                }
                return
            }
            Log.d(TAG, "onCharacteristicWrite: status=$status for ${gatt.device.address}")
            onWriteCompleted(status == BluetoothGatt.GATT_SUCCESS)
        }

        @Suppress("DEPRECATION")
        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            if (descriptor.uuid == CCCD_UUID) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    // CCCD write completed → now write our node ID to the server's
                    // Identity characteristic so the server can map our address
                    writeIdentityOrEmitDiscovered(gatt)
                } else {
                    Log.w(TAG, "CCCD write failed (status=$status), emitting peerDiscovered anyway")
                    emitPeerDiscoveredForAddress(gatt.device.address)
                }
            }
        }

        // API 33+ callback
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid == DATA_RX_UUID) {
                Log.d(TAG, "GATT client: received ${value.size} bytes from ${gatt.device.address}")
                handleFragment(gatt.device.address, value)
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
                Log.d(TAG, "GATT client: received ${value.size} bytes from ${gatt.device.address}")
                handleFragment(gatt.device.address, value)
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun writeIdentityOrEmitDiscovered(gatt: BluetoothGatt) {
        val service = gatt.getService(SERVICE_UUID)
        val identityChar = service?.getCharacteristic(IDENTITY_UUID)
        if (identityChar != null) {
            Log.d(TAG, "Writing our node ID to server identity char at ${gatt.device.address}")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt.writeCharacteristic(
                    identityChar, localNodeId,
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                )
            } else {
                identityChar.value = localNodeId
                identityChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                gatt.writeCharacteristic(identityChar)
            }
            // peerDiscovered will be emitted from onCharacteristicWrite
        } else {
            Log.w(TAG, "No identity characteristic, emitting peerDiscovered directly")
            emitPeerDiscoveredForAddress(gatt.device.address)
        }
    }

    private fun emitPeerDiscoveredForAddress(address: String) {
        val nodeId = peerNodeIds[address]
        if (nodeId != null) {
            listener?.onPeerDiscovered(nodeId)
        }
    }

    private fun handleNodeIdRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        status: Int
    ) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.w(TAG, "Node ID read failed: status=$status")
            return
        }
        val address = gatt.device.address

        if (characteristic.uuid == NODE_ID_UUID && value.size == 32) {
            // Don't connect to ourselves
            if (value.contentEquals(localNodeId)) {
                Log.d(TAG, "Discovered self at $address, ignoring")
                gatt.close()
                connectedGatts.remove(address)
                pendingConnections.remove(address)
                return
            }

            peerNodeIds[address] = value
            nodeIdToAddress[value.toHex()] = address
            Log.i(TAG, "Peer discovered: ${value.toHex().take(16)}... at $address")

            // Subscribe to RX notifications, then write identity, then emit peerDiscovered.
            // peerDiscovered is deferred to onCharacteristicWrite (after identity write)
            // to prevent a GATT write race condition where Rust tries to send data
            // while the identity write is still in flight.
            val service = gatt.getService(SERVICE_UUID)
            val rxChar = service?.getCharacteristic(DATA_RX_UUID)
            if (rxChar != null) {
                gatt.setCharacteristicNotification(rxChar, true)
                val cccd = rxChar.getDescriptor(CCCD_UUID)
                if (cccd != null) {
                    @Suppress("DEPRECATION")
                    cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    gatt.writeDescriptor(cccd)
                } else {
                    // No CCCD → can't subscribe, but still try identity write
                    writeIdentityOrEmitDiscovered(gatt)
                }
            } else {
                // No RX characteristic → skip subscription, try identity write
                writeIdentityOrEmitDiscovered(gatt)
            }
        } else {
            Log.w(TAG, "Node ID read: unexpected size ${value.size} or wrong UUID")
        }
    }

    // --- Fragmentation ---

    private fun handleFragment(address: String, raw: ByteArray) {
        if (raw.isEmpty()) return
        val flags = raw[0]
        val payload = if (raw.size > 1) raw.copyOfRange(1, raw.size) else ByteArray(0)

        val isFirst = (flags.toInt() and 0x01) != 0
        val isLast  = (flags.toInt() and 0x02) != 0

        if (isFirst) {
            reassemblyBuffers[address] = payload
        } else {
            val existing = reassemblyBuffers[address] ?: return
            reassemblyBuffers[address] = existing + payload
        }

        if (isLast) {
            val complete = reassemblyBuffers.remove(address) ?: return
            val peerId = peerNodeIds[address] ?: return
            Log.d(TAG, "Reassembled ${complete.size} bytes from ${address}")
            listener?.onDataReceived(peerId, complete)
        }
    }

    // --- Fragment sizing based on negotiated MTU ---

    private fun fragmentForDevice(address: String, data: ByteArray): List<ByteArray> {
        val mtu = deviceMtus[address] ?: 23
        // ATT header: 3 bytes, our fragmentation header: 1 byte
        val fragSize = maxOf(mtu - 4, DEFAULT_FRAGMENT_SIZE)
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

    // --- Helpers ---

    private fun handlePeerDisconnected(address: String) {
        val nodeId = peerNodeIds.remove(address) ?: return
        nodeIdToAddress.remove(nodeId.toHex())
        Log.i(TAG, "Peer lost: ${nodeId.toHex().take(16)}...")
        listener?.onPeerLost(nodeId)

        // Schedule auto-reconnect if we have a device reference
        val device = bluetoothAdapter?.getRemoteDevice(address)
        if (device != null && running) {
            disconnectedPeers[address] = device
            handler.postDelayed({
                if (running && disconnectedPeers.containsKey(address) &&
                    !connectedGatts.containsKey(address) && !pendingConnections.containsKey(address)) {
                    Log.d(TAG, "Auto-reconnecting to lost peer at $address")
                    disconnectedPeers.remove(address)
                    pendingConnections[address] = true
                    connectToDevice(device, 0)
                }
            }, RECONNECT_DELAY_MS)
        }
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
