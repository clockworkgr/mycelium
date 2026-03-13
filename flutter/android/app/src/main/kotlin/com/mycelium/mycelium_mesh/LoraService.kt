package com.mycelium.mycelium_mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * LoRa BLE GATT bridge service.
 *
 * Connects to an external LoRa radio module (e.g. ESP32+SX1276) over BLE.
 * The phone acts as a GATT client; the LoRa module exposes the GATT server.
 *
 * GATT service layout:
 *   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef12345678a0
 *   Data TX char:   ...78a1  (Write)      — Phone writes outgoing mesh packets
 *   Data RX char:   ...78a2  (Notify)     — LoRa module notifies with received packets
 *   Config char:    ...78a3  (Read/Write)  — Radio config (freq, SF, BW, TX power)
 *   Status char:    ...78a4  (Read/Notify) — Radio status (RSSI, SNR, duty cycle)
 *
 * Config characteristic format (8 bytes, little-endian):
 *   [0..3] frequency_hz (u32)
 *   [4]    spreading_factor (u8)
 *   [5..6] bandwidth_khz (u16)
 *   [7]    tx_power_dbm (i8)
 *
 * Status characteristic format (8 bytes, little-endian):
 *   [0..1] last_rssi (i16)
 *   [2]    last_snr (i8)
 *   [3]    duty_cycle_pct (u8, 0-100)
 *   [4..7] error_count (u32)
 */
@SuppressLint("MissingPermission")
class LoraService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumLoRa"

        val SERVICE_UUID: UUID  = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678a0")
        val DATA_TX_UUID: UUID  = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678a1")
        val DATA_RX_UUID: UUID  = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678a2")
        val CONFIG_UUID: UUID   = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678a3")
        val STATUS_UUID: UUID   = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef12345678a4")
        val CCCD_UUID: UUID     = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val SCAN_PERIOD_MS = 10_000L
        const val RECONNECT_DELAY_MS = 3000L
    }

    interface EventListener {
        /** Called when a LoRa module is connected and ready. */
        fun onModuleConnected(moduleAddress: String)
        /** Called when the LoRa module disconnects. */
        fun onModuleDisconnected(moduleAddress: String)
        /** Called when mesh data is received from the LoRa radio. */
        fun onDataReceived(data: ByteArray, rssi: Int)
        /** Called when a TX operation succeeds (for ADR feedback). */
        fun onTxSuccess()
        /** Called when a TX operation fails (for ADR feedback). */
        fun onTxFailure()
    }

    var listener: EventListener? = null

    private val running = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())

    private var bluetoothManager: BluetoothManager? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var scanner: BluetoothLeScanner? = null
    private var connectedGatt: BluetoothGatt? = null
    private var connectedAddress: String? = null

    // Characteristic references (set after service discovery)
    private var dataTxChar: BluetoothGattCharacteristic? = null
    private var dataRxChar: BluetoothGattCharacteristic? = null
    private var configChar: BluetoothGattCharacteristic? = null
    private var statusChar: BluetoothGattCharacteristic? = null

    // Track known LoRa module addresses for auto-reconnect
    private val knownModules = ConcurrentHashMap<String, Boolean>()

    // --- Public API ---

    fun start() {
        if (running.getAndSet(true)) return

        bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e(TAG, "Bluetooth not available or disabled")
            running.set(false)
            return
        }

        scanner = bluetoothAdapter?.bluetoothLeScanner
        startScan()
        Log.i(TAG, "LoRa BLE bridge started, scanning for modules...")
    }

    fun stop() {
        if (!running.getAndSet(false)) return

        stopScan()
        disconnectModule()
        handler.removeCallbacksAndMessages(null)
        Log.i(TAG, "LoRa BLE bridge stopped")
    }

    /** Send mesh data to the LoRa module for transmission. */
    fun sendData(data: ByteArray): Boolean {
        val char = dataTxChar ?: return false
        val gatt = connectedGatt ?: return false

        char.value = data
        val writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        char.writeType = writeType
        val success = gatt.writeCharacteristic(char)

        if (!success) {
            Log.w(TAG, "Failed to write ${data.size} bytes to Data TX")
        } else {
            Log.d(TAG, "Sent ${data.size} bytes to LoRa module")
        }
        return success
    }

    /** Read current radio configuration from the LoRa module. */
    fun readConfig(): Boolean {
        val char = configChar ?: return false
        val gatt = connectedGatt ?: return false
        return gatt.readCharacteristic(char)
    }

    /** Write radio configuration to the LoRa module. */
    fun writeConfig(frequencyHz: Int, sf: Int, bwKhz: Int, txPowerDbm: Int): Boolean {
        val char = configChar ?: return false
        val gatt = connectedGatt ?: return false

        val data = ByteArray(8)
        // frequency_hz (u32 LE)
        data[0] = (frequencyHz and 0xFF).toByte()
        data[1] = ((frequencyHz shr 8) and 0xFF).toByte()
        data[2] = ((frequencyHz shr 16) and 0xFF).toByte()
        data[3] = ((frequencyHz shr 24) and 0xFF).toByte()
        // spreading_factor (u8)
        data[4] = sf.toByte()
        // bandwidth_khz (u16 LE)
        data[5] = (bwKhz and 0xFF).toByte()
        data[6] = ((bwKhz shr 8) and 0xFF).toByte()
        // tx_power_dbm (i8)
        data[7] = txPowerDbm.toByte()

        char.value = data
        char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        return gatt.writeCharacteristic(char)
    }

    val isConnected: Boolean get() = connectedGatt != null && dataTxChar != null

    // --- BLE Scanning ---

    private fun startScan() {
        if (!running.get()) return

        val filters = listOf(
            ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(SERVICE_UUID))
                .build()
        )
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        try {
            scanner?.startScan(filters, settings, scanCallback)
            Log.d(TAG, "BLE scan started for LoRa modules")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start scan: ${e.message}")
        }

        // Stop scan after period to save power
        handler.postDelayed({
            stopScan()
            if (running.get() && connectedGatt == null) {
                // Restart scan if not connected
                handler.postDelayed({ startScan() }, 2000)
            }
        }, SCAN_PERIOD_MS)
    }

    private fun stopScan() {
        try {
            scanner?.stopScan(scanCallback)
        } catch (_: Exception) {}
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val address = device.address

            if (connectedGatt != null) return // Already connected to a module

            Log.i(TAG, "Found LoRa module: $address (RSSI: ${result.rssi})")
            knownModules[address] = true
            stopScan()
            connectModule(device)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: errorCode=$errorCode")
        }
    }

    // --- GATT Connection ---

    private fun connectModule(device: BluetoothDevice) {
        Log.d(TAG, "Connecting to LoRa module ${device.address}")
        device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
    }

    private fun disconnectModule() {
        connectedGatt?.let { gatt ->
            gatt.disconnect()
            gatt.close()
        }
        connectedGatt = null
        connectedAddress = null
        dataTxChar = null
        dataRxChar = null
        configChar = null
        statusChar = null
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val address = gatt.device.address
            if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "Connected to LoRa module $address")
                connectedGatt = gatt
                connectedAddress = address
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.i(TAG, "Disconnected from LoRa module $address")
                val wasConnected = connectedAddress == address
                gatt.close()
                if (connectedAddress == address) {
                    connectedGatt = null
                    connectedAddress = null
                    dataTxChar = null
                    dataRxChar = null
                    configChar = null
                    statusChar = null
                }
                if (wasConnected) {
                    listener?.onModuleDisconnected(address)
                    // Auto-reconnect after delay
                    if (running.get()) {
                        handler.postDelayed({ startScan() }, RECONNECT_DELAY_MS)
                    }
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "Service discovery failed: $status")
                gatt.disconnect()
                return
            }

            val service = gatt.getService(SERVICE_UUID)
            if (service == null) {
                Log.e(TAG, "LoRa GATT service not found on ${gatt.device.address}")
                gatt.disconnect()
                return
            }

            dataTxChar = service.getCharacteristic(DATA_TX_UUID)
            dataRxChar = service.getCharacteristic(DATA_RX_UUID)
            configChar = service.getCharacteristic(CONFIG_UUID)
            statusChar = service.getCharacteristic(STATUS_UUID)

            if (dataTxChar == null || dataRxChar == null) {
                Log.e(TAG, "Required LoRa characteristics not found")
                gatt.disconnect()
                return
            }

            // Subscribe to Data RX notifications
            gatt.setCharacteristicNotification(dataRxChar, true)
            val descriptor = dataRxChar!!.getDescriptor(CCCD_UUID)
            if (descriptor != null) {
                descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(descriptor)
            }

            // Optionally subscribe to Status notifications
            statusChar?.let { sc ->
                gatt.setCharacteristicNotification(sc, true)
                sc.getDescriptor(CCCD_UUID)?.let { desc ->
                    desc.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    // Queue after RX descriptor write completes
                    handler.postDelayed({
                        connectedGatt?.writeDescriptor(desc)
                    }, 500)
                }
            }

            Log.i(TAG, "LoRa module ready: ${gatt.device.address}")
            listener?.onModuleConnected(gatt.device.address)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            when (characteristic.uuid) {
                DATA_RX_UUID -> {
                    val data = characteristic.value ?: return
                    Log.d(TAG, "Received ${data.size} bytes from LoRa radio")
                    // RSSI is not available per-packet via BLE; use -110 as typical LoRa
                    listener?.onDataReceived(data, -110)
                }
                STATUS_UUID -> {
                    val value = characteristic.value ?: return
                    if (value.size >= 4) {
                        val rssi = (value[0].toInt() and 0xFF) or (value[1].toInt() shl 8)
                        val snr = value[2].toInt()
                        val dutyCycle = value[3].toInt() and 0xFF
                        Log.d(TAG, "LoRa status: RSSI=$rssi, SNR=$snr, duty=$dutyCycle%")
                    }
                }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (characteristic.uuid == DATA_TX_UUID) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    listener?.onTxSuccess()
                } else {
                    Log.w(TAG, "LoRa TX write failed: status=$status")
                    listener?.onTxFailure()
                }
            }
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (characteristic.uuid == CONFIG_UUID && status == BluetoothGatt.GATT_SUCCESS) {
                val value = characteristic.value ?: return
                if (value.size >= 8) {
                    val freqHz = (value[0].toInt() and 0xFF) or
                            ((value[1].toInt() and 0xFF) shl 8) or
                            ((value[2].toInt() and 0xFF) shl 16) or
                            ((value[3].toInt() and 0xFF) shl 24)
                    val sf = value[4].toInt() and 0xFF
                    val bwKhz = (value[5].toInt() and 0xFF) or ((value[6].toInt() and 0xFF) shl 8)
                    val txPower = value[7].toInt()
                    Log.i(TAG, "LoRa config: freq=${freqHz}Hz, SF$sf, BW=${bwKhz}kHz, TX=${txPower}dBm")
                }
            }
        }
    }
}
