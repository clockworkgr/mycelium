package com.mycelium.mycelium_mesh

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.*
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * USB Serial service for connecting to LoRa modules via USB OTG.
 *
 * Supports CDC ACM (standard USB serial) devices. Detected devices are
 * matched against a VID/PID allowlist of known LoRa boards (ESP32, FTDI,
 * CH340, CP210x, etc.).
 *
 * Wire protocol: raw bytes. The Kotlin side reads frames delimited by
 * a simple length-prefix: [2-byte BE length][payload].
 *
 * Received data is forwarded to the LoRa transport via the event listener.
 * Outgoing data from Rust is written to the USB serial port.
 */
class UsbSerialService(private val context: Context) {

    companion object {
        private const val TAG = "MyceliumUSB"
        private const val ACTION_USB_PERMISSION = "com.mycelium.USB_PERMISSION"
        private const val BAUD_RATE = 115200
        private const val READ_TIMEOUT_MS = 100
        private const val WRITE_TIMEOUT_MS = 1000

        /** Known USB VID/PID pairs for LoRa-capable boards. */
        val SUPPORTED_DEVICES = listOf(
            // Silicon Labs CP210x
            VidPid(0x10C4, 0xEA60),
            // FTDI FT232R
            VidPid(0x0403, 0x6001),
            // WCH CH340/CH341
            VidPid(0x1A86, 0x7523),
            // Espressif ESP32 native USB
            VidPid(0x303A, 0x8000),
            // Espressif ESP32-S2/S3 CDC
            VidPid(0x303A, 0x0002),
            // Prolific PL2303
            VidPid(0x067B, 0x2303),
            // QinHeng CH9102
            VidPid(0x1A86, 0x55D3),
        )
    }

    data class VidPid(val vid: Int, val pid: Int)

    interface EventListener {
        fun onDeviceConnected(deviceName: String)
        fun onDeviceDisconnected(deviceName: String)
        fun onDataReceived(data: ByteArray)
    }

    var listener: EventListener? = null

    private val running = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()

    private var usbManager: UsbManager? = null
    private var connection: UsbDeviceConnection? = null
    private var usbInterface: UsbInterface? = null
    private var endpointIn: UsbEndpoint? = null
    private var endpointOut: UsbEndpoint? = null
    private var connectedDevice: UsbDevice? = null

    private val readRunning = AtomicBoolean(false)

    // --- Public API ---

    fun start() {
        if (running.getAndSet(true)) return

        usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
        if (usbManager == null) {
            Log.e(TAG, "USB not available")
            running.set(false)
            return
        }

        // Register for USB attach/detach
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            addAction(ACTION_USB_PERMISSION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(usbReceiver, filter)
        }

        // Check for already-connected devices
        scanForDevices()

        Log.i(TAG, "USB serial service started")
    }

    fun stop() {
        if (!running.getAndSet(false)) return

        readRunning.set(false)
        disconnect()

        try {
            context.unregisterReceiver(usbReceiver)
        } catch (_: Exception) {}

        Log.i(TAG, "USB serial service stopped")
    }

    /** Send data to the connected USB serial device. */
    fun sendData(data: ByteArray): Boolean {
        val conn = connection ?: return false
        val ep = endpointOut ?: return false

        // Length-prefix framing: [2-byte BE length][payload]
        val frame = ByteArray(2 + data.size)
        frame[0] = ((data.size shr 8) and 0xFF).toByte()
        frame[1] = (data.size and 0xFF).toByte()
        System.arraycopy(data, 0, frame, 2, data.size)

        val written = conn.bulkTransfer(ep, frame, frame.size, WRITE_TIMEOUT_MS)
        if (written < 0) {
            Log.w(TAG, "USB write failed")
            return false
        }
        Log.d(TAG, "USB sent ${data.size} bytes")
        return true
    }

    val isConnected: Boolean get() = connection != null && endpointOut != null

    // --- USB Device Detection ---

    private fun scanForDevices() {
        val mgr = usbManager ?: return
        for (device in mgr.deviceList.values) {
            if (isSupportedDevice(device)) {
                Log.i(TAG, "Found supported USB device: ${device.deviceName} " +
                    "(VID=${device.vendorId}, PID=${device.productId})")
                requestPermission(device)
                return
            }
        }
        Log.d(TAG, "No supported USB devices found")
    }

    private fun isSupportedDevice(device: UsbDevice): Boolean {
        return SUPPORTED_DEVICES.any { it.vid == device.vendorId && it.pid == device.productId }
    }

    private fun requestPermission(device: UsbDevice) {
        val mgr = usbManager ?: return
        if (mgr.hasPermission(device)) {
            connectDevice(device)
        } else {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                PendingIntent.FLAG_MUTABLE
            } else {
                0
            }
            val pi = PendingIntent.getBroadcast(context, 0,
                Intent(ACTION_USB_PERMISSION), flags)
            mgr.requestPermission(device, pi)
        }
    }

    // --- USB Connection ---

    private fun connectDevice(device: UsbDevice) {
        val mgr = usbManager ?: return

        // Find CDC ACM data interface (class 0x0A) or fallback to first interface
        var dataInterface: UsbInterface? = null
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            if (iface.interfaceClass == UsbConstants.USB_CLASS_CDC_DATA ||
                iface.interfaceClass == UsbConstants.USB_CLASS_VENDOR_SPEC) {
                dataInterface = iface
                break
            }
        }
        if (dataInterface == null && device.interfaceCount > 0) {
            // Fallback: use last interface (often the data interface on CDC ACM)
            dataInterface = device.getInterface(device.interfaceCount - 1)
        }
        if (dataInterface == null) {
            Log.e(TAG, "No suitable USB interface found")
            return
        }

        // Find bulk IN and OUT endpoints
        var epIn: UsbEndpoint? = null
        var epOut: UsbEndpoint? = null
        for (i in 0 until dataInterface.endpointCount) {
            val ep = dataInterface.getEndpoint(i)
            if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                if (ep.direction == UsbConstants.USB_DIR_IN) epIn = ep
                else epOut = ep
            }
        }
        if (epIn == null || epOut == null) {
            Log.e(TAG, "Missing bulk endpoints")
            return
        }

        val conn = mgr.openDevice(device)
        if (conn == null) {
            Log.e(TAG, "Failed to open USB device")
            return
        }

        if (!conn.claimInterface(dataInterface, true)) {
            Log.e(TAG, "Failed to claim interface")
            conn.close()
            return
        }

        // Configure baud rate via CDC ACM SET_LINE_CODING
        val lineCoding = byteArrayOf(
            (BAUD_RATE and 0xFF).toByte(),
            ((BAUD_RATE shr 8) and 0xFF).toByte(),
            ((BAUD_RATE shr 16) and 0xFF).toByte(),
            ((BAUD_RATE shr 24) and 0xFF).toByte(),
            0, // 1 stop bit
            0, // no parity
            8, // 8 data bits
        )
        conn.controlTransfer(0x21, 0x20, 0, 0, lineCoding, lineCoding.size, WRITE_TIMEOUT_MS)

        // Enable DTR/RTS
        conn.controlTransfer(0x21, 0x22, 0x03, 0, null, 0, WRITE_TIMEOUT_MS)

        connection = conn
        usbInterface = dataInterface
        endpointIn = epIn
        endpointOut = epOut
        connectedDevice = device

        Log.i(TAG, "Connected to USB device: ${device.deviceName}")
        listener?.onDeviceConnected(device.deviceName)

        // Start read thread
        startReading()
    }

    private fun disconnect() {
        readRunning.set(false)
        connection?.let { conn ->
            usbInterface?.let { conn.releaseInterface(it) }
            conn.close()
        }
        val deviceName = connectedDevice?.deviceName
        connection = null
        usbInterface = null
        endpointIn = null
        endpointOut = null
        connectedDevice = null

        if (deviceName != null) {
            listener?.onDeviceDisconnected(deviceName)
        }
    }

    // --- Reading ---

    private fun startReading() {
        readRunning.set(true)
        executor.submit {
            val buffer = ByteArray(1024)
            var frameBuf = ByteArray(0)

            while (readRunning.get()) {
                val conn = connection ?: break
                val ep = endpointIn ?: break

                val bytesRead = conn.bulkTransfer(ep, buffer, buffer.size, READ_TIMEOUT_MS)
                if (bytesRead > 0) {
                    // Append to frame buffer
                    frameBuf += buffer.copyOfRange(0, bytesRead)

                    // Extract complete frames: [2-byte BE length][payload]
                    while (frameBuf.size >= 2) {
                        val frameLen = ((frameBuf[0].toInt() and 0xFF) shl 8) or
                                (frameBuf[1].toInt() and 0xFF)
                        if (frameLen > 256) {
                            // Invalid frame length — skip byte and resync
                            Log.w(TAG, "Invalid frame length $frameLen, resyncing")
                            frameBuf = frameBuf.copyOfRange(1, frameBuf.size)
                            continue
                        }
                        if (frameBuf.size < 2 + frameLen) break // Need more data

                        val payload = frameBuf.copyOfRange(2, 2 + frameLen)
                        frameBuf = frameBuf.copyOfRange(2 + frameLen, frameBuf.size)

                        Log.d(TAG, "USB received frame: ${payload.size} bytes")
                        handler.post {
                            listener?.onDataReceived(payload)
                        }
                    }
                } else if (bytesRead < 0) {
                    // Error — device may have disconnected
                    if (readRunning.get()) {
                        Log.w(TAG, "USB read error, disconnecting")
                        handler.post { disconnect() }
                    }
                    break
                }
            }
        }
    }

    // --- USB Broadcast Receiver ---

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    device?.let {
                        if (isSupportedDevice(it) && connection == null) {
                            Log.i(TAG, "USB device attached: ${it.deviceName}")
                            requestPermission(it)
                        }
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    device?.let {
                        if (connectedDevice?.deviceId == it.deviceId) {
                            Log.i(TAG, "USB device detached: ${it.deviceName}")
                            disconnect()
                        }
                    }
                }
                ACTION_USB_PERMISSION -> {
                    val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    if (granted && device != null) {
                        connectDevice(device)
                    } else {
                        Log.w(TAG, "USB permission denied for ${device?.deviceName}")
                    }
                }
            }
        }
    }
}
