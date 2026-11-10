package com.mycelium.mycelium_mesh

import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val BLE_METHOD_CHANNEL = "com.mycelium.ble"
    private val BLE_EVENT_CHANNEL = "com.mycelium.ble/events"
    private val WIFI_METHOD_CHANNEL = "com.mycelium.wifidirect"
    private val WIFI_EVENT_CHANNEL = "com.mycelium.wifidirect/events"
    private val LORA_METHOD_CHANNEL = "com.mycelium.lora"
    private val LORA_EVENT_CHANNEL = "com.mycelium.lora/events"
    private val BT_CLASSIC_METHOD_CHANNEL = "com.mycelium.btclassic"
    private val BT_CLASSIC_EVENT_CHANNEL = "com.mycelium.btclassic/events"
    private val DAEMON_CHANNEL = "com.mycelium.daemon"

    private var bleService: BleService? = null
    private var wifiDirectService: WifiDirectService? = null
    private var loraService: LoraService? = null
    private var usbSerialService: UsbSerialService? = null
    private var btClassicService: BtClassicService? = null
    private var eventSink: EventChannel.EventSink? = null
    private var wifiEventSink: EventChannel.EventSink? = null
    private var loraEventSink: EventChannel.EventSink? = null
    private var btClassicEventSink: EventChannel.EventSink? = null
    private val handler = Handler(Looper.getMainLooper())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // --- Daemon lifecycle channel ---
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, DAEMON_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startDaemon" -> {
                    startDaemonService()
                    result.success(true)
                }
                "stopDaemon" -> {
                    stopDaemonService()
                    result.success(true)
                }
                "isDaemonRunning" -> {
                    result.success(MyceliumDaemonService.isRunning)
                }
                else -> result.notImplemented()
            }
        }

        // --- BLE transport channels ---
        bleService = BleService(this)
        bleService?.listener = object : BleService.EventListener {
            override fun onPeerDiscovered(peerId: ByteArray) {
                Log.i("MyceliumBLE", "EventListener.onPeerDiscovered, eventSink=${eventSink != null}")
                handler.post {
                    val sink = eventSink
                    if (sink == null) {
                        Log.w("MyceliumBLE", "eventSink is null, cannot send peerDiscovered")
                    } else {
                        Log.d("MyceliumBLE", "Sending peerDiscovered event to Dart")
                        sink.success(mapOf(
                            "type" to "peerDiscovered",
                            "peerId" to peerId.toList()
                        ))
                    }
                }
            }

            override fun onPeerLost(peerId: ByteArray) {
                handler.post {
                    eventSink?.success(mapOf(
                        "type" to "peerLost",
                        "peerId" to peerId.toList()
                    ))
                }
            }

            override fun onDataReceived(peerId: ByteArray, data: ByteArray) {
                handler.post {
                    eventSink?.success(mapOf(
                        "type" to "dataReceived",
                        "peerId" to peerId.toList(),
                        "data" to data.toList()
                    ))
                }
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BLE_METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "start" -> {
                    val nodeId = (call.argument<List<Int>>("nodeId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (nodeId != null && nodeId.size == 32) {
                        bleService?.start(nodeId)
                        result.success(true)
                    } else {
                        result.error("INVALID_ARG", "nodeId must be 32 bytes", null)
                    }
                }
                "stop" -> {
                    bleService?.stop()
                    result.success(true)
                }
                "sendData" -> {
                    val peerId = (call.argument<List<Int>>("peerId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    val data = (call.argument<List<Int>>("data"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (peerId != null && data != null) {
                        val ok = bleService?.sendData(peerId, data) ?: false
                        result.success(ok)
                    } else {
                        result.error("INVALID_ARG", "peerId and data required", null)
                    }
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, BLE_EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.i("MyceliumBLE", "EventChannel onListen, sink=${events != null}")
                    eventSink = events
                }
                override fun onCancel(arguments: Any?) {
                    eventSink = null
                }
            }
        )

        // --- Wi-Fi Direct transport channels ---
        wifiDirectService = WifiDirectService(this)
        wifiDirectService?.listener = object : WifiDirectService.EventListener {
            override fun onPeerConnected(peerId: ByteArray) {
                handler.post {
                    wifiEventSink?.success(mapOf(
                        "type" to "peerConnected",
                        "peerId" to peerId.toList()
                    ))
                }
            }

            override fun onPeerDisconnected(peerId: ByteArray) {
                handler.post {
                    wifiEventSink?.success(mapOf(
                        "type" to "peerDisconnected",
                        "peerId" to peerId.toList()
                    ))
                }
            }

            override fun onDataReceived(peerId: ByteArray, data: ByteArray) {
                handler.post {
                    wifiEventSink?.success(mapOf(
                        "type" to "dataReceived",
                        "peerId" to peerId.toList(),
                        "data" to data.toList()
                    ))
                }
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, WIFI_METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "start" -> {
                    val nodeId = (call.argument<List<Int>>("nodeId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (nodeId != null && nodeId.size == 32) {
                        wifiDirectService?.start(nodeId)
                        result.success(true)
                    } else {
                        result.error("INVALID_ARG", "nodeId must be 32 bytes", null)
                    }
                }
                "stop" -> {
                    wifiDirectService?.stop()
                    result.success(true)
                }
                "sendData" -> {
                    val peerId = (call.argument<List<Int>>("peerId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    val data = (call.argument<List<Int>>("data"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (peerId != null && data != null) {
                        val ok = wifiDirectService?.sendData(peerId, data) ?: false
                        result.success(ok)
                    } else {
                        result.error("INVALID_ARG", "peerId and data required", null)
                    }
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, WIFI_EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.i(TAG, "WiFi Direct EventChannel onListen, sink=${events != null}")
                    wifiEventSink = events
                }
                override fun onCancel(arguments: Any?) {
                    wifiEventSink = null
                }
            }
        )

        setupLoraChannels(flutterEngine)
        setupBtClassicChannels(flutterEngine)
    }

    // --- LoRa: external radio over BLE GATT or USB serial (same Dart channel as iOS) ---

    private fun setupLoraChannels(flutterEngine: FlutterEngine) {
        loraService = LoraService(this)
        loraService?.listener = object : LoraService.EventListener {
            override fun onModuleConnected(moduleAddress: String) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "moduleConnected", "address" to moduleAddress))
                }
            }
            override fun onModuleDisconnected(moduleAddress: String) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "moduleDisconnected", "address" to moduleAddress))
                }
            }
            override fun onDataReceived(data: ByteArray, rssi: Int) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "dataReceived", "data" to data.toList(), "rssi" to rssi))
                }
            }
            override fun onTxSuccess() {
                handler.post { loraEventSink?.success(mapOf("type" to "txSuccess")) }
            }
            override fun onTxFailure() {
                handler.post { loraEventSink?.success(mapOf("type" to "txFailure")) }
            }
        }

        // A LoRa board on USB OTG feeds the same channel; the Dart side does
        // not care which link carries the frames.
        usbSerialService = UsbSerialService(this)
        usbSerialService?.listener = object : UsbSerialService.EventListener {
            override fun onDeviceConnected(deviceName: String) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "moduleConnected", "address" to "usb:$deviceName"))
                }
            }
            override fun onDeviceDisconnected(deviceName: String) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "moduleDisconnected", "address" to "usb:$deviceName"))
                }
            }
            override fun onDataReceived(data: ByteArray) {
                handler.post {
                    loraEventSink?.success(mapOf("type" to "dataReceived", "data" to data.toList(), "rssi" to 0))
                }
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, LORA_METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "start" -> {
                    loraService?.start()
                    usbSerialService?.start()
                    result.success(true)
                }
                "stop" -> {
                    loraService?.stop()
                    usbSerialService?.stop()
                    result.success(true)
                }
                "sendData" -> {
                    val data = (call.argument<List<Int>>("data"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (data == null) {
                        result.error("INVALID_ARG", "data required", null)
                    } else {
                        // Prefer the wired module when both are attached.
                        val ok = if (usbSerialService?.isConnected == true) {
                            usbSerialService?.sendData(data) ?: false
                        } else {
                            loraService?.sendData(data) ?: false
                        }
                        if (!ok) {
                            // No module attached: tell Rust so ADR does not
                            // keep lowering the spreading factor.
                            handler.post { loraEventSink?.success(mapOf("type" to "txFailure")) }
                        }
                        result.success(ok)
                    }
                }
                "readConfig" -> result.success(loraService?.readConfig() ?: false)
                "writeConfig" -> {
                    val freq = call.argument<Int>("frequencyHz")
                    val sf = call.argument<Int>("spreadingFactor")
                    val bw = call.argument<Int>("bandwidthKhz")
                    val power = call.argument<Int>("txPowerDbm")
                    if (freq == null || sf == null || bw == null || power == null) {
                        result.error("INVALID_ARG", "frequencyHz, spreadingFactor, bandwidthKhz, txPowerDbm required", null)
                    } else {
                        result.success(loraService?.writeConfig(freq, sf, bw, power) ?: false)
                    }
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, LORA_EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.i(TAG, "LoRa EventChannel onListen, sink=${events != null}")
                    loraEventSink = events
                }
                override fun onCancel(arguments: Any?) {
                    loraEventSink = null
                }
            }
        )
    }

    // --- Bluetooth Classic SPP transport ---

    private fun setupBtClassicChannels(flutterEngine: FlutterEngine) {
        btClassicService = BtClassicService(this)
        btClassicService?.listener = object : BtClassicService.EventListener {
            override fun onPeerConnected(peerId: ByteArray) {
                handler.post {
                    btClassicEventSink?.success(mapOf("type" to "peerConnected", "peerId" to peerId.toList()))
                }
            }
            override fun onPeerDisconnected(peerId: ByteArray) {
                handler.post {
                    btClassicEventSink?.success(mapOf("type" to "peerDisconnected", "peerId" to peerId.toList()))
                }
            }
            override fun onDataReceived(peerId: ByteArray, data: ByteArray) {
                handler.post {
                    btClassicEventSink?.success(mapOf(
                        "type" to "dataReceived",
                        "peerId" to peerId.toList(),
                        "data" to data.toList()
                    ))
                }
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BT_CLASSIC_METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "start" -> {
                    val nodeId = (call.argument<List<Int>>("nodeId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (nodeId != null && nodeId.size == 32) {
                        btClassicService?.start(nodeId)
                        result.success(true)
                    } else {
                        result.error("INVALID_ARG", "nodeId must be 32 bytes", null)
                    }
                }
                "stop" -> {
                    btClassicService?.stop()
                    result.success(true)
                }
                "sendData" -> {
                    val peerId = (call.argument<List<Int>>("peerId"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    val data = (call.argument<List<Int>>("data"))?.let {
                        ByteArray(it.size) { i -> it[i].toByte() }
                    }
                    if (peerId != null && data != null) {
                        result.success(btClassicService?.sendData(peerId, data) ?: false)
                    } else {
                        result.error("INVALID_ARG", "peerId and data required", null)
                    }
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, BT_CLASSIC_EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.i(TAG, "BT Classic EventChannel onListen, sink=${events != null}")
                    btClassicEventSink = events
                }
                override fun onCancel(arguments: Any?) {
                    btClassicEventSink = null
                }
            }
        )
    }

    private fun startDaemonService() {
        val intent = Intent(this, MyceliumDaemonService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        Log.i("MyceliumDaemon", "Daemon service start requested")
    }

    private fun stopDaemonService() {
        stopService(Intent(this, MyceliumDaemonService::class.java))
        Log.i("MyceliumDaemon", "Daemon service stop requested")
    }

    override fun onDestroy() {
        bleService?.stop()
        wifiDirectService?.stop()
        loraService?.stop()
        usbSerialService?.stop()
        btClassicService?.stop()
        // Note: daemon service intentionally NOT stopped here —
        // it keeps the process alive for the Rust node.
        super.onDestroy()
    }

    companion object {
        private const val TAG = "MyceliumMain"
    }
}
