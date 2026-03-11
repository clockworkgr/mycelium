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
    private val DAEMON_CHANNEL = "com.mycelium.daemon"

    private var bleService: BleService? = null
    private var eventSink: EventChannel.EventSink? = null
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
        // Note: daemon service intentionally NOT stopped here —
        // it keeps the process alive for the Rust node.
        super.onDestroy()
    }
}
