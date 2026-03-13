import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {

    private var bleService: BleService?
    private var loraService: LoraService?
    fileprivate var bleEventSink: FlutterEventSink?
    fileprivate var loraEventSink: FlutterEventSink?

    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let controller = window?.rootViewController as! FlutterViewController
        let messenger = controller.binaryMessenger

        setupDaemonChannel(messenger: messenger)
        setupBleChannels(messenger: messenger)
        setupLoraChannels(messenger: messenger)

        GeneratedPluginRegistrant.register(with: self)
        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    // MARK: - Daemon Channel

    private func setupDaemonChannel(messenger: FlutterBinaryMessenger) {
        let channel = FlutterMethodChannel(name: "com.mycelium.daemon", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] (call, result) in
            switch call.method {
            case "startDaemon":
                // No foreground service on iOS — BLE background modes handle persistence
                result(true)
            case "stopDaemon":
                result(true)
            case "isDaemonRunning":
                // On iOS the node runs in-process; if the app is alive, the daemon is running
                result(true)
            default:
                result(FlutterMethodNotImplemented)
            }
        }
    }

    // MARK: - BLE Channels

    private func setupBleChannels(messenger: FlutterBinaryMessenger) {
        bleService = BleService()
        bleService?.delegate = self

        let methodChannel = FlutterMethodChannel(name: "com.mycelium.ble", binaryMessenger: messenger)
        methodChannel.setMethodCallHandler { [weak self] (call, result) in
            guard let self = self else {
                result(FlutterError(code: "UNAVAILABLE", message: "AppDelegate deallocated", details: nil))
                return
            }
            switch call.method {
            case "start":
                guard let args = call.arguments as? [String: Any],
                      let nodeIdList = args["nodeId"] as? [Int],
                      nodeIdList.count == 32 else {
                    result(FlutterError(code: "INVALID_ARG", message: "nodeId must be 32 bytes", details: nil))
                    return
                }
                let nodeId = Data(nodeIdList.map { UInt8($0 & 0xFF) })
                self.bleService?.start(nodeId: nodeId)
                result(true)
            case "stop":
                self.bleService?.stop()
                result(true)
            case "sendData":
                guard let args = call.arguments as? [String: Any],
                      let peerIdList = args["peerId"] as? [Int],
                      let dataList = args["data"] as? [Int] else {
                    result(FlutterError(code: "INVALID_ARG", message: "peerId and data required", details: nil))
                    return
                }
                let peerId = Data(peerIdList.map { UInt8($0 & 0xFF) })
                let data = Data(dataList.map { UInt8($0 & 0xFF) })
                let ok = self.bleService?.sendData(peerId: peerId, data: data) ?? false
                result(ok)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        let eventChannel = FlutterEventChannel(name: "com.mycelium.ble/events", binaryMessenger: messenger)
        eventChannel.setStreamHandler(BleStreamHandler(appDelegate: self))
    }

    // MARK: - LoRa Channels

    private func setupLoraChannels(messenger: FlutterBinaryMessenger) {
        loraService = LoraService()
        loraService?.delegate = self

        let methodChannel = FlutterMethodChannel(name: "com.mycelium.lora", binaryMessenger: messenger)
        methodChannel.setMethodCallHandler { [weak self] (call, result) in
            guard let self = self else {
                result(FlutterError(code: "UNAVAILABLE", message: "AppDelegate deallocated", details: nil))
                return
            }
            switch call.method {
            case "start":
                self.loraService?.start()
                result(true)
            case "stop":
                self.loraService?.stop()
                result(true)
            case "sendData":
                guard let args = call.arguments as? [String: Any],
                      let dataList = args["data"] as? [Int] else {
                    result(FlutterError(code: "INVALID_ARG", message: "data required", details: nil))
                    return
                }
                let data = Data(dataList.map { UInt8($0 & 0xFF) })
                let ok = self.loraService?.sendData(data) ?? false
                result(ok)
            case "readConfig":
                let ok = self.loraService?.readConfig() ?? false
                result(ok)
            case "writeConfig":
                guard let args = call.arguments as? [String: Any],
                      let freq = args["frequencyHz"] as? Int,
                      let sf = args["spreadingFactor"] as? Int,
                      let bw = args["bandwidthKhz"] as? Int,
                      let txPower = args["txPowerDbm"] as? Int else {
                    result(FlutterError(code: "INVALID_ARG", message: "config parameters required", details: nil))
                    return
                }
                let ok = self.loraService?.writeConfig(
                    frequencyHz: UInt32(freq),
                    spreadingFactor: UInt8(sf),
                    bandwidthKhz: UInt16(bw),
                    txPowerDbm: Int8(txPower)
                ) ?? false
                result(ok)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        let eventChannel = FlutterEventChannel(name: "com.mycelium.lora/events", binaryMessenger: messenger)
        eventChannel.setStreamHandler(LoraStreamHandler(appDelegate: self))
    }

    // MARK: - Cleanup

    override func applicationWillTerminate(_ application: UIApplication) {
        bleService?.stop()
        loraService?.stop()
    }
}

// MARK: - BleServiceDelegate

extension AppDelegate: BleServiceDelegate {
    func bleService(_ service: BleService, didDiscoverPeer peerId: Data) {
        DispatchQueue.main.async { [weak self] in
            self?.bleEventSink?([
                "type": "peerDiscovered",
                "peerId": Array(peerId),
            ])
        }
    }

    func bleService(_ service: BleService, didLosePeer peerId: Data) {
        DispatchQueue.main.async { [weak self] in
            self?.bleEventSink?([
                "type": "peerLost",
                "peerId": Array(peerId),
            ])
        }
    }

    func bleService(_ service: BleService, didReceiveData data: Data, fromPeer peerId: Data) {
        DispatchQueue.main.async { [weak self] in
            self?.bleEventSink?([
                "type": "dataReceived",
                "peerId": Array(peerId),
                "data": Array(data),
            ])
        }
    }
}

// MARK: - LoraServiceDelegate

extension AppDelegate: LoraServiceDelegate {
    func loraService(_ service: LoraService, didConnectModule address: String) {
        DispatchQueue.main.async { [weak self] in
            self?.loraEventSink?([
                "type": "moduleConnected",
                "address": address,
            ])
        }
    }

    func loraService(_ service: LoraService, didDisconnectModule address: String) {
        DispatchQueue.main.async { [weak self] in
            self?.loraEventSink?([
                "type": "moduleDisconnected",
                "address": address,
            ])
        }
    }

    func loraService(_ service: LoraService, didReceiveData data: Data, rssi: Int) {
        DispatchQueue.main.async { [weak self] in
            self?.loraEventSink?([
                "type": "dataReceived",
                "data": Array(data),
                "rssi": rssi,
            ])
        }
    }

    func loraServiceDidSucceedTx(_ service: LoraService) {
        DispatchQueue.main.async { [weak self] in
            self?.loraEventSink?(["type": "txSuccess"])
        }
    }

    func loraServiceDidFailTx(_ service: LoraService) {
        DispatchQueue.main.async { [weak self] in
            self?.loraEventSink?(["type": "txFailure"])
        }
    }
}

// MARK: - Stream Handlers

private class BleStreamHandler: NSObject, FlutterStreamHandler {
    weak var appDelegate: AppDelegate?

    init(appDelegate: AppDelegate) {
        self.appDelegate = appDelegate
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        appDelegate?.bleEventSink = events
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        appDelegate?.bleEventSink = nil
        return nil
    }
}

private class LoraStreamHandler: NSObject, FlutterStreamHandler {
    weak var appDelegate: AppDelegate?

    init(appDelegate: AppDelegate) {
        self.appDelegate = appDelegate
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        appDelegate?.loraEventSink = events
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        appDelegate?.loraEventSink = nil
        return nil
    }
}
