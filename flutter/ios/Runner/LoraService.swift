import CoreBluetooth
import os.log

/// Delegate protocol for LoRa BLE bridge events.
protocol LoraServiceDelegate: AnyObject {
    func loraService(_ service: LoraService, didConnectModule address: String)
    func loraService(_ service: LoraService, didDisconnectModule address: String)
    func loraService(_ service: LoraService, didReceiveData data: Data, rssi: Int)
    func loraServiceDidSucceedTx(_ service: LoraService)
    func loraServiceDidFailTx(_ service: LoraService)
}

/// LoRa BLE GATT bridge service.
///
/// Connects to an external LoRa radio module (e.g. ESP32+SX1276) over BLE.
/// The phone acts as a GATT client; the LoRa module exposes the GATT server.
///
/// GATT service layout:
///   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef12345678a0
///   Data TX char:   ...78a1  (Write)      — Phone writes outgoing mesh packets
///   Data RX char:   ...78a2  (Notify)     — LoRa module notifies with received packets
///   Config char:    ...78a3  (Read/Write)  — Radio config (freq, SF, BW, TX power)
///   Status char:    ...78a4  (Read/Notify) — Radio status (RSSI, SNR, duty cycle)
///
/// Config format (8 bytes LE): [u32 freq_hz][u8 SF][u16 BW_khz][i8 tx_power_dbm]
/// Status format (8 bytes LE): [i16 RSSI][i8 SNR][u8 duty_pct][u32 error_count]
class LoraService: NSObject {

    // MARK: - Constants

    static let serviceUUID = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef12345678a0")
    static let dataTxUUID  = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef12345678a1")
    static let dataRxUUID  = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef12345678a2")
    static let configUUID  = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef12345678a3")
    static let statusUUID  = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef12345678a4")

    private static let scanPeriod: TimeInterval = 10.0
    private static let reconnectDelay: TimeInterval = 3.0

    private let log = Logger(subsystem: "com.mycelium", category: "LoRa")

    // MARK: - Properties

    weak var delegate: LoraServiceDelegate?

    private var running = false
    private var centralManager: CBCentralManager?
    private var connectedPeripheral: CBPeripheral?
    private var connectedAddress: String?

    // Characteristic references (set after service discovery)
    private var dataTxChar: CBCharacteristic?
    private var dataRxChar: CBCharacteristic?
    private var configChar: CBCharacteristic?
    private var statusChar: CBCharacteristic?

    // Scan timer
    private var scanStopTimer: Timer?

    var isConnected: Bool {
        connectedPeripheral != nil && dataTxChar != nil
    }

    // MARK: - Public API

    func start() {
        guard !running else { return }
        running = true

        centralManager = CBCentralManager(delegate: self, queue: nil)
        log.info("LoRa BLE bridge started, scanning for modules...")
    }

    func stop() {
        guard running else { return }
        running = false

        stopScan()
        disconnectModule()
        centralManager = nil
        log.info("LoRa BLE bridge stopped")
    }

    func sendData(_ data: Data) -> Bool {
        guard let char = dataTxChar, let peripheral = connectedPeripheral else { return false }
        peripheral.writeValue(data, for: char, type: .withResponse)
        log.debug("Sent \(data.count) bytes to LoRa module")
        return true
    }

    func readConfig() -> Bool {
        guard let char = configChar, let peripheral = connectedPeripheral else { return false }
        peripheral.readValue(for: char)
        return true
    }

    func writeConfig(frequencyHz: UInt32, spreadingFactor: UInt8, bandwidthKhz: UInt16, txPowerDbm: Int8) -> Bool {
        guard let char = configChar, let peripheral = connectedPeripheral else { return false }

        var data = Data(count: 8)
        data[0] = UInt8(frequencyHz & 0xFF)
        data[1] = UInt8((frequencyHz >> 8) & 0xFF)
        data[2] = UInt8((frequencyHz >> 16) & 0xFF)
        data[3] = UInt8((frequencyHz >> 24) & 0xFF)
        data[4] = spreadingFactor
        data[5] = UInt8(bandwidthKhz & 0xFF)
        data[6] = UInt8((bandwidthKhz >> 8) & 0xFF)
        data[7] = UInt8(bitPattern: txPowerDbm)

        peripheral.writeValue(data, for: char, type: .withResponse)
        return true
    }

    // MARK: - Scanning

    private func startScan() {
        guard running, let cm = centralManager, cm.state == .poweredOn else { return }

        cm.scanForPeripherals(
            withServices: [LoraService.serviceUUID],
            options: nil
        )
        log.debug("BLE scan started for LoRa modules")

        // Stop scan after period to save power
        scanStopTimer?.invalidate()
        scanStopTimer = Timer.scheduledTimer(withTimeInterval: LoraService.scanPeriod, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.stopScan()
            if self.running && self.connectedPeripheral == nil {
                // Restart scan after brief pause
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
                    self?.startScan()
                }
            }
        }
    }

    private func stopScan() {
        scanStopTimer?.invalidate()
        scanStopTimer = nil
        centralManager?.stopScan()
    }

    private func disconnectModule() {
        if let peripheral = connectedPeripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        connectedPeripheral = nil
        connectedAddress = nil
        dataTxChar = nil
        dataRxChar = nil
        configChar = nil
        statusChar = nil
    }
}

// MARK: - CBCentralManagerDelegate

extension LoraService: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn && running {
            startScan()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard connectedPeripheral == nil else { return }

        log.info("Found LoRa module: \(peripheral.identifier) (RSSI: \(RSSI))")
        stopScan()
        connectModule(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        log.info("Connected to LoRa module \(peripheral.identifier)")
        connectedPeripheral = peripheral
        connectedAddress = peripheral.identifier.uuidString
        peripheral.delegate = self
        peripheral.discoverServices([LoraService.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        log.warning("Failed to connect to LoRa module: \(error?.localizedDescription ?? "unknown")")
        if running {
            DispatchQueue.main.asyncAfter(deadline: .now() + LoraService.reconnectDelay) { [weak self] in
                self?.startScan()
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let address = peripheral.identifier.uuidString
        log.info("Disconnected from LoRa module \(address)")
        let wasConnected = connectedAddress == address
        if connectedAddress == address {
            connectedPeripheral = nil
            connectedAddress = nil
            dataTxChar = nil
            dataRxChar = nil
            configChar = nil
            statusChar = nil
        }
        if wasConnected {
            delegate?.loraService(self, didDisconnectModule: address)
            if running {
                DispatchQueue.main.asyncAfter(deadline: .now() + LoraService.reconnectDelay) { [weak self] in
                    self?.startScan()
                }
            }
        }
    }

    private func connectModule(_ peripheral: CBPeripheral) {
        log.debug("Connecting to LoRa module \(peripheral.identifier)")
        peripheral.delegate = self
        centralManager?.connect(peripheral, options: nil)
    }
}

// MARK: - CBPeripheralDelegate

extension LoraService: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            log.error("Service discovery failed: \(error.localizedDescription)")
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }

        guard let service = peripheral.services?.first(where: { $0.uuid == LoraService.serviceUUID }) else {
            log.error("LoRa GATT service not found on \(peripheral.identifier)")
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }

        peripheral.discoverCharacteristics(
            [LoraService.dataTxUUID, LoraService.dataRxUUID, LoraService.configUUID, LoraService.statusUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            log.error("Characteristic discovery failed: \(error.localizedDescription)")
            return
        }

        guard let chars = service.characteristics else { return }

        for char in chars {
            switch char.uuid {
            case LoraService.dataTxUUID:
                dataTxChar = char
            case LoraService.dataRxUUID:
                dataRxChar = char
                peripheral.setNotifyValue(true, for: char)
            case LoraService.configUUID:
                configChar = char
            case LoraService.statusUUID:
                statusChar = char
                peripheral.setNotifyValue(true, for: char)
            default:
                break
            }
        }

        if dataTxChar == nil || dataRxChar == nil {
            log.error("Required LoRa characteristics not found")
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }

        log.info("LoRa module ready: \(peripheral.identifier)")
        delegate?.loraService(self, didConnectModule: peripheral.identifier.uuidString)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let value = characteristic.value else { return }

        switch characteristic.uuid {
        case LoraService.dataRxUUID:
            log.debug("Received \(value.count) bytes from LoRa radio")
            delegate?.loraService(self, didReceiveData: value, rssi: -110)
        case LoraService.statusUUID:
            if value.count >= 4 {
                let rssi = Int(Int16(value[0]) | (Int16(value[1]) << 8))
                let snr = Int(Int8(bitPattern: value[2]))
                let dutyCycle = Int(value[3])
                log.debug("LoRa status: RSSI=\(rssi), SNR=\(snr), duty=\(dutyCycle)%")
            }
        case LoraService.configUUID:
            if value.count >= 8 {
                let freqHz = UInt32(value[0]) | (UInt32(value[1]) << 8) | (UInt32(value[2]) << 16) | (UInt32(value[3]) << 24)
                let sf = value[4]
                let bwKhz = UInt16(value[5]) | (UInt16(value[6]) << 8)
                let txPower = Int8(bitPattern: value[7])
                log.info("LoRa config: freq=\(freqHz)Hz, SF\(sf), BW=\(bwKhz)kHz, TX=\(txPower)dBm")
            }
        default:
            break
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == LoraService.dataTxUUID {
            if error == nil {
                delegate?.loraServiceDidSucceedTx(self)
            } else {
                log.warning("LoRa TX write failed: \(error?.localizedDescription ?? "")")
                delegate?.loraServiceDidFailTx(self)
            }
        }
    }
}
