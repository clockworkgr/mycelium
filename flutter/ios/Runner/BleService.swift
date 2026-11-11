import CoreBluetooth
import os.log

/// Delegate protocol for BLE transport events.
protocol BleServiceDelegate: AnyObject {
    func bleService(_ service: BleService, didDiscoverPeer peerId: Data)
    func bleService(_ service: BleService, didLosePeer peerId: Data)
    func bleService(_ service: BleService, didReceiveData data: Data, fromPeer peerId: Data)
}

/// Dual-role BLE transport service using CoreBluetooth.
///
/// Implements both GATT peripheral (server) and central (client) roles
/// for mesh peer discovery and data exchange. Supports iOS background
/// modes via state preservation/restoration.
///
/// GATT Service Layout (same as Android):
///   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef1234567890
///   Node ID char:   ...7891  (Read)   — the node's own 32-byte NodeId
///                                       (asserted, not proved — ROADMAP T-34)
///   Identity char:  ...7894  (Write)  — maps BLE random address to node ID
///   Data TX char:   ...7892  (Write)  — central writes data to peripheral
///   Data RX char:   ...7893  (Notify) — peripheral notifies central with data
///
/// Fragmentation header (1 byte):
///   0x01 = first fragment
///   0x02 = last fragment
///   0x03 = first+last (single packet)
class BleService: NSObject {

    // MARK: - Constants

    static let serviceUUID    = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    static let nodeIdUUID     = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567891")
    static let dataTxUUID     = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567892")
    static let dataRxUUID     = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567893")
    static let identityUUID   = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567894")

    static let flagFirst:  UInt8 = 0x01
    static let flagLast:   UInt8 = 0x02
    static let flagSingle: UInt8 = 0x03

    /// Conservative default fragment size for 23-byte default MTU (23 - 3 ATT header).
    static let defaultFragmentSize = 20

    private static let maxConnectRetries = 3
    private static let baseRetryDelay: TimeInterval = 1.0
    private static let reconnectDelay: TimeInterval = 2.0
    private static let scanCycleInterval: TimeInterval = 25.0

    private static let centralRestoreId    = "com.mycelium.ble.central"
    private static let peripheralRestoreId = "com.mycelium.ble.peripheral"

    private let log = Logger(subsystem: "com.mycelium", category: "BLE")

    // MARK: - Properties

    weak var delegate: BleServiceDelegate?

    private var localNodeId = Data(count: 32)
    private var running = false

    // Peripheral role
    private var peripheralManager: CBPeripheralManager?
    private var gattService: CBMutableService?
    private var dataRxCharacteristic: CBMutableCharacteristic?
    private var subscribedCentrals: [String: CBCentral] = [:]

    // Central role
    private var centralManager: CBCentralManager?
    private var connectedPeripherals: [UUID: CBPeripheral] = [:]
    /// Peripherals we have asked CoreBluetooth to connect to but that have not
    /// connected yet. CoreBluetooth only keeps a weak reference, so without a
    /// strong one here the connection is cancelled ("unused peripheral").
    private var pendingPeripherals: [UUID: CBPeripheral] = [:]
    private var peerNodeIds: [UUID: Data] = [:]        // peripheral UUID -> node ID
    private var nodeIdToUUID: [String: UUID] = [:]      // hex node ID -> peripheral UUID
    private var pendingConnections: Set<UUID> = []
    private var connectRetryCounts: [UUID: Int] = [:]
    private var disconnectedPeers: [UUID: CBPeripheral] = [:]

    // Server-connected centrals: identifier -> node ID
    private var serverPeerNodeIds: [String: Data] = [:]
    private var serverNodeIdToIdentifier: [String: String] = [:]  // hex node ID -> central identifier

    // Per-device negotiated MTU
    private var deviceMtus: [UUID: Int] = [:]

    // Fragment reassembly: key -> partial buffer
    private var reassemblyBuffers: [String: Data] = [:]

    // Sequential write queue
    private struct WriteOperation {
        let targetId: String           // peripheral UUID or central identifier
        let fragments: [Data]
        var currentIndex: Int = 0
        let isClientWrite: Bool        // true = GATT client write, false = server notify
        let peripheralUUID: UUID?      // set for client writes
    }

    private var writeQueue: [WriteOperation] = []
    private var writeInProgress = false
    private let writeLock = NSLock()

    // Scan cycling timer
    private var scanCycleTimer: Timer?

    // MARK: - Public API

    func start(nodeId: Data) {
        guard !running else { return }
        guard nodeId.count == 32 else {
            log.error("start: nodeId must be 32 bytes, got \(nodeId.count)")
            return
        }
        localNodeId = nodeId
        running = true

        // Initialize managers with background restoration identifiers
        centralManager = CBCentralManager(
            delegate: self,
            queue: nil,
            options: [CBCentralManagerOptionRestoreIdentifierKey: BleService.centralRestoreId]
        )
        peripheralManager = CBPeripheralManager(
            delegate: self,
            queue: nil,
            options: [CBPeripheralManagerOptionRestoreIdentifierKey: BleService.peripheralRestoreId]
        )

        log.info("BLE service started")
    }

    func stop() {
        guard running else { return }
        running = false

        stopCentral()
        stopPeripheral()

        // Clear write queue
        writeLock.lock()
        writeQueue.removeAll()
        writeInProgress = false
        writeLock.unlock()

        // Notify peer lost for all known peers
        for (_, nodeId) in peerNodeIds {
            delegate?.bleService(self, didLosePeer: nodeId)
        }
        for (_, nodeId) in serverPeerNodeIds {
            delegate?.bleService(self, didLosePeer: nodeId)
        }

        peerNodeIds.removeAll()
        nodeIdToUUID.removeAll()
        serverPeerNodeIds.removeAll()
        serverNodeIdToIdentifier.removeAll()
        connectedPeripherals.removeAll()
        pendingPeripherals.removeAll()
        subscribedCentrals.removeAll()
        reassemblyBuffers.removeAll()
        connectRetryCounts.removeAll()
        pendingConnections.removeAll()
        deviceMtus.removeAll()
        disconnectedPeers.removeAll()

        centralManager = nil
        peripheralManager = nil

        log.info("BLE service stopped")
    }

    func sendData(peerId: Data, data: Data) -> Bool {
        let peerHex = peerId.hexString

        // Try GATT client write first (we are central, peer is peripheral)
        if let uuid = nodeIdToUUID[peerHex],
           let peripheral = connectedPeripherals[uuid] {
            let fragments = fragment(data, forDeviceUUID: uuid)
            log.debug("sendData: \(data.count) bytes -> \(fragments.count) fragments via GATT client to \(peerHex.prefix(16))")
            enqueueWrite(WriteOperation(
                targetId: uuid.uuidString,
                fragments: fragments,
                isClientWrite: true,
                peripheralUUID: uuid
            ))
            return true
        }

        // Try GATT server notify (we are peripheral, peer is central)
        if let centralId = serverNodeIdToIdentifier[peerHex],
           subscribedCentrals[centralId] != nil {
            let fragments = fragmentDefault(data)
            log.debug("sendData: \(data.count) bytes -> \(fragments.count) fragments via GATT server to \(peerHex.prefix(16))")
            enqueueWrite(WriteOperation(
                targetId: centralId,
                fragments: fragments,
                isClientWrite: false,
                peripheralUUID: nil
            ))
            return true
        }

        log.warning("sendData: no connection to peer \(peerHex.prefix(16))")
        return false
    }

    // MARK: - Write Queue Management

    private func enqueueWrite(_ op: WriteOperation) {
        writeLock.lock()
        writeQueue.append(op)
        writeLock.unlock()
        processNextWrite()
    }

    private func processNextWrite() {
        writeLock.lock()
        defer { writeLock.unlock() }

        if writeInProgress { return }
        guard !writeQueue.isEmpty else { return }

        if writeQueue[0].currentIndex >= writeQueue[0].fragments.count {
            writeQueue.removeFirst()
            writeLock.unlock()
            processNextWrite()
            writeLock.lock()
            return
        }

        writeInProgress = true
        let frag = writeQueue[0].fragments[writeQueue[0].currentIndex]
        writeQueue[0].currentIndex += 1
        let op = writeQueue[0]

        if op.isClientWrite {
            guard let uuid = op.peripheralUUID,
                  let peripheral = connectedPeripherals[uuid] else {
                log.warning("writeQueue: GATT client gone for \(op.targetId)")
                writeQueue.removeFirst()
                writeInProgress = false
                writeLock.unlock()
                processNextWrite()
                writeLock.lock()
                return
            }

            guard let service = peripheral.services?.first(where: { $0.uuid == BleService.serviceUUID }),
                  let txChar = service.characteristics?.first(where: { $0.uuid == BleService.dataTxUUID }) else {
                log.warning("writeQueue: TX characteristic not found")
                writeQueue.removeFirst()
                writeInProgress = false
                writeLock.unlock()
                processNextWrite()
                writeLock.lock()
                return
            }

            peripheral.writeValue(frag, for: txChar, type: .withResponse)
            // Wait for peripheral(_:didWriteValueFor:error:) callback
        } else {
            // Server notify
            guard let rxChar = dataRxCharacteristic,
                  let central = subscribedCentrals[op.targetId] else {
                log.warning("writeQueue: GATT server or central gone for \(op.targetId)")
                writeQueue.removeFirst()
                writeInProgress = false
                writeLock.unlock()
                processNextWrite()
                writeLock.lock()
                return
            }

            let sent = peripheralManager?.updateValue(frag, for: rxChar, onSubscribedCentrals: [central]) ?? false
            if sent {
                writeInProgress = false
                writeLock.unlock()
                processNextWrite()
                writeLock.lock()
            } else {
                // Transmit queue full: this fragment was NOT sent. Rewind so it is
                // retried when peripheralManagerIsReady(toUpdateSubscribers:) fires,
                // otherwise the peer's reassembly would be missing a fragment.
                if !writeQueue.isEmpty {
                    writeQueue[0].currentIndex -= 1
                }
            }
        }
    }

    private func onWriteCompleted(success: Bool) {
        writeLock.lock()
        if !success && !writeQueue.isEmpty {
            let remaining = writeQueue[0].fragments.count - writeQueue[0].currentIndex
            log.warning("writeQueue: write failed, dropping \(remaining) remaining fragments")
            writeQueue.removeFirst()
        }
        writeInProgress = false
        writeLock.unlock()
        processNextWrite()
    }

    // MARK: - Peripheral Role

    private func startPeripheral() {
        guard let pm = peripheralManager, pm.state == .poweredOn else { return }

        // Build GATT service
        let nodeIdChar = CBMutableCharacteristic(
            type: BleService.nodeIdUUID,
            properties: .read,
            value: nil,  // dynamic read via delegate
            permissions: .readable
        )

        let identityChar = CBMutableCharacteristic(
            type: BleService.identityUUID,
            properties: .write,
            value: nil,
            permissions: .writeable
        )

        let dataTxChar = CBMutableCharacteristic(
            type: BleService.dataTxUUID,
            properties: .write,
            value: nil,
            permissions: .writeable
        )

        let rxChar = CBMutableCharacteristic(
            type: BleService.dataRxUUID,
            properties: .notify,
            value: nil,
            permissions: .readable
        )
        dataRxCharacteristic = rxChar

        let service = CBMutableService(type: BleService.serviceUUID, primary: true)
        service.characteristics = [nodeIdChar, identityChar, dataTxChar, rxChar]
        gattService = service

        pm.add(service)
    }

    private func startAdvertising() {
        guard let pm = peripheralManager, pm.state == .poweredOn else { return }
        pm.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [BleService.serviceUUID],
            CBAdvertisementDataLocalNameKey: "Mycelium",
        ])
    }

    private func stopPeripheral() {
        peripheralManager?.stopAdvertising()
        if let service = gattService {
            peripheralManager?.remove(service)
        }
        gattService = nil
        dataRxCharacteristic = nil
    }

    // MARK: - Central Role

    private func startCentral() {
        guard let cm = centralManager, cm.state == .poweredOn else { return }
        doStartScan()
    }

    private func doStartScan() {
        guard running, let cm = centralManager, cm.state == .poweredOn else { return }

        cm.scanForPeripherals(
            withServices: [BleService.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
        log.info("BLE scanning started")

        // Schedule scan restart (iOS doesn't have Android's 30s kill, but cycling
        // helps discover new devices and triggers reconnection attempts)
        scanCycleTimer?.invalidate()
        scanCycleTimer = Timer.scheduledTimer(withTimeInterval: BleService.scanCycleInterval, repeats: false) { [weak self] _ in
            self?.restartScan()
        }
    }

    private func restartScan() {
        guard running else { return }
        centralManager?.stopScan()

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self = self, self.running else { return }
            self.doStartScan()
            self.retryDisconnectedPeers()
        }
    }

    private func retryDisconnectedPeers() {
        for (uuid, peripheral) in disconnectedPeers {
            if connectedPeripherals[uuid] != nil || pendingConnections.contains(uuid) {
                disconnectedPeers.removeValue(forKey: uuid)
                continue
            }
            log.debug("Auto-reconnecting to previously known peer \(uuid)")
            disconnectedPeers.removeValue(forKey: uuid)
            pendingConnections.insert(uuid)
            connectToPeripheral(peripheral, attempt: 0)
        }
    }

    private func stopCentral() {
        scanCycleTimer?.invalidate()
        scanCycleTimer = nil
        centralManager?.stopScan()

        for (_, peripheral) in connectedPeripherals {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        connectedPeripherals.removeAll()
    }

    private func connectToPeripheral(_ peripheral: CBPeripheral, attempt: Int) {
        pendingPeripherals[peripheral.identifier] = peripheral
        guard running else {
            pendingConnections.remove(peripheral.identifier)
            return
        }

        log.debug("GATT client connecting to \(peripheral.identifier) (attempt \(attempt + 1))")
        peripheral.delegate = self
        connectRetryCounts[peripheral.identifier] = attempt
        centralManager?.connect(peripheral, options: nil)
    }

    // MARK: - Fragmentation

    private func handleFragment(key: String, raw: Data) {
        guard !raw.isEmpty else { return }
        let flags = raw[0]
        let payload = raw.count > 1 ? raw.subdata(in: 1..<raw.count) : Data()

        let isFirst = (flags & 0x01) != 0
        let isLast  = (flags & 0x02) != 0

        if isFirst {
            reassemblyBuffers[key] = payload
        } else {
            guard var existing = reassemblyBuffers[key] else { return }
            existing.append(payload)
            reassemblyBuffers[key] = existing
        }

        if isLast {
            guard let complete = reassemblyBuffers.removeValue(forKey: key) else { return }
            // Look up node ID from peripheral UUID or central identifier
            var peerId: Data?
            if let uuid = UUID(uuidString: key) {
                peerId = peerNodeIds[uuid]
            }
            if peerId == nil {
                peerId = serverPeerNodeIds[key]
            }
            guard let nodeId = peerId else {
                log.warning("Reassembled \(complete.count) bytes but no node ID for key \(key)")
                return
            }
            log.debug("Reassembled \(complete.count) bytes from \(key)")
            delegate?.bleService(self, didReceiveData: complete, fromPeer: nodeId)
        }
    }

    private func fragment(_ data: Data, forDeviceUUID uuid: UUID) -> [Data] {
        let mtu = deviceMtus[uuid] ?? 23
        // ATT header: 3 bytes, our fragmentation header: 1 byte
        let fragSize = max(mtu - 4, BleService.defaultFragmentSize)
        return fragmentWithSize(data, fragSize: fragSize)
    }

    private func fragmentDefault(_ data: Data) -> [Data] {
        return fragmentWithSize(data, fragSize: BleService.defaultFragmentSize)
    }

    private func fragmentWithSize(_ data: Data, fragSize: Int) -> [Data] {
        if data.count <= fragSize {
            return [Data([BleService.flagSingle]) + data]
        }

        var fragments: [Data] = []
        var offset = 0
        while offset < data.count {
            let end = min(offset + fragSize, data.count)
            let chunk = data.subdata(in: offset..<end)

            let flags: UInt8
            if offset == 0 && end == data.count {
                flags = BleService.flagSingle
            } else if offset == 0 {
                flags = BleService.flagFirst
            } else if end == data.count {
                flags = BleService.flagLast
            } else {
                flags = 0x00
            }

            fragments.append(Data([flags]) + chunk)
            offset = end
        }
        return fragments
    }

    // MARK: - Peer Disconnect Handling

    private func handlePeerDisconnected(peripheralUUID uuid: UUID) {
        guard let nodeId = peerNodeIds.removeValue(forKey: uuid) else { return }
        nodeIdToUUID.removeValue(forKey: nodeId.hexString)
        log.info("Peer lost: \(nodeId.hexString.prefix(16))...")
        delegate?.bleService(self, didLosePeer: nodeId)

        // Schedule auto-reconnect if we have a peripheral reference
        if let peripheral = connectedPeripherals[uuid] ?? disconnectedPeers[uuid], running {
            disconnectedPeers[uuid] = peripheral
            DispatchQueue.main.asyncAfter(deadline: .now() + BleService.reconnectDelay) { [weak self] in
                guard let self = self, self.running,
                      self.disconnectedPeers[uuid] != nil,
                      self.connectedPeripherals[uuid] == nil,
                      !self.pendingConnections.contains(uuid) else { return }
                self.log.debug("Auto-reconnecting to lost peer \(uuid)")
                self.disconnectedPeers.removeValue(forKey: uuid)
                self.pendingConnections.insert(uuid)
                self.connectToPeripheral(peripheral, attempt: 0)
            }
        }
    }

    private func handleServerPeerDisconnected(centralIdentifier: String) {
        guard let nodeId = serverPeerNodeIds.removeValue(forKey: centralIdentifier) else { return }
        serverNodeIdToIdentifier.removeValue(forKey: nodeId.hexString)
        subscribedCentrals.removeValue(forKey: centralIdentifier)
        log.info("Server peer lost: \(nodeId.hexString.prefix(16))...")
        delegate?.bleService(self, didLosePeer: nodeId)
    }

    // MARK: - Identity Handshake

    private func writeIdentityOrEmitDiscovered(_ peripheral: CBPeripheral) {
        guard let service = peripheral.services?.first(where: { $0.uuid == BleService.serviceUUID }),
              let identityChar = service.characteristics?.first(where: { $0.uuid == BleService.identityUUID }) else {
            log.warning("No identity characteristic, emitting peerDiscovered directly")
            emitPeerDiscoveredForPeripheral(peripheral)
            return
        }
        log.debug("Writing our node ID to server identity char at \(peripheral.identifier)")
        peripheral.writeValue(localNodeId, for: identityChar, type: .withResponse)
        // peerDiscovered will be emitted from peripheral(_:didWriteValueFor:error:)
    }

    private func emitPeerDiscoveredForPeripheral(_ peripheral: CBPeripheral) {
        guard let nodeId = peerNodeIds[peripheral.identifier] else { return }
        delegate?.bleService(self, didDiscoverPeer: nodeId)
    }
}

// MARK: - CBCentralManagerDelegate

extension BleService: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        log.info("Central manager state: \(central.state.rawValue)")
        if central.state == .poweredOn && running {
            startCentral()
        }
    }

    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        log.info("Central manager restoring state")
        if let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] {
            for peripheral in peripherals {
                peripheral.delegate = self
                connectedPeripherals[peripheral.identifier] = peripheral
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let uuid = peripheral.identifier

        // Skip if already connected or connection pending
        guard connectedPeripherals[uuid] == nil,
              !pendingConnections.contains(uuid),
              peerNodeIds[uuid] == nil else { return }

        log.debug("Discovered Mycelium device: \(uuid)")
        pendingConnections.insert(uuid)

        // Small random jitter to avoid both devices connecting simultaneously
        let delay = Double.random(in: 0...0.3)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self, self.running else {
                self?.pendingConnections.remove(uuid)
                return
            }
            // Re-check
            if self.connectedPeripherals[uuid] != nil || self.peerNodeIds[uuid] != nil {
                self.pendingConnections.remove(uuid)
                return
            }
            self.connectToPeripheral(peripheral, attempt: 0)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        let uuid = peripheral.identifier
        log.debug("GATT client connected to \(uuid)")
        pendingConnections.remove(uuid)
        pendingPeripherals.removeValue(forKey: uuid)
        connectRetryCounts.removeValue(forKey: uuid)
        connectedPeripherals[uuid] = peripheral
        peripheral.delegate = self
        peripheral.discoverServices([BleService.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let uuid = peripheral.identifier
        log.warning("GATT client failed to connect to \(uuid): \(error?.localizedDescription ?? "unknown")")
        connectedPeripherals.removeValue(forKey: uuid)
        pendingPeripherals.removeValue(forKey: uuid)
        deviceMtus.removeValue(forKey: uuid)

        let attempt = connectRetryCounts[uuid] ?? 0
        if attempt < BleService.maxConnectRetries {
            let delay = BleService.baseRetryDelay * Double(attempt + 1) + Double.random(in: 0...0.5)
            log.debug("Retrying connection to \(uuid) in \(delay)s (attempt \(attempt + 2))")
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self, self.running,
                      self.connectedPeripherals[uuid] == nil,
                      self.peerNodeIds[uuid] == nil else {
                    self?.pendingConnections.remove(uuid)
                    return
                }
                self.connectToPeripheral(peripheral, attempt: attempt + 1)
            }
        } else {
            log.warning("Giving up connection to \(uuid) after \(attempt + 1) attempts")
            pendingConnections.remove(uuid)
            connectRetryCounts.removeValue(forKey: uuid)
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let uuid = peripheral.identifier
        log.debug("GATT client disconnected from \(uuid)")
        connectedPeripherals.removeValue(forKey: uuid)
        deviceMtus.removeValue(forKey: uuid)

        if peerNodeIds[uuid] != nil {
            handlePeerDisconnected(peripheralUUID: uuid)
            pendingConnections.remove(uuid)
        } else {
            // Retry connection for never-identified peripherals
            let attempt = connectRetryCounts[uuid] ?? 0
            if attempt < BleService.maxConnectRetries {
                let delay = BleService.baseRetryDelay * Double(attempt + 1) + Double.random(in: 0...0.5)
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                    guard let self = self, self.running,
                          self.connectedPeripherals[uuid] == nil,
                          self.peerNodeIds[uuid] == nil else {
                        self?.pendingConnections.remove(uuid)
                        return
                    }
                    self.connectToPeripheral(peripheral, attempt: attempt + 1)
                }
            } else {
                pendingConnections.remove(uuid)
                connectRetryCounts.removeValue(forKey: uuid)
            }
        }
    }
}

// MARK: - CBPeripheralDelegate

extension BleService: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            log.warning("Service discovery failed for \(peripheral.identifier): \(error.localizedDescription)")
            return
        }

        guard let service = peripheral.services?.first(where: { $0.uuid == BleService.serviceUUID }) else {
            log.warning("Mycelium service not found on \(peripheral.identifier)")
            return
        }

        peripheral.discoverCharacteristics(
            [BleService.nodeIdUUID, BleService.dataTxUUID, BleService.dataRxUUID, BleService.identityUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            log.warning("Characteristic discovery failed: \(error.localizedDescription)")
            return
        }

        // Read Node ID
        if let nodeIdChar = service.characteristics?.first(where: { $0.uuid == BleService.nodeIdUUID }) {
            log.debug("Reading Node ID from \(peripheral.identifier)")
            peripheral.readValue(for: nodeIdChar)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            log.warning("Read/notify failed: \(error.localizedDescription)")
            return
        }

        let uuid = peripheral.identifier

        if characteristic.uuid == BleService.nodeIdUUID {
            guard let value = characteristic.value, value.count == 32 else {
                log.warning("Node ID read: unexpected size \(characteristic.value?.count ?? 0)")
                return
            }

            // Don't connect to ourselves
            if value == localNodeId {
                log.debug("Discovered self at \(uuid), ignoring")
                centralManager?.cancelPeripheralConnection(peripheral)
                connectedPeripherals.removeValue(forKey: uuid)
                pendingConnections.remove(uuid)
                return
            }

            peerNodeIds[uuid] = value
            nodeIdToUUID[value.hexString] = uuid
            log.info("Peer discovered: \(value.hexString.prefix(16))... at \(uuid)")

            // Store MTU. `.withResponse` always reports 512 (long writes are
            // split into prepare/execute, which the Android GATT server does
            // not reassemble); `.withoutResponse` reports the negotiated ATT
            // MTU minus the 3-byte header, which is the real single-packet size.
            let mtu = peripheral.maximumWriteValueLength(for: .withoutResponse)
            if mtu > 0 {
                deviceMtus[uuid] = mtu + 3  // maximumWriteValueLength already subtracts ATT header
            }

            // Subscribe to RX notifications, then write identity, then emit peerDiscovered
            if let rxChar = peripheral.services?
                .first(where: { $0.uuid == BleService.serviceUUID })?
                .characteristics?.first(where: { $0.uuid == BleService.dataRxUUID }) {
                peripheral.setNotifyValue(true, for: rxChar)
                // peerDiscovered will be emitted after identity write in
                // peripheral(_:didWriteValueFor:error:)
            } else {
                writeIdentityOrEmitDiscovered(peripheral)
            }
        } else if characteristic.uuid == BleService.dataRxUUID {
            // Received data notification from peripheral
            guard let value = characteristic.value, !value.isEmpty else { return }
            log.debug("GATT client: received \(value.count) bytes from \(uuid)")
            handleFragment(key: uuid.uuidString, raw: value)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == BleService.dataRxUUID {
            if error != nil {
                log.warning("CCCD subscription failed, emitting peerDiscovered anyway")
                emitPeerDiscoveredForPeripheral(peripheral)
            } else {
                // Subscribed — now write identity
                writeIdentityOrEmitDiscovered(peripheral)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == BleService.identityUUID {
            log.debug("Identity write completed for \(peripheral.identifier)")
            // Identity handshake done — emit peerDiscovered
            emitPeerDiscoveredForPeripheral(peripheral)
            return
        }

        // Data TX write completed
        log.debug("onCharacteristicWrite: \(error == nil ? "success" : "failed") for \(peripheral.identifier)")
        onWriteCompleted(success: error == nil)
    }
}

// MARK: - CBPeripheralManagerDelegate

extension BleService: CBPeripheralManagerDelegate {

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        log.info("Peripheral manager state: \(peripheral.state.rawValue)")
        if peripheral.state == .poweredOn && running {
            startPeripheral()
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, willRestoreState dict: [String: Any]) {
        log.info("Peripheral manager restoring state")
        // Restored services/advertising will be re-configured in didUpdateState
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error = error {
            log.error("Failed to add GATT service: \(error.localizedDescription)")
            return
        }
        log.info("GATT service added, starting advertising")
        startAdvertising()
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error = error {
            log.error("BLE advertising failed: \(error.localizedDescription)")
        } else {
            log.info("BLE advertising started")
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        if request.characteristic.uuid == BleService.nodeIdUUID {
            log.debug("Node ID read by \(request.central.identifier)")
            if request.offset < localNodeId.count {
                request.value = localNodeId.subdata(in: request.offset..<localNodeId.count)
                peripheral.respond(to: request, withResult: .success)
            } else {
                peripheral.respond(to: request, withResult: .invalidOffset)
            }
        } else {
            peripheral.respond(to: request, withResult: .readNotPermitted)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if request.characteristic.uuid == BleService.identityUUID {
                // Client identifying itself
                if let value = request.value, value.count == 32 {
                    let centralId = request.central.identifier.uuidString
                    serverPeerNodeIds[centralId] = value
                    serverNodeIdToIdentifier[value.hexString] = centralId
                    log.info("GATT server: client identified as \(value.hexString.prefix(16))... (central: \(centralId.prefix(8)))")
                    // Emit peer discovered for server-side connections
                    delegate?.bleService(self, didDiscoverPeer: value)
                }
                peripheral.respond(to: request, withResult: .success)
            } else if request.characteristic.uuid == BleService.dataTxUUID {
                if let value = request.value, !value.isEmpty {
                    let centralId = request.central.identifier.uuidString
                    log.debug("GATT server: received \(value.count) bytes from central \(centralId.prefix(8))")
                    handleFragment(key: centralId, raw: value)
                    peripheral.respond(to: request, withResult: .success)
                } else {
                    peripheral.respond(to: request, withResult: .unlikelyError)
                }
            } else {
                peripheral.respond(to: request, withResult: .writeNotPermitted)
            }
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        let centralId = central.identifier.uuidString
        subscribedCentrals[centralId] = central
        log.debug("Central \(centralId.prefix(8)) subscribed to notifications")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        let centralId = central.identifier.uuidString
        subscribedCentrals.removeValue(forKey: centralId)
        handleServerPeerDisconnected(centralIdentifier: centralId)
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        // Called when a previous updateValue returned false. Retry.
        writeLock.lock()
        writeInProgress = false
        writeLock.unlock()
        processNextWrite()
    }
}

// MARK: - Data Extensions

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
