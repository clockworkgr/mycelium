import CoreBluetooth
import os.log

/// Delegate protocol for BLE transport events.
///
/// Links, not peers: this layer carries frames and does not know which node
/// is on the other end. Identity is proved by a handshake in Rust over these
/// frames (ADR-021, ROADMAP T-34).
protocol BleServiceDelegate: AnyObject {
    func bleService(_ service: BleService, didOpenLink linkId: String)
    func bleService(_ service: BleService, didCloseLink linkId: String)
    func bleService(_ service: BleService, didReceiveFrame data: Data, onLink linkId: String)
}

/// Dual-role BLE transport service using CoreBluetooth.
///
/// Implements both GATT peripheral (server) and central (client) roles
/// for mesh peer discovery and data exchange. Supports iOS background
/// modes via state preservation/restoration.
///
/// The Node ID and Identity characteristics that used to exchange a bare,
/// unprovable 32-byte id are gone: a peer's NodeId is derived from the key
/// its handshake proves, and nothing here reports an identity at all.
///
/// GATT Service Layout (same as Android):
///   Service UUID:   a1b2c3d4-e5f6-7890-abcd-ef1234567890
///   Data TX char:   ...7892  (Write)  — central writes frames to peripheral
///   Data RX char:   ...7893  (Notify) — peripheral notifies central with frames
///
/// Links are named `c:<peripheral UUID>` where we are the central and
/// `s:<central identifier>` where we are the server. Both roles can be live
/// with the same device at once, and they are two links with two handshakes.
///
/// Fragmentation header (1 byte), below Rust's own:
///   0x01 = first fragment
///   0x02 = last fragment
///   0x03 = first+last (single packet)
class BleService: NSObject {

    // MARK: - Constants

    static let serviceUUID    = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    static let dataTxUUID     = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567892")
    static let dataRxUUID     = CBUUID(string: "a1b2c3d4-e5f6-7890-abcd-ef1234567893")

    static let flagFirst:  UInt8 = 0x01
    static let flagLast:   UInt8 = 0x02
    static let flagSingle: UInt8 = 0x03

    /// Our role in a link, and the prefix its name carries.
    static let roleCentral = "c:"
    static let roleServer  = "s:"

    /// Payload bytes in one GATT write at the 23-byte default ATT MTU.
    ///
    /// An ATT MTU of 23 carries 20 bytes of attribute value (3 go to the ATT
    /// header), and one of those 20 is our own fragment flag, so 19 are
    /// payload. The old value of 20 produced a 21-byte write the link cannot
    /// carry.
    static let defaultFragmentSize = 19

    private static let maxConnectRetries = 3
    private static let baseRetryDelay: TimeInterval = 1.0
    private static let reconnectDelay: TimeInterval = 2.0
    private static let scanCycleInterval: TimeInterval = 25.0
    /// How long an address refused by the Rust side is left alone.
    private static let refusedBackoff: TimeInterval = 30.0
    /// How long a link may stay announced without being established before
    /// this layer closes it itself. Longer than the Rust side's ten-second
    /// handshake deadline, so its own directive normally arrives first; this
    /// is the backstop for when that directive never does.
    private static let staleLink: TimeInterval = 20.0
    /// How often the stale-link sweep runs.
    private static let linkSweepInterval: TimeInterval = 5.0
    /// Largest frame this layer will reassemble from GATT writes. The Rust
    /// side fragments to its BLE frame MTU, so anything longer is not a
    /// frame it sent — and the bounded reassembler above would never see it,
    /// because it would never be handed over.
    private static let maxFrameBytes = 512
    /// Largest GATT attribute value to write. A peer's Android GATT server
    /// refuses anything above 512, so a 512-byte Rust fragment plus this
    /// layer's flag byte must not be attempted whatever the negotiated MTU
    /// allows locally.
    private static let maxAttValue = 512
    /// How long a partial frame waits for the rest of itself.
    private static let reassemblyTtl: TimeInterval = 10.0
    /// How long a connection has to become announceable before this layer
    /// gives up on it.
    private static let setupDeadline: TimeInterval = 20.0

    private static let centralRestoreId    = "com.mycelium.ble.central"
    private static let peripheralRestoreId = "com.mycelium.ble.peripheral"

    private let log = Logger(subsystem: "com.mycelium", category: "BLE")

    // MARK: - Properties

    weak var delegate: BleServiceDelegate?

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
    private var pendingConnections: Set<UUID> = []
    private var connectRetryCounts: [UUID: Int] = [:]
    private var disconnectedPeers: [UUID: CBPeripheral] = [:]

    /// Links announced to Rust, with when they were announced: one that
    /// never becomes established is swept.
    private var openLinks: [String: Date] = [:]
    /// Links the Rust side has told us completed their handshake.
    private var establishedLinks: Set<String> = []
    /// Links Rust has refused, with the time they may be retried. By link,
    /// not by device: both roles can be live with one device, and a handshake
    /// that failed in one says nothing about the other.
    private var refusedUntil: [String: Date] = [:]

    // Per-device negotiated MTU
    private var deviceMtus: [UUID: Int] = [:]

    // Fragment reassembly: link id -> partial buffer, and when it started
    private var reassemblyBuffers: [String: Data] = [:]
    private var reassemblyStartedAt: [String: Date] = [:]

    // Connections that exist but are not announceable yet, with when they
    // connected: one that stalls in discovery is never announced, so nothing
    // above this layer could notice it.
    private var pendingSetup: [String: Date] = [:]

    // Sequential write queue
    private struct WriteOperation {
        let linkId: String
        let fragments: [Data]
        var currentIndex: Int = 0
        let isClientWrite: Bool        // true = GATT client write, false = server notify
        let peripheralUUID: UUID?      // set for client writes
        let centralId: String?         // set for server notifies
        /// Told to us by the Rust side, which is the only layer that knows:
        /// a link counts as established there as soon as the peer's
        /// confirmation arrives, which can be before our own has left. A
        /// handshake operation is never delayed behind traffic and never
        /// evicted.
        let isHandshake: Bool
    }

    private var writeQueue: [WriteOperation] = []
    private var writeInProgress = false
    private let writeLock = NSLock()
    /// Operations held for the radio at once.
    ///
    /// The Rust outbox is bounded, but polling frees its capacity as soon as
    /// a frame is handed over, so without a bound here a slow peer
    /// accumulates writes without limit. Past this, the oldest operation of
    /// an *established* link is dropped — ordinary traffic, as in the outbox
    /// one layer up (ADR-014) — and a handshake is never the one sacrificed.
    private static let maxWriteQueue = 128

    // Scan cycling timer
    private var scanCycleTimer: Timer?
    // Stale-link sweep timer
    private var linkSweepTimer: Timer?

    // MARK: - Public API

    func start() {
        guard !running else { return }
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

        linkSweepTimer = Timer.scheduledTimer(
            withTimeInterval: BleService.linkSweepInterval,
            repeats: true
        ) { [weak self] _ in
            self?.sweepStaleLinks()
        }
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

        linkSweepTimer?.invalidate()
        linkSweepTimer = nil

        // Report every link down, so Rust drops the peers behind them.
        for linkId in openLinks.keys {
            delegate?.bleService(self, didCloseLink: linkId)
        }
        openLinks.removeAll()
        establishedLinks.removeAll()
        pendingSetup.removeAll()
        reassemblyStartedAt.removeAll()
        refusedUntil.removeAll()
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

    /// Write one frame on a link. The link id says which role carries it, so
    /// the two directions of a dual-role pair cannot be confused.
    func sendData(linkId: String, data: Data, isHandshake: Bool) -> Bool {
        guard let key = BleService.deviceKey(of: linkId) else {
            log.warning("sendData: malformed link id \(linkId)")
            return false
        }

        if linkId.hasPrefix(BleService.roleCentral) {
            guard let uuid = UUID(uuidString: key),
                  connectedPeripherals[uuid] != nil else {
                log.warning("sendData: no GATT client link for \(linkId)")
                return false
            }
            let fragments = fragment(data, forDeviceUUID: uuid)
            enqueueWrite(WriteOperation(
                linkId: linkId,
                fragments: fragments,
                isClientWrite: true,
                peripheralUUID: uuid,
                centralId: nil,
                isHandshake: isHandshake
            ))
            return true
        }

        guard subscribedCentrals[key] != nil else {
            log.warning("sendData: central \(key) is not subscribed")
            return false
        }
        let fragments = fragmentDefault(data)
        enqueueWrite(WriteOperation(
            linkId: linkId,
            fragments: fragments,
            isClientWrite: false,
            peripheralUUID: nil,
            centralId: key,
            isHandshake: isHandshake
        ))
        return true
    }

    /// Close a link Rust refused: its handshake failed, timed out, named us,
    /// or there was no room for it. Nothing was installed for it, so the
    /// connection is of no use; the device is left alone for a while rather
    /// than redialled at once.
    func closeLink(_ linkId: String) {
        guard let key = BleService.deviceKey(of: linkId) else { return }
        log.info("Closing refused link \(linkId)")
        refusedUntil[linkId] = Date().addingTimeInterval(BleService.refusedBackoff)
        purgeWrites(for: linkId)
        reportLinkDown(linkId)

        if linkId.hasPrefix(BleService.roleCentral), let uuid = UUID(uuidString: key) {
            disconnectedPeers.removeValue(forKey: uuid)
            if let peripheral = connectedPeripherals.removeValue(forKey: uuid) {
                centralManager?.cancelPeripheralConnection(peripheral)
            }
        } else {
            // CoreBluetooth gives a peripheral manager no way to disconnect
            // a central: there is no counterpart to Android's
            // `BluetoothGattServer.cancelConnection`. The link is forgotten
            // and its queued writes dropped, and a central that resubscribes
            // opens a fresh link which is refused again — but its connection
            // survives until it gives up, so a peer that keeps failing
            // handshakes can hold a slot in our peripheral role. Recorded as
            // a residual in ADR-021 rather than worked around here.
            subscribedCentrals.removeValue(forKey: key)
        }
    }

    /// A link became established: stop retrying, and stop sweeping it.
    func onLinkEstablished(_ linkId: String) {
        guard let key = BleService.deviceKey(of: linkId) else { return }
        // The directive is polled, so it can arrive after the link it
        // describes has gone. Marking a link we no longer hold would let a
        // replacement of the same name inherit the mark and slip past the
        // stale-link sweep.
        guard openLinks[linkId] != nil else {
            log.debug("Ignoring an establishment for a link we no longer hold: \(linkId)")
            return
        }
        refusedUntil.removeValue(forKey: linkId)
        establishedLinks.insert(linkId)
        if let uuid = UUID(uuidString: key) {
            connectRetryCounts.removeValue(forKey: uuid)
        }
        log.info("Link \(linkId) established")
    }

    /// Close links that never finished their handshake.
    ///
    /// The Rust side reaps them at its own deadline and asks us to close
    /// them, but that directive is polled, and a queue that overflows or an
    /// app that stops polling would leave a connection holding a slot with
    /// nothing left to free it. This layer owns its connections, so it does
    /// not depend on being told.
    private func sweepStaleLinks() {
        guard running else { return }
        let now = Date()
        // Peripheral identifiers are stable, but a central's is not, so an
        // entry only reached when the same link comes back is an entry that
        // never goes.
        refusedUntil = refusedUntil.filter { $0.value > now }

        // A partial frame whose rest never came.
        for (linkId, startedAt) in reassemblyStartedAt
        where now.timeIntervalSince(startedAt) >= BleService.reassemblyTtl {
            reassemblyBuffers.removeValue(forKey: linkId)
            reassemblyStartedAt.removeValue(forKey: linkId)
        }

        // A connection that never became announceable: nothing above this
        // layer knows it exists, so nothing above it can give up on it.
        for (linkId, connectedAt) in pendingSetup {
            if openLinks[linkId] != nil {
                pendingSetup.removeValue(forKey: linkId)
                continue
            }
            if now.timeIntervalSince(connectedAt) < BleService.setupDeadline { continue }
            log.warning("Dropping \(linkId): connected and never subscribed")
            pendingSetup.removeValue(forKey: linkId)
            if let key = BleService.deviceKey(of: linkId), let uuid = UUID(uuidString: key),
               let peripheral = connectedPeripherals.removeValue(forKey: uuid) {
                centralManager?.cancelPeripheralConnection(peripheral)
            }
        }

        for (linkId, openedAt) in openLinks {
            if establishedLinks.contains(linkId) { continue }
            if now.timeIntervalSince(openedAt) < BleService.staleLink { continue }
            log.warning("Closing \(linkId): announced and never established")
            closeLink(linkId)
        }
    }

    // MARK: - Link bookkeeping

    private static func deviceKey(of linkId: String) -> String? {
        guard linkId.hasPrefix(roleCentral) || linkId.hasPrefix(roleServer) else { return nil }
        let key = String(linkId.dropFirst(2))
        return key.isEmpty ? nil : key
    }

    private func reportLinkUp(_ linkId: String) {
        pendingSetup.removeValue(forKey: linkId)
        guard openLinks[linkId] == nil else { return }
        openLinks[linkId] = Date()
        log.info("Link up: \(linkId)")
        delegate?.bleService(self, didOpenLink: linkId)
    }

    private func reportLinkDown(_ linkId: String) {
        reassemblyBuffers.removeValue(forKey: linkId)
        reassemblyStartedAt.removeValue(forKey: linkId)
        pendingSetup.removeValue(forKey: linkId)
        establishedLinks.remove(linkId)
        guard openLinks.removeValue(forKey: linkId) != nil else { return }
        log.info("Link down: \(linkId)")
        delegate?.bleService(self, didCloseLink: linkId)
    }

    private func refused(_ linkId: String) -> Bool {
        guard let until = refusedUntil[linkId] else { return false }
        if Date() >= until {
            refusedUntil.removeValue(forKey: linkId)
            return false
        }
        return true
    }

    private func centralLink(_ uuid: UUID) -> String {
        BleService.roleCentral + uuid.uuidString
    }

    // MARK: - Write Queue Management

    /// Queue an operation. Frames for a link that is not established yet go
    /// ahead of ordinary traffic: the Rust side puts a handshake frame first
    /// in its own queue, and a FIFO native queue holding seconds of data
    /// writes is what would undo that. A link that is not established can
    /// only be carrying its handshake, so no inspection of the frame is
    /// needed, and per-link order is kept because a link has no traffic
    /// until it is established.
    private func enqueueWrite(_ op: WriteOperation) {
        writeLock.lock()
        if writeQueue.count >= BleService.maxWriteQueue {
            // Drop the oldest ordinary operation, never a handshake, and
            // never the one in flight.
            let floorIndex = writeInProgress ? 1 : 0
            let victim = (floorIndex..<writeQueue.count).first {
                !writeQueue[$0].isHandshake
            }
            guard let victim = victim else {
                log.warning("writeQueue: full of handshakes, refusing \(op.linkId)")
                writeLock.unlock()
                return
            }
            let victimLink = writeQueue[victim].linkId
            log.warning("writeQueue: full, dropping an operation for \(victimLink)")
            writeQueue.remove(at: victim)
        }
        if !op.isHandshake {
            writeQueue.append(op)
        } else {
            // After *every* queued handshake, not between a link's own hello
            // and confirmation, which the peer would then read in the wrong
            // order. The operation in flight is never displaced.
            let floorIndex = writeInProgress ? 1 : 0
            var insertAt = writeQueue.count
            for (index, queued) in writeQueue.enumerated() where index >= floorIndex {
                if !queued.isHandshake {
                    insertAt = index
                    break
                }
            }
            writeQueue.insert(op, at: min(max(insertAt, floorIndex), writeQueue.count))
        }
        writeLock.unlock()
        processNextWrite()
    }

    /// Drop queued writes for a link that just went away, or the write queue
    /// would stall on a callback that will never come.
    private func purgeWrites(for linkId: String) {
        writeLock.lock()
        let headWasTheirs = writeQueue.first?.linkId == linkId
        writeQueue.removeAll { $0.linkId == linkId }
        if writeInProgress && headWasTheirs {
            writeInProgress = false
        }
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
                log.warning("writeQueue: GATT client gone for \(op.linkId)")
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
                  let centralId = op.centralId,
                  let central = subscribedCentrals[centralId] else {
                log.warning("writeQueue: GATT server or central gone for \(op.linkId)")
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

    /// A write completed for `uuid`, which is the only identity the
    /// callback carries.
    ///
    /// Matched against the operation in flight, because a callback can
    /// arrive after its own operation was purged — a link dropping takes its
    /// queued writes with it — and an unmatched completion would otherwise
    /// advance or discard the operation that took its place.
    private func onWriteCompleted(peripheralUUID uuid: UUID, success: Bool) {
        writeLock.lock()
        // Only the central role gets a write completion here: a peripheral
        // manager's `updateValue` reports synchronously, and this layer's
        // purges of a central link all follow a cancelled connection — so
        // unlike Android there is no live connection whose late completion
        // could be mistaken for a later operation's.
        guard let head = writeQueue.first, head.peripheralUUID == uuid else {
            log.debug("writeQueue: ignoring a completion from \(uuid)")
            writeLock.unlock()
            return
        }
        if !success {
            let remaining = head.fragments.count - head.currentIndex
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
        service.characteristics = [dataTxChar, rxChar]
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
            if connectedPeripherals[uuid] != nil || pendingConnections.contains(uuid) ||
                refused(centralLink(uuid)) {
                disconnectedPeers.removeValue(forKey: uuid)
                continue
            }
            log.debug("Auto-reconnecting to \(uuid)")
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

    private func handleFragment(linkId: String, raw: Data) {
        guard !raw.isEmpty, raw.count <= BleService.maxFrameBytes + 1 else { return }
        // The peer's first frame can beat our own subscription callback, so
        // a frame for a connection we already hold announces its link rather
        // than being dropped — otherwise that handshake only recovers through
        // the reaper and the backoff. A link just refused is not reopened by
        // what was still in flight.
        if openLinks[linkId] == nil {
            guard let key = BleService.deviceKey(of: linkId), !refused(linkId) else {
                log.debug("Dropping a frame on unannounced link \(linkId)")
                return
            }
            let connected = (UUID(uuidString: key).flatMap { connectedPeripherals[$0] } != nil)
                || subscribedCentrals[key] != nil
            guard connected else {
                log.debug("Dropping a frame on unannounced link \(linkId)")
                return
            }
            log.debug("First frame on \(linkId) arrived before our own callback")
            reportLinkUp(linkId)
        }
        let flags = raw[raw.startIndex]
        let payload = raw.count > 1 ? raw.subdata(in: (raw.startIndex + 1)..<raw.endIndex) : Data()

        let isFirst = (flags & 0x01) != 0
        let isLast  = (flags & 0x02) != 0

        if isFirst {
            reassemblyBuffers[linkId] = payload
            reassemblyStartedAt[linkId] = Date()
        } else {
            guard var existing = reassemblyBuffers[linkId] else { return }
            if existing.count + payload.count > BleService.maxFrameBytes {
                // Longer than any frame the Rust side sends, so not one.
                log.warning("Dropping an over-long reassembly on \(linkId)")
                reassemblyBuffers.removeValue(forKey: linkId)
                reassemblyStartedAt.removeValue(forKey: linkId)
                return
            }
            existing.append(payload)
            reassemblyBuffers[linkId] = existing
        }

        if isLast {
            reassemblyStartedAt.removeValue(forKey: linkId)
            guard let complete = reassemblyBuffers.removeValue(forKey: linkId) else { return }
            log.debug("Reassembled \(complete.count) bytes on \(linkId)")
            delegate?.bleService(self, didReceiveFrame: complete, onLink: linkId)
        }
    }

    private func fragment(_ data: Data, forDeviceUUID uuid: UUID) -> [Data] {
        let mtu = deviceMtus[uuid] ?? 23
        // ATT header: 3 bytes, our fragmentation header: 1 byte, and never a
        // value a peer's GATT server will refuse.
        let fragSize = min(
            max(mtu - 4, BleService.defaultFragmentSize),
            BleService.maxAttValue - 1
        )
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
            let chunk = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + end))

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

    // MARK: - Link Loss

    private func handleCentralLinkLost(peripheralUUID uuid: UUID, retryIfUnopened: Bool) {
        let linkId = BleService.roleCentral + uuid.uuidString
        let wasOpen = openLinks[linkId] != nil
        purgeWrites(for: linkId)
        reportLinkDown(linkId)
        pendingConnections.remove(uuid)

        guard running, !refused(linkId) else {
            // Nothing further will be attempted, so the strong reference
            // goes: peripherals rotate, and one kept per refusal would
            // accumulate for as long as the app runs.
            pendingPeripherals.removeValue(forKey: uuid)
            connectRetryCounts.removeValue(forKey: uuid)
            return
        }

        if wasOpen {
            // A link we had announced is worth getting back. The reference
            // moves to `disconnectedPeers`, which the reconnect consumes.
            if let peripheral = connectedPeripherals[uuid] ?? pendingPeripherals[uuid] ?? disconnectedPeers[uuid] {
                scheduleReconnect(peripheral)
            }
            pendingPeripherals.removeValue(forKey: uuid)
            connectRetryCounts.removeValue(forKey: uuid)
            return
        }

        guard retryIfUnopened,
              let peripheral = pendingPeripherals[uuid] ?? connectedPeripherals[uuid] else { return }
        let attempt = connectRetryCounts[uuid] ?? 0
        if attempt < BleService.maxConnectRetries {
            let delay = BleService.baseRetryDelay * Double(attempt + 1) + Double.random(in: 0...0.5)
            log.debug("Retrying connection to \(uuid) in \(delay)s (attempt \(attempt + 2))")
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self, self.running,
                      self.connectedPeripherals[uuid] == nil,
                      !self.refused(self.centralLink(uuid)) else {
                    self?.pendingConnections.remove(uuid)
                    self?.pendingPeripherals.removeValue(forKey: uuid)
                    return
                }
                self.connectToPeripheral(peripheral, attempt: attempt + 1)
            }
        } else {
            log.warning("Giving up connection to \(uuid) after \(attempt + 1) attempts")
            pendingConnections.remove(uuid)
            pendingPeripherals.removeValue(forKey: uuid)
            connectRetryCounts.removeValue(forKey: uuid)
        }
    }

    private func scheduleReconnect(_ peripheral: CBPeripheral) {
        let uuid = peripheral.identifier
        disconnectedPeers[uuid] = peripheral
        DispatchQueue.main.asyncAfter(deadline: .now() + BleService.reconnectDelay) { [weak self] in
            guard let self = self, self.running,
                  self.disconnectedPeers[uuid] != nil,
                  self.connectedPeripherals[uuid] == nil,
                  !self.pendingConnections.contains(uuid),
                  !self.refused(self.centralLink(uuid)) else { return }
            self.log.debug("Auto-reconnecting to \(uuid)")
            self.disconnectedPeers.removeValue(forKey: uuid)
            self.pendingConnections.insert(uuid)
            self.connectToPeripheral(peripheral, attempt: 0)
        }
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
            // A restored connection is of no use to us. CoreBluetooth
            // brings back the connection *and* its subscription, but the
            // channel keys behind it were in the Rust process that went
            // away, and the remote still believes the link is established —
            // so a fresh cleartext hello sent over it would arrive where a
            // sealed frame is expected, fail to open, and be dropped. The
            // connection is dropped instead; scanning reconnects and both
            // ends handshake from the beginning.
            for peripheral in peripherals {
                peripheral.delegate = self
                log.info("Dropping a restored connection to \(peripheral.identifier)")
                centralManager?.cancelPeripheralConnection(peripheral)
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let uuid = peripheral.identifier

        // Skip if already connected or connection pending, or just refused
        guard connectedPeripherals[uuid] == nil,
              !pendingConnections.contains(uuid),
              !refused(centralLink(uuid)) else { return }

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
            if self.connectedPeripherals[uuid] != nil || self.refused(self.centralLink(uuid)) {
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
        // Announceable only once discovery and subscription finish; if they
        // stall, the sweep is what notices.
        pendingSetup[centralLink(uuid)] = Date()
        connectedPeripherals[uuid] = peripheral
        peripheral.delegate = self
        peripheral.discoverServices([BleService.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let uuid = peripheral.identifier
        log.warning("GATT client failed to connect to \(uuid): \(error?.localizedDescription ?? "unknown")")
        connectedPeripherals.removeValue(forKey: uuid)
        deviceMtus.removeValue(forKey: uuid)
        handleCentralLinkLost(peripheralUUID: uuid, retryIfUnopened: true)
        pendingPeripherals.removeValue(forKey: uuid)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let uuid = peripheral.identifier
        log.debug("GATT client disconnected from \(uuid)")
        pendingPeripherals[uuid] = peripheral
        connectedPeripherals.removeValue(forKey: uuid)
        deviceMtus.removeValue(forKey: uuid)
        handleCentralLinkLost(peripheralUUID: uuid, retryIfUnopened: true)
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
            [BleService.dataTxUUID, BleService.dataRxUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            log.warning("Characteristic discovery failed: \(error.localizedDescription)")
            return
        }

        let uuid = peripheral.identifier

        // Store MTU. `.withResponse` always reports 512 (long writes are
        // split into prepare/execute, which the Android GATT server does
        // not reassemble); `.withoutResponse` reports the negotiated ATT
        // MTU minus the 3-byte header, which is the real single-packet size.
        let mtu = peripheral.maximumWriteValueLength(for: .withoutResponse)
        if mtu > 0 {
            deviceMtus[uuid] = mtu + 3  // maximumWriteValueLength already subtracts ATT header
        }

        // Subscribe to RX notifications. The link is announced once that
        // completes: before it, frames could leave but none could arrive, so
        // a handshake would stall and be reaped.
        guard let rxChar = service.characteristics?.first(where: { $0.uuid == BleService.dataRxUUID }) else {
            log.warning("No RX characteristic on \(uuid), nothing can arrive")
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }
        peripheral.setNotifyValue(true, for: rxChar)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            log.warning("Notify failed: \(error.localizedDescription)")
            return
        }
        guard characteristic.uuid == BleService.dataRxUUID,
              let value = characteristic.value, !value.isEmpty else { return }
        handleFragment(linkId: BleService.roleCentral + peripheral.identifier.uuidString, raw: value)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == BleService.dataRxUUID else { return }
        let uuid = peripheral.identifier
        if error != nil {
            log.warning("Subscription failed for \(uuid); nothing could arrive")
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }
        if !refused(centralLink(uuid)) {
            reportLinkUp(centralLink(uuid))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        onWriteCompleted(peripheralUUID: peripheral.identifier, success: error == nil)
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
        // A restored service brings back its subscribed centrals, and their
        // channel keys were in the Rust process that went away: those
        // centrals believe their links are established, and nothing here
        // could answer them. Every restored service is therefore removed,
        // which invalidates the subscriptions with it, and `startPeripheral`
        // adds a fresh one on `didUpdateState` — the same reasoning as for a
        // restored central connection, and the same cost.
        if let services = dict[CBPeripheralManagerRestoredStateServicesKey] as? [CBMutableService],
           !services.isEmpty {
            log.info("Dropping \(services.count) restored GATT service(s)")
        }
        peripheral.removeAllServices()
        subscribedCentrals.removeAll()
        gattService = nil
        dataRxCharacteristic = nil
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

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if request.characteristic.uuid == BleService.dataTxUUID {
                if let value = request.value, !value.isEmpty {
                    let centralId = request.central.identifier.uuidString
                    handleFragment(linkId: BleService.roleServer + centralId, raw: value)
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
        // Now that we can notify, the link can carry a handshake.
        if !refused(BleService.roleServer + centralId) {
            reportLinkUp(BleService.roleServer + centralId)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        let centralId = central.identifier.uuidString
        subscribedCentrals.removeValue(forKey: centralId)
        let linkId = BleService.roleServer + centralId
        purgeWrites(for: linkId)
        reportLinkDown(linkId)
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        // Called when a previous `updateValue` returned false, and it names
        // no central: it says the transmit queue has room, not that any
        // operation finished. So it resumes the queue only if what is in
        // flight is the notification that was rewound — clearing the flag
        // while a client write is pending would start a second write on a
        // connection that permits one.
        writeLock.lock()
        if let head = writeQueue.first, !head.isClientWrite {
            writeInProgress = false
        }
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
