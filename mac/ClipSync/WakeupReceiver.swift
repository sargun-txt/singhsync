// WakeupReceiver.swift
// The ONE and ONLY Mac-side BLE peripheral (GATT server) for ClipSync.
//
// This used to be two competing CBPeripheralManager instances:
//   - BLEAdvertiser (BLEDiscover.swift) -> served DeviceName (read)
//   - WakeupReceiver (this file)        -> served Wakeup (write)
// Both registered the SAME service UUID independently, which caused CoreBluetooth's
// per-process GATT database to have two owners fighting over one service. Android's
// GATT service-discovery could resolve against whichever registration "won" the race,
// silently missing the wakeup characteristic and leaving the Mac stuck on QRGen.swift.
//
// Fix: exactly one CBPeripheralManager, one CBMutableService, both characteristics
// added together, started once at app launch and never torn down mid-flow.

import Foundation
import CoreBluetooth
import Combine
import CryptoKit
import UserNotifications

// Control messages use BLE protocol v2 (BleControlProtocol.swift): every message in both
// directions is an HMAC-authenticated envelope, verified before any field is trusted.

class WakeupReceiver: NSObject, ObservableObject, CBPeripheralManagerDelegate {

    // MARK: - Constants
    static let shared = WakeupReceiver()

    /// Single ClipSync BLE Service UUID — must match BLEScanner.kt on Android.
    private let serviceUUID = CBUUID(string: "C11C5AC0-0001-1000-8000-00805F9B34FB")
    /// Readable — serves the Mac's device name during initial discovery.
    private let deviceNameCharUUID = CBUUID(string: "C11C5AC1-0001-1000-8000-00805F9B34FB")
    /// Writable — receives pairing_ack / wakeup pings from Android.
    private let wakeupCharUUID = CBUUID(string: "C11C5AC2-0001-1000-8000-00805F9B34FB")
    /// Notify — Mac pushes text/file signals to Android (Mac→Android path).
    private let sendRequestCharUUID = CBUUID(string: "C11C5AC3-0001-1000-8000-00805F9B34FB")

    // MARK: - State
    @Published var lastPing: WakeupPayload? = nil
    @Published var isReady = false

    /// Fired once Android successfully reads the DeviceName characteristic —
    /// replaces BLEAdvertiser.onDeviceConnected from the old dual-manager design.
    var onDeviceConnected: (() -> Void)?

    /// Last Android IP received from a wakeup ping — used by Mac for initiating TCP to Android.
    private(set) var lastAndroidIp: String? = nil
    private var lastAndroidIpDate: Date? = nil

    private var peripheralManager: CBPeripheralManager?
    private var deviceNameCharacteristic: CBMutableCharacteristic?
    private var wakeupCharacteristic: CBMutableCharacteristic?
    private var sendRequestCharacteristic: CBMutableCharacteristic?
    private var subscribedCentrals: [CBCentral] = []
    private var hasAddedService = false

    /// Authenticates, replay-checks and correlates every inbound control message.
    private let inbound = MacBleInbound()
    /// Device-info envelope served for the current (possibly multi-part) read.
    private var cachedDeviceInfo: Data?

    /// The pairing key, root of the BLE auth key. Nil before the first QR code is generated.
    private func pairingRootKey() -> SymmetricKey? {
        guard let hex = KeychainHelper.getEncryptionKey(), hex.count == 64 else { return nil }
        var data = Data(capacity: 32)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        return SymmetricKey(data: data)
    }

    private static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    private static var legacyPeerNotified = false

    /// One notification per launch when an old (pre-v2, unauthenticated) phone is detected.
    static func notifyLegacyPeerOnce() {
        DispatchQueue.main.async {
            guard !legacyPeerNotified else { return }
            legacyPeerNotified = true
            let content = UNMutableNotificationContent()
            content.title = "Update ClipSync on your phone"
            content.body = "This version of ClipSync can't sync securely with the older app on your Android phone."
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: "clipsync.legacy-peer", content: content, trigger: nil))
        }
    }

    /// Returns Android's IP if it was seen within the last 2 minutes, otherwise nil.
    func getFreshAndroidIp() -> String? {
        guard let ip = lastAndroidIp, let date = lastAndroidIpDate else { return nil }
        return Date().timeIntervalSince(date) < 120 ? ip : nil
    }

    /// Builds the authenticated device-info envelope served when Android reads the DeviceName
    /// characteristic (name, LAN IP, TCP port). Before a pairing key exists it carries an
    /// all-zero MAC: the name can be shown in the pre-pairing picker but never verifies.
    private func buildDeviceInfoEnvelope() -> Data {
        let name = String((Host.current().localizedName ?? "Mac").prefix(60))
        var fields: [BleField: Data] = [
            .name: BleControlProtocol.utf8(name),
            .port: BleControlProtocol.u16(ClipSyncServer.shared.dynamicPort)
        ]
        if let ip = getLocalWifiIp(), BleControlProtocol.isValidIPv4OrEmpty(ip) {
            fields[.ip] = BleControlProtocol.utf8(ip)
        }
        let authKey = pairingRootKey().map { BleControlProtocol.authKey(rootKey: $0) }
        return (try? BleControlProtocol.encode(type: .deviceInfo, fields: fields,
                                               messageId: BleControlProtocol.newMessageId(),
                                               timestampMs: Self.nowMs(), authKey: authKey)) ?? Data()
    }

    /// Returns the Mac's current Wi-Fi IPv4 address, or nil if not on Wi-Fi.
    private func getLocalWifiIp() -> String? {
        var address: String? = nil
        var ifaddr: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        defer { freeifaddrs(ifaddr) }
        var ptr = ifaddr
        while let current = ptr {
            let iface = current.pointee
            if iface.ifa_addr.pointee.sa_family == UInt8(AF_INET) {
                let name = String(cString: iface.ifa_name)
                // en0 is the primary Wi-Fi interface on Mac
                if name == "en0" {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(iface.ifa_addr, socklen_t(iface.ifa_addr.pointee.sa_len),
                                &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST)
                    address = String(cString: hostname)
                }
            }
            ptr = iface.ifa_next
        }
        return address
    }

    // MARK: - Start / Stop

    /// Idempotent — safe to call multiple times (from PairingManager, QRGenScreen,
    /// BLEDiscover, etc). Only creates the peripheral manager once; subsequent calls
    /// are no-ops if already running, and re-advertise if the manager exists but
    /// advertising was stopped.
    func start() {
        if peripheralManager == nil {
            // Triggers the one-time system Bluetooth permission dialog on first run.
            peripheralManager = CBPeripheralManager(
                delegate: self,
                queue: DispatchQueue(label: "com.clipsync.ble"),
                options: [CBPeripheralManagerOptionShowPowerAlertKey: true]
            )
            return
        }

        if peripheralManager?.state == .poweredOn {
            addServiceIfNeeded(peripheralManager!)
            startAdvertisingIfNeeded()
        }
    }

    /// Stops advertising but keeps the peripheral manager and service registered.
    /// We deliberately do NOT call removeAllServices() here — tearing the service
    /// down and re-adding it is exactly the race condition that caused this bug.
    /// Only call stop() on full app teardown / explicit unpair, never mid-onboarding.
    func stop() {
        peripheralManager?.stopAdvertising()
        DispatchQueue.main.async { self.isReady = false }
    }

    // MARK: - CBPeripheralManagerDelegate

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            addServiceIfNeeded(peripheral)
        case .unauthorized, .poweredOff:
            break
        default:
            break
        }
    }

    private func addServiceIfNeeded(_ peripheral: CBPeripheralManager) {
        guard !hasAddedService else {
            startAdvertisingIfNeeded()
            return
        }


        let deviceNameChar = CBMutableCharacteristic(
            type: deviceNameCharUUID,
            properties: [.read],
            value: nil,
            permissions: [.readable]
        )
        deviceNameCharacteristic = deviceNameChar

        let wakeupChar = CBMutableCharacteristic(
            type: wakeupCharUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        wakeupCharacteristic = wakeupChar

        // Mac→Android push characteristic: Android subscribes once and receives
        // notify events whenever Mac calls pushToAndroid().
        let sendRequestChar = CBMutableCharacteristic(
            type: sendRequestCharUUID,
            properties: [.notify, .indicate],
            value: nil,
            permissions: []
        )
        sendRequestCharacteristic = sendRequestChar

        // All three characteristics on ONE service, added ONCE.
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [deviceNameChar, wakeupChar, sendRequestChar]
        peripheral.add(service)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if error != nil {
            return
        }

        hasAddedService = true
        startAdvertisingIfNeeded()
    }

    private func startAdvertisingIfNeeded() {
        guard let peripheral = peripheralManager, hasAddedService else { return }

        let macName = Host.current().localizedName ?? "ClipSync"
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [serviceUUID],
            CBAdvertisementDataLocalNameKey: macName
        ])
        DispatchQueue.main.async { self.isReady = true }
    }

    /// Android connected and issued a GATT read on the DeviceName characteristic.
    /// Now serves a JSON payload containing the Mac's name AND current Wi-Fi IP,
    /// so Android can extract the IP and use it for TCP without mDNS discovery.
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard request.characteristic.uuid == deviceNameCharUUID else {
            peripheral.respond(to: request, withResult: .attributeNotFound)
            return
        }

        // A long read arrives as several requests with increasing offsets; serve every part from
        // the same envelope so its MAC stays valid.
        if request.offset == 0 || cachedDeviceInfo == nil {
            cachedDeviceInfo = buildDeviceInfoEnvelope()
        }
        let value = cachedDeviceInfo ?? Data()
        guard request.offset <= value.count else {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }

        request.value = value.subdata(in: request.offset..<value.count)
        peripheral.respond(to: request, withResult: .success)
    }

    /// Called when Android writes to the Wakeup characteristic. Every write must be an
    /// authenticated v2 envelope (or the exact pre-pairing presence bytes); nothing below
    /// changes state, posts UI events or touches the clipboard until `inbound` accepts it.
    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        // A long (prepared) write arrives as several requests; reassemble by offset.
        let parts = requests
            .filter { $0.characteristic.uuid == wakeupCharUUID }
            .sorted { $0.offset < $1.offset }
        var data = Data()
        var contiguous = true
        for part in parts {
            guard part.offset == data.count, let value = part.value else { contiguous = false; break }
            data.append(value)
        }
        if let first = requests.first, first.characteristic.properties.contains(.write) {
            peripheral.respond(to: first, withResult: .success)
        }
        guard contiguous, !parts.isEmpty else { return }

        switch inbound.process(data, rootKey: pairingRootKey(), nowMs: Self.nowMs()) {
        case .presence:
            // Pre-pairing "phone is here" signal: only advances the onboarding UI to the QR
            // screen, and only while this Mac is not paired.
            DispatchQueue.main.async {
                guard !PairingManager.shared.isPaired else { return }
                self.onDeviceConnected?()
            }
        case .rejected:
            // Generic rejection; never log the message bytes. An old phone sends plain JSON:
            // nothing from it is trusted, but the user is told once to update it.
            if data.first == UInt8(ascii: "{") { Self.notifyLegacyPeerOnce() }
            return
        case .message(let message):
            apply(message)
        }
    }

    /// Applies an authenticated, replay-checked (and, for responses, correlated) message.
    private func apply(_ message: BleMessage) {
        let ping = WakeupPayload(
            ip: message.string(.ip) ?? "",
            port: message.uint(.port).map(Int.init) ?? 8765,
            payloadSize: message.int64(.size) ?? 0,
            payloadType: message.type.payloadTypeName,
            directPayload: message.string(.directPayload),
            battery: message.uint(.battery).map(Int.init),
            network: message.string(.network),
            deviceName: message.string(.deviceName),
            isDiagnostic: message.type == .diagnostic
        )

        if ping.isDiagnostic {
            push(.diagnosticAck)
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: NSNotification.Name("DiagnosticPingReceived"), object: nil)
            }
            return
        }

        if let devName = ping.deviceName,
           shouldUpdatePairedDeviceName(current: PairingManager.shared.pairedDeviceName, incoming: devName) {
            DispatchQueue.main.async {
                PairingManager.shared.pairedDeviceName = devName
                UserDefaults.standard.set(devName, forKey: "paired_device_name")
            }
        }

        // Cache Android's IP for Mac-initiated transfers (2-min freshness window)
        if !ping.ip.isEmpty {
            self.lastAndroidIp = ping.ip
            self.lastAndroidIpDate = Date()
        }

        DispatchQueue.main.async {
            self.lastPing = ping

            if let directData = ping.directPayload {
                ClipSyncServer.shared.handleDirectBLEPayload(
                    base64Encrypted: directData,
                    type: ping.payloadType
                )
            } else {
                if !ClipSyncServer.shared.isListening {
                    ClipSyncServer.shared.start()
                }
            }
        }
    }

    private func shouldUpdatePairedDeviceName(current: String, incoming: String) -> Bool {
        let trimmedIncoming = incoming.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedIncoming.isEmpty else { return false }
        if current.isEmpty || current == "Android Device" { return true }
        if current == trimmedIncoming { return false }

        let modelLike = current.range(
            of: #"^[A-Za-z]?\d{3,}[A-Za-z0-9-]*$"#,
            options: .regularExpression
        ) != nil
        let incomingLooksFriendly = trimmedIncoming.contains(" ") || trimmedIncoming.contains("'")
        return modelLike && incomingLooksFriendly
    }

    // MARK: - Subscription tracking

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == sendRequestCharUUID else { return }
        if !subscribedCentrals.contains(where: { $0.identifier == central.identifier }) {
            subscribedCentrals.append(central)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == sendRequestCharUUID else { return }
        subscribedCentrals.removeAll { $0.identifier == central.identifier }
    }

    // MARK: - Mac → Android push

    /// Returns true if at least one Android central is subscribed to the SendRequest characteristic.
    var hasAndroidSubscriber: Bool { !subscribedCentrals.isEmpty }

    /// Sends an authenticated control message to the subscribed Android central(s).
    /// Requests that expect a response (ping, file_incoming, text_incoming) are registered so
    /// only a matching, authenticated reply is accepted. Returns false if not paired, if the
    /// envelope exceeds `maxLength`, or if nothing is subscribed.
    @discardableResult
    func push(_ type: BleMessageType, _ fields: [BleField: Data] = [:], maxLength: Int? = nil) -> Bool {
        guard type.direction == .macToAndroid, let rootKey = pairingRootKey() else { return false }
        let messageId = BleControlProtocol.newMessageId()
        let nowMs = Self.nowMs()
        guard let envelope = try? BleControlProtocol.encode(
                type: type, fields: fields, messageId: messageId, timestampMs: nowMs,
                authKey: BleControlProtocol.authKey(rootKey: rootKey)),
              maxLength.map({ envelope.count <= $0 }) ?? true else { return false }
        if type == .ping || type == .fileIncoming || type == .textIncoming {
            inbound.requests.register(messageId, type: type, nowMs: nowMs)
        }
        return pushToAndroid(envelope)
    }

    /// Pushes raw bytes to all subscribed Android centrals via BLE Notify.
    private func pushToAndroid(_ payload: Data) -> Bool {
        guard let peripheral = peripheralManager,
              let char = sendRequestCharacteristic,
              !subscribedCentrals.isEmpty else {
            return false
        }
        let success = peripheral.updateValue(payload, for: char, onSubscribedCentrals: nil)
        return success
    }
}

// MARK: - Payload model

struct WakeupPayload {
    let ip: String
    let port: Int
    let payloadSize: Int64
    let payloadType: String
    let directPayload: String?
    let battery: Int?
    let network: String?
    let deviceName: String?
    let isDiagnostic: Bool
}
