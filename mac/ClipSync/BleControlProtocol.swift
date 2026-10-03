// BleControlProtocol.swift
// Authenticated BLE control messages (v2), shared byte-for-byte with BleControlProtocol.kt and
// protocol/generate_ble_v2_vectors.py.
//
// Envelope (all integers big-endian):
//   off len field
//     0   4  magic "CLB2"
//     4   1  version = 0x02
//     5   1  message type (see BleMessageType; the high nibble encodes direction)
//     6   1  direction: 0x01 Android→Mac, 0x02 Mac→Android
//     7   1  reserved = 0x00
//     8   8  timestampMs   sender clock, Unix epoch ms
//    16  16  messageId     random, unique per message
//    32   2  payloadLen
//    34   N  payload       TLV fields: [tag(1)][len(2)][value], tags strictly ascending
//  34+N  32  HMAC-SHA256(bleAuthKey, bytes[0 ..< 34+N])
//
//   bleAuthKey = HKDF-SHA256(IKM: pairing key, salt: empty, info: "ClipSync/BLE/Auth/v1", L: 32)
//
// The MAC is verified before any payload field is decoded or trusted. Responses (ping_ack,
// tcp_ready) carry the request's messageId in `replyTo` and are only accepted while that
// request is outstanding.
//
// The only unauthenticated input still honoured is the exact pre-pairing presence bytes
// {"type":"pair"}, sent before the phone has the key. It only advances the Mac's onboarding UI
// to the QR screen and never changes pairing state.
//
// Deliberately limited to Foundation and CryptoKit so it can be tested on its own.

import Foundation
import CryptoKit

nonisolated enum BleDirection: UInt8 {
    case androidToMac = 0x01
    case macToAndroid = 0x02
}

nonisolated enum BleMessageType: UInt8, CaseIterable {
    // Android → Mac (written to the wakeup characteristic)
    case pairingAck    = 0x10
    case handshake     = 0x11
    case pingAck       = 0x12
    case tcpReady      = 0x13
    case wakeText      = 0x14
    case wakeImage     = 0x15
    case wakeFile      = 0x16
    case ipProbe       = 0x17
    case diagnostic    = 0x18
    // Mac → Android (notifications, plus the device-info read)
    case pushText      = 0x20
    case fileIncoming  = 0x21
    case textIncoming  = 0x22
    case setting       = 0x23
    case ping          = 0x24
    case diagnosticAck = 0x25
    case deviceInfo    = 0x26

    var direction: BleDirection { rawValue < 0x20 ? .androidToMac : .macToAndroid }

    /// The legacy payload-type string the rest of the app uses for Android → Mac messages.
    var payloadTypeName: String {
        switch self {
        case .pairingAck: return "pairing_ack"
        case .handshake: return "handshake"
        case .pingAck: return "ping_ack"
        case .tcpReady: return "tcp_ready"
        case .wakeText: return "text"
        case .wakeImage: return "image"
        case .wakeFile: return "file"
        case .ipProbe: return "ip_probe"
        case .diagnostic: return "diagnostic"
        case .pushText: return "text"
        case .fileIncoming: return "file_incoming"
        case .textIncoming: return "text_incoming"
        case .setting: return "setting"
        case .ping: return "ping"
        case .diagnosticAck: return "diagnostic_ack"
        case .deviceInfo: return "device_info"
        }
    }
}

nonisolated enum BleField: UInt8, CaseIterable {
    case ip            = 0x01  // UTF-8 dotted IPv4 (or empty)
    case port          = 0x02  // uint16, 1...65535
    case size          = 0x03  // int64, >= 0
    case directPayload = 0x04  // UTF-8 base64 of an AES-GCM blob
    case battery       = 0x05  // uint8, 0...100
    case network       = 0x06  // UTF-8, <= 128 bytes
    case deviceName    = 0x07  // UTF-8, <= 128 bytes
    case replyTo       = 0x08  // 16-byte messageId of the request being answered
    case fileName      = 0x09  // UTF-8, <= 1024 bytes
    case content       = 0x0A  // UTF-8 base64 of an AES-GCM blob
    case ultraFast     = 0x0B  // uint8, 0 or 1
    case name          = 0x0C  // UTF-8, <= 128 bytes
}

nonisolated enum BleControlError: Error, Equatable {
    case badMagic, unsupportedVersion, malformedEnvelope, unknownType, wrongDirection, badReserved
    case invalidLength, invalidMessageId, badMac, staleTimestamp, replayed
    case malformedPayload, unexpectedField, missingField, invalidValue
    case uncorrelatedResponse, unexpectedType, notPaired
}

/// A verified message. Field values are already range-checked.
nonisolated struct BleMessage: Equatable {
    let type: BleMessageType
    let messageId: Data
    let timestampMs: Int64
    let fields: [BleField: Data]

    func string(_ f: BleField) -> String? { fields[f].flatMap { String(data: $0, encoding: .utf8) } }
    func uint(_ f: BleField) -> UInt64? {
        fields[f].map { $0.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } }
    }
    func int64(_ f: BleField) -> Int64? { uint(f).map { Int64(bitPattern: $0) } }
}

nonisolated enum BleControlProtocol {

    static let magic: [UInt8] = [0x43, 0x4C, 0x42, 0x32] // "CLB2"
    static let version: UInt8 = 0x02
    static let headerLength = 34
    static let macLength = 32
    static let messageIdLength = 16
    static let maxPayloadLength = 8192
    static let timestampWindowMs: Int64 = 15 * 60 * 1000
    /// Exact bytes of the pre-pairing presence signal (no key exists yet on the phone).
    static let legacyPairPresence = Data(#"{"type":"pair"}"#.utf8)

    private static let authInfo = Data("ClipSync/BLE/Auth/v1".utf8)

    static func authKey(rootKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: rootKey, salt: Data(), info: authInfo, outputByteCount: 32)
    }

    static func newMessageId() -> Data {
        var bytes = [UInt8](repeating: 0, count: messageIdLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes)
    }

    // MARK: - Schema

    /// (required, allowed) fields per message type.
    static func schema(_ type: BleMessageType) -> (required: Set<BleField>, allowed: Set<BleField>) {
        let status: Set<BleField> = [.ip, .port, .size, .directPayload, .battery, .network, .deviceName]
        switch type {
        case .pairingAck, .handshake, .wakeText, .wakeImage, .wakeFile, .ipProbe, .diagnostic:
            return ([], status)
        case .pingAck, .tcpReady:
            return ([.replyTo], status.union([.replyTo]))
        case .pushText:
            return ([.content], [.content])
        case .fileIncoming:
            return ([.fileName, .size, .port], [.fileName, .size, .port])
        case .textIncoming:
            return ([.size, .port], [.size, .port])
        case .setting:
            return ([.ultraFast], [.ultraFast])
        case .ping, .diagnosticAck:
            return ([], [])
        case .deviceInfo:
            return ([.name, .port], [.name, .port, .ip])
        }
    }

    // MARK: - Fields

    static func encodeFields(_ fields: [BleField: Data]) -> Data {
        var out = Data()
        for field in fields.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            let value = fields[field]!
            out.append(field.rawValue)
            out.append(UInt8(value.count >> 8)); out.append(UInt8(value.count & 0xFF))
            out.append(value)
        }
        return out
    }

    static func decodeFields(_ payload: Data, type: BleMessageType) throws -> [BleField: Data] {
        let b = [UInt8](payload)
        var fields: [BleField: Data] = [:]
        var pos = 0
        var lastTag = 0
        while pos < b.count {
            guard pos + 3 <= b.count else { throw BleControlError.malformedPayload }
            let tag = Int(b[pos])
            let len = Int(b[pos + 1]) << 8 | Int(b[pos + 2])
            pos += 3
            guard pos + len <= b.count else { throw BleControlError.malformedPayload }
            // Strictly ascending tags: canonical order, and no duplicates.
            guard tag > lastTag else { throw BleControlError.malformedPayload }
            guard let field = BleField(rawValue: UInt8(tag)) else { throw BleControlError.unexpectedField }
            fields[field] = Data(b[pos..<pos + len])
            lastTag = tag
            pos += len
        }
        let (required, allowed) = schema(type)
        guard Set(fields.keys).isSubset(of: allowed) else { throw BleControlError.unexpectedField }
        guard required.isSubset(of: Set(fields.keys)) else { throw BleControlError.missingField }
        for (field, value) in fields { try validate(field, value) }
        return fields
    }

    private static func validate(_ field: BleField, _ v: Data) throws {
        func utf8(max: Int) throws -> String {
            guard v.count <= max, let s = String(data: v, encoding: .utf8) else { throw BleControlError.invalidValue }
            return s
        }
        func noControls(_ s: String) throws {
            guard !s.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else {
                throw BleControlError.invalidValue
            }
        }
        switch field {
        case .ip:
            guard isValidIPv4OrEmpty(try utf8(max: 15)) else { throw BleControlError.invalidValue }
        case .port:
            guard v.count == 2, (Int(v[v.startIndex]) << 8 | Int(v[v.startIndex + 1])) >= 1 else { throw BleControlError.invalidValue }
        case .size:
            guard v.count == 8, v[v.startIndex] & 0x80 == 0 else { throw BleControlError.invalidValue }
        case .directPayload, .content:
            let s = try utf8(max: maxPayloadLength)
            guard !s.isEmpty, Data(base64Encoded: s) != nil else { throw BleControlError.invalidValue }
        case .battery:
            guard v.count == 1, v[v.startIndex] <= 100 else { throw BleControlError.invalidValue }
        case .network, .deviceName, .name:
            try noControls(try utf8(max: 128))
        case .fileName:
            try noControls(try utf8(max: 1024))
        case .replyTo:
            guard v.count == messageIdLength else { throw BleControlError.invalidValue }
        case .ultraFast:
            guard v.count == 1, v[v.startIndex] <= 1 else { throw BleControlError.invalidValue }
        }
    }

    /// Dotted-quad IPv4, implemented identically on both platforms (no platform parsers).
    static func isValidIPv4OrEmpty(_ s: String) -> Bool {
        if s.isEmpty { return true }
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            p.count >= 1 && p.count <= 3 && p.allSatisfy({ $0 >= "0" && $0 <= "9" }) && Int(p)! <= 255
        }
    }

    // MARK: - Envelope

    static func encode(type: BleMessageType, fields: [BleField: Data], messageId: Data, timestampMs: Int64,
                       authKey: SymmetricKey?) throws -> Data {
        guard messageId.count == messageIdLength else { throw BleControlError.invalidMessageId }
        let payload = encodeFields(fields)
        guard payload.count <= maxPayloadLength else { throw BleControlError.invalidLength }
        var out = Data(magic)
        out.append(contentsOf: [version, type.rawValue, type.direction.rawValue, 0x00])
        var ts = UInt64(bitPattern: timestampMs).bigEndian
        withUnsafeBytes(of: &ts) { out.append(contentsOf: $0) }
        out.append(messageId)
        out.append(UInt8(payload.count >> 8)); out.append(UInt8(payload.count & 0xFF))
        out.append(payload)
        if let authKey {
            out.append(Data(HMAC<SHA256>.authenticationCode(for: out, using: authKey)))
        } else {
            // No pairing key yet (pre-pairing discovery): an all-zero MAC that never verifies.
            out.append(Data(count: macLength))
        }
        return out
    }

    /// Verifies the envelope and MAC (constant time), then decodes and validates the payload.
    static func verify(_ data: Data, authKey: SymmetricKey, expectedDirection: BleDirection, nowMs: Int64) throws -> BleMessage {
        let b = [UInt8](data)
        let (type, payloadLen) = try parseHeader(b, expectedDirection: expectedDirection)
        let signedLength = headerLength + payloadLen
        guard HMAC<SHA256>.isValidAuthenticationCode(Data(b[signedLength...]), authenticating: Data(b[0..<signedLength]),
                                                     using: authKey) else {
            throw BleControlError.badMac
        }
        let ts = Int64(bitPattern: b[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        let skew = nowMs - ts
        guard skew <= timestampWindowMs, skew >= -timestampWindowMs else { throw BleControlError.staleTimestamp }
        let fields = try decodeFields(Data(b[headerLength..<signedLength]), type: type)
        return BleMessage(type: type, messageId: Data(b[16..<32]), timestampMs: ts, fields: fields)
    }

    /// Structural checks only (bounds, sizes, type/direction). Nothing here is trusted.
    private static func parseHeader(_ b: [UInt8], expectedDirection: BleDirection) throws -> (BleMessageType, Int) {
        guard b.count >= headerLength + macLength else { throw BleControlError.malformedEnvelope }
        guard Array(b[0..<4]) == magic else { throw BleControlError.badMagic }
        guard b[4] == version else { throw BleControlError.unsupportedVersion }
        guard let type = BleMessageType(rawValue: b[5]) else { throw BleControlError.unknownType }
        guard b[6] == expectedDirection.rawValue, type.direction == expectedDirection else {
            throw BleControlError.wrongDirection
        }
        guard b[7] == 0 else { throw BleControlError.badReserved }
        guard b[16..<32].contains(where: { $0 != 0 }) else { throw BleControlError.invalidMessageId }
        let payloadLen = Int(b[32]) << 8 | Int(b[33])
        guard payloadLen <= maxPayloadLength, b.count == headerLength + payloadLen + macLength else {
            throw BleControlError.invalidLength
        }
        return (type, payloadLen)
    }

    /// Pre-pairing only: the Mac's advertised name from a device-info envelope, without any
    /// authentication. For display in the device picker; never used for state or trust.
    static func unverifiedDisplayName(_ data: Data) -> String? {
        let b = [UInt8](data)
        guard let (type, len) = try? parseHeader(b, expectedDirection: .macToAndroid), type == .deviceInfo,
              let fields = try? decodeFields(Data(b[headerLength..<headerLength + len]), type: type) else { return nil }
        return fields[.name].flatMap { String(data: $0, encoding: .utf8) }
    }

    /// Total envelope size for `fields` (header + TLV payload + MAC).
    static func envelopeLength(_ fields: [BleField: Data]) -> Int {
        headerLength + encodeFields(fields).count + macLength
    }

    // MARK: - Field helpers

    static func u16(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]) }
    static func i64(_ v: Int64) -> Data {
        var be = UInt64(bitPattern: v).bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }
    static func u8(_ v: Int) -> Data { Data([UInt8(v & 0xFF)]) }
    static func utf8(_ s: String) -> Data { Data(s.utf8) }
}

/// Outstanding Mac → Android requests (ping, file_incoming, text_incoming), so that a
/// response is accepted only once and only while its request is pending. Bounded and short-lived.
nonisolated final class BleRequestTracker: @unchecked Sendable {
    private let capacity: Int
    private let ttlMs: Int64
    private var pending: [Data: (type: BleMessageType, expiry: Int64)] = [:]
    private var order: [Data] = []
    private let lock = NSLock()

    init(capacity: Int = 64, ttlMs: Int64 = 30_000) {
        self.capacity = capacity
        self.ttlMs = ttlMs
    }

    func register(_ id: Data, type: BleMessageType, nowMs: Int64) {
        lock.lock(); defer { lock.unlock() }
        while order.count >= capacity { pending.removeValue(forKey: order.removeFirst()) }
        pending[id] = (type, nowMs + ttlMs)
        order.append(id)
    }

    /// Removes and returns true if `id` is pending, unexpired, and one of `types`.
    func consume(_ id: Data, types: Set<BleMessageType>, nowMs: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let entry = pending[id] else { return false }
        pending.removeValue(forKey: id)
        order.removeAll { $0 == id }
        return entry.expiry > nowMs && types.contains(entry.type)
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return pending.count }
}

/// Mac-side gate for every write to the wakeup characteristic. Returns a message only after
/// MAC, timestamp, replay and (for responses) request correlation all pass.
nonisolated final class MacBleInbound: @unchecked Sendable {
    enum Result: Equatable {
        case presence
        case rejected(BleControlError)
        case message(BleMessage)
    }

    let replayCache: TcpReplayCache
    let requests: BleRequestTracker

    init(replayCache: TcpReplayCache = TcpReplayCache(), requests: BleRequestTracker = BleRequestTracker()) {
        self.replayCache = replayCache
        self.requests = requests
    }

    func process(_ data: Data, rootKey: SymmetricKey?, nowMs: Int64) -> Result {
        if data == BleControlProtocol.legacyPairPresence { return .presence }
        guard let rootKey else { return .rejected(.notPaired) }
        do {
            let msg = try BleControlProtocol.verify(data, authKey: BleControlProtocol.authKey(rootKey: rootKey),
                                                     expectedDirection: .androidToMac, nowMs: nowMs)
            guard replayCache.insertIfNew(msg.messageId, nowMs: nowMs) else { return .rejected(.replayed) }
            switch msg.type {
            case .pingAck:
                guard requests.consume(msg.fields[.replyTo]!, types: [.ping], nowMs: nowMs) else {
                    return .rejected(.uncorrelatedResponse)
                }
            case .tcpReady:
                guard requests.consume(msg.fields[.replyTo]!, types: [.fileIncoming, .textIncoming], nowMs: nowMs) else {
                    return .rejected(.uncorrelatedResponse)
                }
            default:
                break
            }
            return .message(msg)
        } catch let e as BleControlError {
            return .rejected(e)
        } catch {
            return .rejected(.malformedEnvelope)
        }
    }
}
