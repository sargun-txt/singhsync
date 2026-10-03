// Tests for ClipSync/BleControlProtocol.swift. Called from main.swift.
// Loads the shared fixtures in protocol/ble-v2-test-vectors.properties.

import Foundation
import CryptoKit

private func hex(_ s: String) -> Data {
    var data = Data(), chars = Array(s), i = 0
    while i + 1 < chars.count { data.append(UInt8(String(chars[i...i + 1]), radix: 16)!); i += 2 }
    return data
}
private func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

private func loadBleVectors() -> [String: String] {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("protocol/ble-v2-test-vectors.properties")
    guard let text = try? String(contentsOf: url, encoding: .utf8) else {
        check(false, "could not read \(url.path)"); return [:]
    }
    var out: [String: String] = [:]
    for line in text.split(separator: "\n") where !line.hasPrefix("#") {
        let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
        if parts.count == 2 { out[parts[0]] = parts[1] }
    }
    return out
}

func runBleProtocolTests() {
    let v = loadBleVectors()
    guard !v.isEmpty else { return }
    let root = SymmetricKey(data: hex(v["rootKey"]!))
    let auth = BleControlProtocol.authKey(rootKey: root)
    let now = Int64(v["timestampMs"]!)!
    let msgId = hex(v["messageId"]!)
    let requestId = hex(v["requestId"]!)

    // MARK: Key derivation and shared fixtures
    check(auth.withUnsafeBytes { hexString(Data($0)) } == v["bleAuthKey"], "BLE auth key matches fixture")
    let tcpAuth = TcpFrameProtocol.authKey(rootKey: root)
    check(auth.withUnsafeBytes { Data($0) } != tcpAuth.withUnsafeBytes { Data($0) }, "BLE and TCP auth keys are separate")

    let pingAckFields: [BleField: Data] = [
        .ip: BleControlProtocol.utf8("192.168.1.42"), .port: BleControlProtocol.u16(8766),
        .deviceName: BleControlProtocol.utf8("Pixel 8 é"), .replyTo: requestId
    ]
    let pingAck = try! BleControlProtocol.encode(type: .pingAck, fields: pingAckFields, messageId: msgId,
                                                 timestampMs: now, authKey: auth)
    check(hexString(pingAck) == v["pingAckEnvelope"], "ping_ack envelope matches fixture")
    let setting = try! BleControlProtocol.encode(type: .setting, fields: [.ultraFast: BleControlProtocol.u8(1)],
                                                 messageId: msgId, timestampMs: now, authKey: auth)
    check(hexString(setting) == v["settingEnvelope"], "setting envelope matches fixture")
    let verified = try? BleControlProtocol.verify(pingAck, authKey: auth, expectedDirection: .androidToMac, nowMs: now)
    check(verified?.string(.ip) == "192.168.1.42" && verified?.uint(.port) == 8766
          && verified?.string(.deviceName) == "Pixel 8 é", "fixture verifies and decodes")

    // MARK: Authentication
    func verifyError(_ d: Data, key: SymmetricKey = auth, dir: BleDirection = .androidToMac, at t: Int64? = nil) -> BleControlError? {
        do { _ = try BleControlProtocol.verify(d, authKey: key, expectedDirection: dir, nowMs: t ?? now); return nil }
        catch let e as BleControlError { return e } catch { return .malformedEnvelope }
    }
    func flip(_ d: Data, _ i: Int, _ value: UInt8? = nil) -> Data { var c = d; c[i] = value ?? (c[i] ^ 1); return c }

    check(verifyError(pingAck) == nil, "valid message accepted")
    check(verifyError(pingAck, key: SymmetricKey(size: .bits256)) == .badMac, "wrong key rejected")
    check(verifyError(pingAck, key: BleControlProtocol.authKey(rootKey: SymmetricKey(size: .bits256))) == .badMac, "other pairing rejected")
    check(verifyError(flip(pingAck, 5, 0x11)) == .badMac, "changed type rejected")
    check(verifyError(flip(pingAck, 40)) == .badMac, "changed payload rejected")
    check(verifyError(flip(pingAck, 12)) == .badMac, "changed timestamp rejected")
    check(verifyError(flip(pingAck, 20)) == .badMac, "changed message ID rejected")
    check(verifyError(flip(pingAck, 6, 0x02)) == .wrongDirection, "changed direction rejected")
    check(verifyError(flip(pingAck, 5, 0x23)) == .wrongDirection, "Mac→Android type on Android→Mac path rejected")
    check(verifyError(flip(pingAck, 4, 0x01)) == .unsupportedVersion, "changed version rejected")
    check(verifyError(flip(pingAck, 5, 0x7F)) == .unknownType, "unknown type rejected")
    check(verifyError(flip(pingAck, 7, 0x01)) == .badReserved, "reserved byte must be zero")
    check(verifyError(flip(pingAck, 0, 0x00)) == .badMagic, "bad magic rejected")
    check(verifyError(pingAck.dropLast()) == .invalidLength, "truncated MAC rejected")
    check(verifyError(pingAck + Data([0])) == .invalidLength, "extended MAC rejected")
    check(verifyError(flip(pingAck, pingAck.count - 1)) == .badMac, "modified MAC rejected")
    check(verifyError(pingAck.prefix(40)) == .malformedEnvelope, "short envelope rejected")
    check(verifyError(pingAck, dir: .macToAndroid) == .wrongDirection, "reflected to the sender rejected")
    check(verifyError(pingAck, at: now + BleControlProtocol.timestampWindowMs + 1) == .staleTimestamp, "stale timestamp rejected")
    check(verifyError(pingAck, at: now - BleControlProtocol.timestampWindowMs - 1) == .staleTimestamp, "future timestamp rejected")
    check(verifyError(Data(#"{"type":"ping_ack","ip":"10.0.0.66"}"#.utf8)) == .malformedEnvelope || verifyError(Data(#"{"type":"ping_ack","ip":"10.0.0.66"}"#.utf8)) == .badMagic,
          "legacy unauthenticated JSON rejected")

    // MARK: Payload validation (authenticated but malformed → still rejected)
    func signed(_ type: BleMessageType, _ fields: [BleField: Data]) -> Data {
        try! BleControlProtocol.encode(type: type, fields: fields, messageId: BleControlProtocol.newMessageId(), timestampMs: now, authKey: auth)
    }
    func payloadError(_ type: BleMessageType, _ fields: [BleField: Data], dir: BleDirection) -> BleControlError? {
        verifyError(signed(type, fields), dir: dir)
    }
    check(payloadError(.setting, [.ultraFast: BleControlProtocol.u8(2)], dir: .macToAndroid) == .invalidValue, "malformed setting value rejected")
    check(payloadError(.setting, [.ultraFast: Data([1, 0])], dir: .macToAndroid) == .invalidValue, "wrong-width setting rejected")
    check(payloadError(.setting, [.ultraFast: BleControlProtocol.u8(1), .name: BleControlProtocol.utf8("x")], dir: .macToAndroid) == .unexpectedField,
          "unknown setting field rejected")
    check(payloadError(.setting, [:], dir: .macToAndroid) == .missingField, "setting without value rejected")
    check(payloadError(.pingAck, [.ip: BleControlProtocol.utf8("10.0.0.5")], dir: .androidToMac) == .missingField, "ping_ack without replyTo rejected")
    check(payloadError(.handshake, [.replyTo: requestId], dir: .androidToMac) == .unexpectedField, "replyTo on unsolicited message rejected")
    check(payloadError(.handshake, [.ip: BleControlProtocol.utf8("10.0.0.256")], dir: .androidToMac) == .invalidValue, "invalid IP rejected")
    check(payloadError(.handshake, [.ip: BleControlProtocol.utf8("evil.example.com")], dir: .androidToMac) == .invalidValue, "hostname rejected")
    check(payloadError(.handshake, [.port: BleControlProtocol.u16(0)], dir: .androidToMac) == .invalidValue, "port 0 rejected")
    check(payloadError(.handshake, [.battery: BleControlProtocol.u8(101)], dir: .androidToMac) == .invalidValue, "battery > 100 rejected")
    check(payloadError(.handshake, [.deviceName: BleControlProtocol.utf8("bad\nname")], dir: .androidToMac) == .invalidValue, "control chars in name rejected")
    check(payloadError(.fileIncoming, [.fileName: BleControlProtocol.utf8("a.txt"), .port: BleControlProtocol.u16(8766)], dir: .macToAndroid) == .missingField,
          "file_incoming without size rejected")
    check(payloadError(.fileIncoming, [.fileName: BleControlProtocol.utf8("a.txt"), .size: BleControlProtocol.i64(-1), .port: BleControlProtocol.u16(8766)], dir: .macToAndroid) == .invalidValue,
          "negative size rejected")
    check(payloadError(.pushText, [.content: BleControlProtocol.utf8("not base64!!")], dir: .macToAndroid) == .invalidValue, "non-base64 content rejected")

    // Non-canonical TLV (duplicate / descending tags) with a valid MAC is still rejected.
    var dupPayload = Data([0x0B, 0x00, 0x01, 0x01, 0x0B, 0x00, 0x01, 0x00])
    var dup = Data(BleControlProtocol.magic) + Data([0x02, 0x23, 0x02, 0x00]) + BleControlProtocol.i64(now)
        + BleControlProtocol.newMessageId() + BleControlProtocol.u16(dupPayload.count) + dupPayload
    dup.append(Data(HMAC<SHA256>.authenticationCode(for: dup, using: auth)))
    check(verifyError(dup, dir: .macToAndroid) == .malformedPayload, "duplicate field rejected")
    dupPayload.removeAll()

    // MARK: Replay + request correlation through the Mac gate
    let gate = MacBleInbound()
    let pingId = BleControlProtocol.newMessageId()
    func ack(_ replyTo: Data, ip: String = "10.0.0.7") -> Data {
        signed(.pingAck, [.ip: BleControlProtocol.utf8(ip), .replyTo: replyTo])
    }
    let forged = Data(#"{"t":"ping_ack","ip":"10.6.6.6"}"#.utf8)
    if case .rejected = gate.process(forged, rootKey: root, nowMs: now) {} else { check(false, "forged legacy ping_ack must be rejected") }
    var forgedEnvelope = ack(pingId, ip: "10.6.6.6"); forgedEnvelope[forgedEnvelope.count - 1] ^= 1
    gate.requests.register(pingId, type: .ping, nowMs: now)
    check(gate.process(forgedEnvelope, rootKey: root, nowMs: now) == .rejected(.badMac), "forged ping_ack (bad MAC) cannot change IP")
    check(gate.process(ack(pingId), rootKey: SymmetricKey(size: .bits256), nowMs: now) == .rejected(.badMac), "ping_ack under another key rejected")
    check(gate.process(ack(BleControlProtocol.newMessageId()), rootKey: root, nowMs: now) == .rejected(.uncorrelatedResponse),
          "ping_ack for an unknown request rejected")
    let goodAck = ack(pingId)
    if case .message(let m) = gate.process(goodAck, rootKey: root, nowMs: now) {
        check(m.type == .pingAck && m.string(.ip) == "10.0.0.7", "valid ping_ack accepted with its IP")
    } else { check(false, "valid ping_ack should be accepted") }
    check(gate.process(goodAck, rootKey: root, nowMs: now) == .rejected(.replayed), "replayed ping_ack rejected")
    check(gate.process(ack(pingId), rootKey: root, nowMs: now) == .rejected(.uncorrelatedResponse), "second response to the same ping rejected")

    let fileReq = BleControlProtocol.newMessageId()
    gate.requests.register(fileReq, type: .fileIncoming, nowMs: now)
    check(gate.process(ack(fileReq), rootKey: root, nowMs: now) == .rejected(.uncorrelatedResponse), "ping_ack answering file_incoming rejected")
    let fileReq2 = BleControlProtocol.newMessageId()
    gate.requests.register(fileReq2, type: .fileIncoming, nowMs: now)
    let tcpReady = signed(.tcpReady, [.ip: BleControlProtocol.utf8("10.0.0.7"), .port: BleControlProtocol.u16(8766), .replyTo: fileReq2])
    if case .message = gate.process(tcpReady, rootKey: root, nowMs: now) {} else { check(false, "tcp_ready for file_incoming accepted") }
    let expiringReq = BleControlProtocol.newMessageId()
    gate.requests.register(expiringReq, type: .ping, nowMs: now)
    check(gate.process(ack(expiringReq), rootKey: root, nowMs: now + 30_001) == .rejected(.uncorrelatedResponse), "expired request rejected")

    // pairing_ack (completes local pairing on the Mac) requires authentication
    check(gate.process(Data(#"{"t":"pairing_ack"}"#.utf8), rootKey: root, nowMs: now) != .presence, "legacy pairing_ack is not presence")
    if case .rejected = gate.process(Data(#"{"t":"pairing_ack"}"#.utf8), rootKey: root, nowMs: now) {} else { check(false, "forged pairing_ack rejected") }
    if case .message(let m) = gate.process(signed(.pairingAck, [.deviceName: BleControlProtocol.utf8("Pixel")]), rootKey: root, nowMs: now) {
        check(m.type.payloadTypeName == "pairing_ack", "authenticated pairing_ack accepted")
    } else { check(false, "authenticated pairing_ack accepted") }
    check(gate.process(signed(.handshake, [:]), rootKey: nil, nowMs: now) == .rejected(.notPaired), "no key → everything rejected")

    // pair presence: exact bytes only
    check(gate.process(BleControlProtocol.legacyPairPresence, rootKey: nil, nowMs: now) == .presence, "pre-pairing presence recognised")
    check(gate.process(Data(#"{"type": "pair"}"#.utf8), rootKey: nil, nowMs: now) != .presence, "presence requires exact bytes")
    check(gate.process(Data(#"{"type":"pair","ip":"1.2.3.4"}"#.utf8), rootKey: nil, nowMs: now) != .presence, "presence with extra fields rejected")

    // Replay cache bounds (BLE uses its own instance)
    let small = MacBleInbound(replayCache: TcpReplayCache(capacity: 4, ttlMs: 1000))
    for _ in 0..<10 { _ = small.process(signed(.handshake, [:]), rootKey: root, nowMs: now) }
    check(small.replayCache.count <= 4, "BLE replay cache bounded")
    let tracker = BleRequestTracker(capacity: 3)
    for _ in 0..<10 { tracker.register(BleControlProtocol.newMessageId(), type: .ping, nowMs: now) }
    check(tracker.count <= 3, "request tracker bounded")

    // Pre-pairing display name (unauthenticated, display only)
    let info = try! BleControlProtocol.encode(type: .deviceInfo, fields: [.name: BleControlProtocol.utf8("Bunty's Mac"), .port: BleControlProtocol.u16(8765)],
                                              messageId: BleControlProtocol.newMessageId(), timestampMs: now, authKey: nil)
    check(BleControlProtocol.unverifiedDisplayName(info) == "Bunty's Mac", "display name readable before pairing")
    check(verifyError(info, dir: .macToAndroid) == .badMac, "keyless device-info never verifies")
}
