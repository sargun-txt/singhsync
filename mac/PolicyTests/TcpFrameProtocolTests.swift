// Tests for ClipSync/TcpFrameProtocol.swift. Called from main.swift; see it for the
// swiftc command line. Loads the shared fixtures in protocol/tcp-v2-test-vectors.properties.

import Foundation
import CryptoKit

private func hex(_ s: String) -> Data {
    var data = Data(), chars = Array(s)
    var i = 0
    while i + 1 < chars.count {
        data.append(UInt8(String(chars[i...i + 1]), radix: 16)!)
        i += 2
    }
    return data
}

private func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

private let vectorsURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("protocol/tcp-v2-test-vectors.properties")

func loadVectors() -> [String: String] {
    guard let text = try? String(contentsOf: vectorsURL, encoding: .utf8) else {
        check(false, "could not read \(vectorsURL.path)")
        return [:]
    }
    var out: [String: String] = [:]
    for line in text.split(separator: "\n") where !line.hasPrefix("#") {
        let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
        if parts.count == 2 { out[parts[0]] = parts[1] }
    }
    return out
}

/// Mirrors ClipSyncServer's receive loop over an in-memory byte stream.
enum ReceiveOutcome: Equatable {
    case success(type: UInt8, name: Data, payload: Data)
    case rejected(TcpFrameError)
    case incomplete
}

func receiveStream(_ wire: Data, rootKey: SymmetricKey, direction: TcpDirection,
                   nowMs: Int64, cache: TcpReplayCache? = nil) -> ReceiveOutcome {
    let b = [UInt8](wire)
    var pos = 0
    func take(_ n: Int) -> Data? {
        guard n >= 0, pos + n <= b.count else { return nil }
        defer { pos += n }
        return Data(b[pos..<pos + n])
    }
    do {
        guard let fixed = take(TcpFrameProtocol.fixedPrefixLength) else { return .rejected(.malformedHeader) }
        let pending = try TcpFrameProtocol.parseFixedPrefix(fixed, expectedDirection: direction)
        guard let name = take(pending.nameLength), let mac = take(TcpFrameProtocol.macLength) else {
            return .rejected(.malformedHeader)
        }
        let header = try TcpFrameProtocol.verifyHeader(
            prefix: fixed + name, mac: mac, authKey: TcpFrameProtocol.authKey(rootKey: rootKey),
            expectedDirection: direction, nowMs: nowMs)
        if let cache, !cache.insertIfNew(header.sessionId, nowMs: nowMs) { return .rejected(.replayed) }

        var payload = Data()
        var index: UInt32 = 0
        while Int64(payload.count) < header.totalSize {
            guard let lenData = take(4) else { return .incomplete }
            let sealedLen = Int(lenData.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
            guard sealedLen == (try TcpFrameProtocol.expectedSealedLength(header, index: index)) else {
                return .rejected(.chunkLengthMismatch)
            }
            guard let sealed = take(sealedLen) else { return .incomplete }
            payload.append(try TcpFrameProtocol.openChunk(sealed, key: rootKey, header: header, index: index))
            index += 1
        }
        return .success(type: header.type, name: header.fileName, payload: payload)
    } catch let e as TcpFrameError {
        return .rejected(e)
    } catch {
        return .rejected(.malformedHeader)
    }
}

/// Mirrors the senders: header + exactly-sized chunks.
func sendStream(_ payload: Data, type: UInt8, direction: TcpDirection, chunkSize: Int, name: Data,
                rootKey: SymmetricKey, sessionId: Data = TcpFrameProtocol.newSessionId(),
                timestampMs: Int64, declaredTotal: Int64? = nil) throws -> (header: TcpFrameHeader, wire: Data, chunks: [Data]) {
    let header = TcpFrameHeader(type: type, direction: direction, totalSize: declaredTotal ?? Int64(payload.count),
                                chunkSize: chunkSize, timestampMs: timestampMs, sessionId: sessionId, fileName: name)
    var wire = try TcpFrameProtocol.encodeHeader(header, authKey: TcpFrameProtocol.authKey(rootKey: rootKey))
    var chunks: [Data] = []
    var offset = 0, index: UInt32 = 0
    while offset < payload.count {
        let end = min(offset + chunkSize, payload.count)
        // When the declared size is wrong the sealed length rules differ; seal raw for tamper tests.
        let plain = payload.subdata(in: offset..<end)
        let chunk: Data
        if let expected = TcpFrameProtocol.plainLength(header, index: index), expected == plain.count {
            chunk = try TcpFrameProtocol.sealChunk(plain, key: rootKey, header: header, index: index)
        } else {
            let sealed = try AES.GCM.seal(plain, using: rootKey, authenticating: TcpFrameProtocol.aad(header, index: index)).combined!
            var c = Data(); var len = UInt32(sealed.count).bigEndian
            withUnsafeBytes(of: &len) { c.append(contentsOf: $0) }
            c.append(sealed); chunk = c
        }
        chunks.append(chunk); wire.append(chunk)
        offset = end; index += 1
    }
    return (header, wire, chunks)
}

func runTcpProtocolTests() {
    let v = loadVectors()
    guard !v.isEmpty else { return }

    let root = SymmetricKey(data: hex(v["rootKey"]!))
    let now: Int64 = 1_700_000_000_000

    // MARK: Fixtures (shared with Kotlin and the Python reference)
    let auth = TcpFrameProtocol.authKey(rootKey: root)
    check(auth.withUnsafeBytes { hexString(Data($0)) } == v["authKey"], "HKDF auth key matches fixture")

    let fixtureHeader = TcpFrameHeader(type: 0x03, direction: .androidToMac, totalSize: 5_000_001,
                                       chunkSize: 1_048_576, timestampMs: now,
                                       sessionId: hex(v["sessionId"]!), fileName: hex(v["fileName"]!))
    check(hexString(try! TcpFrameProtocol.prefixBytes(fixtureHeader)) == v["headerPrefix"], "header prefix bytes match fixture")
    check(hexString(try! TcpFrameProtocol.encodeHeader(fixtureHeader, authKey: auth)) == v["header"], "header + HMAC match fixture")
    check(hexString(TcpFrameProtocol.aad(fixtureHeader, index: 3)) == v["aadChunk3"], "AAD bytes match fixture")
    let fixtureBytes = hex(v["header"]!)
    let verified = try? TcpFrameProtocol.verifyHeader(
        prefix: fixtureBytes.prefix(fixtureBytes.count - 32), mac: fixtureBytes.suffix(32),
        authKey: auth, expectedDirection: .androidToMac, nowMs: now)
    check(verified == fixtureHeader, "fixture header verifies and round-trips")

    // GCM fixture: fixed nonce, chunk 0 of a small text transfer. Printed if missing so it can
    // be added to the shared file; verified on both platforms.
    let gcmHeader = TcpFrameHeader(type: 0x01, direction: .androidToMac, totalSize: 11, chunkSize: 1024,
                                   timestampMs: now, sessionId: hex(v["sessionId"]!), fileName: Data())
    let gcmNonce = try! AES.GCM.Nonce(data: hex("000102030405060708090a0b"))
    let gcmSealed = try! TcpFrameProtocol.sealChunk(Data("hello world".utf8), key: root, header: gcmHeader, index: 0, nonce: gcmNonce)
    if let expected = v["gcmSealedChunk0"] {
        check(hexString(gcmSealed) == expected, "GCM chunk fixture matches")
        check((try? TcpFrameProtocol.openChunk(hex(expected).dropFirst(4), key: root, header: gcmHeader, index: 0))
              == Data("hello world".utf8), "GCM chunk fixture opens")
    } else {
        print("gcmNonce=000102030405060708090a0b")
        print("gcmPlaintext=\(hexString(Data("hello world".utf8)))")
        print("gcmSealedChunk0=\(hexString(gcmSealed))")
        check(false, "gcm fixture missing from vectors file")
    }

    // MARK: totalSize semantics
    let text = Data(String(repeating: "x", count: 5000).utf8)
    let textSend = try! sendStream(text, type: 0x01, direction: .androidToMac, chunkSize: 1_048_576,
                                   name: Data(), rootKey: root, timestampMs: now)
    check(textSend.header.totalSize == 5000, "totalSize declares plaintext bytes")
    check(textSend.wire.count > 5000 + 46 + 32, "wire carries GCM overhead that is not counted")
    check(receiveStream(textSend.wire, rootKey: root, direction: .androidToMac, nowMs: now)
          == .success(type: 0x01, name: Data(), payload: text), "encrypted text completes")

    var big = Data(count: 9 * 1_048_576 + 123)
    big.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
    for chunk in [1_048_576, 4 * 1_048_576] {
        let s = try! sendStream(big, type: 0x03, direction: .macToAndroid, chunkSize: chunk,
                                name: Data("v.mp4".utf8), rootKey: root, timestampMs: now)
        check(s.header.totalSize == Int64(big.count), "chunk size \(chunk) does not change totalSize")
        check(receiveStream(s.wire, rootKey: root, direction: .macToAndroid, nowMs: now)
              == .success(type: 0x03, name: Data("v.mp4".utf8), payload: big), "multi-chunk file (\(chunk)) completes")
    }
    let smaller = try! sendStream(text, type: 0x01, direction: .androidToMac, chunkSize: 1024, name: Data(),
                                  rootKey: root, timestampMs: now, declaredTotal: 4000)
    check(receiveStream(smaller.wire, rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.chunkLengthMismatch),
          "declared size smaller than payload is rejected")
    let larger = try! sendStream(text, type: 0x01, direction: .androidToMac, chunkSize: 1024, name: Data(),
                                 rootKey: root, timestampMs: now, declaredTotal: 6000)
    let largerOutcome = receiveStream(larger.wire, rootKey: root, direction: .androidToMac, nowMs: now)
    check(largerOutcome == .rejected(.chunkLengthMismatch) || largerOutcome == .incomplete, "declared size larger than payload fails")
    // Old v1 behaviour: totalSize = ciphertext length (plaintext + 28). Under v2 that mismatch fails.
    let ciphertextSized = try! sendStream(text, type: 0x01, direction: .androidToMac, chunkSize: 1_048_576, name: Data(),
                                          rootKey: root, timestampMs: now, declaredTotal: Int64(text.count + 28))
    let oldOutcome = receiveStream(ciphertextSized.wire, rootKey: root, direction: .androidToMac, nowMs: now)
    check(oldOutcome == .rejected(.chunkLengthMismatch), "ciphertext-sized totalSize (old bug) is rejected, got \(oldOutcome)")

    // Normal and Ultra Fast (Mac -> Android) through the real v2 code: both encrypted, same totalSize.
    let marker = big.prefix(64)
    var totals: [Int64] = []
    for purpose in [OutgoingPayloadPurpose.userFile(ultraFastRequested: false), .userFile(ultraFastRequested: true)] {
        let s = try! sendStream(big, type: TransferSecurityPolicy.outgoingTypeCode(for: purpose), direction: .macToAndroid,
                                chunkSize: TransferSecurityPolicy.outgoingChunkSize(for: purpose),
                                name: Data("v.mp4".utf8), rootKey: root, timestampMs: now)
        totals.append(s.header.totalSize)
        check(s.wire.range(of: marker) == nil, "\(purpose): plaintext must not appear on the wire")
        check([UInt8](s.wire)[5] != TransferTypeCode.retiredPlaintextFile, "\(purpose): never emits 0x04")
        check(receiveStream(s.wire, rootKey: root, direction: .macToAndroid, nowMs: now)
              == .success(type: 0x03, name: Data("v.mp4".utf8), payload: big), "\(purpose): receiver recovers the file")
    }
    check(totals.count == 2 && totals[0] == totals[1], "Normal and Ultra Fast declare the same totalSize")

    // MARK: Header authentication
    let good = try! sendStream(Data("abc".utf8), type: 0x03, direction: .androidToMac, chunkSize: 1024,
                               name: Data("a.txt".utf8), rootKey: root, timestampMs: now)
    check(receiveStream(good.wire, rootKey: root, direction: .androidToMac, nowMs: now)
          == .success(type: 0x03, name: Data("a.txt".utf8), payload: Data("abc".utf8)), "valid header accepted")
    check(receiveStream(good.wire, rootKey: SymmetricKey(size: .bits256), direction: .androidToMac, nowMs: now)
          == .rejected(.badMac), "wrong key rejected")

    func flipped(_ offset: Int, _ value: UInt8? = nil) -> Data {
        var w = good.wire; w[offset] = value ?? (w[offset] ^ 0x01); return w
    }
    check(receiveStream(flipped(5, 0x01), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified type rejected")
    check(receiveStream(flipped(46), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified filename rejected")
    check(receiveStream(flipped(15), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified total size rejected")
    check(receiveStream(flipped(30), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified session ID rejected")
    check(receiveStream(flipped(25), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified timestamp rejected")
    check(receiveStream(flipped(19), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified chunk size rejected")
    check(receiveStream(flipped(4, 0x03), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.unsupportedVersion), "modified version rejected")
    check(receiveStream(flipped(4, 0x01), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.unsupportedVersion), "downgraded version rejected")
    check(receiveStream(flipped(60), rootKey: root, direction: .androidToMac, nowMs: now) == .rejected(.badMac), "modified MAC rejected")
    let prefixLen = 46 + 5
    let truncatedMac = try? TcpFrameProtocol.verifyHeader(prefix: good.wire.prefix(prefixLen), mac: good.wire.subdata(in: prefixLen..<prefixLen + 31),
        authKey: auth, expectedDirection: .androidToMac, nowMs: now)
    check(truncatedMac == nil, "truncated MAC rejected")
    let extendedMac = try? TcpFrameProtocol.verifyHeader(prefix: good.wire.prefix(prefixLen), mac: good.wire.subdata(in: prefixLen..<prefixLen + 32) + Data([0]),
        authKey: auth, expectedDirection: .androidToMac, nowMs: now)
    check(extendedMac == nil, "extended MAC rejected")
    check(receiveStream(good.wire, rootKey: root, direction: .macToAndroid, nowMs: now) == .rejected(.wrongDirection), "reflected direction rejected")
    check(receiveStream(good.wire, rootKey: root, direction: .androidToMac, nowMs: now + TcpFrameProtocol.timestampWindowMs + 1)
          == .rejected(.staleTimestamp), "stale timestamp rejected")
    check(receiveStream(good.wire, rootKey: root, direction: .androidToMac, nowMs: now - TcpFrameProtocol.timestampWindowMs - 1)
          == .rejected(.staleTimestamp), "future timestamp rejected")

    // MARK: Fail-closed parser
    func prefixWith(_ mutate: (inout [UInt8]) -> Void) -> Data {
        var b = [UInt8](good.wire.prefix(46)); mutate(&b); return Data(b)
    }
    func parseError(_ d: Data, _ dir: TcpDirection = .androidToMac) -> TcpFrameError? {
        do { _ = try TcpFrameProtocol.parseFixedPrefix(d, expectedDirection: dir); return nil }
        catch let e as TcpFrameError { return e } catch { return .malformedHeader }
    }
    check(parseError(prefixWith { $0[3] = 0x59 }) == .legacyProtocol, "legacy v1 magic rejected")
    check(parseError(prefixWith { $0[0] = 0x00 }) == .badMagic, "bad magic rejected")
    check(parseError(prefixWith { $0[5] = 0x04 }) == .unknownType, "legacy plaintext type 0x04 rejected in v2")
    check(parseError(prefixWith { $0[5] = 0x99 }) == .unknownType, "unknown type rejected")
    check(parseError(prefixWith { $0[7] = 0x01 }) == .badReserved, "reserved byte must be zero")
    check(parseError(good.wire.prefix(45)) == .malformedHeader, "short header rejected")
    check(parseError(prefixWith { $0[44] = 0x04; $0[45] = 0x01 }) == .invalidNameLength, "oversized filename length rejected")
    check(parseError(prefixWith { for i in 28..<44 { $0[i] = 0 } }) == .invalidSessionId, "all-zero session ID rejected")
    check(parseError(prefixWith { for i in 8..<16 { $0[i] = 0xFF } }) == .invalidTotalSize, "negative total size rejected")
    check(parseError(prefixWith { $0[8] = 0x7F }) == .invalidTotalSize, "huge total size rejected")
    check(parseError(prefixWith { $0[5] = 0x01; for i in 8..<16 { $0[i] = 0 } }) == .invalidTotalSize, "empty text rejected")
    check(parseError(prefixWith { for i in 16..<20 { $0[i] = 0 } }) == .invalidChunkSize, "zero chunk size rejected")
    check(parseError(prefixWith { $0[16] = 0x01 }) == .invalidChunkSize, "oversized chunk size rejected")

    // MARK: Chunk integrity
    var payload3 = Data(count: 3 * 1024 + 7)
    payload3.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
    let multi = try! sendStream(payload3, type: 0x03, direction: .androidToMac, chunkSize: 1024,
                                name: Data("m.bin".utf8), rootKey: root, timestampMs: now)
    let headerBytes = multi.wire.prefix(46 + 5 + 32)
    func assemble(_ chunks: [Data]) -> Data { chunks.reduce(Data(headerBytes), +) }
    check(receiveStream(assemble(multi.chunks), rootKey: root, direction: .androidToMac, nowMs: now)
          == .success(type: 0x03, name: Data("m.bin".utf8), payload: payload3), "ordered chunks succeed")
    var swapped = multi.chunks; swapped.swapAt(0, 1)
    check(receiveStream(assemble(swapped), rootKey: root, direction: .androidToMac, nowMs: now)
          == .rejected(.chunkAuthenticationFailed), "swapped chunks fail")
    var duplicated = multi.chunks; duplicated[1] = duplicated[0]
    check(receiveStream(assemble(duplicated), rootKey: root, direction: .androidToMac, nowMs: now)
          == .rejected(.chunkAuthenticationFailed), "duplicated chunk fails")
    let other = try! sendStream(payload3, type: 0x03, direction: .androidToMac, chunkSize: 1024,
                                name: Data("m.bin".utf8), rootKey: root, timestampMs: now)
    var spliced = multi.chunks; spliced[2] = other.chunks[2]
    check(receiveStream(assemble(spliced), rootKey: root, direction: .androidToMac, nowMs: now)
          == .rejected(.chunkAuthenticationFailed), "chunk spliced from another session fails")
    var tampered = multi.chunks; tampered[1][20] ^= 0x01
    check(receiveStream(assemble(tampered), rootKey: root, direction: .androidToMac, nowMs: now)
          == .rejected(.chunkAuthenticationFailed), "tampered ciphertext fails")
    let wrongIndexAAD = try? TcpFrameProtocol.openChunk(multi.chunks[1].dropFirst(4), key: root, header: multi.header, index: 2)
    check(wrongIndexAAD == nil, "chunk opened at the wrong index fails")
    let otherTypeHeader = TcpFrameHeader(type: 0x02, direction: .androidToMac, totalSize: multi.header.totalSize,
                                         chunkSize: 1024, timestampMs: now, sessionId: multi.header.sessionId, fileName: Data())
    check((try? TcpFrameProtocol.openChunk(multi.chunks[0].dropFirst(4), key: root, header: otherTypeHeader, index: 0)) == nil,
          "chunk under a different type (AAD metadata) fails")
    check(receiveStream(assemble(Array(multi.chunks.dropLast())), rootKey: root, direction: .androidToMac, nowMs: now) == .incomplete,
          "truncated stream does not complete")
    check((try? TcpFrameProtocol.expectedSealedLength(multi.header, index: 4)) == nil, "chunk index past the end rejected")

    // MARK: Replay cache
    let cache = TcpReplayCache(capacity: 3, ttlMs: 1000)
    let s1 = TcpFrameProtocol.newSessionId()
    check(TcpFrameProtocol.newSessionId() != s1, "session IDs differ per transfer")
    check(cache.insertIfNew(s1, nowMs: 0), "first session accepted")
    check(!cache.insertIfNew(s1, nowMs: 10), "exact replay rejected")
    for i in 0..<10 { _ = cache.insertIfNew(Data(repeating: UInt8(i + 1), count: 16), nowMs: 20) }
    check(cache.count <= 3, "cache stays bounded, count=\(cache.count)")
    let expiring = TcpReplayCache(capacity: 10, ttlMs: 1000)
    _ = expiring.insertIfNew(s1, nowMs: 0)
    check(!expiring.insertIfNew(s1, nowMs: 999), "replay inside TTL rejected")
    check(expiring.insertIfNew(s1, nowMs: 1000), "entry expires after TTL (header timestamp window then rejects old frames)")
    let streamCache = TcpReplayCache()
    check(receiveStream(good.wire, rootKey: root, direction: .androidToMac, nowMs: now, cache: streamCache)
          != .rejected(.replayed), "stream accepted once")
    check(receiveStream(good.wire, rootKey: root, direction: .androidToMac, nowMs: now, cache: streamCache)
          == .rejected(.replayed), "replayed stream rejected")
}
