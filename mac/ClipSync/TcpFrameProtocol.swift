// TcpFrameProtocol.swift
// ClipSync local TCP protocol v2: authenticated header + AES-GCM chunks bound to the session.
//
// Canonical layout (all integers big-endian, strings UTF-8). Must match TcpFrameProtocol.kt
// and protocol/generate_tcp_v2_vectors.py byte for byte.
//
//   Header
//     off len field
//       0   4  magic "CLS2"
//       4   1  version = 0x02
//       5   1  type: 0x01 text, 0x02 image, 0x03 file
//       6   1  direction: 0x01 Android→Mac, 0x02 Mac→Android
//       7   1  reserved = 0x00
//       8   8  totalSize    plaintext/application bytes
//      16   4  chunkSize    plaintext bytes per chunk
//      20   8  timestampMs  sender clock, Unix epoch ms
//      28  16  sessionId    random, unique per transfer
//      44   2  nameLen
//      46   N  name (UTF-8)
//    46+N  32  HMAC-SHA256(authKey, bytes[0 ..< 46+N])
//
//   authKey = HKDF-SHA256(IKM: pairing key, salt: empty, info: "ClipSync/TCP/Auth/v1", L: 32)
//
//   Chunk i (index counted by both sides, never sent):
//     [4-byte sealedLen][12-byte nonce][ciphertext][16-byte tag]
//     sealedLen = plainLen(i) + 28, plainLen(i) = min(chunkSize, totalSize − i·chunkSize)
//     AES-256-GCM with the pairing key, AAD (31 bytes) =
//       version(1) ‖ sessionId(16) ‖ type(1) ‖ direction(1) ‖ totalSize(8) ‖ chunkIndex(4)
//
// Deliberately limited to Foundation and CryptoKit so it can be tested on its own
// (mac/PolicyTests).

import Foundation
import CryptoKit

nonisolated enum TcpDirection: UInt8 {
    case androidToMac = 0x01
    case macToAndroid = 0x02
}

/// A header whose MAC has been verified. Nothing here may be trusted before verification.
nonisolated struct TcpFrameHeader: Equatable {
    let type: UInt8
    let direction: TcpDirection
    let totalSize: Int64
    let chunkSize: Int
    let timestampMs: Int64
    let sessionId: Data
    let fileName: Data
}

/// Fixed-length part of a header, structurally checked but NOT yet authenticated.
/// Only `nameLength` may be used, to know how many more bytes to read.
nonisolated struct TcpUnverifiedPrefix {
    let nameLength: Int
}

nonisolated enum TcpFrameError: Error, Equatable {
    case legacyProtocol
    case badMagic
    case malformedHeader
    case unsupportedVersion
    case unknownType
    case wrongDirection
    case badReserved
    case invalidTotalSize
    case invalidChunkSize
    case invalidNameLength
    case invalidSessionId
    case badMac
    case staleTimestamp
    case replayed
    case chunkLengthMismatch
    case chunkIndexOutOfRange
    case chunkAuthenticationFailed
}

nonisolated enum TcpFrameProtocol {

    static let magic: [UInt8] = [0x43, 0x4C, 0x53, 0x32]       // "CLS2"
    /// v1 magic. v1 frames are unauthenticated and refused, except the no-data diagnostic ping.
    static let legacyMagic: [UInt8] = [0x43, 0x4C, 0x53, 0x59] // "CLSY"
    static let version: UInt8 = 0x02

    static let fixedPrefixLength = 46
    static let macLength = 32
    static let sessionIdLength = 16
    static let maxNameLength = 1024
    static let minChunkSize = 1024
    static let maxChunkSize = 4 * 1024 * 1024
    static let gcmOverhead = 28
    static let maxTotalSize: Int64 = 64 * 1024 * 1024 * 1024        // 64 GiB
    /// Text and images are buffered in memory before reaching the clipboard.
    static let maxInMemoryTotalSize: Int64 = 128 * 1024 * 1024       // 128 MiB
    /// Accepted sender/receiver clock difference.
    static let timestampWindowMs: Int64 = 15 * 60 * 1000

    static let typeText: UInt8 = 0x01
    static let typeImage: UInt8 = 0x02
    static let typeFile: UInt8 = 0x03

    private static let authInfo = Data("ClipSync/TCP/Auth/v1".utf8)

    // MARK: - Keys

    static func authKey(rootKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: rootKey, salt: Data(), info: authInfo, outputByteCount: 32)
    }

    static func newSessionId() -> Data {
        var bytes = [UInt8](repeating: 0, count: sessionIdLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes)
    }

    // MARK: - Header encoding

    static func prefixBytes(_ h: TcpFrameHeader) throws -> Data {
        guard h.sessionId.count == sessionIdLength else { throw TcpFrameError.invalidSessionId }
        guard h.fileName.count <= maxNameLength else { throw TcpFrameError.invalidNameLength }
        var out = Data(magic)
        out.append(contentsOf: [version, h.type, h.direction.rawValue, 0x00])
        out.append(bigEndian: UInt64(bitPattern: h.totalSize))
        out.append(bigEndian: UInt32(h.chunkSize))
        out.append(bigEndian: UInt64(bitPattern: h.timestampMs))
        out.append(h.sessionId)
        out.append(bigEndian: UInt16(h.fileName.count))
        out.append(h.fileName)
        return out
    }

    /// Full header: prefix followed by its HMAC-SHA256.
    static func encodeHeader(_ h: TcpFrameHeader, authKey: SymmetricKey) throws -> Data {
        let prefix = try prefixBytes(h)
        return prefix + Data(HMAC<SHA256>.authenticationCode(for: prefix, using: authKey))
    }

    // MARK: - Header parsing

    /// Structural checks on the 46-byte fixed prefix, done only to bound further reads.
    static func parseFixedPrefix(_ data: Data, expectedDirection: TcpDirection) throws -> TcpUnverifiedPrefix {
        let b = [UInt8](data)
        guard b.count == fixedPrefixLength else { throw TcpFrameError.malformedHeader }
        if Array(b[0..<4]) == legacyMagic { throw TcpFrameError.legacyProtocol }
        guard Array(b[0..<4]) == magic else { throw TcpFrameError.badMagic }
        guard b[4] == version else { throw TcpFrameError.unsupportedVersion }
        let type = b[5]
        guard type == typeText || type == typeImage || type == typeFile else { throw TcpFrameError.unknownType }
        guard b[6] == expectedDirection.rawValue else { throw TcpFrameError.wrongDirection }
        guard b[7] == 0 else { throw TcpFrameError.badReserved }

        let totalSize = Int64(bitPattern: readBE(b, 8, 8))
        let inMemory = type != typeFile
        guard totalSize >= (inMemory ? 1 : 0),
              totalSize <= (inMemory ? maxInMemoryTotalSize : maxTotalSize) else {
            throw TcpFrameError.invalidTotalSize
        }
        let chunkSize = Int(readBE(b, 16, 4))
        guard chunkSize >= minChunkSize, chunkSize <= maxChunkSize else { throw TcpFrameError.invalidChunkSize }
        guard (totalSize + Int64(chunkSize) - 1) / Int64(chunkSize) <= Int64(UInt32.max) else {
            throw TcpFrameError.invalidChunkSize
        }
        guard b[28..<44].contains(where: { $0 != 0 }) else { throw TcpFrameError.invalidSessionId }
        let nameLength = Int(readBE(b, 44, 2))
        guard nameLength <= maxNameLength else { throw TcpFrameError.invalidNameLength }
        return TcpUnverifiedPrefix(nameLength: nameLength)
    }

    /// Verifies the MAC (constant time) and the timestamp window, then returns the header.
    /// `prefix` is the fixed prefix plus name bytes; `mac` must be exactly 32 bytes.
    static func verifyHeader(prefix: Data, mac: Data, authKey: SymmetricKey,
                             expectedDirection: TcpDirection, nowMs: Int64) throws -> TcpFrameHeader {
        let b = [UInt8](prefix)
        guard b.count >= fixedPrefixLength else { throw TcpFrameError.malformedHeader }
        let unverified = try parseFixedPrefix(Data(b[0..<fixedPrefixLength]), expectedDirection: expectedDirection)
        guard b.count == fixedPrefixLength + unverified.nameLength else { throw TcpFrameError.invalidNameLength }
        guard mac.count == macLength else { throw TcpFrameError.badMac }
        // CryptoKit's isValidAuthenticationCode compares in constant time.
        guard HMAC<SHA256>.isValidAuthenticationCode(Data(mac), authenticating: Data(b), using: authKey) else {
            throw TcpFrameError.badMac
        }

        let header = TcpFrameHeader(
            type: b[5],
            direction: expectedDirection,
            totalSize: Int64(bitPattern: readBE(b, 8, 8)),
            chunkSize: Int(readBE(b, 16, 4)),
            timestampMs: Int64(bitPattern: readBE(b, 20, 8)),
            sessionId: Data(b[28..<44]),
            fileName: Data(b[fixedPrefixLength...])
        )
        let skew = nowMs - header.timestampMs
        guard skew <= timestampWindowMs, skew >= -timestampWindowMs else { throw TcpFrameError.staleTimestamp }
        return header
    }

    // MARK: - Chunks

    static func chunkCount(_ h: TcpFrameHeader) -> Int64 {
        (h.totalSize + Int64(h.chunkSize) - 1) / Int64(h.chunkSize)
    }

    /// Plaintext length of chunk `index`, or nil if the index is past the end.
    static func plainLength(_ h: TcpFrameHeader, index: UInt32) -> Int? {
        let offset = Int64(index) * Int64(h.chunkSize)
        guard offset < h.totalSize else { return nil }
        return Int(min(Int64(h.chunkSize), h.totalSize - offset))
    }

    static func aad(_ h: TcpFrameHeader, index: UInt32) -> Data {
        var out = Data([version])
        out.append(h.sessionId)
        out.append(contentsOf: [h.type, h.direction.rawValue])
        out.append(bigEndian: UInt64(bitPattern: h.totalSize))
        out.append(bigEndian: index)
        return out
    }

    /// Wire bytes for chunk `index`: length prefix + nonce + ciphertext + tag.
    static func sealChunk(_ plaintext: Data, key: SymmetricKey, header: TcpFrameHeader, index: UInt32,
                          nonce: AES.GCM.Nonce = AES.GCM.Nonce()) throws -> Data {
        guard let expected = plainLength(header, index: index) else { throw TcpFrameError.chunkIndexOutOfRange }
        guard plaintext.count == expected else { throw TcpFrameError.chunkLengthMismatch }
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad(header, index: index))
        guard let combined = sealed.combined else { throw TcpFrameError.chunkAuthenticationFailed }
        var out = Data()
        out.append(bigEndian: UInt32(combined.count))
        out.append(combined)
        return out
    }

    /// The sealed length the receiver must see for chunk `index`, checked before reading it.
    static func expectedSealedLength(_ h: TcpFrameHeader, index: UInt32) throws -> Int {
        guard let plain = plainLength(h, index: index) else { throw TcpFrameError.chunkIndexOutOfRange }
        return plain + gcmOverhead
    }

    /// Opens chunk `index` (`sealed` excludes the 4-byte length prefix).
    static func openChunk(_ sealed: Data, key: SymmetricKey, header: TcpFrameHeader, index: UInt32) throws -> Data {
        guard sealed.count == (try expectedSealedLength(header, index: index)) else {
            throw TcpFrameError.chunkLengthMismatch
        }
        do {
            let box = try AES.GCM.SealedBox(combined: Data(sealed))
            return try AES.GCM.open(box, using: key, authenticating: aad(header, index: index))
        } catch {
            throw TcpFrameError.chunkAuthenticationFailed
        }
    }

    // MARK: - Helpers

    private static func readBE(_ b: [UInt8], _ offset: Int, _ length: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in offset..<(offset + length) { value = (value << 8) | UInt64(b[i]) }
        return value
    }
}

/// Bounded, time-limited record of session IDs already accepted by this receiver.
/// Entries live for twice the timestamp window, so a header old enough to have been evicted
/// is also outside the accepted timestamp window. Capacity bounds memory; if more than
/// `capacity` legitimate transfers arrive within that period, the oldest IDs are evicted early.
nonisolated final class TcpReplayCache: @unchecked Sendable {
    private let capacity: Int
    private let ttlMs: Int64
    private var expiry: [Data: Int64] = [:]
    private var order: [Data] = []
    private let lock = NSLock()

    init(capacity: Int = 1024, ttlMs: Int64 = 2 * TcpFrameProtocol.timestampWindowMs) {
        self.capacity = capacity
        self.ttlMs = ttlMs
    }

    /// Records `sessionId`; returns false if it was already seen and has not expired.
    func insertIfNew(_ sessionId: Data, nowMs: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        while let oldest = order.first, let exp = expiry[oldest], exp <= nowMs {
            order.removeFirst()
            expiry.removeValue(forKey: oldest)
        }
        if let exp = expiry[sessionId] {
            if exp > nowMs { return false }
            // Expired but not yet swept (e.g. the clock moved backwards): drop the stale entry.
            expiry.removeValue(forKey: sessionId)
            order.removeAll { $0 == sessionId }
        }
        while order.count >= capacity {
            expiry.removeValue(forKey: order.removeFirst())
        }
        expiry[sessionId] = nowMs + ttlMs
        order.append(sessionId)
        return true
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return order.count
    }
}

private extension Data {
    nonisolated mutating func append<T: FixedWidthInteger>(bigEndian value: T) {
        var be = value.bigEndian
        Swift.withUnsafeBytes(of: &be) { append(contentsOf: $0) }
    }
}
