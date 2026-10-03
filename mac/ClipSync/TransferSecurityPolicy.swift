// TransferSecurityPolicy.swift
// Security decisions for the local TCP transfer protocol (see ClipSyncServer.swift).
//
// Deliberately Foundation-only, with no app or Firebase dependencies, so the policy can be
// compiled and tested on its own — see mac/PolicyTests/main.swift. Wire framing and crypto
// live in TcpFrameProtocol.swift.

import Foundation

/// Frame type codes (byte 5 of the protocol header; see TcpFrameProtocol.swift).
nonisolated enum TransferTypeCode {
    static let text: UInt8 = 0x01
    static let image: UInt8 = 0x02
    static let file: UInt8 = 0x03
    /// Retired legacy "Ultra Fast" frame: raw bytes with no AES-GCM envelope. Kept only so
    /// receivers can name and refuse it. Never sent, and never reused for another meaning,
    /// because older clients would still read it as plaintext.
    static let retiredPlaintextFile: UInt8 = 0x04
    static let diagnosticPing: UInt8 = 0x99
}

/// Why an outgoing TCP stream is being sent. Every purpose uses the encrypted frame;
/// Ultra Fast only changes transfer parameters, and clipboard text cannot request it.
nonisolated enum OutgoingPayloadPurpose: Equatable {
    case clipboardText
    case userFile(ultraFastRequested: Bool)
}

nonisolated enum TransferSecurityPolicy {

    /// Upper bound for an incoming file. Far above anything practical over local Wi-Fi;
    /// it exists to reject absurd sender-supplied sizes. Free disk space is checked separately.
    static let maxIncomingFileSize: Int64 = 64 * 1024 * 1024 * 1024 // 64 GiB

    /// Plaintext bytes per AES-GCM chunk for normal transfers.
    static let standardChunkSize = 1024 * 1024 // 1 MiB
    /// Plaintext bytes per AES-GCM chunk for Ultra Fast: fewer chunks, so fewer GCM
    /// setups, length prefixes and send callbacks. Each chunk is still sealed with AES-GCM.
    static let ultraFastChunkSize = 4 * 1024 * 1024 // 4 MiB
    /// Smallest encrypted-chunk limit among receivers (Android: 5,000,000 bytes;
    /// Mac: 5 MiB + 512). Outgoing chunks must stay below it.
    static let maxEncryptedChunkAcceptedByReceivers = 5_000_000
    /// AES-GCM framing added to each chunk: 12-byte nonce + 16-byte tag.
    static let gcmChunkOverhead = 28

    /// Maximum UTF-8 length of a sanitized file name. APFS allows 255 bytes; the headroom
    /// leaves room for a " (n)" de-duplication suffix.
    static let maxFileNameBytes = 200

    private static let maxPreservedExtensionBytes = 16
    private static let maxUniqueNameAttempts = 1000

    // MARK: - Frame type

    /// True for frame types that carry unauthenticated plaintext and must be refused.
    static func isPlaintextFrame(_ typeCode: UInt8) -> Bool {
        typeCode == TransferTypeCode.retiredPlaintextFile
    }

    /// The frame type to put in an outgoing (encrypted, authenticated) header. Clipboard text
    /// uses the text frame so a captured file transfer cannot be replayed as clipboard text.
    /// No purpose, including Ultra Fast, can select a plaintext frame.
    static func outgoingTypeCode(for purpose: OutgoingPayloadPurpose) -> UInt8 {
        switch purpose {
        case .clipboardText: return TransferTypeCode.text
        case .userFile:      return TransferTypeCode.file
        }
    }

    /// Plaintext bytes per encrypted chunk. Ultra Fast uses larger chunks; clipboard text
    /// always uses the standard size.
    static func outgoingChunkSize(for purpose: OutgoingPayloadPurpose) -> Int {
        switch purpose {
        case .clipboardText:
            return standardChunkSize
        case .userFile(let ultraFastRequested):
            return ultraFastRequested ? ultraFastChunkSize : standardChunkSize
        }
    }

    // MARK: - Size

    /// Validates the sender-declared payload size before anything is created or allocated.
    /// - Parameter availableCapacity: free space on the destination volume, or nil if unknown.
    static func isAcceptableTotalSize(_ totalSize: Int64, typeCode: UInt8, availableCapacity: Int64?) -> Bool {
        guard totalSize > 0 else { return false }
        guard typeCode == TransferTypeCode.file else { return true }
        guard totalSize <= maxIncomingFileSize else { return false }
        if let availableCapacity, totalSize > availableCapacity { return false }
        return true
    }

    // MARK: - File names

    /// Reduces a network-supplied name to a single safe path component, or returns nil if
    /// nothing usable remains (empty, ".", ".."). Directory components are discarded, never
    /// interpreted.
    static func sanitizedFileName(_ raw: String?) -> String? {
        guard let raw else { return nil }

        let lastComponent = raw
            .split(whereSeparator: { $0 == "/" || $0 == "\\" })
            .last
            .map(String.init) ?? ""

        var scalars = String.UnicodeScalarView()
        for scalar in lastComponent.unicodeScalars {
            scalars.append(isUnsafeFileNameScalar(scalar) ? "_" : scalar)
        }
        let cleaned = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)

        guard !cleaned.isEmpty, cleaned != ".", cleaned != ".." else { return nil }
        return truncated(cleaned, maxBytes: maxFileNameBytes)
    }

    /// Atomically creates a new, empty file directly inside `directory`, never opening an
    /// existing one. On a name clash it tries "name (1).ext", "name (2).ext", …
    /// `preferredName` must already be sanitized.
    static func createUniqueFile(in directory: URL, preferredName: String) throws -> (url: URL, handle: FileHandle) {
        let base = preferredName as NSString
        let ext = base.pathExtension
        let stem = base.deletingPathExtension
        let directoryPath = directory.standardizedFileURL.path

        for attempt in 0..<maxUniqueNameAttempts {
            let name: String
            if attempt == 0 {
                name = preferredName
            } else if ext.isEmpty {
                name = "\(stem) (\(attempt))"
            } else {
                name = "\(stem) (\(attempt)).\(ext)"
            }

            let url = directory.appendingPathComponent(name, isDirectory: false)
            // Defense in depth: the destination must be a direct child of `directory`.
            guard url.deletingLastPathComponent().standardizedFileURL.path == directoryPath,
                  url.lastPathComponent == name else {
                throw POSIXError(.EINVAL)
            }

            // O_EXCL makes "check if exists" and "create" a single atomic step; O_NOFOLLOW
            // refuses to follow a symlink planted at the destination.
            let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
            if fd >= 0 {
                return (url, FileHandle(fileDescriptor: fd, closeOnDealloc: true))
            }
            let err = errno
            if err == EEXIST { continue }
            throw POSIXError(POSIXErrorCode(rawValue: err) ?? .EIO)
        }
        throw POSIXError(.EEXIST)
    }

    // MARK: - Private helpers

    /// Control characters, the HFS ":" separator, and bidi overrides (used to disguise
    /// extensions, e.g. "invoice\u{202E}fdp.app").
    private static func isUnsafeFileNameScalar(_ scalar: Unicode.Scalar) -> Bool {
        if scalar.properties.generalCategory == .control { return true }
        switch scalar.value {
        case 0x3A,                // ":"
             0x200E, 0x200F,      // LRM, RLM
             0x202A...0x202E,     // LRE, RLE, PDF, LRO, RLO
             0x2066...0x2069:     // LRI, RLI, FSI, PDI
            return true
        default:
            return false
        }
    }

    /// Truncates to `maxBytes` of UTF-8 on a character boundary, keeping a short extension.
    private static func truncated(_ name: String, maxBytes: Int) -> String {
        guard name.utf8.count > maxBytes else { return name }

        let ext = (name as NSString).pathExtension
        let keepExtension = !ext.isEmpty && ext.utf8.count <= maxPreservedExtensionBytes
        let stem = keepExtension ? (name as NSString).deletingPathExtension : name
        let suffix = keepExtension ? "." + ext : ""

        let budget = maxBytes - suffix.utf8.count
        var out = ""
        var used = 0
        for character in stem {
            let size = String(character).utf8.count
            if used + size > budget { break }
            out.append(character)
            used += size
        }
        return out + suffix
    }
}
