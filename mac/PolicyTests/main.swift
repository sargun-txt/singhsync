// Standalone tests for ClipSync/TransferSecurityPolicy.swift.
//
// The Xcode project has no test target, and the policy file is Foundation-only, so these
// tests compile it directly with swiftc (Command Line Tools are enough):
//
//   swiftc -swift-version 5 -default-isolation MainActor \
//     mac/ClipSync/TransferSecurityPolicy.swift mac/ClipSync/TcpFrameProtocol.swift \
//     mac/ClipSync/BleControlProtocol.swift mac/ClipSync/CloudPairingAuth.swift \
//     mac/ClipSync/UpdatePolicy.swift mac/ClipSync/UpdateStager.swift mac/ClipSync/CodeSignatureVerifier.swift \
//     mac/PolicyTests/*.swift \
//     -o /tmp/clipsync-policy-tests && /tmp/clipsync-policy-tests
//
// Exits non-zero if any check fails.

import Foundation
import CryptoKit

nonisolated(unsafe) var failures = 0
nonisolated(unsafe) var checks = 0

func check(_ condition: Bool, _ message: String, line: Int = #line) {
    checks += 1
    if !condition {
        failures += 1
        print("FAIL (line \(line)): \(message)")
    }
}

func makeTempDir() -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("crossiva-policy-tests-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// Mirrors ClipSyncServer.beginPayload: sanitize, fall back, create uniquely.
func destination(for raw: String?, in dir: URL) throws -> URL {
    let name = TransferSecurityPolicy.sanitizedFileName(raw) ?? "Crossiva_fallback"
    let created = try TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: name)
    created.handle.closeFile()
    return created.url
}

func isDirectChild(_ url: URL, of dir: URL) -> Bool {
    url.deletingLastPathComponent().standardizedFileURL.path == dir.standardizedFileURL.path
}

// MARK: - Frame type (Fix 1)

check(TransferSecurityPolicy.isPlaintextFrame(0x04), "legacy 0x04 must be treated as plaintext and refused")
check(TransferTypeCode.retiredPlaintextFile == 0x04, "retired constant still names 0x04")
for code: UInt8 in [0x01, 0x02, 0x03] {
    check(!TransferSecurityPolicy.isPlaintextFrame(code), "encrypted type \(code) must continue to the chunk path")
}

// MARK: - Outgoing type and chunking (Fix 2, Ultra Fast)

let allPurposes: [OutgoingPayloadPurpose] = [
    .clipboardText, .userFile(ultraFastRequested: false), .userFile(ultraFastRequested: true)
]
check(TransferSecurityPolicy.outgoingTypeCode(for: .clipboardText) == TransferTypeCode.text,
      "clipboard text uses the text frame")
for purpose in allPurposes {
    let type = TransferSecurityPolicy.outgoingTypeCode(for: purpose)
    check(type != TransferTypeCode.retiredPlaintextFile, "\(purpose) must never emit 0x04")
    check(!TransferSecurityPolicy.isPlaintextFrame(type), "\(purpose) frame is accepted by updated receivers")
}
for purpose in [OutgoingPayloadPurpose.userFile(ultraFastRequested: false), .userFile(ultraFastRequested: true)] {
    check(TransferSecurityPolicy.outgoingTypeCode(for: purpose) == TransferTypeCode.file,
          "\(purpose) uses the encrypted file frame")
}
check(TransferSecurityPolicy.outgoingChunkSize(for: .userFile(ultraFastRequested: true)) == TransferSecurityPolicy.ultraFastChunkSize,
      "Ultra Fast uses the larger chunk size")
check(TransferSecurityPolicy.outgoingChunkSize(for: .userFile(ultraFastRequested: false)) == TransferSecurityPolicy.standardChunkSize,
      "normal file uses the standard chunk size")
for purpose in allPurposes {
    let chunk = TransferSecurityPolicy.outgoingChunkSize(for: purpose)
    check(chunk + TransferSecurityPolicy.gcmChunkOverhead <= TransferSecurityPolicy.maxEncryptedChunkAcceptedByReceivers,
          "\(purpose) chunk must fit every receiver's limit")
    check(chunk >= TcpFrameProtocol.minChunkSize && chunk <= TcpFrameProtocol.maxChunkSize,
          "\(purpose) chunk size is valid in protocol v2")
}
do {
    // The global toggle exists but the clipboard-text call site carries no flag to honour.
    UserDefaults.standard.set(true, forKey: "UltraFastTransfer")
    defer { UserDefaults.standard.removeObject(forKey: "UltraFastTransfer") }
    check(TransferSecurityPolicy.outgoingTypeCode(for: .clipboardText) == TransferTypeCode.text,
          "clipboard text stays in the encrypted text frame while the Ultra Fast toggle is on")
    check(TransferSecurityPolicy.outgoingChunkSize(for: .clipboardText) == TransferSecurityPolicy.standardChunkSize,
          "clipboard text uses standard chunks while the Ultra Fast toggle is on")
}

// MARK: - Size validation (Fix 4D)

let gib: Int64 = 1024 * 1024 * 1024
check(TransferSecurityPolicy.isAcceptableTotalSize(10 * 1024 * 1024, typeCode: TransferTypeCode.file, availableCapacity: 100 * gib),
      "normal 10 MB file accepted")
check(TransferSecurityPolicy.isAcceptableTotalSize(10 * 1024 * 1024, typeCode: TransferTypeCode.file, availableCapacity: nil),
      "normal file accepted when free space is unknown")
check(!TransferSecurityPolicy.isAcceptableTotalSize(TransferSecurityPolicy.maxIncomingFileSize + 1, typeCode: TransferTypeCode.file, availableCapacity: nil),
      "file above the cap rejected")
check(!TransferSecurityPolicy.isAcceptableTotalSize(Int64.max, typeCode: TransferTypeCode.file, availableCapacity: nil),
      "Int64.max rejected")
check(!TransferSecurityPolicy.isAcceptableTotalSize(5 * gib, typeCode: TransferTypeCode.file, availableCapacity: 1 * gib),
      "file larger than free space rejected")
check(!TransferSecurityPolicy.isAcceptableTotalSize(0, typeCode: TransferTypeCode.file, availableCapacity: nil),
      "zero-size file rejected")
check(!TransferSecurityPolicy.isAcceptableTotalSize(-1, typeCode: TransferTypeCode.file, availableCapacity: nil),
      "negative size rejected")
check(!TransferSecurityPolicy.isAcceptableTotalSize(Int64.min, typeCode: TransferTypeCode.text, availableCapacity: nil),
      "negative size rejected for text")
check(TransferSecurityPolicy.isAcceptableTotalSize(33, typeCode: TransferTypeCode.text, availableCapacity: nil),
      "small text payload accepted")

// Oversized transfer is rejected before any file exists (mirrors processHeader order).
do {
    let dir = makeTempDir()
    defer { try? FileManager.default.removeItem(at: dir) }
    if TransferSecurityPolicy.isAcceptableTotalSize(Int64.max, typeCode: TransferTypeCode.file, availableCapacity: nil) {
        _ = try? destination(for: "big.bin", in: dir)
    }
    let contents = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? ["<error>"]
    check(contents.isEmpty, "no file created for an oversized transfer, found \(contents)")
}

// MARK: - File name sanitation (Fix 4A/B)

let s = TransferSecurityPolicy.sanitizedFileName
check(s("../../evil.txt") == "evil.txt", "../../evil.txt -> evil.txt, got \(String(describing: s("../../evil.txt")))")
check(s("../evil.txt") == "evil.txt", "../evil.txt -> evil.txt")
check(s("folder/file.txt") == "file.txt", "folder/file.txt -> file.txt")
check(s("/tmp/file.txt") == "file.txt", "/tmp/file.txt -> file.txt")
check(s("..\\..\\evil.txt") == "evil.txt", "backslash traversal -> evil.txt")
check(s(".") == nil, ". rejected")
check(s("..") == nil, ".. rejected")
check(s("foo/..") == nil, "foo/.. rejected")
check(s("/") == nil, "/ rejected")
check(s("") == nil, "empty rejected")
check(s("   ") == nil, "whitespace-only rejected")
check(s(nil) == nil, "nil rejected")
check(s("photo.jpg") == "photo.jpg", "plain name unchanged")
check(s("my report (final).pdf") == "my report (final).pdf", "spaces and parens preserved")
check(s("a:b.txt") == "a_b.txt", "HFS separator replaced")
check(s("bad\u{0}name.txt") == "bad_name.txt", "NUL replaced")
check(s("line\nbreak.txt") == "line_break.txt", "newline replaced")
check(s("invoice\u{202E}fdp.app") == "invoice_fdp.app", "bidi override replaced")
check(s("👨‍👩‍👧 family.png") == "👨‍👩‍👧 family.png", "emoji ZWJ sequences preserved")

let longName = String(repeating: "a", count: 1000) + ".jpg"
if let truncated = s(longName) {
    check(truncated.utf8.count <= TransferSecurityPolicy.maxFileNameBytes, "long name truncated to byte budget")
    check(truncated.hasSuffix(".jpg"), "long name keeps its extension")
} else {
    check(false, "long name should be truncated, not rejected")
}
let longMultibyte = String(repeating: "é", count: 500) + ".txt"
if let truncated = s(longMultibyte) {
    check(truncated.utf8.count <= TransferSecurityPolicy.maxFileNameBytes, "multibyte name truncated within budget")
    check(String(data: truncated.data(using: .utf8)!, encoding: .utf8) == truncated, "truncation keeps valid UTF-8")
    check(truncated.hasSuffix(".txt"), "multibyte name keeps extension")
} else {
    check(false, "long multibyte name should be truncated")
}

// MARK: - Destination stays inside the directory, never overwrites (Fix 4A/C)

do {
    let dir = makeTempDir()
    defer { try? FileManager.default.removeItem(at: dir) }

    for raw in ["../../evil.txt", "../evil.txt", "folder/file.txt", "/tmp/file.txt", ".", "..", "", String(repeating: "x", count: 600)] {
        do {
            let url = try destination(for: raw, in: dir)
            check(isDirectChild(url, of: dir), "\(raw.prefix(40)) resolved to \(url.path), outside \(dir.path)")
        } catch {
            check(false, "\(raw.prefix(40)) threw \(error)")
        }
    }
    // Existing file: must not be opened or modified.
    let existing = dir.appendingPathComponent("photo.jpg")
    try! Data("ORIGINAL".utf8).write(to: existing)
    let first = try! TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: "photo.jpg")
    first.handle.write(Data("NEW".utf8))
    first.handle.closeFile()
    check(first.url.lastPathComponent == "photo (1).jpg", "first duplicate is photo (1).jpg, got \(first.url.lastPathComponent)")
    check((try? String(contentsOf: existing, encoding: .utf8)) == "ORIGINAL", "existing file content unchanged")

    let second = try! TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: "photo.jpg")
    second.handle.closeFile()
    check(second.url.lastPathComponent == "photo (2).jpg", "second duplicate is photo (2).jpg")

    let noExt = try! TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: "README")
    noExt.handle.closeFile()
    let noExt2 = try! TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: "README")
    noExt2.handle.closeFile()
    check(noExt2.url.lastPathComponent == "README (1)", "extensionless duplicate is README (1)")

    // A symlink planted at the destination must not be followed.
    let outside = makeTempDir()
    defer { try? FileManager.default.removeItem(at: outside) }
    let target = outside.appendingPathComponent("target.txt")
    try! Data("TARGET".utf8).write(to: target)
    try! FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("link.txt"), withDestinationURL: target)
    let viaLink = try! TransferSecurityPolicy.createUniqueFile(in: dir, preferredName: "link.txt")
    viaLink.handle.write(Data("ATTACK".utf8))
    viaLink.handle.closeFile()
    check(viaLink.url.lastPathComponent == "link (1).txt", "symlinked name skipped, got \(viaLink.url.lastPathComponent)")
    check((try? String(contentsOf: target, encoding: .utf8)) == "TARGET", "symlink target not written")
}

runTcpProtocolTests()
runBleProtocolTests()
runCloudPairingAuthTests()
check(FirebaseRegion.forCountry("Canada") == "CA", "Canada selects CA")
check(FirebaseRegion.forCountry("United States") == "US", "United States selects US")
check(FirebaseRegion.forCountry("India") == "IN", "India selects IN")
check(FirebaseRegion.projectID(for: "CA") == "crossiva-dev-ca", "CA project")
check(FirebaseRegion.projectID(for: "US") == "crossiva-dev-us", "US project")
check(FirebaseRegion.projectID(for: "IN") == "crossiva-dev-in", "IN project")
check(FirebaseRegion.projectID(for: "unknown") == nil, "unknown region fails closed")
runUpdatePolicyTests()

print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
