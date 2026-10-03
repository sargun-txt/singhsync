// UpdateStager.swift
// Stages, extracts and verifies a downloaded update in a private directory. Nothing in the
// archive is executed, opened, chmod-ed or de-quarantined; the running app is never touched.
// A verified ClipSync.app is then handed to the user (Finder) to install — the app is
// sandboxed and cannot replace itself, and no privileged step exists.

import Foundation

nonisolated struct UpdateStager {

    typealias Verifier = (_ appURL: URL, _ requirement: String) -> UpdatePolicy.SignatureCheck

    struct StagedUpdate {
        let appURL: URL
        let version: String
        let stagingDirectory: URL
    }

    /// Parent of per-update staging directories (the app container's temporary directory).
    let stagingRoot: URL
    /// Code-signature check; `CodeSignatureVerifier.check` in the app, injectable for tests.
    let verifier: Verifier

    /// Moves `downloadedArchive` into a fresh staging directory and runs every check. On any
    /// failure the staging directory (and the archive) are deleted; nothing else is touched.
    func prepare(downloadedArchive: URL, expectedTeam: String?, expectedBundleId: String,
                 currentVersion: String) -> Result<StagedUpdate, UpdatePolicy.Rejection> {
        guard let team = expectedTeam else {
            try? FileManager.default.removeItem(at: downloadedArchive)
            return .failure(.noTrustAnchor)
        }
        let staging = stagingRoot.appendingPathComponent("ClipSyncUpdate-\(UUID().uuidString)", isDirectory: true)
        let result = stage(archive: downloadedArchive, in: staging, team: team,
                           expectedBundleId: expectedBundleId, currentVersion: currentVersion)
        if case .failure = result {
            try? FileManager.default.removeItem(at: staging)
            try? FileManager.default.removeItem(at: downloadedArchive)
        }
        return result
    }

    private func stage(archive: URL, in staging: URL, team: String, expectedBundleId: String,
                       currentVersion: String) -> Result<StagedUpdate, UpdatePolicy.Rejection> {
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: staging, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            return .failure(.extractionFailed)
        }

        let zip = staging.appendingPathComponent("update.zip")
        guard (try? fm.moveItem(at: archive, to: zip)) != nil else { return .failure(.extractionFailed) }
        let size = (try? fm.attributesOfItem(atPath: zip.path)[.size] as? NSNumber)?.int64Value ?? Int64.max
        guard size <= UpdatePolicy.maxDownloadBytes else { return .failure(.tooLarge) }

        // 1. Validate every entry name before anything is written.
        guard let entries = Self.listZipEntries(zip) else { return .failure(.extractionFailed) }
        if case .failure(let r) = UpdatePolicy.validateArchiveEntries(entries) { return .failure(r) }

        // 2. Extract with the system tool (quarantine is propagated, never stripped).
        let extracted = staging.appendingPathComponent("extracted", isDirectory: true)
        guard (try? fm.createDirectory(at: extracted, withIntermediateDirectories: false)) != nil,
              Self.run("/usr/bin/ditto", ["-x", "-k", zip.path, extracted.path]) != nil else {
            return .failure(.extractionFailed)
        }
        try? fm.removeItem(at: extracted.appendingPathComponent("__MACOSX"))

        // 3. Exactly one top-level item: a real ClipSync.app directory.
        let top = (try? fm.contentsOfDirectory(atPath: extracted.path)) ?? []
        guard top == [UpdatePolicy.expectedAppName] else {
            return .failure(top.contains(UpdatePolicy.expectedAppName) ? .unexpectedArchiveContent : .missingApp)
        }
        let app = extracted.appendingPathComponent(UpdatePolicy.expectedAppName, isDirectory: true)
        guard (try? fm.attributesOfItem(atPath: app.path)[.type] as? FileAttributeType) == .typeDirectory else {
            return .failure(.unsafeLink)
        }

        // 4. Every item inside: regular file, directory, or downward-only symlink; no hard links.
        if case .failure(let r) = Self.inspectTree(app) { return .failure(r) }

        // 5. Signature first; only then trust the (signed) Info.plist.
        let requirement = UpdatePolicy.designatedRequirement(teamIdentifier: team, bundleIdentifier: expectedBundleId)
        let signature = verifier(app, requirement)
        let info = Self.candidateInfo(app)
        switch UpdatePolicy.evaluateCandidate(info, signature: signature, expectedTeam: team,
                                              expectedBundleId: expectedBundleId, currentVersion: currentVersion) {
        case .success(let version):
            try? fm.removeItem(at: zip)
            return .success(StagedUpdate(appURL: app, version: version, stagingDirectory: staging))
        case .failure(let r):
            return .failure(r)
        }
    }

    /// Moves a verified app into `directory` under a fresh name (never overwriting anything)
    /// and removes the staging directory. Returns the new location.
    static func handOff(_ staged: StagedUpdate, to directory: URL) -> URL? {
        let fm = FileManager.default
        defer { try? fm.removeItem(at: staged.stagingDirectory) }
        let safeVersion = staged.version.filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
        for attempt in 0..<100 {
            let name = attempt == 0 ? "ClipSync \(safeVersion).app" : "ClipSync \(safeVersion) (\(attempt)).app"
            let dest = directory.appendingPathComponent(name, isDirectory: true)
            if fm.fileExists(atPath: dest.path) { continue }
            if (try? fm.moveItem(at: staged.appURL, to: dest)) != nil { return dest }
            return nil
        }
        return nil
    }

    // MARK: - Helpers

    private static func inspectTree(_ app: URL) -> Result<Void, UpdatePolicy.Rejection> {
        let fm = FileManager.default
        guard let walker = fm.enumerator(atPath: app.path) else { return .failure(.extractionFailed) }
        for case let relative as String in walker {
            if relative.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) {
                return .failure(.unsafeArchiveEntry)
            }
            let path = app.appendingPathComponent(relative).path
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let type = attrs[.type] as? FileAttributeType else { return .failure(.extractionFailed) }
            switch type {
            case .typeDirectory:
                continue
            case .typeRegular:
                // A regular file with more than one link could alias something outside staging.
                if let links = attrs[.referenceCount] as? NSNumber, links.intValue > 1 { return .failure(.unsafeLink) }
            case .typeSymbolicLink:
                guard let target = try? fm.destinationOfSymbolicLink(atPath: path),
                      UpdatePolicy.isSafeSymlinkTarget(target) else { return .failure(.unsafeLink) }
            default:
                return .failure(.unexpectedArchiveContent) // devices, FIFOs, sockets
            }
        }
        return .success(())
    }

    private static func candidateInfo(_ app: URL) -> UpdatePolicy.CandidateInfo {
        let plist = app.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return UpdatePolicy.CandidateInfo(bundleIdentifier: nil, shortVersion: nil, executableExists: false)
        }
        var executableExists = false
        if let exe = dict["CFBundleExecutable"] as? String, !exe.isEmpty, !exe.contains("/") {
            let exePath = app.appendingPathComponent("Contents/MacOS").appendingPathComponent(exe).path
            executableExists = (try? FileManager.default.attributesOfItem(atPath: exePath)[.type] as? FileAttributeType) == .typeRegular
        }
        return UpdatePolicy.CandidateInfo(bundleIdentifier: dict["CFBundleIdentifier"] as? String,
                                          shortVersion: dict["CFBundleShortVersionString"] as? String,
                                          executableExists: executableExists)
    }

    private static func listZipEntries(_ zip: URL) -> [String]? {
        guard let out = run("/usr/bin/zipinfo", ["-1", zip.path]) else { return nil }
        return String(decoding: out, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    /// Runs a fixed system tool with fixed arguments (never anything from the archive).
    /// Returns stdout on exit status 0, else nil.
    private static func run(_ tool: String, _ args: [String]) -> Data? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return p.terminationStatus == 0 ? data : nil
    }
}
