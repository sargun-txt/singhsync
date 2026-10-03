// UpdatePolicy.swift
// Pure security decisions for the macOS updater (no I/O, no Security framework), so every rule
// can be unit tested — see mac/PolicyTests/UpdatePolicyTests.swift.
//
// Trust model: an update is installable only if the downloaded ClipSync.app carries a valid
// Apple code signature from the SAME Developer ID team as the running app (and the same bundle
// identifier), and its own signed Info.plist declares a newer version. HTTPS and GitHub are
// transport only, never a trust anchor. Nothing downloaded is ever executed by the updater.

import Foundation

nonisolated enum UpdatePolicy {

    static let expectedAppName = "ClipSync.app"
    static let maxDownloadBytes: Int64 = 500 * 1024 * 1024
    static let maxArchiveEntries = 20_000
    /// Hosts GitHub uses for the release API, release pages and asset downloads (redirects).
    static let allowedHosts: Set<String> = [
        "api.github.com", "github.com", "objects.githubusercontent.com",
        "release-assets.githubusercontent.com", "codeload.github.com",
    ]

    enum Rejection: String, Error, Equatable {
        case noTrustAnchor = "This copy of ClipSync isn't signed with a Developer ID, so updates can't be verified automatically."
        case noMacAsset = "The release has no macOS download."
        case ambiguousAsset = "The release has more than one possible macOS download."
        case untrustedURL = "The download location isn't an expected GitHub address."
        case tooLarge = "The download is larger than expected."
        case unsafeArchiveEntry = "The update archive contains an unsafe path."
        case unexpectedArchiveContent = "The update archive contains unexpected files."
        case missingApp = "The update archive doesn't contain ClipSync.app."
        case unsafeLink = "The update contains a link that points outside the app."
        case invalidSignature = "The update isn't signed by the ClipSync developer."
        case wrongBundle = "The downloaded app isn't ClipSync."
        case badVersion = "The downloaded app has an unreadable version."
        case notNewer = "The downloaded app isn't newer than this version."
        case missingExecutable = "The downloaded app is incomplete."
        case extractionFailed = "The update archive couldn't be extracted."
    }

    // MARK: - Versions

    struct Version: Equatable {
        let numbers: [Int]
        let prerelease: String?
    }

    /// Strict "1.2.3" / "v1.2.3" / "1.2.3-beta" parsing. Anything else is nil (rejected).
    static func parseVersion(_ raw: String) -> Version? {
        var s = raw.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("v") || s.hasPrefix("V") { s.removeFirst() }
        let parts = s.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let numberParts = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(numberParts.count) else { return nil }
        var numbers: [Int] = []
        for p in numberParts {
            guard !p.isEmpty, p.count <= 6, p.allSatisfy({ $0 >= "0" && $0 <= "9" }), let n = Int(p) else { return nil }
            numbers.append(n)
        }
        var pre: String?
        if parts.count == 2 {
            let tag = String(parts[1])
            guard !tag.isEmpty, tag.count <= 32,
                  tag.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == ".") }) else { return nil }
            pre = tag
        }
        return Version(numbers: numbers, prerelease: pre)
    }

    /// True only if `candidate` is strictly newer than `current`. Equal or older → false.
    static func isNewer(_ candidate: Version, than current: Version) -> Bool {
        for i in 0..<max(candidate.numbers.count, current.numbers.count) {
            let c = i < candidate.numbers.count ? candidate.numbers[i] : 0
            let o = i < current.numbers.count ? current.numbers[i] : 0
            if c != o { return c > o }
        }
        switch (candidate.prerelease, current.prerelease) {
        case (nil, .some): return true          // 3.0.0 > 3.0.0-beta
        case (.some, nil), (nil, nil): return false
        case let (.some(c), .some(o)): return c > o
        }
    }

    // MARK: - Release asset / URLs

    struct ReleaseAsset: Equatable {
        let name: String
        let url: URL?
        let size: Int64
    }

    static func isAllowedDownloadURL(_ url: URL?) -> Bool {
        guard let url, url.scheme?.lowercased() == "https", let host = url.host?.lowercased() else { return false }
        return allowedHosts.contains(host) && url.user == nil && url.password == nil
    }

    /// Exactly one macOS archive (`.zip`, not an Android package) must exist; anything ambiguous
    /// is rejected rather than guessed.
    static func selectAsset(_ assets: [ReleaseAsset]) -> Result<ReleaseAsset, Rejection> {
        let zips = assets.filter {
            let n = $0.name.lowercased()
            return n.hasSuffix(".zip") && !n.contains("android") && !n.contains("apk")
        }
        let macNamed = zips.filter { $0.name.lowercased().contains("mac") }
        let candidates = macNamed.isEmpty ? zips : macNamed
        guard !candidates.isEmpty else { return .failure(.noMacAsset) }
        guard candidates.count == 1, let asset = candidates.first else { return .failure(.ambiguousAsset) }
        guard isAllowedDownloadURL(asset.url) else { return .failure(.untrustedURL) }
        guard asset.size >= 0, asset.size <= maxDownloadBytes else { return .failure(.tooLarge) }
        return .success(asset)
    }

    // MARK: - Archive contents

    /// Every entry must be a relative path inside the single top-level `ClipSync.app/`
    /// (macOS resource-fork entries under `__MACOSX/` are ignored and not extracted into the app).
    /// Absolute paths, `..`, backslashes, control characters and any other top-level item —
    /// including install scripts — are rejected.
    static func validateArchiveEntries(_ entries: [String]) -> Result<Void, Rejection> {
        guard !entries.isEmpty, entries.count <= maxArchiveEntries else { return .failure(.unexpectedArchiveContent) }
        var sawApp = false
        for entry in entries {
            guard !entry.isEmpty, !entry.hasPrefix("/"), !entry.contains("\\"),
                  !entry.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
                return .failure(.unsafeArchiveEntry)
            }
            let components = entry.split(separator: "/", omittingEmptySubsequences: false)
            for (i, c) in components.enumerated() {
                if c == ".." || c == "." { return .failure(.unsafeArchiveEntry) }
                // An empty component is only allowed as the trailing slash of a directory entry.
                if c.isEmpty && i != components.count - 1 { return .failure(.unsafeArchiveEntry) }
            }
            if components[0] == "__MACOSX" { continue }
            guard components[0] == expectedAppName else { return .failure(.unexpectedArchiveContent) }
            sawApp = true
        }
        return sawApp ? .success(()) : .failure(.missingApp)
    }

    /// Symlinks inside the app may only point *downward*: relative, with no `.` or `..`
    /// components (e.g. framework links like `Versions/Current` → `A`). Lexically "contained"
    /// targets with `..` are refused too, because chained links (one to `.`, another to
    /// `that/..`) can resolve physically outside the bundle.
    static func isSafeSymlinkTarget(_ target: String) -> Bool {
        guard !target.isEmpty, !target.hasPrefix("/"), !target.contains("\\") else { return false }
        return target.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }

    // MARK: - Signature identity

    /// The Developer ID team the update must be signed by: the running app's own team. An ad-hoc
    /// or unsigned build has none, so it cannot verify updates (fail closed).
    static func expectedTeamIdentifier(selfTeam: String?) -> String? {
        guard let team = selfTeam, team.count == 10,
              team.allSatisfy({ ($0 >= "A" && $0 <= "Z") || ($0 >= "0" && $0 <= "9") }) else { return nil }
        return team
    }

    /// Code requirement: Apple-anchored certificate chain, this team, this bundle identifier.
    static func designatedRequirement(teamIdentifier: String, bundleIdentifier: String) -> String {
        "anchor apple generic and identifier \"\(bundleIdentifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    enum SignatureCheck: Equatable {
        case valid(teamIdentifier: String)
        case invalid
    }

    struct CandidateInfo: Equatable {
        let bundleIdentifier: String?
        let shortVersion: String?
        let executableExists: Bool
    }

    /// Final gate. Requires a verified signature from the expected team, then (from the signed
    /// Info.plist) the right bundle, an existing executable, and a strictly newer version.
    static func evaluateCandidate(_ info: CandidateInfo, signature: SignatureCheck?, expectedTeam: String?,
                                  expectedBundleId: String, currentVersion: String) -> Result<String, Rejection> {
        guard let expectedTeam else { return .failure(.noTrustAnchor) }
        guard case .valid(let team)? = signature, team == expectedTeam else { return .failure(.invalidSignature) }
        guard info.bundleIdentifier == expectedBundleId else { return .failure(.wrongBundle) }
        guard info.executableExists else { return .failure(.missingExecutable) }
        guard let raw = info.shortVersion, let candidate = parseVersion(raw), let current = parseVersion(currentVersion) else {
            return .failure(.badVersion)
        }
        guard isNewer(candidate, than: current) else { return .failure(.notNewer) }
        return .success(raw)
    }
}
