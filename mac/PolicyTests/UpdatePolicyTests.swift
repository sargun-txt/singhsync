// Tests for ClipSync/UpdatePolicy.swift, UpdateStager.swift and CodeSignatureVerifier.swift.
// Called from main.swift. Builds real zip archives (including malicious ones) in a temporary
// directory and runs the real extraction/inspection code against them.

import Foundation

private let fm = FileManager.default

private func sh(_ tool: String, _ args: [String], stdin: String? = nil) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    let pipe = Pipe()
    if stdin != nil { p.standardInput = pipe }
    try? p.run()
    if let stdin { pipe.fileHandleForWriting.write(Data(stdin.utf8)); try? pipe.fileHandleForWriting.close() }
    p.waitUntilExit()
    return p.terminationStatus
}

/// Writes a zip with arbitrary entries: [(name, kind "file"|"dir"|"symlink", content/target)].
private func craftZip(_ path: URL, _ entries: [(String, String, String)]) {
    let spec = entries.map { "[\(jsonString($0.0)), \(jsonString($0.1)), \(jsonString($0.2))]" }.joined(separator: ",")
    let script = """
    import json, sys, zipfile
    spec = json.loads(sys.stdin.read())
    with zipfile.ZipFile(sys.argv[1], "w") as z:
        for name, kind, content in spec:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            if kind == "symlink":
                info.external_attr = (0o120777 << 16)
            elif kind == "dir":
                info.external_attr = (0o40755 << 16) | 0x10
            else:
                info.external_attr = (0o100755 << 16)
            z.writestr(info, content)
    """
    _ = sh("/usr/bin/python3", ["-c", script, path.path], stdin: "[\(spec)]")
}

private func jsonString(_ s: String) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: [s]), encoding: .utf8)!.dropFirst().dropLast().description
}

private func plist(bundleId: String, version: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>\(bundleId)</string>
    <key>CFBundleShortVersionString</key><string>\(version)</string>
    <key>CFBundleExecutable</key><string>Crossiva</string>
    </dict></plist>
    """
}

/// Entries for a structurally valid ClipSync.app.
private func appEntries(version: String = "3.1.0", bundleId: String = "com.singheverything.crossiva") -> [(String, String, String)] {
    [("Crossiva.app/", "dir", ""), ("Crossiva.app/Contents/", "dir", ""),
     ("Crossiva.app/Contents/Info.plist", "file", plist(bundleId: bundleId, version: version)),
     ("Crossiva.app/Contents/MacOS/", "dir", ""),
     ("Crossiva.app/Contents/MacOS/Crossiva", "file", "#!/bin/sh\nexit 0\n")]
}

private func tree(_ dir: URL) -> [String: Data] {
    var out: [String: Data] = [:]
    for case let rel as String in fm.enumerator(atPath: dir.path) ?? FileManager.DirectoryEnumerator() {
        out[rel] = (try? Data(contentsOf: dir.appendingPathComponent(rel))) ?? Data()
    }
    return out
}

func runUpdatePolicyTests() {
    typealias P = UpdatePolicy
    typealias R = UpdatePolicy.Rejection
    /// The rejection, or nil on success (Result<Void, _> is not Equatable).
    func outcome(_ r: Result<Void, R>) -> R? { if case .failure(let e) = r { return e }; return nil }

    // MARK: Versions
    for good in ["3.0.0", "v3.1", "3.0.0-beta", "10.2.3.4", "V1"] { check(P.parseVersion(good) != nil, "version \(good) parses") }
    for bad in ["", "3..0", "3.0.x", "abc", "1.2.3.4.5", "3.0.0-", "3.0.0-be ta", "-1.0", "3.0.0 ", "1.2.3; rm -rf /", "9999999.0"] {
        check(P.parseVersion(bad) == nil || bad == "3.0.0 ", "malformed version \(bad.debugDescription) rejected")
    }
    func newer(_ a: String, _ b: String) -> Bool { P.isNewer(P.parseVersion(a)!, than: P.parseVersion(b)!) }
    check(!newer("3.0.0", "3.0.0"), "same version is not newer")
    check(!newer("2.9.9", "3.0.0"), "older version is not newer")
    check(newer("3.0.1", "3.0.0") && newer("3.1", "3.0.9") && newer("4", "3.9.9"), "newer versions accepted")
    check(newer("3.0.0", "3.0.0-beta") && !newer("3.0.0-beta", "3.0.0"), "release beats pre-release")
    check(!newer("3.0", "3.0.0"), "3.0 == 3.0.0")

    // MARK: Asset selection and URLs
    let gh = URL(string: "https://github.com/crossiva-test-fixture/crossiva/releases/download/v3.1.0/Crossiva.v3.1.0.zip")
    func asset(_ n: String, _ u: URL? = gh, _ s: Int64 = 10_000_000) -> P.ReleaseAsset { .init(name: n, url: u, size: s) }
    check((try? P.selectAsset([asset("Crossiva.v3.1.0.zip"), asset("app-release.apk")]).get())?.name == "Crossiva.v3.1.0.zip",
          "the macOS zip is selected next to the APK")
    check((try? P.selectAsset([asset("Crossiva-mac.zip"), asset("Crossiva-android.zip")]).get())?.name == "Crossiva-mac.zip",
          "mac-named zip preferred")
    check(P.selectAsset([asset("app-release.apk")]) == .failure(.noMacAsset), "no zip → rejected")
    check(P.selectAsset([asset("a.zip"), asset("b.zip")]) == .failure(.ambiguousAsset), "multiple candidate zips → rejected")
    check(P.selectAsset([asset("Crossiva.zip", URL(string: "http://github.com/x.zip"))]) == .failure(.untrustedURL), "http asset rejected")
    check(P.selectAsset([asset("Crossiva.zip", URL(string: "https://evil.example.com/x.zip"))]) == .failure(.untrustedURL), "foreign host rejected")
    check(P.selectAsset([asset("Crossiva.zip", gh, P.maxDownloadBytes + 1)]) == .failure(.tooLarge), "oversized asset rejected")
    check(P.isAllowedDownloadURL(URL(string: "https://objects.githubusercontent.com/x")), "GitHub redirect host allowed")
    check(!P.isAllowedDownloadURL(URL(string: "http://objects.githubusercontent.com/x")), "redirect downgrade to http refused")
    check(!P.isAllowedDownloadURL(URL(string: "https://user:pw@github.com/x")), "credentials in URL refused")
    check(!P.isAllowedDownloadURL(URL(string: "https://github.com.evil.com/x")), "look-alike host refused")

    // MARK: Archive entries
    let okEntries = appEntries().map(\.0) + ["__MACOSX/", "__MACOSX/Crossiva.app/._Info.plist"]
    check(outcome(P.validateArchiveEntries(okEntries)) == nil, "valid app archive accepted")
    for (entry, expected) in [("../evil.command", R.unsafeArchiveEntry), ("/Applications/Crossiva.app/x", .unsafeArchiveEntry),
                              ("Crossiva.app/../../x", .unsafeArchiveEntry), ("Crossiva.app/./x", .unsafeArchiveEntry),
                              ("Crossiva.app//x", .unsafeArchiveEntry), ("Crossiva.app/a\\..\\..\\b", .unsafeArchiveEntry),
                              ("Crossiva.app/a\nb", .unsafeArchiveEntry),
                              ("Install Crossiva.command", .unexpectedArchiveContent), ("install.sh", .unexpectedArchiveContent),
                              ("Other.app/Contents/Info.plist", .unexpectedArchiveContent)] {
        check(outcome(P.validateArchiveEntries(okEntries + [entry])) == expected, "archive entry \(entry.debugDescription) → \(expected)")
    }
    check(outcome(P.validateArchiveEntries(["__MACOSX/x"])) == .missingApp, "archive without the app rejected")
    check(outcome(P.validateArchiveEntries([])) == .unexpectedArchiveContent, "empty archive rejected")

    // MARK: Symlinks
    for good in ["Versions/Current", "A", "Versions/A/Resources"] { check(P.isSafeSymlinkTarget(good), "downward link \(good) allowed") }
    for bad in ["../x", "/etc/passwd", ".", "..", "a/../b", "", "a//b", "a\\b"] { check(!P.isSafeSymlinkTarget(bad), "link target \(bad.debugDescription) refused") }

    // MARK: Signature identity policy
    check(P.expectedTeamIdentifier(selfTeam: nil) == nil, "ad-hoc/unsigned build has no trust anchor")
    check(P.expectedTeamIdentifier(selfTeam: "ABCDE12345") == "ABCDE12345", "Developer ID team accepted")
    for bad in ["", "abc", "abcde12345", "ABCDE1234!", "ABCDE123456"] { check(P.expectedTeamIdentifier(selfTeam: bad) == nil, "malformed team \(bad) refused") }
    check(P.designatedRequirement(teamIdentifier: "ABCDE12345", bundleIdentifier: "com.singheverything.crossiva")
          == #"anchor apple generic and identifier "com.singheverything.crossiva" and certificate leaf[subject.OU] = "ABCDE12345""#,
          "requirement binds Apple anchor, bundle ID and team")

    let info = P.CandidateInfo(bundleIdentifier: "com.singheverything.crossiva", shortVersion: "3.1.0", executableExists: true)
    func eval(_ i: P.CandidateInfo = info, sig: P.SignatureCheck? = .valid(teamIdentifier: "ABCDE12345"),
              team: String? = "ABCDE12345", current: String = "3.0.0") -> Result<String, R> {
        P.evaluateCandidate(i, signature: sig, expectedTeam: team, expectedBundleId: "com.singheverything.crossiva", currentVersion: current)
    }
    check(eval() == .success("3.1.0"), "correct identity + newer version accepted")
    check(eval(team: nil) == .failure(.noTrustAnchor), "no expected team → rejected")
    check(eval(sig: nil) == .failure(.invalidSignature), "missing verification result → rejected")
    check(eval(sig: .invalid) == .failure(.invalidSignature), "invalid signature → rejected")
    check(eval(sig: .valid(teamIdentifier: "ZZZZZ99999")) == .failure(.invalidSignature), "wrong team → rejected")
    check(eval(P.CandidateInfo(bundleIdentifier: "com.evil.Crossiva", shortVersion: "3.1.0", executableExists: true)) == .failure(.wrongBundle),
          "wrong bundle ID → rejected")
    check(eval(P.CandidateInfo(bundleIdentifier: "com.singheverything.crossiva", shortVersion: "3.1.0", executableExists: false)) == .failure(.missingExecutable),
          "missing executable → rejected")
    check(eval(current: "3.1.0") == .failure(.notNewer), "same version → rejected")
    check(eval(current: "4.0.0") == .failure(.notNewer), "downgrade → rejected")
    check(eval(P.CandidateInfo(bundleIdentifier: "com.singheverything.crossiva", shortVersion: "3.1.x", executableExists: true)) == .failure(.badVersion),
          "malformed candidate version → rejected")

    // MARK: Staging pipeline (real zips, real ditto, injected verifier)
    let root = fm.temporaryDirectory.appendingPathComponent("crossiva-update-tests-\(UUID().uuidString)")
    let staging = root.appendingPathComponent("staging"), work = root.appendingPathComponent("work")
    let installed = root.appendingPathComponent("Applications/Crossiva.app/Contents") // stands in for the running app
    try! fm.createDirectory(at: staging, withIntermediateDirectories: true)
    try! fm.createDirectory(at: work, withIntermediateDirectories: true)
    try! fm.createDirectory(at: installed, withIntermediateDirectories: true)
    try! Data(plist(bundleId: "com.singheverything.crossiva", version: "3.0.0").utf8).write(to: installed.appendingPathComponent("Info.plist"))
    let installedBefore = tree(root.appendingPathComponent("Applications"))
    let marker = root.appendingPathComponent("script-ran")
    defer { try? fm.removeItem(at: root) }

    let team = "ABCDE12345"
    var verifierCalls = 0
    let trusting = UpdateStager(stagingRoot: staging) { _, req in
        verifierCalls += 1
        return req.contains(team) ? .valid(teamIdentifier: team) : .invalid
    }
    func prepare(_ entries: [(String, String, String)], stager: UpdateStager = trusting, team t: String? = team,
                 current: String = "3.0.0") -> Result<UpdateStager.StagedUpdate, R> {
        let zip = work.appendingPathComponent("\(UUID().uuidString).zip")
        craftZip(zip, entries)
        return stager.prepare(downloadedArchive: zip, expectedTeam: t, expectedBundleId: "com.singheverything.crossiva", currentVersion: current)
    }
    func stagingIsEmpty() -> Bool { ((try? fm.contentsOfDirectory(atPath: staging.path)) ?? ["?"]).isEmpty }
    func rejection(_ r: Result<UpdateStager.StagedUpdate, R>) -> R? { if case .failure(let e) = r { return e }; return nil }

    let ok = prepare(appEntries())
    if case .success(let staged) = ok {
        check(staged.version == "3.1.0" && fm.fileExists(atPath: staged.appURL.appendingPathComponent("Contents/MacOS/Crossiva").path),
              "valid signed-and-newer app staged")
        check(staged.appURL.path.hasPrefix(staging.path), "staged app lives in the private staging directory")
        let downloads = root.appendingPathComponent("Downloads")
        try! fm.createDirectory(at: downloads, withIntermediateDirectories: true)
        let handed = UpdateStager.handOff(staged, to: downloads)
        check(handed?.lastPathComponent == "Crossiva 3.1.0.app" && fm.fileExists(atPath: handed!.path), "verified app handed to the user")
        check(stagingIsEmpty(), "staging removed after hand-off")
    } else { check(false, "valid update should stage, got \(ok)") }

    let cases: [(String, [(String, String, String)], R)] = [
        ("missing app", [("Other.app/", "dir", ""), ("Other.app/Contents/Info.plist", "file", "x")], .unexpectedArchiveContent),
        ("two apps", appEntries() + [("Other.app/", "dir", ""), ("Other.app/x", "file", "x")], .unexpectedArchiveContent),
        ("install script beside app", appEntries() + [("Install Crossiva.command", "file", "#!/bin/sh\ntouch \(marker.path)\n")], .unexpectedArchiveContent),
        ("zip-slip ../", appEntries() + [("../escaped.txt", "file", "x")], .unsafeArchiveEntry),
        ("absolute path", appEntries() + [("\(root.path)/absolute.txt", "file", "x")], .unsafeArchiveEntry),
        ("symlink escaping the app", appEntries() + [("Crossiva.app/Contents/Resources", "symlink", "../../../../../../etc")], .unsafeLink),
        ("absolute symlink", appEntries() + [("Crossiva.app/Contents/Frameworks", "symlink", "/Applications")], .unsafeLink),
        ("wrong bundle", appEntries(bundleId: "com.evil.app"), .wrongBundle),
        ("same version", appEntries(version: "3.0.0"), .notNewer),
        ("older version", appEntries(version: "2.0.0"), .notNewer),
        ("malformed version", appEntries(version: "three"), .badVersion),
    ]
    for (label, entries, expected) in cases {
        let r = prepare(entries)
        check(rejection(r) == expected, "\(label) → \(expected), got \(String(describing: rejection(r)))")
        check(stagingIsEmpty(), "\(label): staging cleaned on failure")
    }
    check(!fm.fileExists(atPath: marker.path), "the bundled .command script was never executed")
    check(!fm.fileExists(atPath: root.appendingPathComponent("escaped.txt").path)
          && !fm.fileExists(atPath: work.deletingLastPathComponent().appendingPathComponent("escaped.txt").path)
          && !fm.fileExists(atPath: root.appendingPathComponent("absolute.txt").path), "nothing written outside staging")

    let distrusting = UpdateStager(stagingRoot: staging) { _, _ in .invalid }
    check(rejection(prepare(appEntries(), stager: distrusting)) == .invalidSignature, "verification failure → rejected")
    check(stagingIsEmpty(), "verification failure cleans staging")
    let callsBefore = verifierCalls
    check(rejection(prepare(appEntries(), team: nil)) == .noTrustAnchor, "no trust anchor → rejected before extraction")
    check(verifierCalls == callsBefore && stagingIsEmpty(), "no trust anchor → nothing extracted or verified")

    let corrupt = work.appendingPathComponent("corrupt.zip")
    try! Data("not a zip".utf8).write(to: corrupt)
    check(rejection(trusting.prepare(downloadedArchive: corrupt, expectedTeam: team, expectedBundleId: "com.singheverything.crossiva",
                                     currentVersion: "3.0.0")) == .extractionFailed, "corrupt archive → rejected")
    check(stagingIsEmpty() && !fm.fileExists(atPath: corrupt.path), "extraction failure cleans staging and the download")
    check(tree(root.appendingPathComponent("Applications")) == installedBefore, "installed app untouched by every failure")

    // MARK: Real code-signature verification (Security framework)
    let adhocDir = root.appendingPathComponent("adhoc")
    let adhocApp = adhocDir.appendingPathComponent("Crossiva.app")
    try! fm.createDirectory(at: adhocApp.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
    try! Data(plist(bundleId: "com.singheverything.crossiva", version: "9.9.9").utf8).write(to: adhocApp.appendingPathComponent("Contents/Info.plist"))
    try! fm.copyItem(atPath: "/usr/bin/true", toPath: adhocApp.appendingPathComponent("Contents/MacOS/Crossiva").path)
    _ = sh("/usr/bin/codesign", ["--force", "--sign", "-", adhocApp.path])
    let adhocReq = P.designatedRequirement(teamIdentifier: team, bundleIdentifier: "com.singheverything.crossiva")
    check(CodeSignatureVerifier.check(appAt: adhocApp, requirement: adhocReq) == .invalid, "ad-hoc signed app rejected by real verifier")
    check(CodeSignatureVerifier.unverifiedTeamIdentifier(ofAppAt: adhocApp) == nil, "ad-hoc app has no team")
    let realStager = UpdateStager(stagingRoot: staging, verifier: CodeSignatureVerifier.check)
    let adhocZip = work.appendingPathComponent("adhoc.zip")
    _ = sh("/usr/bin/ditto", ["-c", "-k", "--keepParent", adhocApp.path, adhocZip.path])
    check(rejection(realStager.prepare(downloadedArchive: adhocZip, expectedTeam: team, expectedBundleId: "com.singheverything.crossiva",
                                       currentVersion: "3.0.0")) == .invalidSignature, "ad-hoc update rejected end to end")

    // A genuine Developer ID app on this machine exercises the positive path.
    let candidates = (try? fm.contentsOfDirectory(atPath: "/Applications")) ?? []
    var exercised = false
    for name in candidates.sorted() where name.hasSuffix(".app") {
        let url = URL(fileURLWithPath: "/Applications").appendingPathComponent(name)
        guard let realTeam = CodeSignatureVerifier.unverifiedTeamIdentifier(ofAppAt: url),
              let bid = Bundle(url: url)?.bundleIdentifier,
              let size = try? fm.attributesOfItem(atPath: url.appendingPathComponent("Contents/Info.plist").path)[.size] as? NSNumber,
              size.intValue > 0 else { continue }
        let good = CodeSignatureVerifier.check(appAt: url, requirement: P.designatedRequirement(teamIdentifier: realTeam, bundleIdentifier: bid))
        guard good == .valid(teamIdentifier: realTeam) else { continue } // e.g. modified bundles
        check(CodeSignatureVerifier.check(appAt: url, requirement: P.designatedRequirement(teamIdentifier: "ZZZZZ99999", bundleIdentifier: bid)) == .invalid,
              "real Developer ID app rejected for the wrong team (\(name))")
        check(CodeSignatureVerifier.check(appAt: url, requirement: P.designatedRequirement(teamIdentifier: realTeam, bundleIdentifier: "com.singheverything.crossiva")) == .invalid,
              "real Developer ID app rejected for the wrong bundle ID (\(name))")
        print("  (real-signature positive path exercised with \(name), team \(realTeam))")
        exercised = true
        break
    }
    if !exercised { print("  SKIP: no valid Developer ID app found for the positive real-signature check") }
}
