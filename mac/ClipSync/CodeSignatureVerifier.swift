// CodeSignatureVerifier.swift
// macOS code-signature checks for the updater, using the Security framework only (no shell,
// no codesign/spctl subprocesses). Testable against real signed bundles — see UpdatePolicyTests.

import Foundation
import Security

nonisolated enum CodeSignatureVerifier {

    /// Team identifier from the running app's own signature; nil for ad-hoc/unsigned builds.
    static func selfTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        return teamIdentifier(of: staticCode)
    }

    /// Team identifier recorded in the bundle's signature, without validating it. Diagnostic
    /// only — never use this as a trust decision; use `check(appAt:requirement:)`.
    static func unverifiedTeamIdentifier(ofAppAt url: URL) -> String? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        return teamIdentifier(of: staticCode)
    }

    /// Full static validation of the bundle (every architecture, nested code, strict resource
    /// checks) against `requirement`. Returns `.valid(team)` only if everything passes.
    static func check(appAt url: URL, requirement: String) -> UpdatePolicy.SignatureCheck {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode else {
            return .invalid
        }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req else {
            return .invalid
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate)
        guard SecStaticCodeCheckValidity(staticCode, flags, req) == errSecSuccess,
              let team = teamIdentifier(of: staticCode) else {
            return .invalid
        }
        return .valid(teamIdentifier: team)
    }

    private static func teamIdentifier(of code: SecStaticCode) -> String? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
