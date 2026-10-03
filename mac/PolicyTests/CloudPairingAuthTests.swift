// Tests for ClipSync/CloudPairingAuth.swift. Called from main.swift.
// Loads the shared fixtures in protocol/firestore-pairing-v1-test-vectors.properties.

import Foundation
import CryptoKit

private func hex(_ s: String) -> Data {
    var data = Data(), chars = Array(s), i = 0
    while i + 1 < chars.count { data.append(UInt8(String(chars[i...i + 1]), radix: 16)!); i += 2 }
    return data
}
private func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func runCloudPairingAuthTests() {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("protocol/firestore-pairing-v1-test-vectors.properties")
    guard let text = try? String(contentsOf: url, encoding: .utf8) else { check(false, "missing \(url.path)"); return }
    var v: [String: String] = [:]
    for line in text.split(separator: "\n") where !line.hasPrefix("#") {
        let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
        if parts.count == 2 { v[parts[0]] = parts[1] }
    }
    let root = SymmetricKey(data: hex(v["rootKey"]!))
    let pid = v["pairingId"]!, a = v["androidUid"]!, m = v["macUid"]!
    let nonce = hex(v["nonce"]!)

    let restored: [String: Any] = ["version": 2, "pairingId": pid, "androidUid": a,
                                   "macUid": m, "members": [a, m]]
    check(CloudPairingAuth.canRestore(docId: pid, data: restored, myUid: m), "complete v2 pairing restores")
    check(!CloudPairingAuth.canRestore(docId: pid, data: [:], myUid: m), "legacy pairing requires re-pair")
    check(!CloudPairingAuth.canRestore(docId: pid, data: restored, myUid: "replacementUid"), "changed UID requires re-pair")
    var incomplete = restored; incomplete["members"] = [a]
    check(!CloudPairingAuth.canRestore(docId: pid, data: incomplete, myUid: m), "pending membership cannot restore")
    var legacy = restored; legacy["version"] = 1
    check(!CloudPairingAuth.canRestore(docId: pid, data: legacy, myUid: m), "old version cannot restore")
    check(!CloudPairingAuth.canRestore(docId: "wrongDoc", data: restored, myUid: m), "restored pairing ID must match")

    // MARK: Fixtures and key separation
    check(CloudPairingAuth.membershipKey(rootKey: root).withUnsafeBytes { hexString(Data($0)) } == v["membershipKey"],
          "membership key matches fixture")
    check(hexString(CloudPairingAuth.message(pairingId: pid, androidUid: a, macUid: m, nonce: nonce)) == v["message"],
          "canonical message matches fixture")
    check(CloudPairingAuth.proof(rootKey: root, pairingId: pid, androidUid: a, macUid: m, nonce: nonce) == v["proof"],
          "proof matches fixture")
    let mk = CloudPairingAuth.membershipKey(rootKey: root).withUnsafeBytes { Data($0) }
    check(mk != TcpFrameProtocol.authKey(rootKey: root).withUnsafeBytes { Data($0) }
          && mk != BleControlProtocol.authKey(rootKey: root).withUnsafeBytes { Data($0) },
          "membership key is separate from TCP and BLE keys")

    // MARK: Mac acceptance of a pending pairing
    func doc(_ overrides: [String: Any] = [:], removing: [String] = []) -> [String: Any] {
        var d: [String: Any] = [
            "pairingId": pid, "version": NSNumber(value: 2), "members": [a], "androidUid": a, "macUid": m,
            "proof": v["proof"]!, "proofNonce": v["nonce"]!, "status": "pending", "androidDeviceName": "Pixel 8",
        ]
        for (k, val) in overrides { d[k] = val }
        for k in removing { d.removeValue(forKey: k) }
        return d
    }
    func rejection(_ d: [String: Any], docId: String? = nil, me: String? = nil, key: SymmetricKey? = nil, noKey: Bool = false)
        -> CloudPairingAuth.Rejection? {
        switch CloudPairingAuth.evaluatePending(docId: docId ?? pid, data: d, myUid: me ?? m, rootKey: noKey ? nil : (key ?? root)) {
        case .success: return nil
        case .failure(let r): return r
        }
    }

    if case .success(let p) = CloudPairingAuth.evaluatePending(docId: pid, data: doc(), myUid: m, rootKey: root) {
        check(p.androidUid == a && p.androidDeviceName == "Pixel 8", "valid pending pairing accepted")
    } else { check(false, "valid pending pairing accepted") }

    check(rejection(doc(), key: SymmetricKey(size: .bits256)) == .badProof, "Mac with a different pairing key rejects")
    check(rejection(doc(), noKey: true) == .noPairingKey, "no pairing key → reject")
    check(rejection(doc(), me: "someOtherMacUid") == .notAddressedToThisMac, "pairing addressed to another Mac rejected")
    check(rejection(doc(["proof": String(repeating: "0", count: 64)])) == .badProof, "forged proof rejected")
    check(rejection(doc(["proofNonce": String(repeating: "1", count: 32)])) == .badProof, "changed nonce rejected")
    check(rejection(doc(["androidUid": "attackerUid", "members": ["attackerUid"]])) == .badProof,
          "substituted phone identity rejected")
    check(rejection(doc(), docId: "otherDocId") == .idMismatch, "pairingId/doc ID mismatch rejected")
    check(rejection(doc(["pairingId": "otherDocId"]), docId: "otherDocId") == .badProof, "proof bound to pairingId")
    check(rejection(doc(["members": [a, m]])) == .badMembers, "already-joined pairing not re-accepted")
    check(rejection(doc(["members": ["attackerUid"]])) == .badMembers, "members not matching androidUid rejected")
    check(rejection(doc(["androidUid": m, "members": [m]])) == .badMembers, "Mac UID as phone rejected")
    check(rejection(doc(["version": NSNumber(value: 1)])) == .wrongVersion, "legacy version rejected")
    check(rejection(doc(removing: ["version"])) == .wrongVersion, "legacy document without version rejected")
    check(rejection(doc(["status": "active"])) == nil, "phone marking status active before the Mac joins is still accepted")
    check(rejection(doc(["status": "revoked"])) == .notPending, "unknown status rejected")
    check(rejection(doc(removing: ["status"])) == .notPending, "missing status rejected")
    check(rejection(doc(removing: ["proof"])) == .missingField, "missing proof rejected")
    check(rejection(doc(["proof": "abc"])) == .missingField, "short proof rejected")
    check(rejection(doc(["proof": String(repeating: "zz", count: 32)])) == .missingField, "non-hex proof rejected")

    // MARK: Upload gating
    check(CloudPairingAuth.clipboardItemFields(uid: nil, pairingId: pid, encryptedContent: "CT==", deviceId: "d") == nil,
          "no Firebase identity → no clipboard upload")
    check(CloudPairingAuth.clipboardItemFields(uid: m, pairingId: nil, encryptedContent: "CT==", deviceId: "d") == nil,
          "no pairing → no clipboard upload")
    check(CloudPairingAuth.clipboardItemFields(uid: m, pairingId: pid, encryptedContent: nil, deviceId: "d") == nil,
          "encryption failure → no clipboard upload")
    let fields = CloudPairingAuth.clipboardItemFields(uid: m, pairingId: pid, encryptedContent: "CT==", deviceId: "d")
    check(fields?["sourceUid"] as? String == m && fields?["content"] as? String == "CT==" && fields?.count == 5,
          "authenticated upload carries sourceUid and ciphertext only")
    check(!CloudPairingAuth.isValidUid("a/b") && !CloudPairingAuth.isValidUid("") && !CloudPairingAuth.isValidUid(String(repeating: "x", count: 129)),
          "malformed UIDs refused")
}
