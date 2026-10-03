// CloudPairingAuth.swift
// Firestore pairing membership (v2). Byte-for-byte compatible with CloudPairingAuth.kt and
// protocol/generate_firestore_pairing_vectors.py.
//
// The phone creates pairings/{pairingId} as its only member, naming this Mac's Firebase UID
// (taken from the QR code) and storing
//
//   proof = hex(HMAC-SHA256(HKDF(pairing key, "ClipSync/Firestore/Pairing/v1"),
//               len16(pairingId) ‖ pairingId ‖ len16(androidUid) ‖ androidUid ‖
//               len16(macUid) ‖ macUid ‖ len16(nonce) ‖ nonce))
//
// The Mac accepts (adds itself to `members`) only after `evaluatePending` verifies the proof
// with the pairing key from its Keychain. The key never reaches Firestore.
//
// Deliberately limited to Foundation and CryptoKit so it can be tested on its own.

import Foundation
import CryptoKit

nonisolated enum CloudPairingAuth {

    static let version: Int64 = 2
    static let nonceLength = 16
    static let maxUidLength = 128
    private static let info = Data("ClipSync/Firestore/Pairing/v1".utf8)

    enum Rejection: Error, Equatable {
        case noPairingKey, wrongVersion, idMismatch, notAddressedToThisMac, badMembers
        case missingField, notPending, badProof
    }

    struct PendingPairing: Equatable {
        let pairingId: String
        let androidUid: String
        let androidDeviceName: String
    }

    static func membershipKey(rootKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: rootKey, salt: Data(), info: info, outputByteCount: 32)
    }

    static func message(pairingId: String, androidUid: String, macUid: String, nonce: Data) -> Data {
        var out = Data()
        for part in [Data(pairingId.utf8), Data(androidUid.utf8), Data(macUid.utf8), nonce] {
            precondition(part.count <= 0xFFFF)
            out.append(UInt8(part.count >> 8)); out.append(UInt8(part.count & 0xFF))
            out.append(part)
        }
        return out
    }

    static func proof(rootKey: SymmetricKey, pairingId: String, androidUid: String, macUid: String, nonce: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: message(pairingId: pairingId, androidUid: androidUid, macUid: macUid, nonce: nonce),
            using: membershipKey(rootKey: rootKey))
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    static func isValidUid(_ uid: String?) -> Bool {
        guard let uid, !uid.isEmpty, uid.count <= maxUidLength else { return false }
        return !uid.unicodeScalars.contains {
            $0 == "/" || CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0)
        }
    }

    /// Decides whether this Mac may join a pending pairing document. Everything in `data` was
    /// written by a client, so it is all checked; the proof is verified in constant time.
    static func evaluatePending(docId: String, data: [String: Any], myUid: String,
                                rootKey: SymmetricKey?) -> Result<PendingPairing, Rejection> {
        guard let rootKey else { return .failure(.noPairingKey) }
        guard (data["version"] as? NSNumber)?.int64Value == version else { return .failure(.wrongVersion) }
        guard data["pairingId"] as? String == docId else { return .failure(.idMismatch) }
        guard isValidUid(myUid), data["macUid"] as? String == myUid else { return .failure(.notAddressedToThisMac) }
        guard let androidUid = data["androidUid"] as? String, isValidUid(androidUid), androidUid != myUid,
              let members = data["members"] as? [String], members == [androidUid] else {
            return .failure(.badMembers)
        }
        // `members == [androidUid]` above is what marks the pairing as not yet joined; the phone
        // may already have set the cosmetic status to "active" before this Mac joins.
        guard let status = data["status"] as? String, status == "pending" || status == "active" else {
            return .failure(.notPending)
        }
        guard let proofHex = data["proof"] as? String, let proof = hexData(proofHex), proof.count == 32,
              let nonceHex = data["proofNonce"] as? String, let nonce = hexData(nonceHex), nonce.count == nonceLength else {
            return .failure(.missingField)
        }
        let msg = message(pairingId: docId, androidUid: androidUid, macUid: myUid, nonce: nonce)
        guard HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: msg,
                                                     using: membershipKey(rootKey: rootKey)) else {
            return .failure(.badProof)
        }
        let name = (data["androidDeviceName"] as? String).map { String($0.prefix(64)) } ?? "Android Device"
        return .success(PendingPairing(pairingId: docId, androidUid: androidUid, androidDeviceName: name))
    }

    /// A restored pairing must have completed v2 membership for this identity.
    static func canRestore(docId: String, data: [String: Any], myUid: String) -> Bool {
        guard isValidUid(myUid), (data["version"] as? NSNumber)?.int64Value == version,
              data["pairingId"] as? String == docId,
              let androidUid = data["androidUid"] as? String, isValidUid(androidUid),
              data["macUid"] as? String == myUid, androidUid != myUid,
              let members = data["members"] as? [String], members == [androidUid, myUid] else { return false }
        return true
    }

    /// Fields for a cloud clipboard item, or nil if the upload must not happen (no
    /// authenticated identity, no pairing, or no ciphertext). There is no plaintext path.
    static func clipboardItemFields(uid: String?, pairingId: String?, encryptedContent: String?,
                                    deviceId: String) -> [String: Any]? {
        guard isValidUid(uid), let pairingId, !pairingId.isEmpty,
              let encryptedContent, !encryptedContent.isEmpty else { return nil }
        return ["content": encryptedContent, "pairingId": pairingId, "sourceDeviceId": deviceId,
                "sourceUid": uid!, "type": "text"]
    }

    /// The pairing key from its stored 64-character hex form.
    static func rootKey(hex: String?) -> SymmetricKey? {
        guard let hex, hex.count == 64, let data = hexData(hex) else { return nil }
        return SymmetricKey(data: data)
    }

    private static func hexData(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        return out
    }
}
