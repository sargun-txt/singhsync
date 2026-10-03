


// PairingManager.swift
// Manages the full device pairing lifecycle: listening for a new QR-scan pairing
// from Android, persisting state to UserDefaults, watching for remote unpairs,
// and restoring a valid pairing on relaunch (within the same boot session).

import Foundation
import FirebaseFirestore
import Combine
import CryptoKit

// MARK: - PairingManager

class PairingManager: ObservableObject {
    static let shared = PairingManager()

    // MARK: - Published State

    @Published var isPaired: Bool = KeychainHelper.load(for: "current_pairing_id") != nil || UserDefaults.standard.string(forKey: "current_pairing_id") != nil
    @Published var pairedDeviceName: String = UserDefaults.standard.string(forKey: "paired_device_name") ?? ""
    @Published var pairingId: String? = KeychainHelper.load(for: "current_pairing_id") ?? UserDefaults.standard.string(forKey: "current_pairing_id")
    @Published var isSetupComplete: Bool = UserDefaults.standard.bool(forKey: "is_setup_complete")
    @Published var pairingError: String? = nil
    /// Persistent "pair again" notice after an old/unauthorized cloud pairing was dropped;
    /// survives the QR screen resetting `pairingError`, cleared once a new pairing completes.
    @Published var repairNotice: String? = nil

    private var pairingListener: ListenerRegistration?
    private var unpairingListener: ListenerRegistration?
    private var db: Firestore { FirebaseManager.shared.db }
    private var listenStartTime: Date?

    private var isLocalOnlyMode: Bool {
        UserDefaults.standard.string(forKey: "sync_mode") == "local"
    }

    // MARK: - Pairing Listener

    /// Begins listening for pending pairing documents addressed to this Mac's Firebase UID.
    /// `macDeviceId` is kept for API compatibility; discovery is by authenticated UID only.
    func listenForPairing(macDeviceId: String) {
        guard !isPaired else { return }
        guard !isLocalOnlyMode else {
            stopListening()
            return
        }

        listenStartTime = Date().addingTimeInterval(-3600)
        DispatchQueue.main.async { self.pairingError = nil }

        FirebaseManager.shared.withAuthenticatedUid { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let uid):
                self.startFirestoreListener(macUid: uid)
            case .failure:
                // Fail closed: no Firestore access without an identity.
                DispatchQueue.main.async { self.pairingError = FirebaseManager.authFailureMessage }
            }
        }
    }


    /// Creates (or replaces) the Firestore snapshot listener for pending pairings addressed to `macUid`.
    private func startFirestoreListener(macUid: String) {
        guard !isLocalOnlyMode else { return }
        pairingListener?.remove()
        pairingListener = nil

        pairingListener = db.collection("pairings")
            .whereField("macUid", isEqualTo: macUid)
            .addSnapshotListener { [weak self] snapshot, error in
                guard let self = self else { return }

                if let error = error {
                    let nsError = error as NSError
                    if nsError.code == 7 {
                        DispatchQueue.main.async {
                            self.pairingError = "Permission denied. Check Firestore rules."
                        }
                    } else if nsError.code == 14 {
                        DispatchQueue.main.async {
                            self.pairingError = "Network error. Check connection."
                        }
                    }
                    return
                }

                guard let documents = snapshot?.documents else { return }

                if documents.isEmpty { return }

                self.processDocuments(documents, macUid: macUid)
            }
    }


    /// Accepts the first recent pending pairing whose proof verifies with this Mac's pairing key.
    /// Documents that fail verification (wrong key, forged, legacy) are ignored.
    private func processDocuments(_ documents: [QueryDocumentSnapshot], macUid: String) {
        let rootKey = CloudPairingAuth.rootKey(hex: KeychainHelper.getEncryptionKey())

        for doc in documents {
            let data = doc.data()

            guard let timestamp = data["timestamp"] as? Timestamp,
                  let startTime = self.listenStartTime,
                  timestamp.dateValue() > startTime else {
                continue
            }

            if case .success(let pending) = CloudPairingAuth.evaluatePending(
                docId: doc.documentID, data: data, myUid: macUid, rootKey: rootKey) {
                acceptPairing(pending, macUid: macUid)
                return
            }
        }
    }


    /// Joins the verified pending pairing (rules only allow the addressed Mac to add itself,
    /// once), then updates published state + UserDefaults.
    private func acceptPairing(_ pending: CloudPairingAuth.PendingPairing, macUid: String) {
        guard !isLocalOnlyMode else { return }
        self.pairingListener?.remove()
        self.pairingListener = nil

        db.collection("pairings").document(pending.pairingId).updateData([
            "members": FieldValue.arrayUnion([macUid]),
            "status": "active"
        ]) { [weak self] error in
            guard let self else { return }
            if error != nil {
                DispatchQueue.main.async { self.pairingError = "Couldn't complete pairing. Try scanning again." }
                self.startFirestoreListener(macUid: macUid)
                return
            }
            self.processPairingData(pairingId: pending.pairingId, androidDeviceName: pending.androidDeviceName)
        }
    }


    /// Updates published state + UserDefaults for an accepted pairing.
    private func processPairingData(pairingId: String, androidDeviceName: String) {
        DispatchQueue.main.async {
            self.pairingId = pairingId
            self.pairedDeviceName = androidDeviceName
            self.isPaired = true
            self.pairingError = nil
            self.repairNotice = nil

            ClipboardManager.shared.listenForAndroidClipboard()
        }

        _ = KeychainHelper.save(pairingId, for: "current_pairing_id")
        UserDefaults.standard.set(pairingId, forKey: "current_pairing_id")
        UserDefaults.standard.set(androidDeviceName, forKey: "paired_device_name")

        self.startMonitoringPairingStatus(pairingId: pairingId)
    }

    /// Completes a local-only pairing without creating or validating any Firebase document.
    func completeLocalPairing(pairingId: String, androidDeviceName: String = "Android Device") {
        stopListening()
        unpairingListener?.remove()
        unpairingListener = nil

        _ = KeychainHelper.save(pairingId, for: "current_pairing_id")
        UserDefaults.standard.set(pairingId, forKey: "current_pairing_id")
        UserDefaults.standard.set(androidDeviceName, forKey: "paired_device_name")
        UserDefaults.standard.set("local", forKey: "sync_mode")

        DispatchQueue.main.async {
            self.pairingId = pairingId
            self.pairedDeviceName = androidDeviceName
            self.isPaired = true
            self.pairingError = nil
            self.repairNotice = nil
            self.isSetupComplete = false

            // Re-publish Bonjour TXT record now that pairingId exists.
            // The server started at QRGen time had an empty pairingId in its TXT
            // record — Android uses this field to identify the correct Mac.
            ClipSyncServer.shared.stop()
            ClipSyncServer.shared.start()
        }

        WakeupReceiver.shared.start()
    }


    // MARK: - Unpairing

    /// Watches the pairing document for deletion so the Mac can react to a remote unpair from Android.
    func startMonitoringPairingStatus(pairingId: String) {
        guard !isLocalOnlyMode else { return }
        guard FirebaseManager.shared.isAuthenticated else { return } // fail closed
        unpairingListener?.remove()

        unpairingListener = db.collection("pairings").document(pairingId)
            .addSnapshotListener { [weak self] snapshot, error in
                guard let self = self else { return }

                if let error {
                    _ = self.handleCloudPermissionError(error)
                    return
                }

                if let snapshot = snapshot, !snapshot.exists {
                    self.unpair()
                }
            }
    }


    /// Tears down the active pairing Firestore listener.
    func stopListening() {
        pairingListener?.remove()
        pairingListener = nil
        listenStartTime = nil
    }


    /// Deletes the pairing document from Firestore, then calls unpair() regardless
    /// of whether the delete succeeded, so local state is always cleaned up.
    func clearPairing(onSuccess: @escaping () -> Void = {}, onFailure: @escaping (Error) -> Void = { _ in }) {
        if isLocalOnlyMode {
            unpair()
            DispatchQueue.main.async { onSuccess() }
            return
        }

        guard let pairingId = self.pairingId, FirebaseManager.shared.isAuthenticated else {
            // No pairing, or no Firebase identity (so no remote access): unpair locally.
            unpair()
            DispatchQueue.main.async { onSuccess() }
            return
        }

        db.collection("pairings")
            .document(pairingId)
            .delete { [weak self] error in
                DispatchQueue.main.async {
                    if let error = error {
                        self?.unpair()
                        onFailure(error)
                    } else {
                        self?.unpair()
                        onSuccess()
                    }
                }
            }
    }


    /// Resets all in-memory paired state, wipes UserDefaults keys, and stops clipboard sync.
    func unpair() {
        unpairingListener?.remove()
        unpairingListener = nil

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.isPaired = false
            self.pairedDeviceName = ""
            self.pairingId = nil
            self.isSetupComplete = false
            self.pairingError = nil
        }

        KeychainHelper.delete(for: "current_pairing_id")
        UserDefaults.standard.removeObject(forKey: "current_pairing_id")
        UserDefaults.standard.removeObject(forKey: "paired_device_name")
        UserDefaults.standard.removeObject(forKey: "is_setup_complete")

        ClipboardManager.shared.clearHistory()
        ClipboardManager.shared.stopMonitoring()
        ClipboardManager.shared.stopListening()
    }

    /// Membership rejection requires a new pairing, rather than retrying the same denied query.
    func handleCloudPermissionError(_ error: Error) -> Bool {
        guard (error as NSError).code == FirestoreErrorCode.permissionDenied.rawValue else { return false }
        stopListening()
        unpair()
        repairNotice = "ClipSync's cloud sync was updated for security. Please pair your phone again."
        return true
    }

    // MARK: - Launch Restoration

    func restorePairing() {
        if let savedPairingId = KeychainHelper.load(for: "current_pairing_id") ?? UserDefaults.standard.string(forKey: "current_pairing_id"),
           let savedDeviceName = UserDefaults.standard.string(forKey: "paired_device_name") {

            self.pairingId = savedPairingId
            self.pairedDeviceName = savedDeviceName
            self.isPaired = true
            self.isSetupComplete = UserDefaults.standard.bool(forKey: "is_setup_complete")

            if isLocalOnlyMode {
                ClipSyncServer.shared.start()
                WakeupReceiver.shared.start()
                return
            }

            // Validate the pairing in Firestore (as an authenticated member). If the Android side
            // deleted it while the Mac was turned off, unpair gracefully.
            FirebaseManager.shared.withAuthenticatedUid { [weak self] result in
                guard let self else { return }
                guard case .success(let uid) = result else {
                    // Fail closed: keep the local pairing, but no Firestore access until signed in.
                    DispatchQueue.main.async { self.pairingError = FirebaseManager.authFailureMessage }
                    return
                }
                guard !self.isLocalOnlyMode else { return }
                self.db.collection("pairings").document(savedPairingId).getDocument { [weak self] snapshot, error in
                    guard let self = self else { return }

                    if let error = error as NSError? {
                        if error.code == FirestoreErrorCode.permissionDenied.rawValue {
                            // Not a member: a pairing created before membership-based security
                            // rules (or one this identity never joined). It cannot be used; the
                            // user must pair again.
                            DispatchQueue.main.async {
                                _ = self.handleCloudPermissionError(error)
                            }
                        }
                        // Other errors (offline, unavailable): keep the pairing and retry next launch.
                        return
                    }
                    if let snapshot = snapshot, snapshot.exists {
                        guard let data = snapshot.data(),
                              CloudPairingAuth.canRestore(docId: savedPairingId, data: data, myUid: uid) else {
                            self.stopListening()
                            self.unpair()
                            self.repairNotice = "ClipSync's cloud sync was updated for security. Please pair your phone again."
                            return
                        }
                        // Pairing is valid — start monitoring for remote unpairs
                        self.startMonitoringPairingStatus(pairingId: savedPairingId)
                    } else {
                        // Pairing document was verified deleted remotely.
                        DispatchQueue.main.async {
                            self.unpair()
                        }
                    }
                }
            }
        }
    }


    /// Marks onboarding as done.
    func completeSetup() {
        DispatchQueue.main.async {
            self.isSetupComplete = true
            ClipboardManager.shared.startMonitoring()
            ClipboardManager.shared.listenForAndroidClipboard()
            ClipSyncServer.shared.start()
            WakeupReceiver.shared.start()
        }
        UserDefaults.standard.set(true, forKey: "is_setup_complete")
    }

    /// Updates the pairing document status to "active" once connection is established
    func updateStatusToActive() {
        guard !isLocalOnlyMode else {
            return
        }
        guard let pairingId = self.pairingId, FirebaseManager.shared.isAuthenticated else { return }
        db.collection("pairings").document(pairingId).updateData(["status": "active"]) { _ in
        }
    }
}
