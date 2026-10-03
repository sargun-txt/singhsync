


// FirebaseManager.swift
// Singleton that configures FirebaseApp on first access and exposes a shared
// Firestore instance. Reads the server region from UserDefaults to select the
// correct Firebase project via RegionConfig.

import Foundation
import FirebaseCore
import FirebaseFirestore
import FirebaseAuth

// MARK: - FirebaseManager

class FirebaseManager {
    static let shared = FirebaseManager()
    let db: Firestore
    /// The region whose Firebase project this process is configured with (fixed until relaunch).
    let configuredRegion: String

    /// Configures Firebase with the region-appropriate options (or default if none),
    /// then creates a Firestore instance with in-memory caching.
    private init() {
        let region = UserDefaults.standard.string(forKey: "server_region") ?? "IN"
        configuredRegion = region
        if FirebaseApp.app() == nil {
            if let options = RegionConfig.getOptions(for: region) {
                FirebaseApp.configure(options: options)
            } else {
                FirebaseApp.configure()
            }
        }

        db = Firestore.firestore()

        let settings = FirestoreSettings()
        settings.cacheSettings = MemoryCacheSettings()
        db.settings = settings

        testNetworkConnection()
    }


    private func testNetworkConnection() {
        guard let url = URL(string: "https://www.google.com") else { return }

        let task = URLSession.shared.dataTask(with: url) { _, _, _ in }
        task.resume()
    }

    var isReady: Bool {
        return FirebaseApp.app() != nil
    }

    /// True only when this Mac holds a Firebase identity. Firestore rules require one for
    /// every protected document; there is no unauthenticated fallback.
    var isAuthenticated: Bool {
        return Auth.auth().currentUser != nil
    }

    /// This Mac's anonymous Firebase UID (persisted by FirebaseAuth across launches), if signed in.
    var currentUid: String? {
        return Auth.auth().currentUser?.uid
    }

    /// Calls back with the signed-in UID, signing in anonymously first if needed. On failure
    /// the caller must not touch Firestore (fail closed) and should surface a retry path.
    func withAuthenticatedUid(_ completion: @escaping (Result<String, Error>) -> Void) {
        if let uid = Auth.auth().currentUser?.uid {
            completion(.success(uid))
            return
        }
        Auth.auth().signInAnonymously { result, error in
            if let uid = result?.user.uid {
                completion(.success(uid))
            } else {
                completion(.failure(error ?? NSError(domain: "ClipSync.FirebaseAuth", code: -1)))
            }
        }
    }

    /// Async form of `withAuthenticatedUid`; nil means "not signed in — do not proceed".
    func authenticatedUid() async -> String? {
        await withCheckedContinuation { continuation in
            withAuthenticatedUid { result in
                continuation.resume(returning: try? result.get())
            }
        }
    }

    /// Shown when cloud sync cannot sign in. Firestore is not contacted in that state.
    static let authFailureMessage = "Couldn't connect to ClipSync cloud sync. Check your internet connection and try again."


    /// Convenience accessor that returns a typed Firestore CollectionReference.
    func collection(_ path: String) -> CollectionReference {
        return db.collection(path)
    }
}
