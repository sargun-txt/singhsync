


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
    let app: FirebaseApp
    let auth: Auth
    let db: Firestore
    /// The region whose Firebase project this process is configured with (fixed until relaunch).
    let configuredRegion: String

    /// Configures Firebase with the region-appropriate options (or default if none),
    /// then creates a Firestore instance with in-memory caching.
    private init() {
        let region = UserDefaults.standard.string(forKey: "server_region") ?? "CA"
        configuredRegion = region
        if FirebaseApp.app() == nil { FirebaseApp.configure() }
        guard let defaultApp = FirebaseApp.app(),
              defaultApp.options.projectID == "crossiva-dev-ca",
              let expected = FirebaseRegion.projectID(for: region) else {
            preconditionFailure("Default or regional Firebase project mismatch")
        }
        if region == "CA" {
            app = defaultApp
        } else {
            guard let name = FirebaseRegion.appName(for: region),
                  let options = RegionConfig.getOptions(for: region) else {
                preconditionFailure("Regional Firebase configuration unavailable")
            }
            if FirebaseApp.app(name: name) == nil { FirebaseApp.configure(name: name, options: options) }
            guard let regionalApp = FirebaseApp.app(name: name), regionalApp.options.projectID == expected else {
                preconditionFailure("Regional Firebase initialization failed")
            }
            app = regionalApp
        }
        auth = Auth.auth(app: app)
        db = Firestore.firestore(app: app)

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
        return auth.currentUser != nil
    }

    /// This Mac's anonymous Firebase UID (persisted by FirebaseAuth across launches), if signed in.
    var currentUid: String? {
        return auth.currentUser?.uid
    }

    /// Calls back with the signed-in UID, signing in anonymously first if needed. On failure
    /// the caller must not touch Firestore (fail closed) and should surface a retry path.
    func withAuthenticatedUid(_ completion: @escaping (Result<String, Error>) -> Void) {
        if let uid = auth.currentUser?.uid {
            completion(.success(uid))
            return
        }
        auth.signInAnonymously { result, error in
            if let uid = result?.user.uid {
                completion(.success(uid))
            } else {
                completion(.failure(error ?? NSError(domain: "Crossiva.FirebaseAuth", code: -1)))
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
    static let authFailureMessage = "Couldn't connect to Crossiva cloud sync. Check your internet connection and try again."


    /// Convenience accessor that returns a typed Firestore CollectionReference.
    func collection(_ path: String) -> CollectionReference {
        return db.collection(path)
    }
}
