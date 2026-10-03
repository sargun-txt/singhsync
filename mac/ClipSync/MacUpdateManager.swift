import Foundation
import AppKit
import Combine

/// macOS updater.
///
/// GitHub (over HTTPS) is only the transport. A download becomes installable only after
/// `UpdateStager` has staged it privately, rejected unsafe archive contents, and verified that
/// the extracted ClipSync.app carries a valid Apple code signature from the SAME Developer ID
/// team as this running app (same bundle ID) and a newer signed version.
///
/// Nothing downloaded is ever executed, de-quarantined, chmod-ed or run with privileges. The app
/// is sandboxed and cannot replace itself, so the verified app is moved to Downloads and
/// revealed in Finder; the user drags it into Applications and Gatekeeper evaluates it as usual.
/// Builds without a Developer ID signature (ad-hoc) cannot verify updates and only offer the
/// release page.
class MacUpdateManager: NSObject, ObservableObject, URLSessionDownloadDelegate {
    static let shared = MacUpdateManager()

    @Published var isCheckingForUpdate = false
    @Published var updateAvailable: GithubRelease? = nil
    @Published var isDownloading = false
    @Published var downloadProgress: Double = 0.0
    @Published var isDownloadComplete = false
    @Published var updateError: String? = nil
    @Published var isUpToDate = false
    /// Where the verified update was placed for the user, once handed off.
    @Published var handedOffUpdateURL: URL? = nil

    /// The Developer ID team updates must be signed by (this app's own); nil → cannot verify.
    let expectedTeam: String? = UpdatePolicy.expectedTeamIdentifier(selfTeam: CodeSignatureVerifier.selfTeamIdentifier())
    var canVerifyUpdates: Bool { expectedTeam != nil }

    private let repoURL = ProductIdentity.updateAPIURL
    private var downloadTask: URLSessionDownloadTask?
    private var session: URLSession!
    private var stagedUpdate: UpdateStager.StagedUpdate?
    /// Why the current download was cancelled by a safety check (redirect, size), if it was.
    private var downloadRejection: UpdatePolicy.Rejection?
    private let processingQueue = DispatchQueue(label: "com.singheverything.crossiva.update", qos: .userInitiated)

    private var bundleIdentifier: String { Bundle.main.bundleIdentifier ?? "com.singheverything.crossiva" }
    private var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    struct GithubRelease {
        let version: String
        /// nil when the release has no single, trusted macOS archive.
        let downloadUrl: URL?
        let releaseNotes: String
        /// The GitHub release page (https://github.com/...), for manual download.
        let pageURL: URL?
    }

    override private init() {
        super.init()
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        // Delegate callbacks on the main queue (app state is main-actor); staging runs on processingQueue.
        self.session = URLSession(configuration: config, delegate: self, delegateQueue: .main)
    }

    func checkForUpdate(manual: Bool = false) {
        DispatchQueue.main.async {
            guard !self.isCheckingForUpdate && !self.isDownloading else { return }

            self.isCheckingForUpdate = true
            self.updateError = nil
            self.isUpToDate = false

            guard !self.repoURL.isEmpty, let url = URL(string: self.repoURL) else {
                self.isCheckingForUpdate = false
                if manual { self.updateError = "Crossiva update repository is not configured." }
                return
            }

            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.setValue("application/vnd.github.v3+json", forHTTPHeaderField: "Accept")
            request.setValue("Crossiva-Mac-App", forHTTPHeaderField: "User-Agent")

            URLSession.shared.dataTask(with: request) { [weak self] data, _, error in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.isCheckingForUpdate = false

                    guard error == nil, let data,
                          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                        if manual { self.updateError = "Failed to check for updates." }
                        return
                    }

                    // The tag only decides whether to offer an update; the installed version is
                    // checked again against the downloaded app's own signed Info.plist.
                    let tagName = json["tag_name"] as? String ?? ""
                    guard let tagVersion = UpdatePolicy.parseVersion(tagName),
                          let current = UpdatePolicy.parseVersion(self.currentVersion),
                          UpdatePolicy.isNewer(tagVersion, than: current) else {
                        if manual { self.isUpToDate = true }
                        return
                    }

                    let assets = (json["assets"] as? [[String: Any]] ?? []).map {
                        UpdatePolicy.ReleaseAsset(
                            name: $0["name"] as? String ?? "",
                            url: ($0["browser_download_url"] as? String).flatMap(URL.init(string:)),
                            size: ($0["size"] as? NSNumber)?.int64Value ?? -1)
                    }
                    let pageURL = (json["html_url"] as? String).flatMap(URL.init(string:))
                    self.updateAvailable = GithubRelease(
                        version: tagName.hasPrefix("v") ? String(tagName.dropFirst()) : tagName,
                        downloadUrl: try? UpdatePolicy.selectAsset(assets).get().url,
                        releaseNotes: json["body"] as? String ?? "New update available from GitHub!",
                        pageURL: UpdatePolicy.isAllowedDownloadURL(pageURL) ? pageURL : nil)
                }
            }.resume()
        }
    }

    /// Opens the GitHub release page in the browser (manual download; nothing is executed).
    func openReleasePage() {
        guard let url = updateAvailable?.pageURL, UpdatePolicy.isAllowedDownloadURL(url) else { return }
        NSWorkspace.shared.open(url)
    }

    func startDownload(release: GithubRelease) {
        guard canVerifyUpdates else {
            fail(.noTrustAnchor)
            return
        }
        guard let url = release.downloadUrl, UpdatePolicy.isAllowedDownloadURL(url) else {
            fail(.noMacAsset)
            return
        }
        isDownloading = true
        downloadProgress = 0.0
        isDownloadComplete = false
        updateError = nil
        downloadRejection = nil

        downloadTask = session.downloadTask(with: url)
        downloadTask?.resume()
    }

    // MARK: - URLSessionDownloadDelegate

    /// Redirects must stay on HTTPS GitHub hosts; anything else cancels the download.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        if UpdatePolicy.isAllowedDownloadURL(request.url) {
            completionHandler(request)
        } else {
            downloadRejection = .untrustedURL
            completionHandler(nil)
            task.cancel()
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        if totalBytesWritten > UpdatePolicy.maxDownloadBytes || totalBytesExpectedToWrite > UpdatePolicy.maxDownloadBytes {
            downloadRejection = .tooLarge
            downloadTask.cancel()
            return
        }
        let progress = totalBytesExpectedToWrite > 0 ? Double(totalBytesWritten) / Double(totalBytesExpectedToWrite) : 0
        DispatchQueue.main.async { self.downloadProgress = progress }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard let http = downloadTask.response as? HTTPURLResponse, http.statusCode == 200,
              UpdatePolicy.isAllowedDownloadURL(http.url) else {
            downloadRejection = downloadRejection ?? .untrustedURL
            return
        }
        // `location` is deleted when this method returns: move it into private temp storage now.
        let fm = FileManager.default
        let archive = fm.temporaryDirectory.appendingPathComponent("CrossivaDownload-\(UUID().uuidString).zip")
        guard (try? fm.moveItem(at: location, to: archive)) != nil else {
            downloadRejection = .extractionFailed
            return
        }

        let stager = UpdateStager(stagingRoot: fm.temporaryDirectory, verifier: CodeSignatureVerifier.check)
        let team = expectedTeam, bundleId = bundleIdentifier, current = currentVersion
        processingQueue.async { [weak self] in
            let result = stager.prepare(downloadedArchive: archive, expectedTeam: team,
                                        expectedBundleId: bundleId, currentVersion: current)
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success(let staged):
                    self.stagedUpdate = staged
                    self.isDownloading = false
                    self.isDownloadComplete = true
                case .failure(let rejection):
                    self.fail(rejection)
                }
            }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let rejection = downloadRejection
        guard error != nil || rejection != nil else { return } // success continues in didFinishDownloadingTo
        DispatchQueue.main.async {
            if let rejection {
                self.fail(rejection)
            } else if !self.isDownloadComplete {
                self.fail(nil, message: "Download failed. Check your connection and try again.")
            }
        }
    }

    // MARK: - Install hand-off

    /// Moves the verified app to Downloads (never over an existing item) and reveals it, so the
    /// user can quit ClipSync and drag it into Applications. Nothing is executed.
    func installVerifiedUpdate() {
        guard let staged = stagedUpdate,
              let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first else { return }
        stagedUpdate = nil
        isDownloadComplete = false
        if let url = UpdateStager.handOff(staged, to: downloads) {
            handedOffUpdateURL = url
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            fail(nil, message: "Couldn't move the verified update to Downloads.")
        }
    }

    func cancelInstall() {
        if let staging = stagedUpdate?.stagingDirectory {
            try? FileManager.default.removeItem(at: staging)
        }
        downloadTask?.cancel()
        stagedUpdate = nil
        isDownloading = false
        isDownloadComplete = false
        updateAvailable = nil
        handedOffUpdateURL = nil
        downloadProgress = 0.0
    }

    private func fail(_ rejection: UpdatePolicy.Rejection?, message: String? = nil) {
        isDownloading = false
        isDownloadComplete = false
        stagedUpdate = nil
        updateAvailable = nil
        updateError = message ?? rejection?.rawValue ?? "The update couldn't be verified."
    }
}
