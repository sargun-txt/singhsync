import SwiftUI
import AppKit

struct UpdateWindow: View {
    @ObservedObject private var updateManager = MacUpdateManager.shared
    
    var body: some View {
        VStack(spacing: 20) {
            
            // Header Image/Icon
            Image(systemName: "arrow.triangle.2.circlepath.circle.fill")
                .font(.system(size: 60))
                .foregroundColor(.accentColor)
                .padding(.top, 20)
            
            if let url = updateManager.handedOffUpdateURL {
                // STATE 4: Verified app handed to the user
                handedOffView(url: url)
            } else if updateManager.isDownloadComplete {
                // STATE 3: Ready to Install
                readyToInstallView
            } else if updateManager.isDownloading {
                // STATE 2: Downloading
                downloadingView
            } else if let release = updateManager.updateAvailable {
                // STATE 1: Info (Download & Install)
                infoView(release: release)
            } else if updateManager.isUpToDate {
                // STATE: Already up to date
                upToDateView
            } else if updateManager.updateError != nil {
                // STATE Error
                errorView
            } else {
                // Loading or up to date
                loadingView
            }
        }
        .padding(30)
        .frame(width: 400, height: 450)
        .background(EffectView(material: .windowBackground, blendingMode: .behindWindow))
    }
    
    // MARK: - State Views
    
    private func infoView(release: MacUpdateManager.GithubRelease) -> some View {
        VStack(spacing: 16) {
            Text("Update Available!")
                .font(.title2)
                .fontWeight(.bold)
            
            Text("Version \(release.version) is now available.")
                .font(.headline)
                .foregroundColor(.secondary)
            
            ScrollView {
                Text(release.releaseNotes)
                    .font(.body)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(Color.black.opacity(0.05))
            .cornerRadius(10)
            .frame(height: 150)
            
            Spacer()
            
            HStack(spacing: 16) {
                Button(action: {
                    UpdateWindowController.shared.closeWindow()
                }) {
                    Text("Remind Me Later")
                        .frame(width: 130)
                }
                .controlSize(.large)
                
                if updateManager.canVerifyUpdates && release.downloadUrl != nil {
                    Button(action: {
                        updateManager.startDownload(release: release)
                    }) {
                        Text("Download & Verify")
                            .frame(width: 140)
                            .fontWeight(.medium)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                } else {
                    // Unsigned (ad-hoc) builds can't verify a download: offer the release page only.
                    Button(action: {
                        updateManager.openReleasePage()
                    }) {
                        Text("Open Download Page")
                            .frame(width: 140)
                            .fontWeight(.medium)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(release.pageURL == nil)
                }
            }
        }
    }
    
    private var downloadingView: some View {
        VStack(spacing: 20) {
            Text("Downloading Update...")
                .font(.title2)
                .fontWeight(.bold)
            
            ProgressView(value: updateManager.downloadProgress, total: 1.0)
                .progressViewStyle(.linear)
                .frame(width: 250)
                .padding(.top, 20)
            
            Text("\(Int(updateManager.downloadProgress * 100))%")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            Spacer()
        }
        .padding(.top, 30)
    }
    
    private var readyToInstallView: some View {
        VStack(spacing: 16) {
            Text("Verified Update Ready")
                .font(.title2)
                .fontWeight(.bold)
            
            Text("The new version is signed by the Crossiva developer. Click Show in Finder, quit Crossiva, then drag the new app into your Applications folder to replace the old one.")
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .padding(.horizontal, 20)
            
            Spacer()
            
            HStack(spacing: 16) {
                Button(action: {
                    updateManager.cancelInstall()
                    UpdateWindowController.shared.closeWindow()
                }) {
                    Text("Cancel")
                        .frame(width: 130)
                }
                .controlSize(.large)
                
                Button(action: {
                    updateManager.installVerifiedUpdate()
                }) {
                    Text("Show in Finder")
                        .frame(width: 140)
                        .fontWeight(.bold)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
        }
        .padding(.top, 20)
    }
    
    private func handedOffView(url: URL) -> some View {
        VStack(spacing: 16) {
            Text("Almost Done")
                .font(.title2)
                .fontWeight(.bold)

            Text("\(url.lastPathComponent) is in your Downloads folder. Quit Crossiva, drag it into Applications (replace the old version), then open it.")
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .padding(.horizontal, 20)

            Spacer()

            Button("Done") {
                updateManager.cancelInstall()
                UpdateWindowController.shared.closeWindow()
            }
            .controlSize(.large)
        }
        .padding(.top, 20)
    }

    private var errorView: some View {
        VStack(spacing: 16) {
            Text("Update Failed")
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(.red)
            
            Text(updateManager.updateError ?? "Unknown error occurred.")
                .font(.body)
                .multilineTextAlignment(.center)
                .padding()
            
            Spacer()
            
            Button("Close") {
                UpdateWindowController.shared.closeWindow()
            }
            .controlSize(.large)
        }
    }
    
    private var loadingView: some View {
        VStack(spacing: 20) {
            ProgressView()
                .scaleEffect(1.5)
            Text("Checking for updates...")
                .font(.headline)
                .foregroundColor(.secondary)
        }
        .padding(.top, 50)
    }
    
    private var upToDateView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 44))
                .foregroundColor(.green)
            
            Text("You're Up to Date!")
                .font(.title2)
                .fontWeight(.bold)
            
            Text("Crossiva is running the latest version. No update is needed.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 20)
            
            Spacer()
            
            Button("Close") {
                UpdateWindowController.shared.closeWindow()
            }
            .controlSize(.large)
        }
        .padding(.top, 10)
    }
}

// MARK: - Window Controller

class UpdateWindowController: NSObject {
    static let shared = UpdateWindowController()
    private var window: NSWindow?
    
    func showWindow() {
        if let window = window, window.isVisible {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        
        let updateView = UpdateWindow()
        let hostingController = NSHostingController(rootView: updateView)
        
        let newWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 450),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        
        newWindow.title = "Crossiva Updater"
        newWindow.titlebarAppearsTransparent = true
        newWindow.isMovableByWindowBackground = true
        newWindow.isReleasedWhenClosed = false
        newWindow.contentViewController = hostingController
        newWindow.center()
        
        self.window = newWindow
        newWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    
    func closeWindow() {
        window?.close()
        window = nil
    }
}
