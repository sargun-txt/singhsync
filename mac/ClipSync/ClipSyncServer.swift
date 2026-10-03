// ClipSyncServer.swift
// Always-on TCP server that listens on port 8765 for encrypted clipboard payloads
// from the paired Android device.  Also advertises itself via Bonjour/mDNS so
// Android's NSD layer can discover the Mac's IP without manual configuration.
//
// Wire protocol: TCP protocol v2 (see TcpFrameProtocol.swift, shared with TcpFrameProtocol.kt).
// An HMAC-SHA256-authenticated header (magic "CLS2", type, direction, plaintext totalSize,
// chunk size, timestamp, random session ID, file name) followed by AES-256-GCM chunks whose
// AAD binds each one to the session, type, direction, total size and chunk index.
// Legacy v1 ("CLSY") frames are refused, except the no-data diagnostic ping.

import Foundation
import Network
import CryptoKit
import AppKit
import Combine
import UserNotifications
import FirebaseCrashlytics

class ClipSyncServer: ObservableObject {

    // MARK: - Constants
    static let shared   = ClipSyncServer()
    @Published private(set) var dynamicPort: Int = 8765

    /// Session IDs of recently accepted v2 transfers (bounded, time-limited).
    private let replayCache = TcpReplayCache()
    private let queue = DispatchQueue(label: "com.singheverything.crossiva.tcpserver", qos: .userInitiated)
    private let diskWriteQueue = DispatchQueue(label: "com.singheverything.crossiva.diskwrite", qos: .userInitiated)
    private let diskWriteSemaphore = DispatchSemaphore(value: 8)

    // MARK: - State (observed by UI)
    @Published var isListening       = false
    @Published var hasActiveClient   = false
    @Published var lastError: String?      = nil
    @Published var bytesReceived: Int64    = 0
    @Published var transferProgress: Double = 0.0

    // Send-side state
    @Published var isSendingFile: Bool     = false
    @Published var sendFileProgress: Double = 0.0
    @Published var transferSpeedString: String = ""
    @Published var transferTotalBytes: Int64 = 0
    @Published var currentTransferFileName: String? = nil

    private var lastBytesSnapshot: Int64 = 0
    private var speedTimer: Timer?
    private var queuedAndroidFiles: [URL] = []

    private var activeReceiveConnection: NWConnection?
    private var activeSendConnection: NWConnection?
    private var activeReceiveFileHandle: FileHandle?
    private var activeReceiveFileURL: URL?
    private var activeSendFileURL: URL?

    private var listener: NWListener?
    // MARK: - Start / Stop

    func start() {
        guard listener == nil else {
            return
        }


        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcpOptions)
        params.allowLocalEndpointReuse = true
        // Explicitly force IPv4 so Android (192.168.x.x) can reach us.
        // NWParameters.tcp defaults to dual-stack but macOS often binds
        // to IPv6 only in practice. Setting ip.version = .v4 on the
        // protocol stack is the reliable way to ensure IPv4 binding.
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
        }

        do {
            let tcpListener = try NWListener(using: params) // Binds to any available ephemeral port
            advertiseBonjour(on: tcpListener)
            listener = tcpListener
        } catch {
            if UserDefaults.standard.string(forKey: "sync_mode") != "local" {
                Crashlytics.crashlytics().record(error: error)
            }
            lastError = "Failed to create listener: \(error.localizedDescription)"
            return
        }

        listener?.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    self?.isListening = true
                    self?.lastError   = nil
                    if let p = self?.listener?.port?.rawValue {
                        self?.dynamicPort = Int(p)
                    }
                    if self?.listener?.service != nil {
                    }
                case .failed(let err):
                    self?.isListening = false
                    self?.lastError   = err.localizedDescription
                default:
                    break
                }
            }
        }

        listener?.newConnectionHandler = { [weak self] connection in
            DispatchQueue.main.async { self?.hasActiveClient = true }
            self?.handleConnection(connection)
        }

        listener?.start(queue: queue)
    }

    func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async { 
            self.isListening = false 
            self.hasActiveClient = false
        }
    }

    /// Handles an incoming small payload transferred directly via BLE.
    func handleDirectBLEPayload(base64Encrypted: String, type: String) {
        guard ClipboardManager.shared.syncToMac else {
            return
        }
        guard let data = Data(base64Encoded: base64Encrypted),
              let decrypted = decryptChunk(data) else {
            return
        }
        
        let typeCode: UInt8
        switch type {
        case "text": typeCode = 0x01
        case "image": typeCode = 0x02
        case "file": typeCode = 0x03
        default: typeCode = 0x01
        }
        
        deliver(data: decrypted, typeCode: typeCode, fileName: nil, fileUrl: nil)
    }

    // MARK: - mDNS / Bonjour advertisement

    private let bonjourType = "_crossiva._tcp"

    /// Advertises "_crossiva._tcp." with a TXT record containing the pairingId.
    /// This allows Android to find exactly this Mac (not any other ClipSync Mac on
    /// the same network) by matching the pairingId from the QR code.
    private func advertiseBonjour(on listener: NWListener) {
        let macName = Host.current().localizedName ?? "Crossiva Mac"
        let pairingId = PairingManager.shared.pairingId ?? ""

        var txt = NWTXTRecord()
        txt["v"]         = "1"
        txt["pairingId"] = pairingId
        txt["device"]    = macName

        listener.service = NWListener.Service(
            name:      macName,
            type:      bonjourType,
            domain:    nil,
            txtRecord: txt
        )
    }

    // MARK: - Connection handling

    private func handleConnection(_ connection: NWConnection) {
        guard ClipboardManager.shared.syncToMac else {
            connection.cancel()
            return
        }
        
        connection.start(queue: queue)
        activeReceiveConnection = connection

        // The 4-byte magic selects the protocol: "CLS2" (authenticated v2) or legacy "CLSY".
        readExact(connection: connection, length: 4) { [weak self] magicData in
            guard let self, let magicData else {
                connection.cancel()
                return
            }
            if [UInt8](magicData) == TcpFrameProtocol.legacyMagic {
                self.handleLegacyFrame(connection: connection)
            } else if [UInt8](magicData) == TcpFrameProtocol.magic {
                self.readAuthenticatedHeader(magic: magicData, connection: connection)
            } else {
                connection.cancel()
            }
        }
    }

    /// Legacy v1 frames are unauthenticated. The only one still honoured is the no-data
    /// diagnostic ping (type 0x99) from ConnectionDiagnostics, which just posts a UI event.
    /// Every other v1 frame — including the retired plaintext 0x04 — is refused.
    private func handleLegacyFrame(connection: NWConnection) {
        readExact(connection: connection, length: 20) { rest in
            connection.cancel()
            guard let rest, rest.count == 20, [UInt8](rest)[1] == TransferTypeCode.diagnosticPing else {
                // A real v1 transfer from an old phone: refused (never parsed further), user told once.
                WakeupReceiver.notifyLegacyPeerOnce()
                return
            }
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: NSNotification.Name("DiagnosticTCPPingReceived"), object: nil)
            }
        }
    }

    /// Reads and verifies the v2 header. Nothing from the header is trusted, and nothing is
    /// created on disk, until its HMAC, timestamp and session ID have all been checked.
    private func readAuthenticatedHeader(magic magicData: Data, connection: NWConnection) {
        readExact(connection: connection, length: TcpFrameProtocol.fixedPrefixLength - 4) { [weak self] rest in
            guard let self, let rest else { connection.cancel(); return }
            let fixed = magicData + rest
            guard let unverified = try? TcpFrameProtocol.parseFixedPrefix(fixed, expectedDirection: .androidToMac) else {
                connection.cancel()
                return
            }
            self.readExact(connection: connection, length: unverified.nameLength + TcpFrameProtocol.macLength) { [weak self] tail in
                guard let self, let tail else { connection.cancel(); return }
                let tailBytes = [UInt8](tail)
                let prefix = fixed + Data(tailBytes[0..<unverified.nameLength])
                let mac = Data(tailBytes[unverified.nameLength...])

                guard let rootKey = self.pairingRootKey() else { connection.cancel(); return }
                let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
                guard let header = try? TcpFrameProtocol.verifyHeader(
                        prefix: prefix, mac: mac,
                        authKey: TcpFrameProtocol.authKey(rootKey: rootKey),
                        expectedDirection: .androidToMac, nowMs: nowMs),
                      self.replayCache.insertIfNew(header.sessionId, nowMs: nowMs) else {
                    connection.cancel()
                    return
                }
                self.processVerifiedHeader(header, rootKey: rootKey, connection: connection)
            }
        }
    }

    private func processVerifiedHeader(_ header: TcpFrameHeader, rootKey: SymmetricKey, connection: NWConnection) {
        let typeCode = header.type
        let totalSize = header.totalSize

        let isFile = typeCode == TransferTypeCode.file
        let destinationDir: URL?
        if isFile {
            guard let dir = incomingFileDirectory() else {
                connection.cancel()
                return
            }
            destinationDir = dir
        } else {
            destinationDir = nil
        }

        // Validate the (now authenticated) size before anything is created or buffered.
        guard TransferSecurityPolicy.isAcceptableTotalSize(
            totalSize,
            typeCode: typeCode,
            availableCapacity: destinationDir.flatMap { availableCapacity(of: $0) }
        ) else {
            connection.cancel()
            return
        }

        DispatchQueue.main.async {
            self.bytesReceived = 0
            self.transferProgress = 0
            self.transferTotalBytes = totalSize
            self.transferSpeedString = ""
            self.currentTransferFileName = nil
            self.lastBytesSnapshot = 0
            self.startSpeedTimer()
        }

        let rawName = header.fileName.isEmpty ? nil : String(data: header.fileName, encoding: .utf8)
        beginPayload(connection: connection, header: header, rootKey: rootKey, rawFileName: rawName, destinationDir: destinationDir)
    }

    /// Opens the destination (files only) and starts reading encrypted chunks.
    /// Files are always created fresh under `destinationDir`; an existing file is never opened.
    private func beginPayload(connection: NWConnection, header: TcpFrameHeader, rootKey: SymmetricKey, rawFileName: String?, destinationDir: URL?) {
        let fileName = TransferSecurityPolicy.sanitizedFileName(rawFileName)
            ?? "Crossiva_\(Int(Date().timeIntervalSince1970))"

        var handle: FileHandle? = nil
        var destUrl: URL? = nil
        if let destinationDir {
            guard let created = try? TransferSecurityPolicy.createUniqueFile(in: destinationDir, preferredName: fileName) else {
                connection.cancel()
                return
            }
            handle = created.handle
            destUrl = created.url
            self.activeReceiveFileHandle = handle
            self.activeReceiveFileURL = destUrl
        }

        let displayName = destUrl?.lastPathComponent ?? fileName
        DispatchQueue.main.async { self.currentTransferFileName = displayName }

        readChunks(connection: connection, header: header, rootKey: rootKey, index: 0, buffer: Data(), fileName: displayName, fileHandle: handle, fileUrl: destUrl, accumulatedReceived: 0)
    }

    /// Where received files are saved: the user's preferred location, else ~/Downloads.
    private func incomingFileDirectory() -> URL? {
        let prefPath = UserDefaults.standard.string(forKey: "PreferredFileStorageLocation") ?? ""
        if !prefPath.isEmpty {
            return URL(fileURLWithPath: prefPath, isDirectory: true)
        }
        return FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
    }

    /// Free space on the volume holding `directory`, or nil if it cannot be determined.
    private func availableCapacity(of directory: URL) -> Int64? {
        let values = try? directory.resourceValues(forKeys: [
            .volumeAvailableCapacityForImportantUsageKey,
            .volumeAvailableCapacityKey
        ])
        let important = values?.volumeAvailableCapacityForImportantUsage ?? 0
        let plain = Int64(values?.volumeAvailableCapacity ?? 0)
        let best = max(important, plain)
        // Some volumes report 0 when the value is unavailable; treat that as unknown.
        return best > 0 ? best : nil
    }

    /// The pairing key used for chunk encryption and as the HKDF root for header auth.
    private func pairingRootKey() -> SymmetricKey? {
        guard let hexKey = KeychainHelper.getEncryptionKey(),
              hexKey.count == 64,
              let keyData = hexKey.hexToData() else { return nil }
        return SymmetricKey(data: keyData)
    }

    /// Reads chunk `index`. Its sealed length must be exactly what the authenticated header
    /// implies, and it must open under AAD bound to this session, type, size and index.
    private func readChunks(
        connection:          NWConnection,
        header:              TcpFrameHeader,
        rootKey:             SymmetricKey,
        index:               UInt32,
        buffer:              Data,
        fileName:            String?,
        fileHandle:          FileHandle?,
        fileUrl:             URL?,
        accumulatedReceived: Int64
    ) {
        let totalSize = header.totalSize
        let typeCode = header.type

        func fail() {
            connection.cancel()
            fileHandle?.closeFile()
            if let fileUrl { try? FileManager.default.removeItem(at: fileUrl) }
            self.activeReceiveFileHandle = nil
            self.activeReceiveFileURL = nil
        }

        // Read 4-byte chunk length prefix
        readExact(connection: connection, length: 4) { [weak self] lenData in
            guard let self = self else { return }
            guard let lenData = lenData,
                  let expectedLen = try? TcpFrameProtocol.expectedSealedLength(header, index: index),
                  Int(lenData.readUInt32BE(at: 0)) == expectedLen else {
                fail()
                return
            }

            self.readExact(connection: connection, length: expectedLen) { [weak self] chunkData in
                guard let self = self else { return }
                guard let chunkData,
                      let decrypted = try? TcpFrameProtocol.openChunk(chunkData, key: rootKey, header: header, index: index) else {
                    fail()
                    return
                }

                var accumulated = buffer
                var bytesToCount = 0
                if let handle = fileHandle {
                    guard self.activeReceiveFileHandle != nil else { return } // Cancelled mid-read

                    // Decouple disk write from network read
                    self.diskWriteSemaphore.wait()
                    self.diskWriteQueue.async {
                        defer { self.diskWriteSemaphore.signal() }
                        handle.write(decrypted)
                    }
                    bytesToCount = decrypted.count
                } else {
                    accumulated.append(decrypted)
                }

                // Counts plaintext only; equals totalSize exactly after the last chunk.
                let received = fileHandle != nil ? accumulatedReceived + Int64(bytesToCount) : Int64(accumulated.count)
                DispatchQueue.main.async {
                    self.bytesReceived = received
                    self.transferProgress = totalSize > 0
                        ? Double(received) / Double(totalSize)
                        : 1.0
                }

                if received >= totalSize {
                    // All chunks received
                    self.diskWriteQueue.async {
                        if typeCode != 0x03 {
                            self.deliver(data: accumulated, typeCode: typeCode, fileName: fileName, fileUrl: fileUrl)
                        } else {
                            self.deliver(data: Data(), typeCode: typeCode, fileName: fileName, fileUrl: fileUrl)
                        }
                        fileHandle?.closeFile()
                        DispatchQueue.main.async {
                            self.activeReceiveFileHandle = nil
                            self.activeReceiveFileURL = nil
                        }
                    }
                } else {
                    // More chunks to read
                    self.readChunks(
                        connection:          connection,
                        header:              header,
                        rootKey:             rootKey,
                        index:               index + 1,
                        buffer:              accumulated,
                        fileName:            fileName,
                        fileHandle:          fileHandle,
                        fileUrl:             fileUrl,
                        accumulatedReceived: received
                    )
                }
            }
        }
    }

    // MARK: - Decryption

    private func decryptChunk(_ data: Data) -> Data? {
        guard let hexKey = KeychainHelper.getEncryptionKey(),
              hexKey.count == 64,
              let keyData = hexKey.hexToData() else {
            return nil
        }

        guard data.count > 12 else { return nil }

        let ivData         = data.prefix(12)
        let ciphertextData = data.dropFirst(12)

        do {
            let key       = SymmetricKey(data: keyData)
            let sealed    = try AES.GCM.SealedBox(combined: ivData + ciphertextData)
            let plaintext = try AES.GCM.open(sealed, using: key)
            return plaintext
        } catch _ {
            return nil
        }
    }

    // MARK: - Clipboard delivery

    private func deliver(data: Data, typeCode: UInt8, fileName: String?, fileUrl: URL?) {
        DispatchQueue.main.async {
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()

            var historyContent: String? = nil

            switch typeCode {
            case 0x01: // text
                if let text = String(data: data, encoding: .utf8) {
                    pasteboard.setString(text, forType: .string)
                    historyContent = text

                    // If the received text looks like a standalone OTP (4–8 digits),
                    // fire the OTP bubble — covers local-synced OTPs (BLE/TCP route)
                    // that never go through Firestore and thus bypass OTPNotificationManager.
                    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    if trimmed.range(of: #"^\d{4,8}$"#, options: .regularExpression) != nil {
                        OTPNotificationManager.shared.triggerBubble(otpCode: trimmed)
                    }
                }
            case 0x02: // image
                if let image = NSImage(data: data) {
                    pasteboard.writeObjects([image])
                    historyContent = "Image received"
                }
            case 0x03: // file — saved to Downloads
                if let url = fileUrl {
                    historyContent = url.lastPathComponent

                    let content = UNMutableNotificationContent()
                    content.title = "File Received"
                    content.body = "\(url.lastPathComponent) saved to Downloads"
                    content.userInfo = ["type": "file", "path": url.path]
                    content.sound = .default
                    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
                    UNUserNotificationCenter.current().add(request)
                }
            default:
                if let text = String(data: data, encoding: .utf8) {
                    pasteboard.setString(text, forType: .string)
                    historyContent = text
                }
            }

            if let content = historyContent {
                let deviceName = PairingManager.shared.pairedDeviceName
                let isImage = (typeCode == 0x02)
                let isFile = (typeCode == 0x03)
                let newItem = ClipboardItem(
                    content: content,
                    timestamp: Date(),
                    deviceName: deviceName,
                    direction: .received,
                    isImage: isImage,
                    isFile: isFile,
                    filePath: isFile ? fileUrl?.path : nil
                )
                ClipboardManager.shared.history.insert(newItem, at: 0)
                ClipboardManager.shared.ignoreNextChange = true
                ClipboardManager.shared.lastCopiedText = (typeCode == 0x01 || typeCode == 0x03) ? content : ""
            }

            self.transferProgress = 1.0
            self.currentTransferFileName = nil
            self.stopSpeedTimer()
            UserDefaults.standard.set(false, forKey: "UltraFastTransfer")
            // Also reset send-side state if this was a receive-complete call
            // (send-side cleaned up in finishAndroidFileSend)
        }
    }

    // MARK: - Speed Timer

    private func startSpeedTimer() {
        stopSpeedTimer()
        lastBytesSnapshot = 0
        speedTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            let current = self.bytesReceived
            let delta = current - self.lastBytesSnapshot
            self.lastBytesSnapshot = current
            let mbps = Double(delta) / 1_048_576.0
            DispatchQueue.main.async {
                if mbps > 0.01 {
                    self.transferSpeedString = String(format: "%.1f MB/s", mbps)
                } else {
                    self.transferSpeedString = ""
                }
            }
        }
    }

    private func stopSpeedTimer() {
        speedTimer?.invalidate()
        speedTimer = nil
        transferSpeedString = ""
    }

    // MARK: - Manual Cancellation

    func cancelReceive() {
        activeReceiveConnection?.cancel()
        activeReceiveConnection = nil

        activeReceiveFileHandle?.closeFile()
        activeReceiveFileHandle = nil
        if let url = activeReceiveFileURL {
            try? FileManager.default.removeItem(at: url)
            activeReceiveFileURL = nil
        }

        DispatchQueue.main.async {
            self.transferProgress = 0
            self.bytesReceived = 0
            self.currentTransferFileName = nil
        }
    }

    func cancelSend() {
        for url in queuedAndroidFiles {
            if url.path.contains("PendingDrops") {
                try? FileManager.default.removeItem(at: url)
            }
        }
        queuedAndroidFiles.removeAll()

        if let currentURL = activeSendFileURL, currentURL.path.contains("PendingDrops") {
            try? FileManager.default.removeItem(at: currentURL)
        }
        activeSendFileURL = nil

        activeSendConnection?.cancel()
        activeSendConnection = nil
        DispatchQueue.main.async {
            self.isSendingFile = false
            self.sendFileProgress = 0
            self.currentTransferFileName = nil
        }
    }

    // MARK: - Outbound Sending (Mac -> Android) (Local BLE + TCP path)

    /// Send plain text to Android.
    /// Payloads whose encrypted JSON fits in a single BLE notify (≤ 500 B) are sent inline.
    /// Larger payloads are streamed over TCP using the same encrypted-chunk protocol as file
    /// transfers, signalled with `text_incoming` so Android sets the clipboard instead of
    /// saving to Downloads.
    func sendTextToAndroid(_ text: String, completion: @escaping (Bool) -> Void = { _ in }) {
        guard ClipboardManager.shared.syncFromMac else {
            completion(false)
            return
        }
        guard let hexKey = KeychainHelper.getEncryptionKey(),
              let keyData = hexKey.hexToData() else {
            completion(false)
            return
        }

        queue.async { [weak self] in
            guard let self else { completion(false); return }
            guard let plainData = text.data(using: .utf8) else { completion(false); return }

            // Encrypt the payload
            let key = SymmetricKey(data: keyData)
            let nonce = AES.GCM.Nonce()
            guard let sealed = try? AES.GCM.seal(plainData, using: key, nonce: nonce) else {
                completion(false)
                return
            }
            let encryptedData = sealed.combined! // nonce(12) + ciphertext + tag(16)
            let base64 = encryptedData.base64EncodedString()

            // Authenticated BLE envelope carrying the encrypted text
            let fields: [BleField: Data] = [.content: BleControlProtocol.utf8(base64)]

            if BleControlProtocol.envelopeLength(fields) <= 500 {
                // Fast path: fits in a single BLE notify
                let pushed = WakeupReceiver.shared.push(.pushText, fields)
                if pushed {
                    completion(true)
                } else {
                    completion(false)
                }
            } else {
                // Payload too large for BLE — stream raw UTF-8 bytes over TCP.
                // Android's `text_incoming` handler reads the bytes and sets the clipboard
                // instead of saving to Downloads (cf. file_incoming).
                self.sendLargeTextViaTCP(text: text, completion: completion)
            }
        }
    }

    /// Streams [text] to Android over TCP using the same encrypted-chunk protocol as file
    /// transfers. Sends a `text_incoming` BLE signal (instead of `file_incoming`) so Android
    /// knows to push the received bytes to the system clipboard rather than save to Downloads.
    private func sendLargeTextViaTCP(text: String, completion: @escaping (Bool) -> Void) {
        guard WakeupReceiver.shared.hasAndroidSubscriber else {
            completion(false)
            return
        }

        guard let textData = text.data(using: .utf8) else {
            completion(false)
            return
        }

        // Write to a temp file so we can hand a FileHandle to the existing streaming path.
        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("crossiva_text_\(UUID().uuidString).tmp")
        do {
            try textData.write(to: tmpURL)
        } catch _ {
            completion(false)
            return
        }

        let fileSize = Int64(textData.count)
        let androidTcpPort = 8766

        // 1. Pre-ping Android to get a fresh IP and wake it from doze.
        //    Clear lastPing FIRST — otherwise the wait loop below can match
        //    a stale ping_ack from a previous transfer and exit immediately,
        //    causing Mac to dial Android before it's actually awake.
        DispatchQueue.main.sync { WakeupReceiver.shared.lastPing = nil }
        WakeupReceiver.shared.push(.ping)

        let pingDeadline = Date().addingTimeInterval(5.0)
        while Date() < pingDeadline {
            if let p = WakeupReceiver.shared.lastPing, p.payloadType == "ping_ack" { break }
            usleep(50_000)
        }

        guard let androidIp = WakeupReceiver.shared.getFreshAndroidIp() else {
            try? FileManager.default.removeItem(at: tmpURL)
            completion(false)
            return
        }

        // 2. Signal Android: text is incoming (clipboard, not a file download)
        WakeupReceiver.shared.push(.textIncoming, [
            .size: BleControlProtocol.i64(fileSize),
            .port: BleControlProtocol.u16(androidTcpPort)
        ])

        // 3. Wait for tcp_ready ACK
        let tcpDeadline = Date().addingTimeInterval(3.0)
        while Date() < tcpDeadline {
            if let ping = WakeupReceiver.shared.lastPing, ping.payloadType == "tcp_ready" { break }
            usleep(50_000)
        }

        guard let fileHandle = try? FileHandle(forReadingFrom: tmpURL) else {
            try? FileManager.default.removeItem(at: tmpURL)
            completion(false)
            return
        }

        // Reuse the existing encrypted-chunk TCP streaming path.
        streamFileToAndroid(
            fileHandle: fileHandle,
            fileSize:   fileSize,
            fileName:   "__clipsync_text__",  // sentinel; Android reads this, ignores name
            ip:         androidIp,
            port:       androidTcpPort,
            purpose:    .clipboardText  // always encrypted, regardless of the Ultra Fast toggle
        ) {
            // Clean up temp file after send (success or failure)
            try? FileManager.default.removeItem(at: tmpURL)
            completion(true)
        }
    }

    // MARK: - Share Extension Integration
    // The Darwin notification listener and pending file draining are handled in ClipSyncApp.swift (AppDelegate)
    // to allow it to simultaneously open the Menu Bar popover so the user sees the transfer progress.

    /// Send a file to the paired Android device via local Wi-Fi.
    /// Flow: BLE Notify {type:"file_incoming"} → Android starts TCP server →
    ///        Mac waits for BLE ACK → Mac streams file bytes over TCP.
    func sendFiles(urls: [URL]) {
        let files = urls.filter { !$0.hasDirectoryPath }
        guard !files.isEmpty else { return }

        DispatchQueue.main.async {
            self.queuedAndroidFiles.append(contentsOf: files)
            self.sendNextQueuedFileIfNeeded()
        }
    }

    private func sendNextQueuedFileIfNeeded() {
        guard !isSendingFile, !queuedAndroidFiles.isEmpty else { return }
        
        // Mark as sending synchronously so re-entrant calls don't pop multiple files at once.
        self.isSendingFile = true
        
        let next = queuedAndroidFiles.removeFirst()
        sendFileToAndroid(url: next) { [weak self] in
            // Clean up App Group share files after send
            if next.path.contains("PendingDrops") {
                try? FileManager.default.removeItem(at: next)
            }
            
            DispatchQueue.main.async {
                self?.sendNextQueuedFileIfNeeded()
            }
        }
    }

    func sendFileToAndroid(url: URL) {
        sendFiles(urls: [url])
    }

    private func sendFileToAndroid(url: URL, completion: @escaping () -> Void) {
        guard ClipboardManager.shared.syncFromMac else {
            DispatchQueue.main.async { self.isSendingFile = false }
            completion()
            return
        }
        guard WakeupReceiver.shared.hasAndroidSubscriber else {
            DispatchQueue.main.async {
                self.isSendingFile = false
                self.lastError = "Android is not reachable. Open the Crossiva app on your phone."
            }
            completion()
            return
        }

        DispatchQueue.main.async {
            self.sendFileProgress = 0
            self.transferSpeedString = ""
            self.activeSendFileURL = url
        }

        queue.async { [weak self] in
            guard let self else { return }

            // Security-scoped URLs from fileImporter / drag-and-drop require this
            // before the sandbox will permit reading the file.
            let accessing = url.startAccessingSecurityScopedResource()

            var fileName  = url.lastPathComponent
            
            // Share Extension prepends a UUID and an underscore to avoid collisions.
            // Strip it so the user and the Android device see the original file name.
            let components = fileName.components(separatedBy: "_")
            if components.count > 1, UUID(uuidString: components[0]) != nil {
                // Re-join the rest in case originalName had underscores
                fileName = components.dropFirst().joined(separator: "_")
            }
            
            let fileSize  = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
            DispatchQueue.main.async {
                self.currentTransferFileName = fileName
                self.transferTotalBytes = fileSize
            }

            guard let fileHandle = try? FileHandle(forReadingFrom: url) else {
                if accessing { url.stopAccessingSecurityScopedResource() }
                DispatchQueue.main.async {
                    self.isSendingFile = false
                    self.currentTransferFileName = nil
                    self.lastError = "Could not read file. Try moving it to Downloads first."
                    completion()
                }
                return
            }

            // Stop the scope once the handle is open — the kernel file descriptor
            // keeps the file accessible for the lifetime of the handle.
            if accessing { url.stopAccessingSecurityScopedResource() }

            let androidTcpPort = 8766

            // 1. Pre-ping Android to get a fresh IP and wake it from doze.
            //    Android responds with a "ping_ack" wakeup ping containing its current IP.
            //    Clear lastPing FIRST — otherwise the wait loop below can match
            //    a stale ping_ack from a previous transfer and exit immediately,
            //    causing Mac to dial Android before it's actually awake.
            DispatchQueue.main.sync { WakeupReceiver.shared.lastPing = nil }
            WakeupReceiver.shared.push(.ping)

            // Wait up to 5s for ping_ack. 3s was too tight for dozing Android
            // whose BLE stack can take 2-4s to fully process the wakeup.
            let pingDeadline = Date().addingTimeInterval(5.0)
            while Date() < pingDeadline {
                if let p = WakeupReceiver.shared.lastPing, p.payloadType == "ping_ack" { break }
                usleep(50_000)
            }

            guard let androidIp = WakeupReceiver.shared.getFreshAndroidIp() else {
                fileHandle.closeFile()
                DispatchQueue.main.async {
                    self.isSendingFile = false
                    self.currentTransferFileName = nil
                    self.transferSpeedString = ""
                    self.lastError = "Could not reach Android. Make sure both devices are on the same Wi-Fi."
                    completion()
                }
                return
            }

            // 2. BLE Notify: tell Android a file is incoming (now Android starts TCP server)
            WakeupReceiver.shared.push(.fileIncoming, [
                .fileName: BleControlProtocol.utf8(fileName),
                .size: BleControlProtocol.i64(fileSize),
                .port: BleControlProtocol.u16(androidTcpPort)
            ])

            // 3. Wait for tcp_ready ACK (Android confirms its TCP server is up)
            let tcpDeadline = Date().addingTimeInterval(3.0)
            while Date() < tcpDeadline {
                if let ping = WakeupReceiver.shared.lastPing, ping.payloadType == "tcp_ready" { break }
                usleep(50_000)
            }

            // 4. Dial Android's TCP server and stream
            self.streamFileToAndroid(
                fileHandle: fileHandle,
                fileSize:   fileSize,
                fileName:   fileName,
                ip:         androidIp,
                port:       androidTcpPort,
                purpose:    .userFile(ultraFastRequested: UserDefaults.standard.bool(forKey: "UltraFastTransfer")),
                completion: completion
            )
        }
    }

    /// Alias kept for backwards compatibility with MenuBarView and other callers.
    func sendFile(url: URL) {
        sendFiles(urls: [url])
    }

    // MARK: - TCP stream to Android (streaming — no full RAM load)

    private func streamFileToAndroid(
        fileHandle: FileHandle,
        fileSize:   Int64,
        fileName:   String,
        ip:         String,
        port:       Int,
        purpose:    OutgoingPayloadPurpose,
        completion: @escaping () -> Void
    ) {
        guard let hexKey = KeychainHelper.getEncryptionKey(),
              let keyData = hexKey.hexToData() else {
            fileHandle.closeFile()
            DispatchQueue.main.async {
                self.isSendingFile = false
                self.currentTransferFileName = nil
                self.transferSpeedString = ""
                completion()
            }
            return
        }

        let key = SymmetricKey(data: keyData)
        // v2 authenticated header. Every purpose uses an encrypted frame; Ultra Fast only selects
        // a larger chunk size. totalSize is the plaintext byte count, independent of chunking.
        let header = TcpFrameHeader(
            type:        TransferSecurityPolicy.outgoingTypeCode(for: purpose),
            direction:   .macToAndroid,
            totalSize:   fileSize,
            chunkSize:   TransferSecurityPolicy.outgoingChunkSize(for: purpose),
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000),
            sessionId:   TcpFrameProtocol.newSessionId(),
            fileName:    purpose == .clipboardText ? Data() : Data(fileName.utf8)
        )
        guard let headerBytes = try? TcpFrameProtocol.encodeHeader(header, authKey: TcpFrameProtocol.authKey(rootKey: key)) else {
            fileHandle.closeFile()
            DispatchQueue.main.async {
                self.isSendingFile = false
                self.currentTransferFileName = nil
                self.transferSpeedString = ""
                self.lastError = "Transfer failed: could not build transfer header."
                completion()
            }
            return
        }

        let host       = NWEndpoint.Host(ip)
        let nwPort     = NWEndpoint.Port(rawValue: UInt16(port))!
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let outgoingParams = NWParameters(tls: nil, tcp: tcpOptions)
        let connection = NWConnection(host: host, port: nwPort, using: outgoingParams)
        activeSendConnection = connection

        let startTime  = Date()

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:

                // Send the authenticated header first, then stream chunks
                connection.send(content: headerBytes, completion: .contentProcessed { [weak self] error in
                    guard let self else { return }
                    if let error {
                        fileHandle.closeFile()
                        self.finishAndroidFileSend(connection: connection, fileName: fileName, error: error, completion: completion)
                        return
                    }
                    // Kick off recursive encrypted chunk streaming
                    self.sendNextChunk(
                        connection:  connection,
                        fileHandle:  fileHandle,
                        fileName:    fileName,
                        key:         key,
                        header:      header,
                        index:       0,
                        totalSent:   0,
                        startTime:   startTime,
                        completion:  completion
                    )
                })

            case .failed(let err):
                fileHandle.closeFile()
                DispatchQueue.main.async {
                    self.isSendingFile = false
                    self.currentTransferFileName = nil
                    self.transferSpeedString = ""
                    self.lastError = "Transfer failed: \(err.localizedDescription)"
                    completion()
                }
                connection.cancel()
            default: break
            }
        }
        connection.start(queue: queue)

        // Safety timeout — 5 min for large files
        queue.asyncAfter(deadline: .now() + 300) {
            connection.cancel()
        }
    }

    /// Reads chunk `index` (exactly the length the header implies), seals it with AAD bound to
    /// the session, and sends it. Recurses until all `header.totalSize` bytes are sent.
    /// If the source turns out shorter or longer than declared, the transfer fails before the
    /// final chunk is sent, so the receiver never completes with a wrong file.
    private func sendNextChunk(
        connection: NWConnection,
        fileHandle: FileHandle,
        fileName:   String,
        key:        SymmetricKey,
        header:     TcpFrameHeader,
        index:      UInt32,
        totalSent:  Int64,
        startTime:  Date,
        completion: @escaping () -> Void
    ) {
        let fileSize = header.totalSize

        func sourceHasMoreBytes() -> Bool {
            !((try? fileHandle.read(upToCount: 1)) ?? Data()).isEmpty
        }

        guard let expectedLength = TcpFrameProtocol.plainLength(header, index: index) else {
            // Every declared byte has been sent (or the transfer is empty).
            let error: Error? = (index == 0 && sourceHasMoreBytes()) ? ClipSyncServerError.sourceSizeMismatch : nil
            fileHandle.closeFile()
            finishAndroidFileSend(connection: connection, fileName: fileName, error: error, completion: completion)
            return
        }

        let rawChunk = (try? fileHandle.read(upToCount: expectedLength)) ?? Data()
        let isLast = Int64(index) + 1 == TcpFrameProtocol.chunkCount(header)
        guard rawChunk.count == expectedLength, !(isLast && sourceHasMoreBytes()) else {
            fileHandle.closeFile()
            finishAndroidFileSend(connection: connection, fileName: fileName, error: ClipSyncServerError.sourceSizeMismatch, completion: completion)
            return
        }

        guard let packet = try? TcpFrameProtocol.sealChunk(rawChunk, key: key, header: header, index: index) else {
            fileHandle.closeFile()
            finishAndroidFileSend(connection: connection, fileName: fileName, error: ClipSyncServerError.encryptionFailed, completion: completion)
            return
        }

        let newTotalSent = totalSent + Int64(rawChunk.count)
        let elapsed = max(Date().timeIntervalSince(startTime), 0.001)
        let mbps = Double(newTotalSent) / elapsed / 1_048_576.0
        DispatchQueue.main.async {
            self.sendFileProgress = Double(newTotalSent) / Double(max(fileSize, 1))
            self.transferSpeedString = mbps > 0.01 ? String(format: "%.1f MB/s", mbps) : ""
        }

        connection.send(content: packet, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                fileHandle.closeFile()
                self.finishAndroidFileSend(connection: connection, fileName: fileName, error: error, completion: completion)
                return
            }
            // Send next chunk — recurse
            self.sendNextChunk(
                connection: connection,
                fileHandle: fileHandle,
                fileName:   fileName,
                key:        key,
                header:     header,
                index:      index + 1,
                totalSent:  newTotalSent,
                startTime:  startTime,
                completion: completion
            )
        })
    }

    private func finishAndroidFileSend(connection: NWConnection, fileName: String, error: Error?, completion: @escaping () -> Void) {
        let sentFileURL = activeSendFileURL
        if let currentURL = activeSendFileURL, currentURL.path.contains("PendingDrops") {
            try? FileManager.default.removeItem(at: currentURL)
        }
        activeSendFileURL = nil

        if let error {
        } else {
        }

        DispatchQueue.main.async {
            if let error {
                self.lastError = "Transfer error: \(error.localizedDescription)"
            } else {
                let isImg = fileName.lowercased().hasSuffix(".png") || fileName.lowercased().hasSuffix(".jpg") || fileName.lowercased().hasSuffix(".jpeg")
                let deviceName = PairingManager.shared.pairedDeviceName
                let newItem = ClipboardItem(
                    content: fileName,
                    timestamp: Date(),
                    deviceName: deviceName,
                    direction: .sent,
                    isImage: isImg,
                    isFile: true,
                    filePath: sentFileURL?.path
                )
                ClipboardManager.shared.history.insert(newItem, at: 0)
            }
            self.isSendingFile = false
            self.sendFileProgress = error == nil ? 1.0 : 0.0
            self.currentTransferFileName = nil
            self.transferSpeedString = ""
            UserDefaults.standard.set(false, forKey: "UltraFastTransfer")
            completion()
        }
        connection.cancel()
    }

    // MARK: - File Receive (unchanged)

    private func saveFileToDisk(data: Data, fileName: String?) {
        // Intentionally left blank as file saving is now incremental in readChunks
    }

    // MARK: - Low-level read helpers

    /// Reads exactly [length] bytes, calling [completion] on success or nil on failure.
    private func readExact(
        connection: NWConnection,
        length:     Int,
        completion: @escaping (Data?) -> Void
    ) {
        connection.receive(
            minimumIncompleteLength: length,
            maximumLength:           length
        ) { data, _, isDone, error in
            if let error {
                completion(nil)
                return
            }
            guard let data, data.count == length else {
                completion(nil)
                return
            }
            completion(data)
        }
    }
}

private enum ClipSyncServerError: LocalizedError {
    case encryptionFailed
    case sourceSizeMismatch

    var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "Could not encrypt file chunk"
        case .sourceSizeMismatch:
            return "File size changed during transfer"
        }
    }
}

// MARK: - Data helpers

private extension Data {
    func readUInt32BE(at offset: Int) -> UInt32 {
        let slice = self[offset ..< offset + 4]
        return slice.reversed().enumerated().reduce(0) { acc, pair in
            acc | (UInt32(pair.element) << (pair.offset * 8))
        }
    }
}

private extension String {
    func hexToData() -> Data? {
        let clean = self.lowercased()
        guard clean.count % 2 == 0 else { return nil }
        var data = Data(capacity: clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let nextIdx = clean.index(idx, offsetBy: 2)
            guard let byte = UInt8(clean[idx ..< nextIdx], radix: 16) else { return nil }
            data.append(byte)
            idx = nextIdx
        }
        return data
    }
}
