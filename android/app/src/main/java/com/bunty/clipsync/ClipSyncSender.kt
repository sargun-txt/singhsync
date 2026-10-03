package com.bunty.clipsync

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Raw TCP socket sender for the local Wi-Fi sync path (Android → Mac).
 *
 * Every connection carries one transfer in protocol v2 (see [TcpFrameProtocol]):
 * an HMAC-authenticated header followed by AES-256-GCM chunks whose AAD binds them to the
 * session, type, total size and chunk index.
 *
 * `totalSize` in the header is always the plaintext/application byte count — never the
 * encrypted size — so it does not depend on chunk size or GCM overhead.
 */
object ClipSyncSender {

    /**
     * Performance parameters for file streaming. Both profiles use the same encrypted,
     * authenticated frame; Ultra Fast never changes confidentiality or integrity.
     *
     * Ultra Fast uses 4 MB plaintext chunks (vs 1 MB) and larger socket buffers.
     */
    enum class TransferProfile(val chunkSize: Int, val socketBufferSize: Int) {
        NORMAL(chunkSize = 1_048_576, socketBufferSize = 2 * 1024 * 1024),
        ULTRA_FAST(chunkSize = 4 * 1_048_576, socketBufferSize = 4 * 1024 * 1024);

        companion object {
            fun forUltraFast(enabled: Boolean) = if (enabled) ULTRA_FAST else NORMAL
        }
    }

    private const val TAG = "LocalSync"
    internal const val TYPE_TEXT  = TcpFrameProtocol.TYPE_TEXT
    internal const val TYPE_IMAGE = TcpFrameProtocol.TYPE_IMAGE
    internal const val TYPE_FILE  = TcpFrameProtocol.TYPE_FILE

    // ── Small payload (text / small images) ───────────────────────────────────

    /**
     * Encrypts [text] and streams it to [ip]:[port] over a single TCP connection.
     *
     * @param ip           Mac's LAN IP address (e.g. "192.168.1.5").
     * @param port         Mac's TCP server port ([LocalSyncManager.TCP_PORT]).
     * @param text         Plain-text clipboard content.
     * @param hexKey       64-char hex AES-256 session key.
     * @param connectMs    TCP connect timeout in milliseconds (default 3 s).
     */
    suspend fun sendText(
        ip: String,
        port:      Int,
        text:      String,
        hexKey:    String,
        connectMs: Int = 3_000
    ) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        stream(ip, port, TYPE_TEXT, null, bytes.size.toLong(), TransferProfile.NORMAL, hexKey, connectMs,
            { ByteArrayInputStream(bytes) })
    }

    /**
     * Encrypts [imageBytes] and streams it to [ip]:[port].
     */
    suspend fun sendImage(
        ip: String,
        port:      Int,
        imageBytes: ByteArray,
        hexKey:    String,
        connectMs: Int = 3_000
    ) {
        stream(ip, port, TYPE_IMAGE, null, imageBytes.size.toLong(), TransferProfile.NORMAL, hexKey, connectMs,
            { ByteArrayInputStream(imageBytes) })
    }

    // ── Large file streaming ───────────────────────────────────────────────────

    /**
     * Streams data from an InputStream to [ip]:[port] as AES-256-GCM encrypted chunks of
     * [TransferProfile.chunkSize] plaintext bytes. Every [profile] is encrypted.
     *
     * [fileSize] must be the exact number of bytes the stream yields; if it does not, the
     * transfer fails before its final chunk and the Mac discards the partial file.
     */
    suspend fun sendFileStream(
        ip: String,
        port:       Int,
        fileName:   String,
        fileSize:   Long,
        inputStreamProvider: () -> java.io.InputStream,
        hexKey:     String,
        connectMs:  Int = 3_000,
        profile:    TransferProfile = TransferProfile.NORMAL,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ) {
        stream(ip, port, TYPE_FILE, fileName, fileSize, profile, hexKey, connectMs, inputStreamProvider, onProgress)
    }

    /**
     * Streams [file] to [ip]:[port] in encrypted chunks.
     *
     * Each chunk is individually encrypted so the Mac can begin decrypting before
     * all bytes arrive (streaming decryption). Progress is reported via [onProgress]
     * as a value in [0.0, 1.0].
     *
     * @param file       The file to transfer (any MIME type: PDF, video, zip, …).
     * @param hexKey     64-char hex AES-256 session key.
     * @param onProgress Called on the IO thread with fraction [0.0, 1.0] and speed as bytes are sent.
     */
    suspend fun sendFile(
        ip: String,
        port:       Int,
        file:       File,
        hexKey:     String,
        connectMs:  Int = 3_000,
        profile:    TransferProfile = TransferProfile.NORMAL,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ) {
        sendFileStream(
            ip = ip,
            port = port,
            fileName = file.name,
            fileSize = file.length(),
            inputStreamProvider = { FileInputStream(file) },
            hexKey = hexKey,
            connectMs = connectMs,
            profile = profile,
            onProgress = onProgress
        )
    }

    /**
     * Streams an image [file] from disk to [ip]:[port] as an image transfer (type 0x02).
     *
     * Unlike [sendFile], which makes the Mac save the file to Downloads, this tells the Mac
     * to write the data directly to the clipboard as an NSImage — so CMD+V pastes the image.
     */
    suspend fun sendImageFile(
        ip: String,
        port:       Int,
        file:       File,
        hexKey:     String,
        connectMs:  Int = 3_000,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ) {
        stream(ip, port, TYPE_IMAGE, file.name, file.length(), TransferProfile.NORMAL, hexKey, connectMs,
            { FileInputStream(file) }, onProgress)
    }

    // ── Probe ─────────────────────────────────────────────────────────────────

    /**
     * Tries to open a TCP connection to [ip]:[port] within [timeoutMs].
     * Returns `true` if the Mac's server is reachable (same LAN / hotspot).
     */
    fun probeTcp(ip: String, port: Int, timeoutMs: Int = 500): Boolean {
        return try {
            Socket().use { s ->
                s.sendBufferSize = 8 * 1024 * 1024
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /** Opens a connection and writes one v2 transfer of exactly [totalSize] plaintext bytes. */
    private suspend fun stream(
        ip:          String,
        port:        Int,
        type:        Byte,
        fileName:    String?,
        totalSize:   Long,
        profile:     TransferProfile,
        hexKey:      String,
        connectMs:   Int,
        source:      () -> java.io.InputStream,
        onProgress:  (Float, String) -> Unit = { _, _ -> }
    ) = withContext(Dispatchers.IO) {
        val rootKey = TcpFrameProtocol.rootKey(hexKey)
        val header = TcpFrameProtocol.Header(
            type        = type,
            direction   = TcpFrameProtocol.DIRECTION_ANDROID_TO_MAC,
            totalSize   = totalSize,
            chunkSize   = profile.chunkSize,
            timestampMs = System.currentTimeMillis(),
            sessionId   = TcpFrameProtocol.newSessionId(),
            fileName    = fileName?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        )

        Socket().use { socket ->
            socket.tcpNoDelay = true // Disable Nagle's algorithm
            socket.sendBufferSize = profile.socketBufferSize
            socket.receiveBufferSize = profile.socketBufferSize
            socket.connect(InetSocketAddress(ip, port), connectMs)
            socket.soTimeout = 30_000  // 30 s read/write timeout

            val out = java.io.BufferedOutputStream(socket.getOutputStream(), profile.chunkSize)
            var lastUpdate = System.currentTimeMillis()
            var lastSent = 0L
            try {
                source().use { input ->
                    TcpFrameProtocol.writeTransfer(out, rootKey, header, input, isActive = { isActive }) { sent ->
                        val now = System.currentTimeMillis()
                        val diff = now - lastUpdate
                        if (diff > 500) {
                            val speedMbps = ((sent - lastSent) * 1000L / diff) / (1024.0 * 1024.0)
                            onProgress(sent.toFloat() / totalSize.toFloat(), String.format("%.1f MB/s", speedMbps))
                            lastUpdate = now
                            lastSent = sent
                        }
                    }
                }
                onProgress(1f, "0 MB/s")
            } catch (e: TcpFrameProtocol.FrameException) {
                Log.e(TAG, "Transfer aborted: ${e.reason}")
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Error streaming file: ${e.message}")
                throw e
            }
        }
    }
}
