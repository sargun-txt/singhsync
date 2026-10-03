package com.bunty.clipsync

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import androidx.core.app.NotificationCompat
import com.google.firebase.crashlytics.FirebaseCrashlytics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * AndroidTcpReceiver — on-demand TCP server that accepts exactly ONE file transfer from the Mac.
 *
 * Lifecycle:
 *   [start] → opens ServerSocket → returns true once ready → waits for Mac to connect
 *   → streams bytes to disk incrementally → closes socket → shows notification
 *   Auto-closes after 60 seconds if Mac never connects.
 *
 * Wire protocol: TCP protocol v2 (see [TcpFrameProtocol]) — an HMAC-authenticated header
 * followed by AES-256-GCM chunks bound to the session. Legacy v1 frames are refused.
 */
object AndroidTcpReceiver {

    private const val TAG = "AndroidTcpReceiver"
    private const val TIMEOUT_MS = 60_000
    private const val NOTIF_CHANNEL = "clipsync_file_transfer"
    private const val NOTIF_ID = 7701

    /** Session IDs of recently accepted transfers (bounded, time-limited). */
    private val replayCache = TcpReplayCache()

    /** The pairing key, or null if this device is not paired / the key is malformed. */
    private fun pairingRootKey(context: Context): ByteArray? =
        DeviceManager.getEncryptionKey(context)?.let {
            try { TcpFrameProtocol.rootKey(it) } catch (e: TcpFrameProtocol.FrameException) { null }
        }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var serverSocket: ServerSocket? = null
    @Volatile private var activeClient: Socket? = null
    @Volatile private var isCancelled: Boolean = false

    // State exposed to UI
    private val _isReceiving = kotlinx.coroutines.flow.MutableStateFlow(false)
    val isReceiving: kotlinx.coroutines.flow.StateFlow<Boolean> = _isReceiving

    private val _receiveProgress = kotlinx.coroutines.flow.MutableStateFlow(0f)
    val receiveProgress: kotlinx.coroutines.flow.StateFlow<Float> = _receiveProgress

    private val _receiveSpeedString = kotlinx.coroutines.flow.MutableStateFlow("")
    val receiveSpeedString: kotlinx.coroutines.flow.StateFlow<String> = _receiveSpeedString

    /**
     * Opens a ServerSocket on [port] and starts accepting in the background.
     * Returns true immediately once the port is open (so caller can send the ACK).
     * Returns false if the port could not be bound.
     */
    suspend fun start(
        context: Context,
        port: Int,
        expectedSize: Long,
        expectedFilename: String
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // Close any lingering previous socket
            serverSocket?.close()

            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(port))
            server.soTimeout = TIMEOUT_MS
            serverSocket = server

            // Accept loop in background
            scope.launch {
                try {
                    val client: Socket = server.accept()
                    server.close()
                    serverSocket = null
                    receiveFile(context, client, expectedFilename)
                } catch (e: Exception) {
                    Log.w(TAG, "TCP server accept error (may be timeout): ${e.message}")
                    serverSocket = null
                }
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open TCP server on port $port", e)
            FirebaseCrashlytics.getInstance().recordException(e)
            false
        }
    }

    /**
     * Like [start], but receives the stream into memory and delivers the decoded UTF-8 text
     * via [onReceived] instead of writing to Downloads.
     * Used for large clipboard text transfers (Mac `text_incoming` signal).
     */
    suspend fun startForText(
        context: Context,
        port: Int,
        expectedSize: Long,
        onReceived: (String) -> Unit
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            serverSocket?.close()
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(port))
            server.soTimeout = TIMEOUT_MS
            serverSocket = server

            scope.launch {
                try {
                    val client: Socket = server.accept()
                    server.close()
                    serverSocket = null
                    receiveTextStream(context, client, expectedSize, onReceived)
                } catch (e: Exception) {
                    Log.w(TAG, "TCP text-server accept error: ${e.message}")
                    serverSocket = null
                }
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open TCP text-server on port $port", e)
            FirebaseCrashlytics.getInstance().recordException(e)
            false
        }
    }

    /**
     * Receives an encrypted-chunk TCP stream (same wire protocol as file transfers) into a
     * ByteArrayOutputStream, then decodes and delivers the result as a UTF-8 String.
     */
    private suspend fun receiveTextStream(
        context: Context,
        client: Socket,
        expectedSize: Long,
        onReceived: (String) -> Unit
    ) = withContext(Dispatchers.IO) {
        try {
            val inp = client.getInputStream()
            val rootKey = pairingRootKey(context) ?: run {
                Log.e(TAG, "receiveTextStream — no encryption key"); return@withContext
            }

            // 1. Authenticated header: nothing is trusted or allocated before this succeeds.
            val header = try {
                TcpFrameProtocol.readVerifiedHeader(
                    inp, rootKey, TcpFrameProtocol.DIRECTION_MAC_TO_ANDROID, System.currentTimeMillis(), replayCache)
            } catch (e: TcpFrameProtocol.FrameException) {
                Log.e(TAG, "receiveTextStream — rejected: ${e.reason}"); return@withContext
            }
            if (header.type != TcpFrameProtocol.TYPE_TEXT) {
                Log.e(TAG, "receiveTextStream — rejected: unexpected type"); return@withContext
            }

            // 2. Chunks, each bound to this session and index. totalSize is plaintext bytes.
            val buffer = java.io.ByteArrayOutputStream(header.totalSize.coerceAtMost(10 * 1024 * 1024).toInt())
            try {
                TcpFrameProtocol.readChunks(inp, header, rootKey) { plain -> buffer.write(plain) }
            } catch (e: TcpFrameProtocol.FrameException) {
                Log.e(TAG, "receiveTextStream — rejected: ${e.reason}"); return@withContext
            }
            client.runCatching { close() }

            val text = buffer.toString(Charsets.UTF_8.name())
            onReceived(text)

        } catch (e: Exception) {
            Log.e(TAG, "receiveTextStream error", e)
            FirebaseCrashlytics.getInstance().recordException(e)
        } finally {
            client.runCatching { close() }
        }
    }


    /**
     * Forcefully cancels the active file receive transfer by closing the sockets.
     */
    fun cancel() {
        isCancelled = true
        serverSocket?.runCatching { close() }
        serverSocket = null
        activeClient?.runCatching { close() }
        activeClient = null
    }

    // ── File receive ─────────────────────────────────────────────────────────

    private suspend fun receiveFile(context: Context, client: Socket, expectedFilename: String) =
        withContext(Dispatchers.IO) {
            activeClient = client
            isCancelled = false
            _isReceiving.value = true
            _receiveProgress.value = 0f
            var fileName = expectedFilename

            // Track the MediaStore URI so we can delete the partial entry on failure
            var pendingUri: android.net.Uri? = null

            try {
                val inp = client.getInputStream()

                // ── 1. Authenticated header ───────────────────────────────────
                // Fail closed before any file or MediaStore entry is created.
                fun reject(reason: String) {
                    Log.e(TAG, "Rejected incoming transfer: $reason")
                    client.runCatching { close() }
                    activeClient = null
                    _isReceiving.value = false
                }
                val rootKey = pairingRootKey(context) ?: run {
                    reject("no encryption key"); return@withContext
                }
                val header = try {
                    TcpFrameProtocol.readVerifiedHeader(
                        inp, rootKey, TcpFrameProtocol.DIRECTION_MAC_TO_ANDROID, System.currentTimeMillis(), replayCache)
                } catch (e: TcpFrameProtocol.FrameException) {
                    reject(e.reason.name); return@withContext
                }
                val typeCode = header.type
                if (typeCode != TcpFrameProtocol.TYPE_FILE && typeCode != TcpFrameProtocol.TYPE_IMAGE) {
                    reject("unexpected type"); return@withContext
                }
                // totalSize is the plaintext byte count, authenticated by the header MAC.
                val totalSize = header.totalSize

                // ── 2. File name (authenticated; MediaStore sanitizes it further) ──
                if (header.fileName.isNotEmpty()) {
                    fileName = header.fileName.toString(Charsets.UTF_8)
                }

                // ── 4. Choose destination based on payload type ───────────────────
                val isImagePayload = typeCode == 0x02.toByte()

                val outputStream: java.io.OutputStream
                val resolver = context.contentResolver
                var stagedImageFile: File? = null

                if (isImagePayload) {
                    // Images go to a private cache file — NOT MediaStore/Downloads.
                    // ClipboardGhostActivity will read this file and place it directly
                    // on the clipboard once the transfer completes.
                    val stageDir = File(context.cacheDir, "clipboard_images").apply { mkdirs() }
                    stagedImageFile = File(stageDir, "received_image_${System.currentTimeMillis()}.jpg")
                    outputStream = FileOutputStream(stagedImageFile)
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    // Android 10+ — MediaStore with IS_PENDING
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                        ?: run {
                            Log.e(TAG, "MediaStore insert failed"); return@withContext
                        }
                    pendingUri = uri
                    outputStream = resolver.openOutputStream(uri)
                        ?: run {
                            Log.e(TAG, "Could not open MediaStore OutputStream"); return@withContext
                        }
                } else {
                    // Android 9 and below — write directly to public Downloads dir
                    @Suppress("DEPRECATION")
                    val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                    dir.mkdirs()
                    outputStream = FileOutputStream(File(dir, fileName))
                }

                showProgressNotification(context, fileName, 0, totalSize)

                // ── 5. Stream chunks directly to the destination ──────────────
                var received = 0L
                var lastUpdate = System.currentTimeMillis()
                var lastNotifTime = 0L
                var lastBytes = 0L
                
                outputStream.use { out ->
                    // Each chunk must have exactly the length the header implies and must open
                    // under AAD bound to this session, type, size and index; anything else throws.
                    received = TcpFrameProtocol.readChunks(inp, header, rootKey, isCancelled = { isCancelled }) { decrypted ->
                        out.write(decrypted)
                        val done = received + decrypted.size
                        received = done

                        val now = System.currentTimeMillis()
                        val dt = (now - lastUpdate) / 1000.0
                        if (dt >= 0.2) {
                            val progress = if (totalSize > 0) done.toDouble() / totalSize else 1.0
                            _receiveProgress.value = progress.toFloat()
                            val db = done - lastBytes
                            val speedMBs = (db / (1024.0 * 1024.0)) / dt
                            _receiveSpeedString.value = String.format(java.util.Locale.US, "%.1f MB/s", speedMBs)
                            if (now - lastNotifTime >= 1000) {
                                showProgressNotification(context, fileName, (progress * 100).toInt(), totalSize)
                                lastNotifTime = now
                            }
                            lastUpdate = now
                            lastBytes = done
                        }
                    }
                }
                
                // Final guaranteed progress update
                _receiveProgress.value = 1f
                _receiveSpeedString.value = ""
                showProgressNotification(context, fileName, 100, totalSize)

                client.close()
                activeClient = null
                _isReceiving.value = false

                // ── 6. Handle cancellation / incomplete transfer ──────────────
                if (isCancelled) {
                    Log.w(TAG, "Transfer was cancelled midway")
                    showFailedNotification(context, fileName, "Cancelled by user")
                    deletePendingEntry(context, pendingUri)
                    return@withContext
                }

                if (received < totalSize) {
                    Log.w(TAG, "Transfer incomplete: $received / $totalSize bytes")
                    showFailedNotification(context, fileName, "Connection dropped")
                    deletePendingEntry(context, pendingUri)
                    return@withContext
                }

                // ── 7. Finalize ─────────────────────────────────────────────────
                if (isImagePayload) {
                    stagedImageFile?.let { file ->
                        ClipboardGhostActivity.copyImageFileToClipboard(context, file.absolutePath)
                    }
                    // No Downloads notification for images — they're not going to Downloads at all now
                } else {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && pendingUri != null) {
                        val doneValues = ContentValues().apply {
                            put(MediaStore.Downloads.IS_PENDING, 0)
                        }
                        resolver.update(pendingUri!!, doneValues, null, null)
                    }
                    var finalUri = pendingUri
                    if (finalUri == null && Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                        @Suppress("DEPRECATION")
                        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                        finalUri = Uri.fromFile(File(dir, fileName))
                    }
                    showCompleteNotification(context, fileName, "Downloads", finalUri)
                }

            } catch (e: Exception) {
                Log.e(TAG, "receiveFile error", e)
                FirebaseCrashlytics.getInstance().recordException(e)
                client.runCatching { close() }
                activeClient = null
                _isReceiving.value = false
                deletePendingEntry(context, pendingUri)
                val reason = if (isCancelled) "Cancelled" else "Connection error"
                showFailedNotification(context, fileName, reason)
            } finally {
                DeviceManager.setUltraFastModeEnabled(context, false)
            }
        }

    /** Deletes a partial MediaStore entry if something went wrong mid-transfer. */
    private fun deletePendingEntry(context: Context, uri: android.net.Uri?) {
        if (uri == null) return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                context.contentResolver.delete(uri, null, null)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not delete pending entry: ${e.message}")
        }
    }


    // ── Notifications ─────────────────────────────────────────────────────────

    private fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(NOTIF_CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(NOTIF_CHANNEL, "File Transfers", NotificationManager.IMPORTANCE_LOW)
                        .apply { description = "ClipSync file transfer progress" }
                )
            }
        }
    }

    private fun showProgressNotification(context: Context, filename: String, percent: Int, totalBytes: Long) {
        ensureChannel(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val sizeMb = String.format("%.1f MB", totalBytes / 1_048_576.0)
        
        val cancelIntent = android.content.Intent(context, CancelTransferReceiver::class.java).apply {
            action = CancelTransferReceiver.ACTION_CANCEL_RECEIVE
        }
        val cancelPendingIntent = android.app.PendingIntent.getBroadcast(
            context, 0, cancelIntent, android.app.PendingIntent.FLAG_IMMUTABLE
        )

        val notif = NotificationCompat.Builder(context, NOTIF_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("Receiving from Mac")
            .setContentText("$filename — $percent% of $sizeMb")
            .setProgress(100, percent, percent == 0)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", cancelPendingIntent)
            .build()
        nm.notify(NOTIF_ID, notif)
    }

    private fun showCompleteNotification(context: Context, filename: String, destLabel: String, uri: Uri?) {
        ensureChannel(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val builder = NotificationCompat.Builder(context, NOTIF_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("File received")
            .setContentText("$filename saved to $destLabel")
            .setAutoCancel(true)

        if (uri != null) {
            val viewIntent = android.content.Intent(android.content.Intent.ACTION_VIEW).apply {
                setDataAndType(uri, context.contentResolver.getType(uri) ?: "*/*")
                addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val pendingIntent = android.app.PendingIntent.getActivity(
                context, 0, viewIntent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            builder.setContentIntent(pendingIntent)
        }

        val notif = builder.build()
        nm.cancel(NOTIF_ID)
        nm.notify(NOTIF_ID + 1, notif)
    }

    private fun showFailedNotification(context: Context, filename: String, reason: String) {
        ensureChannel(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notif = NotificationCompat.Builder(context, NOTIF_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Transfer Failed")
            .setContentText("$filename: $reason")
            .setAutoCancel(true)
            .build()
        nm.cancel(NOTIF_ID)
        nm.notify(NOTIF_ID + 1, notif)
    }

    /**
     * Copies [srcFile] into the system public Downloads folder.
     * Kept for legacy/pre-Q fallback paths only.
     */
    private fun saveToPublicDownloads(context: Context, srcFile: File, fileName: String): Uri? {
        return try {
            @Suppress("DEPRECATION")
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            downloadsDir.mkdirs()
            val destFile = File(downloadsDir, fileName)
            srcFile.copyTo(destFile, overwrite = true)
            Uri.fromFile(destFile)
        } catch (e: Exception) {
            Log.e(TAG, "saveToPublicDownloads failed", e)
            null
        }
    }
}
