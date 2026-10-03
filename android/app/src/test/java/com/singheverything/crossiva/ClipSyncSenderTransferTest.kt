package com.singheverything.crossiva

import com.singheverything.crossiva.ClipSyncSender.TransferProfile
import com.singheverything.crossiva.TcpFrameProtocol.DIRECTION_ANDROID_TO_MAC
import com.singheverything.crossiva.TcpTestSupport.Outcome
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Runs the real [ClipSyncSender] APIs over loopback and checks the captured bytes the way the
 * Mac receiver does (protocol v2: verified header, then session-bound chunks).
 */
class ClipSyncSenderTransferTest {

    private val random = SecureRandom()
    private val rootKey = ByteArray(32).also { random.nextBytes(it) }
    private val hexKey = TcpTestSupport.hexOf(rootKey)
    private val payload = ByteArray(9 * 1_048_576 + 123).also { random.nextBytes(it) }

    /** Runs [send] against a loopback server and returns every byte the server saw. */
    private fun capture(send: suspend (port: Int) -> Unit): ByteArray {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                val received = executor.submit(Callable { server.accept().use { it.getInputStream().readBytes() } })
                runBlocking { send(server.localPort) }
                return received.get(30, TimeUnit.SECONDS)
            } finally {
                executor.shutdownNow()
            }
        }
    }

    private fun receiveAtMac(wire: ByteArray) =
        TcpTestSupport.receive(wire, rootKey, DIRECTION_ANDROID_TO_MAC, System.currentTimeMillis())

    private fun declaredTotalSize(wire: ByteArray) = ByteBuffer.wrap(wire).getLong(8)

    private fun containsPlaintext(wire: ByteArray, plaintext: ByteArray): Boolean =
        String(wire, Charsets.ISO_8859_1).contains(String(plaintext, 0, minOf(64, plaintext.size), Charsets.ISO_8859_1))

    private fun captureFile(profile: TransferProfile) = capture { port ->
        ClipSyncSender.sendFileStream("127.0.0.1", port, "video.mp4", payload.size.toLong(),
            { ByteArrayInputStream(payload) }, hexKey, profile = profile)
    }

    private fun assertEncryptedFileTransfer(profile: TransferProfile) {
        val wire = captureFile(profile)
        assertEquals("authenticated v2 frame", TcpFrameProtocol.VERSION, wire[4])
        assertEquals("frame type", ClipSyncSender.TYPE_FILE, wire[5])
        assertNotEquals("retired plaintext frame emitted", TcpFrameProtocol.RETIRED_PLAINTEXT_TYPE, wire[5])
        assertTrue("plaintext visible on the wire", !containsPlaintext(wire, payload))
        assertEquals(payload.size.toLong(), declaredTotalSize(wire))
        assertEquals(TcpTestSupport.success(ClipSyncSender.TYPE_FILE, "video.mp4", payload), receiveAtMac(wire))
    }

    @Test
    fun normalFileTransferIsEncrypted() = assertEncryptedFileTransfer(TransferProfile.NORMAL)

    @Test
    fun ultraFastFileTransferIsEncrypted() = assertEncryptedFileTransfer(TransferProfile.ULTRA_FAST)

    @Test
    fun normalAndUltraFastDeclareTheSameTotalSize() {
        assertEquals(declaredTotalSize(captureFile(TransferProfile.NORMAL)),
            declaredTotalSize(captureFile(TransferProfile.ULTRA_FAST)))
    }

    @Test
    fun ultraFastSettingSelectsAValidEncryptedProfile() {
        assertEquals(TransferProfile.ULTRA_FAST, TransferProfile.forUltraFast(true))
        assertEquals(TransferProfile.NORMAL, TransferProfile.forUltraFast(false))
        for (profile in TransferProfile.values()) {
            assertTrue(profile.chunkSize in TcpFrameProtocol.MIN_CHUNK_SIZE..TcpFrameProtocol.MAX_CHUNK_SIZE)
        }
    }

    /** Regression: the old sender declared ciphertext length, so the Mac never completed. */
    @Test
    fun sendTextDeclaresPlaintextSizeAndCompletes() {
        val text = "clipboard ".repeat(600) // 6000 bytes: too large for BLE, goes over TCP
        val wire = capture { port -> ClipSyncSender.sendText("127.0.0.1", port, text, hexKey) }
        assertEquals(text.toByteArray().size.toLong(), declaredTotalSize(wire))
        assertEquals(TcpTestSupport.success(ClipSyncSender.TYPE_TEXT, "", text.toByteArray()), receiveAtMac(wire))
    }

    @Test
    fun sendImageDeclaresPlaintextSizeAndCompletes() {
        val image = ByteArray(70_000).also { random.nextBytes(it) }
        val wire = capture { port -> ClipSyncSender.sendImage("127.0.0.1", port, image, hexKey) }
        assertEquals(image.size.toLong(), declaredTotalSize(wire))
        assertEquals(TcpTestSupport.success(ClipSyncSender.TYPE_IMAGE, "", image), receiveAtMac(wire))
    }

    @Test
    fun tamperedChunkIsRejected() {
        val wire = captureFile(TransferProfile.ULTRA_FAST)
        wire[wire.size - 1] = (wire[wire.size - 1].toInt() xor 0x01).toByte()
        assertEquals(Outcome.Rejected(TcpFrameProtocol.Reason.CHUNK_AUTHENTICATION_FAILED), receiveAtMac(wire))
    }
}
