package com.singheverything.crossiva

import com.singheverything.crossiva.TcpFrameProtocol.DIRECTION_ANDROID_TO_MAC
import com.singheverything.crossiva.TcpFrameProtocol.DIRECTION_MAC_TO_ANDROID
import com.singheverything.crossiva.TcpFrameProtocol.FrameException
import com.singheverything.crossiva.TcpFrameProtocol.Reason
import com.singheverything.crossiva.TcpFrameProtocol.TYPE_FILE
import com.singheverything.crossiva.TcpFrameProtocol.TYPE_IMAGE
import com.singheverything.crossiva.TcpFrameProtocol.TYPE_TEXT
import com.singheverything.crossiva.TcpTestSupport.Outcome
import com.singheverything.crossiva.TcpTestSupport.header
import com.singheverything.crossiva.TcpTestSupport.hex
import com.singheverything.crossiva.TcpTestSupport.hexOf
import com.singheverything.crossiva.TcpTestSupport.receive
import com.singheverything.crossiva.TcpTestSupport.send
import com.singheverything.crossiva.TcpTestSupport.success
import com.singheverything.crossiva.TcpTestSupport.vectors
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class TcpFrameProtocolTest {

    private val now = 1_700_000_000_000L
    private val root = hex(vectors.getValue("rootKey"))
    private val random = SecureRandom()

    private fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }
    private fun rejected(r: Reason) = Outcome.Rejected(r)

    // ── Shared fixtures (Swift + Python produce the same bytes) ──────────────

    @Test
    fun hkdfMatchesRfc5869TestCase1() {
        val okm = TcpFrameProtocol.hkdfSha256(
            ByteArray(22) { 0x0b }, ByteArray(13) { it.toByte() }, ByteArray(10) { (0xf0 + it).toByte() }, 42)
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hexOf(okm))
    }

    @Test
    fun crossPlatformFixturesMatch() {
        val auth = TcpFrameProtocol.authKey(root)
        assertEquals(vectors["authKey"], hexOf(auth))

        val h = TcpFrameProtocol.Header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 5_000_001, 1_048_576, now,
            hex(vectors.getValue("sessionId")), hex(vectors.getValue("fileName")))
        assertEquals(vectors["headerPrefix"], hexOf(TcpFrameProtocol.prefixBytes(h)))
        assertEquals(vectors["header"], hexOf(TcpFrameProtocol.encodeHeader(h, auth)))
        assertEquals(vectors["aadChunk3"], hexOf(TcpFrameProtocol.aad(h, 3)))

        val bytes = hex(vectors.getValue("header"))
        val verified = TcpFrameProtocol.verifyHeader(bytes.copyOfRange(0, bytes.size - 32),
            bytes.copyOfRange(bytes.size - 32, bytes.size), auth, DIRECTION_ANDROID_TO_MAC, now)
        assertEquals(5_000_001L, verified.totalSize)
        assertEquals("photo é.jpg", verified.fileName.toString(Charsets.UTF_8))
        assertArrayEquals(h.sessionId, verified.sessionId)
    }

    @Test
    fun crossPlatformGcmChunkFixtureMatches() {
        val h = TcpFrameProtocol.Header(TYPE_TEXT, DIRECTION_ANDROID_TO_MAC, 11, 1024, now,
            hex(vectors.getValue("sessionId")), ByteArray(0))
        val plain = hex(vectors.getValue("gcmPlaintext"))
        val sealed = TcpFrameProtocol.sealChunk(plain, root, h, 0, nonce = hex(vectors.getValue("gcmNonce")))
        assertEquals("Kotlin seal must equal the CryptoKit fixture", vectors["gcmSealedChunk0"], hexOf(sealed))
        assertArrayEquals(plain, TcpFrameProtocol.openChunk(sealed.copyOfRange(4, sealed.size), root, h, 0))
    }

    // ── totalSize semantics ──────────────────────────────────────────────────

    @Test
    fun totalSizeIsPlaintextBytesAndTextCompletes() {
        val text = "x".repeat(5000).toByteArray()
        val h = header(TYPE_TEXT, DIRECTION_ANDROID_TO_MAC, text.size.toLong(), 1_048_576, now)
        val (wire, _) = send(text, h, root)
        assertTrue("wire includes GCM overhead", wire.size > text.size + TcpTestSupport.headerLength(h))
        assertEquals(success(TYPE_TEXT, "", text), receive(wire, root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun ciphertextSizedTotalSizeFromOldSenderIsRejected() {
        // The old Android sender declared plaintext + 28 bytes; that must never complete.
        val text = "x".repeat(5000).toByteArray()
        val h = header(TYPE_TEXT, DIRECTION_ANDROID_TO_MAC, text.size + 28L, 1_048_576, now)
        assertEquals(rejected(Reason.CHUNK_LENGTH_MISMATCH),
            receive(TcpTestSupport.mismatchedStream(text, h, root), root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun smallerAndLargerDeclaredSizesFail() {
        val payload = randomBytes(5000)
        val smaller = header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 4000, 1024, now)
        assertEquals(rejected(Reason.CHUNK_LENGTH_MISMATCH),
            receive(TcpTestSupport.mismatchedStream(payload, smaller, root), root, DIRECTION_ANDROID_TO_MAC, now))
        val larger = header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 6000, 1024, now)
        assertEquals(rejected(Reason.CHUNK_LENGTH_MISMATCH),
            receive(TcpTestSupport.mismatchedStream(payload, larger, root), root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun multiChunkSucceedsAndChunkSizeDoesNotChangeTotalSize() {
        val payload = randomBytes(9 * 1_048_576 + 123)
        val totals = mutableSetOf<Long>()
        for (profile in ClipSyncSender.TransferProfile.values()) {
            val h = header(TYPE_FILE, DIRECTION_MAC_TO_ANDROID, payload.size.toLong(), profile.chunkSize, now, "v.mp4")
            totals += h.totalSize
            val (wire, chunks) = send(payload, h, root)
            assertEquals(TcpFrameProtocol.chunkCount(h), chunks.size.toLong())
            assertEquals(success(TYPE_FILE, "v.mp4", payload), receive(wire, root, DIRECTION_MAC_TO_ANDROID, now))
        }
        assertEquals(setOf(payload.size.toLong()), totals)
    }

    @Test
    fun senderRefusesSourceShorterOrLongerThanDeclared() {
        val h = header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 3000, 1024, now)
        for (source in listOf(randomBytes(2999), randomBytes(3001))) {
            val out = ByteArrayOutputStream()
            try {
                TcpFrameProtocol.writeTransfer(out, root, h, ByteArrayInputStream(source))
                fail("size ${source.size} should be refused")
            } catch (e: FrameException) {
                assertEquals(Reason.SOURCE_SIZE_MISMATCH, e.reason)
            }
            // The final chunk was never written, so the receiver cannot complete.
            assertEquals(rejected(Reason.INCOMPLETE), receive(out.toByteArray(), root, DIRECTION_ANDROID_TO_MAC, now))
        }
    }

    @Test
    fun emptyFileIsAllowedButEmptyTextIsNot() {
        val h = header(TYPE_FILE, DIRECTION_MAC_TO_ANDROID, 0, 1024, now, "empty.txt")
        val (wire, _) = send(ByteArray(0), h, root)
        assertEquals(success(TYPE_FILE, "empty.txt", ByteArray(0)), receive(wire, root, DIRECTION_MAC_TO_ANDROID, now))
        val text = header(TYPE_TEXT, DIRECTION_MAC_TO_ANDROID, 0, 1024, now)
        assertEquals(rejected(Reason.INVALID_TOTAL_SIZE),
            receive(TcpFrameProtocol.encodeHeader(text, TcpFrameProtocol.authKey(root)), root, DIRECTION_MAC_TO_ANDROID, now))
    }

    // ── Header authentication ────────────────────────────────────────────────

    private val good by lazy {
        val h = header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 3, 1024, now, "a.txt")
        send("abc".toByteArray(), h, root).first
    }

    private fun flipped(offset: Int, value: Int? = null) =
        good.copyOf().also { it[offset] = value?.toByte() ?: (it[offset].toInt() xor 1).toByte() }

    @Test
    fun validHeaderAccepted() {
        assertEquals(success(TYPE_FILE, "a.txt", "abc".toByteArray()), receive(good, root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun tamperedOrForeignHeadersRejected() {
        assertEquals(rejected(Reason.BAD_MAC), receive(good, randomBytes(32), DIRECTION_ANDROID_TO_MAC, now))
        val cases = mapOf(
            "type" to flipped(5, 0x01), "filename" to flipped(46), "total size" to flipped(15),
            "session ID" to flipped(30), "timestamp" to flipped(25), "chunk size" to flipped(19), "MAC" to flipped(60)
        )
        for ((field, wire) in cases) {
            assertEquals("modified $field", rejected(Reason.BAD_MAC), receive(wire, root, DIRECTION_ANDROID_TO_MAC, now))
        }
        assertEquals(rejected(Reason.UNSUPPORTED_VERSION), receive(flipped(4, 0x03), root, DIRECTION_ANDROID_TO_MAC, now))
        assertEquals(rejected(Reason.UNSUPPORTED_VERSION), receive(flipped(4, 0x01), root, DIRECTION_ANDROID_TO_MAC, now))
        assertEquals("reflected back to the sender", rejected(Reason.WRONG_DIRECTION),
            receive(good, root, DIRECTION_MAC_TO_ANDROID, now))
    }

    @Test
    fun truncatedAndExtendedMacRejected() {
        val auth = TcpFrameProtocol.authKey(root)
        val prefix = good.copyOfRange(0, 46 + 5)
        for (mac in listOf(good.copyOfRange(51, 51 + 31), good.copyOfRange(51, 51 + 32) + 0.toByte())) {
            try {
                TcpFrameProtocol.verifyHeader(prefix, mac, auth, DIRECTION_ANDROID_TO_MAC, now)
                fail("MAC of length ${mac.size} accepted")
            } catch (e: FrameException) {
                assertEquals(Reason.BAD_MAC, e.reason)
            }
        }
        assertEquals("stream cut inside the MAC", rejected(Reason.MALFORMED_HEADER),
            receive(good.copyOfRange(0, 51 + 20), root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun staleAndFutureTimestampsRejected() {
        val w = TcpFrameProtocol.TIMESTAMP_WINDOW_MS
        assertEquals(rejected(Reason.STALE_TIMESTAMP), receive(good, root, DIRECTION_ANDROID_TO_MAC, now + w + 1))
        assertEquals(rejected(Reason.STALE_TIMESTAMP), receive(good, root, DIRECTION_ANDROID_TO_MAC, now - w - 1))
        assertTrue(receive(good, root, DIRECTION_ANDROID_TO_MAC, now + w) is Outcome.Success)
    }

    // ── Fail-closed parser ───────────────────────────────────────────────────

    private fun parseReason(mutate: (ByteArray) -> Unit, direction: Byte = DIRECTION_ANDROID_TO_MAC): Reason? {
        val b = good.copyOfRange(0, 46).also(mutate)
        return try { TcpFrameProtocol.parseFixedPrefix(b, direction); null } catch (e: FrameException) { e.reason }
    }

    @Test
    fun malformedHeadersRejectedBeforeAnythingIsTrusted() {
        assertEquals(Reason.LEGACY_PROTOCOL, parseReason({ it[3] = 0x59 }))
        assertEquals(Reason.BAD_MAGIC, parseReason({ it[0] = 0 }))
        assertEquals(Reason.UNKNOWN_TYPE, parseReason({ it[5] = TcpFrameProtocol.RETIRED_PLAINTEXT_TYPE }))
        assertEquals(Reason.UNKNOWN_TYPE, parseReason({ it[5] = 0x99.toByte() }))
        assertEquals(Reason.BAD_RESERVED, parseReason({ it[7] = 1 }))
        assertEquals(Reason.INVALID_NAME_LENGTH, parseReason({ it[44] = 0x04; it[45] = 0x01 }))
        assertEquals(Reason.INVALID_SESSION_ID, parseReason({ for (i in 28 until 44) it[i] = 0 }))
        assertEquals(Reason.INVALID_TOTAL_SIZE, parseReason({ for (i in 8 until 16) it[i] = 0xFF.toByte() }))
        assertEquals(Reason.INVALID_TOTAL_SIZE, parseReason({ it[8] = 0x7F }))
        assertEquals(Reason.INVALID_TOTAL_SIZE, parseReason({ it[5] = TYPE_TEXT; for (i in 8 until 16) it[i] = 0 }))
        assertEquals(Reason.INVALID_TOTAL_SIZE, parseReason({ it[5] = TYPE_IMAGE; it[11] = 0x7F }))
        assertEquals(Reason.INVALID_CHUNK_SIZE, parseReason({ for (i in 16 until 20) it[i] = 0 }))
        assertEquals(Reason.INVALID_CHUNK_SIZE, parseReason({ it[16] = 0x01 }))
        assertEquals(Reason.MALFORMED_HEADER,
            try { TcpFrameProtocol.parseFixedPrefix(good.copyOfRange(0, 45), DIRECTION_ANDROID_TO_MAC); null }
            catch (e: FrameException) { e.reason })
    }

    @Test
    fun legacyV1FramesAreRejectedByAndroidReceivers() {
        // v1 header (24 bytes) including the retired plaintext type 0x04, padded to 46.
        val legacy = byteArrayOf(0x43, 0x4C, 0x53, 0x59, 0x01, 0x04) + ByteArray(40)
        assertEquals(rejected(Reason.LEGACY_PROTOCOL), receive(legacy, root, DIRECTION_MAC_TO_ANDROID, now))
    }

    // ── Chunk integrity ──────────────────────────────────────────────────────

    private val payload3 = randomBytes(3 * 1024 + 7)
    private val multiHeader = header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, payload3.size.toLong(), 1024, now, "m.bin")
    private val multi = send(payload3, multiHeader, root)

    private fun assemble(chunks: List<ByteArray>): ByteArray =
        chunks.fold(multi.first.copyOfRange(0, TcpTestSupport.headerLength(multiHeader))) { acc, c -> acc + c }

    @Test
    fun chunkOrderingAndSessionBindingEnforced() {
        val c = multi.second
        assertEquals(success(TYPE_FILE, "m.bin", payload3), receive(assemble(c), root, DIRECTION_ANDROID_TO_MAC, now))

        val failed = rejected(Reason.CHUNK_AUTHENTICATION_FAILED)
        assertEquals("swapped", failed, receive(assemble(listOf(c[1], c[0], c[2], c[3])), root, DIRECTION_ANDROID_TO_MAC, now))
        assertEquals("duplicated", failed, receive(assemble(listOf(c[0], c[0], c[2], c[3])), root, DIRECTION_ANDROID_TO_MAC, now))

        val other = send(payload3, header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, payload3.size.toLong(), 1024, now, "m.bin"), root)
        assertEquals("spliced from another session", failed,
            receive(assemble(listOf(c[0], c[1], other.second[2], c[3])), root, DIRECTION_ANDROID_TO_MAC, now))

        val tampered = c[1].copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertEquals("tampered ciphertext", failed, receive(assemble(listOf(c[0], tampered, c[2], c[3])), root, DIRECTION_ANDROID_TO_MAC, now))

        assertEquals("truncated", rejected(Reason.INCOMPLETE), receive(assemble(c.dropLast(1)), root, DIRECTION_ANDROID_TO_MAC, now))
    }

    @Test
    fun chunkOpenedWithDifferentIndexOrMetadataFails() {
        val sealed = multi.second[1].let { it.copyOfRange(4, it.size) }
        assertArrayEquals(payload3.copyOfRange(1024, 2048), TcpFrameProtocol.openChunk(sealed, root, multiHeader, 1))
        for ((label, h, index) in listOf(
            Triple("index", multiHeader, 2L),
            Triple("type", TcpFrameProtocol.Header(TYPE_IMAGE, multiHeader.direction, multiHeader.totalSize, 1024, now, multiHeader.sessionId, ByteArray(0)), 1L),
            Triple("direction", TcpFrameProtocol.Header(TYPE_FILE, DIRECTION_MAC_TO_ANDROID, multiHeader.totalSize, 1024, now, multiHeader.sessionId, ByteArray(0)), 1L),
            Triple("total size", TcpFrameProtocol.Header(TYPE_FILE, multiHeader.direction, multiHeader.totalSize + 1, 1024, now, multiHeader.sessionId, ByteArray(0)), 1L)
        )) {
            try {
                TcpFrameProtocol.openChunk(sealed, root, h, index)
                fail("chunk opened under different $label")
            } catch (e: FrameException) {
                assertEquals(label, Reason.CHUNK_AUTHENTICATION_FAILED, e.reason)
            }
        }
        try {
            TcpFrameProtocol.expectedSealedLength(multiHeader, 4)
            fail("index past the end accepted")
        } catch (e: FrameException) {
            assertEquals(Reason.CHUNK_INDEX_OUT_OF_RANGE, e.reason)
        }
    }

    // ── Replay ───────────────────────────────────────────────────────────────

    @Test
    fun replayCacheRejectsRepeatsAndStaysBounded() {
        val cache = TcpReplayCache(capacity = 3, ttlMs = 1000)
        val s1 = TcpFrameProtocol.newSessionId()
        assertFalse(s1.contentEquals(TcpFrameProtocol.newSessionId()))
        assertTrue("first session accepted", cache.insertIfNew(s1, 0))
        assertFalse("exact replay rejected", cache.insertIfNew(s1, 10))
        repeat(10) { cache.insertIfNew(ByteArray(16) { _ -> (it + 1).toByte() }, 20) }
        assertTrue("bounded, size=${cache.size}", cache.size <= 3)

        val expiring = TcpReplayCache(capacity = 10, ttlMs = 1000)
        expiring.insertIfNew(s1, 0)
        assertFalse(expiring.insertIfNew(s1, 999))
        assertTrue("expired entries are dropped", expiring.insertIfNew(s1, 1000))
    }

    @Test
    fun replayedStreamRejected() {
        val cache = TcpReplayCache()
        assertTrue(receive(good, root, DIRECTION_ANDROID_TO_MAC, now, cache) is Outcome.Success)
        assertEquals(rejected(Reason.REPLAYED), receive(good, root, DIRECTION_ANDROID_TO_MAC, now, cache))
        assertNotEquals(rejected(Reason.REPLAYED), receive(send("abc".toByteArray(),
            header(TYPE_FILE, DIRECTION_ANDROID_TO_MAC, 3, 1024, now, "a.txt"), root).first, root, DIRECTION_ANDROID_TO_MAC, now, cache))
    }
}
