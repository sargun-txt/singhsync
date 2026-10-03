package com.bunty.clipsync

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ClipSync local TCP protocol v2: authenticated header + AES-GCM chunks bound to the session.
 *
 * Canonical layout (all integers big-endian, strings UTF-8). Must match TcpFrameProtocol.swift
 * and protocol/generate_tcp_v2_vectors.py byte for byte.
 *
 * ```
 * Header
 *   off len field
 *     0   4  magic "CLS2"
 *     4   1  version = 0x02
 *     5   1  type: 0x01 text, 0x02 image, 0x03 file
 *     6   1  direction: 0x01 Android→Mac, 0x02 Mac→Android
 *     7   1  reserved = 0x00
 *     8   8  totalSize    plaintext/application bytes
 *    16   4  chunkSize    plaintext bytes per chunk
 *    20   8  timestampMs  sender clock, Unix epoch ms
 *    28  16  sessionId    random, unique per transfer
 *    44   2  nameLen
 *    46   N  name (UTF-8)
 *  46+N  32  HMAC-SHA256(authKey, bytes[0 until 46+N])
 *
 * authKey = HKDF-SHA256(IKM = pairing key, salt = empty, info = "ClipSync/TCP/Auth/v1", L = 32)
 *
 * Chunk i (index counted by both sides, never sent):
 *   [4-byte sealedLen][12-byte nonce][ciphertext][16-byte tag]
 *   sealedLen = plainLen(i) + 28, plainLen(i) = min(chunkSize, totalSize − i·chunkSize)
 *   AES-256-GCM with the pairing key, AAD (31 bytes) =
 *     version(1) ‖ sessionId(16) ‖ type(1) ‖ direction(1) ‖ totalSize(8) ‖ chunkIndex(4)
 * ```
 *
 * Pure JVM (no Android APIs) so the whole protocol is covered by local unit tests.
 */
object TcpFrameProtocol {

    val MAGIC = byteArrayOf(0x43, 0x4C, 0x53, 0x32)        // "CLS2"
    /** v1 magic. v1 frames are unauthenticated and always refused by Android receivers. */
    val LEGACY_MAGIC = byteArrayOf(0x43, 0x4C, 0x53, 0x59) // "CLSY"
    const val VERSION: Byte = 0x02

    const val FIXED_PREFIX_LENGTH = 46
    const val MAC_LENGTH = 32
    const val SESSION_ID_LENGTH = 16
    const val MAX_NAME_LENGTH = 1024
    const val MIN_CHUNK_SIZE = 1024
    const val MAX_CHUNK_SIZE = 4 * 1024 * 1024
    const val GCM_OVERHEAD = 28
    const val MAX_TOTAL_SIZE = 64L * 1024 * 1024 * 1024          // 64 GiB
    /** Text and images are buffered in memory before reaching the clipboard. */
    const val MAX_IN_MEMORY_TOTAL_SIZE = 128L * 1024 * 1024      // 128 MiB
    /** Accepted sender/receiver clock difference. */
    const val TIMESTAMP_WINDOW_MS = 15L * 60 * 1000

    const val TYPE_TEXT: Byte = 0x01
    const val TYPE_IMAGE: Byte = 0x02
    const val TYPE_FILE: Byte = 0x03
    /** Retired legacy "Ultra Fast" plaintext type. Never sent; rejected as an unknown type. */
    const val RETIRED_PLAINTEXT_TYPE: Byte = 0x04

    const val DIRECTION_ANDROID_TO_MAC: Byte = 0x01
    const val DIRECTION_MAC_TO_ANDROID: Byte = 0x02

    private const val GCM_NONCE_LENGTH = 12
    private const val GCM_TAG_BITS = 128
    private val AUTH_INFO = "ClipSync/TCP/Auth/v1".toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    /** Why a frame was refused. Safe to log: carries no payload, key or header bytes. */
    enum class Reason {
        LEGACY_PROTOCOL, BAD_MAGIC, MALFORMED_HEADER, UNSUPPORTED_VERSION, UNKNOWN_TYPE,
        WRONG_DIRECTION, BAD_RESERVED, INVALID_TOTAL_SIZE, INVALID_CHUNK_SIZE, INVALID_NAME_LENGTH,
        INVALID_SESSION_ID, BAD_MAC, STALE_TIMESTAMP, REPLAYED, CHUNK_LENGTH_MISMATCH,
        CHUNK_INDEX_OUT_OF_RANGE, CHUNK_AUTHENTICATION_FAILED, SOURCE_SIZE_MISMATCH, INCOMPLETE,
        BAD_KEY
    }

    class FrameException(val reason: Reason) : Exception(reason.name)

    /** A header whose MAC has been verified (or one being built for sending). */
    class Header(
        val type: Byte,
        val direction: Byte,
        val totalSize: Long,
        val chunkSize: Int,
        val timestampMs: Long,
        val sessionId: ByteArray,
        val fileName: ByteArray
    )

    // ── Keys ──────────────────────────────────────────────────────────────────

    /** Parses the stored 64-hex-char pairing key. */
    fun rootKey(hexKey: String): ByteArray {
        if (hexKey.length != 64) throw FrameException(Reason.BAD_KEY)
        return try {
            ByteArray(32) { i -> hexKey.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        } catch (e: NumberFormatException) {
            throw FrameException(Reason.BAD_KEY)
        }
    }

    fun authKey(rootKey: ByteArray): ByteArray =
        // An empty HKDF salt is defined as HashLen zero bytes (RFC 5869 §2.2).
        hkdfSha256(rootKey, ByteArray(32), AUTH_INFO, 32)

    /** RFC 5869 HKDF with HMAC-SHA256. [salt] must be non-empty (javax.crypto rejects empty keys). */
    internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(salt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var produced = 0
        var counter = 1
        while (produced < length) {
            previous = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            val n = minOf(previous.size, length - produced)
            System.arraycopy(previous, 0, out, produced, n)
            produced += n
            counter++
        }
        return out
    }

    fun newSessionId(): ByteArray = ByteArray(SESSION_ID_LENGTH).also { random.nextBytes(it) }

    // ── Header encoding ───────────────────────────────────────────────────────

    fun prefixBytes(h: Header): ByteArray {
        if (h.sessionId.size != SESSION_ID_LENGTH) throw FrameException(Reason.INVALID_SESSION_ID)
        if (h.fileName.size > MAX_NAME_LENGTH) throw FrameException(Reason.INVALID_NAME_LENGTH)
        return ByteBuffer.allocate(FIXED_PREFIX_LENGTH + h.fileName.size).apply {
            put(MAGIC)
            put(VERSION); put(h.type); put(h.direction); put(0)
            putLong(h.totalSize)
            putInt(h.chunkSize)
            putLong(h.timestampMs)
            put(h.sessionId)
            putShort(h.fileName.size.toShort())
            put(h.fileName)
        }.array()
    }

    /** Full header: prefix followed by its HMAC-SHA256. */
    fun encodeHeader(h: Header, authKey: ByteArray): ByteArray {
        val prefix = prefixBytes(h)
        return prefix + hmac(authKey, prefix)
    }

    // ── Header parsing ────────────────────────────────────────────────────────

    /**
     * Structural checks on the 46-byte fixed prefix, done only to bound further reads.
     * Returns the name length. Nothing here is trusted until [verifyHeader] succeeds.
     */
    fun parseFixedPrefix(b: ByteArray, expectedDirection: Byte): Int {
        if (b.size != FIXED_PREFIX_LENGTH) throw FrameException(Reason.MALFORMED_HEADER)
        val magic = b.copyOfRange(0, 4)
        if (magic.contentEquals(LEGACY_MAGIC)) throw FrameException(Reason.LEGACY_PROTOCOL)
        if (!magic.contentEquals(MAGIC)) throw FrameException(Reason.BAD_MAGIC)
        if (b[4] != VERSION) throw FrameException(Reason.UNSUPPORTED_VERSION)
        val type = b[5]
        if (type != TYPE_TEXT && type != TYPE_IMAGE && type != TYPE_FILE) throw FrameException(Reason.UNKNOWN_TYPE)
        if (b[6] != expectedDirection) throw FrameException(Reason.WRONG_DIRECTION)
        if (b[7] != 0.toByte()) throw FrameException(Reason.BAD_RESERVED)

        val buf = ByteBuffer.wrap(b)
        val totalSize = buf.getLong(8)
        val inMemory = type != TYPE_FILE
        val min = if (inMemory) 1L else 0L
        val max = if (inMemory) MAX_IN_MEMORY_TOTAL_SIZE else MAX_TOTAL_SIZE
        if (totalSize < min || totalSize > max) throw FrameException(Reason.INVALID_TOTAL_SIZE)
        val chunkSize = buf.getInt(16).toLong() and 0xFFFFFFFFL
        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) throw FrameException(Reason.INVALID_CHUNK_SIZE)
        if ((totalSize + chunkSize - 1) / chunkSize > 0xFFFFFFFFL) throw FrameException(Reason.INVALID_CHUNK_SIZE)
        if ((28 until 44).all { b[it] == 0.toByte() }) throw FrameException(Reason.INVALID_SESSION_ID)
        val nameLength = buf.getShort(44).toInt() and 0xFFFF
        if (nameLength > MAX_NAME_LENGTH) throw FrameException(Reason.INVALID_NAME_LENGTH)
        return nameLength
    }

    /**
     * Verifies the MAC (constant time) and the timestamp window, then returns the header.
     * [prefix] is the fixed prefix plus name bytes; [mac] must be exactly 32 bytes.
     */
    fun verifyHeader(prefix: ByteArray, mac: ByteArray, authKey: ByteArray, expectedDirection: Byte, nowMs: Long): Header {
        if (prefix.size < FIXED_PREFIX_LENGTH) throw FrameException(Reason.MALFORMED_HEADER)
        val nameLength = parseFixedPrefix(prefix.copyOfRange(0, FIXED_PREFIX_LENGTH), expectedDirection)
        if (prefix.size != FIXED_PREFIX_LENGTH + nameLength) throw FrameException(Reason.INVALID_NAME_LENGTH)
        if (mac.size != MAC_LENGTH) throw FrameException(Reason.BAD_MAC)
        // MessageDigest.isEqual is a constant-time comparison.
        if (!MessageDigest.isEqual(hmac(authKey, prefix), mac)) throw FrameException(Reason.BAD_MAC)

        val buf = ByteBuffer.wrap(prefix)
        val header = Header(
            type = prefix[5],
            direction = expectedDirection,
            totalSize = buf.getLong(8),
            chunkSize = buf.getInt(16),
            timestampMs = buf.getLong(20),
            sessionId = prefix.copyOfRange(28, 44),
            fileName = prefix.copyOfRange(FIXED_PREFIX_LENGTH, prefix.size)
        )
        val skew = nowMs - header.timestampMs
        if (skew > TIMESTAMP_WINDOW_MS || skew < -TIMESTAMP_WINDOW_MS) throw FrameException(Reason.STALE_TIMESTAMP)
        return header
    }

    // ── Chunks ────────────────────────────────────────────────────────────────

    fun chunkCount(h: Header): Long = (h.totalSize + h.chunkSize - 1) / h.chunkSize

    /** Plaintext length of chunk [index], or null if the index is past the end. */
    fun plainLength(h: Header, index: Long): Int? {
        val offset = index * h.chunkSize
        if (index < 0 || offset >= h.totalSize) return null
        return minOf(h.chunkSize.toLong(), h.totalSize - offset).toInt()
    }

    fun expectedSealedLength(h: Header, index: Long): Int =
        (plainLength(h, index) ?: throw FrameException(Reason.CHUNK_INDEX_OUT_OF_RANGE)) + GCM_OVERHEAD

    fun aad(h: Header, index: Long): ByteArray =
        ByteBuffer.allocate(31).apply {
            put(VERSION)
            put(h.sessionId)
            put(h.type)
            put(h.direction)
            putLong(h.totalSize)
            putInt(index.toInt())
        }.array()

    /** Wire bytes for chunk [index]: length prefix + nonce + ciphertext + tag. */
    fun sealChunk(plain: ByteArray, rootKey: ByteArray, h: Header, index: Long, nonce: ByteArray? = null): ByteArray {
        val expected = plainLength(h, index) ?: throw FrameException(Reason.CHUNK_INDEX_OUT_OF_RANGE)
        if (plain.size != expected) throw FrameException(Reason.CHUNK_LENGTH_MISMATCH)
        val iv = nonce ?: ByteArray(GCM_NONCE_LENGTH).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(rootKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad(h, index))
        val ct = cipher.doFinal(plain)
        return ByteBuffer.allocate(4 + iv.size + ct.size).putInt(iv.size + ct.size).put(iv).put(ct).array()
    }

    /** Opens chunk [index]; [sealed] excludes the 4-byte length prefix. */
    fun openChunk(sealed: ByteArray, rootKey: ByteArray, h: Header, index: Long): ByteArray {
        if (sealed.size != expectedSealedLength(h, index)) throw FrameException(Reason.CHUNK_LENGTH_MISMATCH)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rootKey, "AES"),
                GCMParameterSpec(GCM_TAG_BITS, sealed, 0, GCM_NONCE_LENGTH))
            cipher.updateAAD(aad(h, index))
            cipher.doFinal(sealed, GCM_NONCE_LENGTH, sealed.size - GCM_NONCE_LENGTH)
        } catch (e: Exception) {
            throw FrameException(Reason.CHUNK_AUTHENTICATION_FAILED)
        }
    }

    // ── Streams ───────────────────────────────────────────────────────────────

    /**
     * Reads and verifies a v2 header from [inp]. Nothing from the header may be trusted
     * (and nothing should be created) before this returns. Records the session ID in
     * [replayCache], rejecting one already seen.
     */
    fun readVerifiedHeader(
        inp: InputStream,
        rootKey: ByteArray,
        expectedDirection: Byte,
        nowMs: Long,
        replayCache: TcpReplayCache?
    ): Header {
        val fixed = inp.readExactly(FIXED_PREFIX_LENGTH) ?: throw FrameException(Reason.MALFORMED_HEADER)
        val nameLength = parseFixedPrefix(fixed, expectedDirection)
        val name = inp.readExactly(nameLength) ?: throw FrameException(Reason.MALFORMED_HEADER)
        val mac = inp.readExactly(MAC_LENGTH) ?: throw FrameException(Reason.MALFORMED_HEADER)
        val header = verifyHeader(fixed + name, mac, authKey(rootKey), expectedDirection, nowMs)
        if (replayCache != null && !replayCache.insertIfNew(header.sessionId, nowMs)) {
            throw FrameException(Reason.REPLAYED)
        }
        return header
    }

    /**
     * Reads, length-checks and opens every chunk in order, passing plaintext to [onChunk].
     * Returns the plaintext byte count: equal to [Header.totalSize] on success, or less if
     * [isCancelled] stopped it early. Throws [FrameException] on any integrity failure.
     */
    fun readChunks(
        inp: InputStream,
        h: Header,
        rootKey: ByteArray,
        isCancelled: () -> Boolean = { false },
        onChunk: (ByteArray) -> Unit
    ): Long {
        var received = 0L
        var index = 0L
        while (received < h.totalSize) {
            if (isCancelled()) return received
            val lenBytes = inp.readExactly(4) ?: throw FrameException(Reason.INCOMPLETE)
            val sealedLen = ByteBuffer.wrap(lenBytes).int
            if (sealedLen != expectedSealedLength(h, index)) throw FrameException(Reason.CHUNK_LENGTH_MISMATCH)
            val sealed = inp.readExactly(sealedLen) ?: throw FrameException(Reason.INCOMPLETE)
            val plain = openChunk(sealed, rootKey, h, index)
            onChunk(plain)
            received += plain.size
            index++
        }
        return received
    }

    /**
     * Writes [h] (authenticated) and then exactly [Header.totalSize] bytes from [source] as
     * sealed chunks. If [source] is shorter or longer than declared, throws before the final
     * chunk is written, so the receiver never completes with a wrong payload.
     * [onProgress] receives the plaintext bytes sent so far.
     */
    fun writeTransfer(
        out: OutputStream,
        rootKey: ByteArray,
        h: Header,
        source: InputStream,
        isActive: () -> Boolean = { true },
        onProgress: (Long) -> Unit = {}
    ) {
        out.write(encodeHeader(h, authKey(rootKey)))
        val count = chunkCount(h)
        var sent = 0L
        var index = 0L
        while (index < count) {
            if (!isActive()) throw kotlinx.coroutines.CancellationException("Transfer cancelled")
            val len = plainLength(h, index)!!
            val plain = source.readExactly(len) ?: throw FrameException(Reason.SOURCE_SIZE_MISMATCH)
            if (index == count - 1 && source.read() != -1) throw FrameException(Reason.SOURCE_SIZE_MISMATCH)
            out.write(sealChunk(plain, rootKey, h, index))
            sent += len
            index++
            onProgress(sent)
        }
        if (count == 0L && source.read() != -1) throw FrameException(Reason.SOURCE_SIZE_MISMATCH)
        out.flush()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    /** Reads exactly [n] bytes, or returns null at end of stream. */
    private fun InputStream.readExactly(n: Int): ByteArray? {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = read(buf, off, n - off)
            if (r < 0) return null
            off += r
        }
        return buf
    }
}

/**
 * Bounded, time-limited record of session IDs already accepted by this receiver.
 * Entries live for twice the timestamp window, so a header old enough to have been evicted
 * is also outside the accepted timestamp window. Capacity bounds memory; if more than
 * [capacity] legitimate transfers arrive within that period, the oldest IDs are evicted early.
 */
class TcpReplayCache(
    private val capacity: Int = 1024,
    private val ttlMs: Long = 2 * TcpFrameProtocol.TIMESTAMP_WINDOW_MS
) {
    // Insertion order == expiry order (constant TTL), so the head is always the oldest.
    private val expiry = LinkedHashMap<String, Long>()

    /** Records [sessionId]; returns false if it was already seen and has not expired. */
    @Synchronized
    fun insertIfNew(sessionId: ByteArray, nowMs: Long): Boolean {
        val it = expiry.entries.iterator()
        while (it.hasNext()) {
            if (it.next().value <= nowMs) it.remove() else break
        }
        val id = sessionId.joinToString("") { "%02x".format(it) }
        val existing = expiry[id]
        if (existing != null) {
            if (existing > nowMs) return false
            expiry.remove(id) // expired but not yet swept (clock moved backwards)
        }
        while (expiry.size >= capacity) {
            expiry.remove(expiry.keys.first())
        }
        expiry[id] = nowMs + ttlMs
        return true
    }

    @get:Synchronized
    val size: Int get() = expiry.size
}
