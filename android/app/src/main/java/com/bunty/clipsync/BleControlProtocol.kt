package com.bunty.clipsync

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Authenticated BLE control messages (v2), byte-for-byte compatible with
 * BleControlProtocol.swift and protocol/generate_ble_v2_vectors.py.
 *
 * ```
 * Envelope (big-endian)
 *   off len field
 *     0   4  magic "CLB2"
 *     4   1  version = 0x02
 *     5   1  message type (0x10-0x18 Android→Mac, 0x20-0x26 Mac→Android)
 *     6   1  direction: 0x01 Android→Mac, 0x02 Mac→Android
 *     7   1  reserved = 0x00
 *     8   8  timestampMs
 *    16  16  messageId (random)
 *    32   2  payloadLen
 *    34   N  payload: TLV [tag(1)][len(2)][value], tags strictly ascending
 *  34+N  32  HMAC-SHA256(bleAuthKey, bytes[0 until 34+N])
 *
 * bleAuthKey = HKDF-SHA256(IKM = pairing key, salt = empty, info = "ClipSync/BLE/Auth/v1", L = 32)
 * ```
 *
 * The MAC is verified before any payload field is decoded. Responses (ping_ack, tcp_ready)
 * echo the request's messageId in [Field.REPLY_TO]; the Mac only accepts them while that
 * request is outstanding. Pure JVM so it is covered by local unit tests.
 */
object BleControlProtocol {

    val MAGIC = byteArrayOf(0x43, 0x4C, 0x42, 0x32) // "CLB2"
    const val VERSION: Byte = 0x02
    const val HEADER_LENGTH = 34
    const val MAC_LENGTH = 32
    const val MESSAGE_ID_LENGTH = 16
    const val MAX_PAYLOAD_LENGTH = 8192
    const val TIMESTAMP_WINDOW_MS = 15L * 60 * 1000

    const val DIRECTION_ANDROID_TO_MAC: Byte = 0x01
    const val DIRECTION_MAC_TO_ANDROID: Byte = 0x02

    /** Exact bytes of the pre-pairing presence signal, sent before the phone has the key. */
    val LEGACY_PAIR_PRESENCE = "{\"type\":\"pair\"}".toByteArray(Charsets.UTF_8)

    private val AUTH_INFO = "ClipSync/BLE/Auth/v1".toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    enum class Type(val code: Byte, val payloadTypeName: String) {
        // Android → Mac
        PAIRING_ACK(0x10, "pairing_ack"), HANDSHAKE(0x11, "handshake"), PING_ACK(0x12, "ping_ack"),
        TCP_READY(0x13, "tcp_ready"), WAKE_TEXT(0x14, "text"), WAKE_IMAGE(0x15, "image"),
        WAKE_FILE(0x16, "file"), IP_PROBE(0x17, "ip_probe"), DIAGNOSTIC(0x18, "diagnostic"),
        // Mac → Android
        PUSH_TEXT(0x20, "text"), FILE_INCOMING(0x21, "file_incoming"), TEXT_INCOMING(0x22, "text_incoming"),
        SETTING(0x23, "setting"), PING(0x24, "ping"), DIAGNOSTIC_ACK(0x25, "diagnostic_ack"),
        DEVICE_INFO(0x26, "device_info");

        val direction: Byte get() = if ((code.toInt() and 0xFF) < 0x20) DIRECTION_ANDROID_TO_MAC else DIRECTION_MAC_TO_ANDROID

        companion object {
            fun fromCode(code: Byte): Type? = values().firstOrNull { it.code == code }

            /** Maps the app's existing Android → Mac payload-type strings. */
            fun forAndroidPayloadType(name: String): Type? =
                values().firstOrNull { it.direction == DIRECTION_ANDROID_TO_MAC && it.payloadTypeName == name }
        }
    }

    enum class Field(val tag: Byte) {
        IP(0x01), PORT(0x02), SIZE(0x03), DIRECT_PAYLOAD(0x04), BATTERY(0x05), NETWORK(0x06),
        DEVICE_NAME(0x07), REPLY_TO(0x08), FILE_NAME(0x09), CONTENT(0x0A), ULTRA_FAST(0x0B), NAME(0x0C);

        companion object {
            fun fromTag(tag: Int): Field? = values().firstOrNull { (it.tag.toInt() and 0xFF) == tag }
        }
    }

    enum class Reason {
        BAD_MAGIC, UNSUPPORTED_VERSION, MALFORMED_ENVELOPE, UNKNOWN_TYPE, WRONG_DIRECTION, BAD_RESERVED,
        INVALID_LENGTH, INVALID_MESSAGE_ID, BAD_MAC, STALE_TIMESTAMP, REPLAYED,
        MALFORMED_PAYLOAD, UNEXPECTED_FIELD, MISSING_FIELD, INVALID_VALUE,
        UNEXPECTED_TYPE, NOT_PAIRED
    }

    /** Carries only a [Reason]: safe to log. */
    class BleException(val reason: Reason) : Exception(reason.name)

    /** A verified message whose fields are already range-checked. */
    class Message(val type: Type, val messageId: ByteArray, val timestampMs: Long, val fields: Map<Field, ByteArray>) {
        fun string(f: Field): String? = fields[f]?.toString(Charsets.UTF_8)
        fun uint(f: Field): Long? = fields[f]?.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
    }

    // ── Keys ──────────────────────────────────────────────────────────────────

    fun authKey(rootKey: ByteArray): ByteArray =
        // An empty HKDF salt is defined as HashLen zero bytes (RFC 5869 §2.2).
        TcpFrameProtocol.hkdfSha256(rootKey, ByteArray(32), AUTH_INFO, 32)

    fun newMessageId(): ByteArray = ByteArray(MESSAGE_ID_LENGTH).also { random.nextBytes(it) }

    // ── Schema ────────────────────────────────────────────────────────────────

    private val STATUS = setOf(Field.IP, Field.PORT, Field.SIZE, Field.DIRECT_PAYLOAD, Field.BATTERY, Field.NETWORK, Field.DEVICE_NAME)

    /** (required, allowed) fields per type. */
    fun schema(type: Type): Pair<Set<Field>, Set<Field>> = when (type) {
        Type.PAIRING_ACK, Type.HANDSHAKE, Type.WAKE_TEXT, Type.WAKE_IMAGE, Type.WAKE_FILE,
        Type.IP_PROBE, Type.DIAGNOSTIC -> emptySet<Field>() to STATUS
        Type.PING_ACK, Type.TCP_READY -> setOf(Field.REPLY_TO) to STATUS + Field.REPLY_TO
        Type.PUSH_TEXT -> setOf(Field.CONTENT) to setOf(Field.CONTENT)
        Type.FILE_INCOMING -> setOf(Field.FILE_NAME, Field.SIZE, Field.PORT).let { it to it }
        Type.TEXT_INCOMING -> setOf(Field.SIZE, Field.PORT).let { it to it }
        Type.SETTING -> setOf(Field.ULTRA_FAST) to setOf(Field.ULTRA_FAST)
        Type.PING, Type.DIAGNOSTIC_ACK -> emptySet<Field>() to emptySet()
        Type.DEVICE_INFO -> setOf(Field.NAME, Field.PORT) to setOf(Field.NAME, Field.PORT, Field.IP)
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    fun encodeFields(fields: Map<Field, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for (field in fields.keys.sortedBy { it.tag.toInt() and 0xFF }) {
            val v = fields.getValue(field)
            out.write(field.tag.toInt())
            out.write(v.size shr 8)
            out.write(v.size and 0xFF)
            out.write(v)
        }
        return out.toByteArray()
    }

    fun decodeFields(payload: ByteArray, type: Type): Map<Field, ByteArray> {
        val fields = LinkedHashMap<Field, ByteArray>()
        var pos = 0
        var lastTag = 0
        while (pos < payload.size) {
            if (pos + 3 > payload.size) throw BleException(Reason.MALFORMED_PAYLOAD)
            val tag = payload[pos].toInt() and 0xFF
            val len = ((payload[pos + 1].toInt() and 0xFF) shl 8) or (payload[pos + 2].toInt() and 0xFF)
            pos += 3
            if (pos + len > payload.size) throw BleException(Reason.MALFORMED_PAYLOAD)
            // Strictly ascending tags: canonical order, and no duplicates.
            if (tag <= lastTag) throw BleException(Reason.MALFORMED_PAYLOAD)
            val field = Field.fromTag(tag) ?: throw BleException(Reason.UNEXPECTED_FIELD)
            fields[field] = payload.copyOfRange(pos, pos + len)
            lastTag = tag
            pos += len
        }
        val (required, allowed) = schema(type)
        if (!allowed.containsAll(fields.keys)) throw BleException(Reason.UNEXPECTED_FIELD)
        if (!fields.keys.containsAll(required)) throw BleException(Reason.MISSING_FIELD)
        for ((field, value) in fields) validate(field, value)
        return fields
    }

    private fun validate(field: Field, v: ByteArray) {
        fun fail(): Nothing = throw BleException(Reason.INVALID_VALUE)
        fun utf8(max: Int): String {
            if (v.size > max) fail()
            val decoder = Charsets.UTF_8.newDecoder()
            return try { decoder.decode(ByteBuffer.wrap(v)).toString() } catch (e: Exception) { fail() }
        }
        fun noControls(s: String) { if (s.any { Character.getType(it) == Character.CONTROL.toInt() }) fail() }
        when (field) {
            Field.IP -> if (!isValidIpv4OrEmpty(utf8(15))) fail()
            Field.PORT -> if (v.size != 2 || (((v[0].toInt() and 0xFF) shl 8) or (v[1].toInt() and 0xFF)) < 1) fail()
            Field.SIZE -> if (v.size != 8 || v[0] < 0) fail()
            Field.DIRECT_PAYLOAD, Field.CONTENT -> {
                val s = utf8(MAX_PAYLOAD_LENGTH)
                if (s.isEmpty()) fail()
                try { java.util.Base64.getDecoder().decode(s) } catch (e: IllegalArgumentException) { fail() }
            }
            Field.BATTERY -> if (v.size != 1 || (v[0].toInt() and 0xFF) > 100) fail()
            Field.NETWORK, Field.DEVICE_NAME, Field.NAME -> noControls(utf8(128))
            Field.FILE_NAME -> noControls(utf8(1024))
            Field.REPLY_TO -> if (v.size != MESSAGE_ID_LENGTH) fail()
            Field.ULTRA_FAST -> if (v.size != 1 || (v[0].toInt() and 0xFF) > 1) fail()
        }
    }

    /** Dotted-quad IPv4, implemented identically on both platforms. */
    fun isValidIpv4OrEmpty(s: String): Boolean {
        if (s.isEmpty()) return true
        val parts = s.split(".")
        return parts.size == 4 && parts.all { p ->
            p.length in 1..3 && p.all { it in '0'..'9' } && p.toInt() <= 255
        }
    }

    // ── Envelope ──────────────────────────────────────────────────────────────

    /** Builds an envelope. A null [authKey] (pre-pairing) yields an all-zero MAC that never verifies. */
    fun encode(type: Type, fields: Map<Field, ByteArray>, messageId: ByteArray, timestampMs: Long, authKey: ByteArray?): ByteArray {
        if (messageId.size != MESSAGE_ID_LENGTH) throw BleException(Reason.INVALID_MESSAGE_ID)
        val payload = encodeFields(fields)
        if (payload.size > MAX_PAYLOAD_LENGTH) throw BleException(Reason.INVALID_LENGTH)
        val signed = ByteBuffer.allocate(HEADER_LENGTH + payload.size).apply {
            put(MAGIC); put(VERSION); put(type.code); put(type.direction); put(0)
            putLong(timestampMs)
            put(messageId)
            putShort(payload.size.toShort())
            put(payload)
        }.array()
        return signed + (authKey?.let { hmac(it, signed) } ?: ByteArray(MAC_LENGTH))
    }

    fun envelopeLength(fields: Map<Field, ByteArray>): Int = HEADER_LENGTH + encodeFields(fields).size + MAC_LENGTH

    /** Verifies envelope and MAC (constant time), then decodes and validates the payload. */
    fun verify(data: ByteArray, authKey: ByteArray, expectedDirection: Byte, nowMs: Long): Message {
        val (type, payloadLen) = parseHeader(data, expectedDirection)
        val signedLength = HEADER_LENGTH + payloadLen
        val expected = hmac(authKey, data.copyOfRange(0, signedLength))
        // MessageDigest.isEqual is a constant-time comparison.
        if (!MessageDigest.isEqual(expected, data.copyOfRange(signedLength, data.size))) throw BleException(Reason.BAD_MAC)
        val ts = ByteBuffer.wrap(data, 8, 8).long
        val skew = nowMs - ts
        if (skew > TIMESTAMP_WINDOW_MS || skew < -TIMESTAMP_WINDOW_MS) throw BleException(Reason.STALE_TIMESTAMP)
        val fields = decodeFields(data.copyOfRange(HEADER_LENGTH, signedLength), type)
        return Message(type, data.copyOfRange(16, 32), ts, fields)
    }

    /** Structural checks only (bounds, sizes, type/direction). Nothing here is trusted. */
    private fun parseHeader(b: ByteArray, expectedDirection: Byte): Pair<Type, Int> {
        if (b.size < HEADER_LENGTH + MAC_LENGTH) throw BleException(Reason.MALFORMED_ENVELOPE)
        if (!b.copyOfRange(0, 4).contentEquals(MAGIC)) throw BleException(Reason.BAD_MAGIC)
        if (b[4] != VERSION) throw BleException(Reason.UNSUPPORTED_VERSION)
        val type = Type.fromCode(b[5]) ?: throw BleException(Reason.UNKNOWN_TYPE)
        if (b[6] != expectedDirection || type.direction != expectedDirection) throw BleException(Reason.WRONG_DIRECTION)
        if (b[7] != 0.toByte()) throw BleException(Reason.BAD_RESERVED)
        if ((16 until 32).all { b[it] == 0.toByte() }) throw BleException(Reason.INVALID_MESSAGE_ID)
        val payloadLen = ((b[32].toInt() and 0xFF) shl 8) or (b[33].toInt() and 0xFF)
        if (payloadLen > MAX_PAYLOAD_LENGTH || b.size != HEADER_LENGTH + payloadLen + MAC_LENGTH) {
            throw BleException(Reason.INVALID_LENGTH)
        }
        return type to payloadLen
    }

    /**
     * Pre-pairing only: the Mac's advertised name from a device-info envelope, without any
     * authentication. For the device picker; never used for state or trust.
     */
    fun unverifiedDisplayName(data: ByteArray): String? = try {
        val (type, len) = parseHeader(data, DIRECTION_MAC_TO_ANDROID)
        if (type != Type.DEVICE_INFO) null
        else decodeFields(data.copyOfRange(HEADER_LENGTH, HEADER_LENGTH + len), type)[Field.NAME]?.toString(Charsets.UTF_8)
    } catch (e: BleException) {
        null
    }

    // ── Field helpers ─────────────────────────────────────────────────────────

    fun u16(v: Int): ByteArray = byteArrayOf((v shr 8).toByte(), v.toByte())
    fun u8(v: Int): ByteArray = byteArrayOf(v.toByte())
    fun i64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()
    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }
}

/**
 * Android-side gate for Mac → Android control messages (notifications and the device-info
 * read). Returns a message only after MAC, timestamp, replay and allowed-type checks pass.
 * Android does not issue requests that the Mac answers, so there is no correlation here; the
 * Mac correlates Android's responses.
 */
class AndroidBleInbound(private val replayCache: TcpReplayCache = TcpReplayCache()) {

    sealed class Result {
        data class Accepted(val message: BleControlProtocol.Message) : Result()
        data class Rejected(val reason: BleControlProtocol.Reason) : Result()
    }

    fun process(
        data: ByteArray,
        rootKey: ByteArray?,
        nowMs: Long,
        allowed: Set<BleControlProtocol.Type>
    ): Result {
        if (rootKey == null) return Result.Rejected(BleControlProtocol.Reason.NOT_PAIRED)
        return try {
            val msg = BleControlProtocol.verify(
                data, BleControlProtocol.authKey(rootKey), BleControlProtocol.DIRECTION_MAC_TO_ANDROID, nowMs)
            when {
                msg.type !in allowed -> Result.Rejected(BleControlProtocol.Reason.UNEXPECTED_TYPE)
                !replayCache.insertIfNew(msg.messageId, nowMs) -> Result.Rejected(BleControlProtocol.Reason.REPLAYED)
                else -> Result.Accepted(msg)
            }
        } catch (e: BleControlProtocol.BleException) {
            Result.Rejected(e.reason)
        }
    }

    companion object {
        /** Types the Mac may send as notifications. */
        val NOTIFICATION_TYPES = setOf(
            BleControlProtocol.Type.PUSH_TEXT, BleControlProtocol.Type.FILE_INCOMING,
            BleControlProtocol.Type.TEXT_INCOMING, BleControlProtocol.Type.SETTING,
            BleControlProtocol.Type.PING, BleControlProtocol.Type.DIAGNOSTIC_ACK
        )
        val DEVICE_INFO_TYPES = setOf(BleControlProtocol.Type.DEVICE_INFO)
    }
}
