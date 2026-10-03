package com.bunty.clipsync

import com.bunty.clipsync.BleControlProtocol.BleException
import com.bunty.clipsync.BleControlProtocol.DIRECTION_ANDROID_TO_MAC
import com.bunty.clipsync.BleControlProtocol.DIRECTION_MAC_TO_ANDROID
import com.bunty.clipsync.BleControlProtocol.Field
import com.bunty.clipsync.BleControlProtocol.Reason
import com.bunty.clipsync.BleControlProtocol.Type
import com.bunty.clipsync.TcpTestSupport.hex
import com.bunty.clipsync.TcpTestSupport.hexOf
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class BleControlProtocolTest {

    private val v = TcpTestSupport.loadVectors("ble-v2-test-vectors.properties")
    private val root = hex(v.getValue("rootKey"))
    private val auth = BleControlProtocol.authKey(root)
    private val now = v.getValue("timestampMs").toLong()
    private val msgId = hex(v.getValue("messageId"))
    private val requestId = hex(v.getValue("requestId"))

    private fun signed(type: Type, fields: Map<Field, ByteArray>, key: ByteArray = auth, ts: Long = now) =
        BleControlProtocol.encode(type, fields, BleControlProtocol.newMessageId(), ts, key)

    private fun verifyReason(d: ByteArray, dir: Byte, key: ByteArray = auth, at: Long = now): Reason? =
        try { BleControlProtocol.verify(d, key, dir, at); null } catch (e: BleException) { e.reason }

    private fun flip(d: ByteArray, i: Int, value: Int? = null) =
        d.copyOf().also { it[i] = value?.toByte() ?: (it[i].toInt() xor 1).toByte() }

    private val pingAckFields = mapOf(
        Field.IP to BleControlProtocol.utf8("192.168.1.42"),
        Field.PORT to BleControlProtocol.u16(8766),
        Field.DEVICE_NAME to BleControlProtocol.utf8("Pixel 8 é"),
        Field.REPLY_TO to requestId
    )
    private val pingAck by lazy { BleControlProtocol.encode(Type.PING_ACK, pingAckFields, msgId, now, auth) }

    // ── Key derivation + shared fixtures ─────────────────────────────────────

    @Test
    fun bleAuthKeyMatchesFixtureAndIsSeparateFromTcp() {
        assertEquals(v["bleAuthKey"], hexOf(auth))
        assertFalse(auth.contentEquals(TcpFrameProtocol.authKey(root)))
    }

    @Test
    fun envelopesMatchCrossPlatformFixtures() {
        assertEquals(v["pingAckEnvelope"], hexOf(pingAck))
        assertEquals(v["pingAckMac"], hexOf(pingAck.copyOfRange(pingAck.size - 32, pingAck.size)))
        val setting = BleControlProtocol.encode(Type.SETTING, mapOf(Field.ULTRA_FAST to BleControlProtocol.u8(1)), msgId, now, auth)
        assertEquals(v["settingEnvelope"], hexOf(setting))

        val m = BleControlProtocol.verify(hex(v.getValue("pingAckEnvelope")), auth, DIRECTION_ANDROID_TO_MAC, now)
        assertEquals(Type.PING_ACK, m.type)
        assertEquals("192.168.1.42", m.string(Field.IP))
        assertEquals(8766L, m.uint(Field.PORT))
        assertEquals("Pixel 8 é", m.string(Field.DEVICE_NAME))
        assertArrayEquals(requestId, m.fields[Field.REPLY_TO])
    }

    // ── Authentication ───────────────────────────────────────────────────────

    @Test
    fun tamperedOrForeignEnvelopesRejected() {
        val r = SecureRandom()
        assertNull(verifyReason(pingAck, DIRECTION_ANDROID_TO_MAC))
        assertEquals(Reason.BAD_MAC, verifyReason(pingAck, DIRECTION_ANDROID_TO_MAC, key = ByteArray(32).also { r.nextBytes(it) }))
        assertEquals("type", Reason.BAD_MAC, verifyReason(flip(pingAck, 5, 0x11), DIRECTION_ANDROID_TO_MAC))
        assertEquals("payload", Reason.BAD_MAC, verifyReason(flip(pingAck, 40), DIRECTION_ANDROID_TO_MAC))
        assertEquals("timestamp", Reason.BAD_MAC, verifyReason(flip(pingAck, 12), DIRECTION_ANDROID_TO_MAC))
        assertEquals("message ID", Reason.BAD_MAC, verifyReason(flip(pingAck, 20), DIRECTION_ANDROID_TO_MAC))
        assertEquals("MAC", Reason.BAD_MAC, verifyReason(flip(pingAck, pingAck.size - 1), DIRECTION_ANDROID_TO_MAC))
        assertEquals("direction", Reason.WRONG_DIRECTION, verifyReason(flip(pingAck, 6, 0x02), DIRECTION_ANDROID_TO_MAC))
        assertEquals("reflected", Reason.WRONG_DIRECTION, verifyReason(pingAck, DIRECTION_MAC_TO_ANDROID))
        assertEquals(Reason.UNSUPPORTED_VERSION, verifyReason(flip(pingAck, 4, 0x01), DIRECTION_ANDROID_TO_MAC))
        assertEquals(Reason.UNKNOWN_TYPE, verifyReason(flip(pingAck, 5, 0x7F), DIRECTION_ANDROID_TO_MAC))
        assertEquals(Reason.BAD_RESERVED, verifyReason(flip(pingAck, 7, 0x01), DIRECTION_ANDROID_TO_MAC))
        assertEquals(Reason.BAD_MAGIC, verifyReason(flip(pingAck, 0, 0x00), DIRECTION_ANDROID_TO_MAC))
        assertEquals("truncated MAC", Reason.INVALID_LENGTH, verifyReason(pingAck.copyOf(pingAck.size - 1), DIRECTION_ANDROID_TO_MAC))
        assertEquals("extended MAC", Reason.INVALID_LENGTH, verifyReason(pingAck + 0.toByte(), DIRECTION_ANDROID_TO_MAC))
        assertEquals(Reason.MALFORMED_ENVELOPE, verifyReason(pingAck.copyOf(40), DIRECTION_ANDROID_TO_MAC))
        val w = BleControlProtocol.TIMESTAMP_WINDOW_MS
        assertEquals(Reason.STALE_TIMESTAMP, verifyReason(pingAck, DIRECTION_ANDROID_TO_MAC, at = now + w + 1))
        assertEquals(Reason.STALE_TIMESTAMP, verifyReason(pingAck, DIRECTION_ANDROID_TO_MAC, at = now - w - 1))
    }

    @Test
    fun legacyUnauthenticatedJsonRejected() {
        for (json in listOf("""{"type":"setting","ultra_fast":true}""", """{"type":"file_incoming","filename":"x","size":1,"port":8766}""",
                            """{"type":"ping"}""", """{"diagnostic_ack":true}""")) {
            val reason = verifyReason(json.toByteArray(), DIRECTION_MAC_TO_ANDROID)
            assertTrue("$json → $reason", reason == Reason.MALFORMED_ENVELOPE || reason == Reason.BAD_MAGIC)
        }
    }

    // ── Payload validation ───────────────────────────────────────────────────

    @Test
    fun malformedAuthenticatedPayloadsRejected() {
        fun reason(type: Type, f: Map<Field, ByteArray>) = verifyReason(signed(type, f), type.direction)
        val u8 = BleControlProtocol::u8
        val u16 = BleControlProtocol::u16
        val s = BleControlProtocol::utf8
        assertEquals(Reason.INVALID_VALUE, reason(Type.SETTING, mapOf(Field.ULTRA_FAST to u8(2))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.SETTING, mapOf(Field.ULTRA_FAST to byteArrayOf(1, 0))))
        assertEquals(Reason.UNEXPECTED_FIELD, reason(Type.SETTING, mapOf(Field.ULTRA_FAST to u8(1), Field.NAME to s("x"))))
        assertEquals(Reason.MISSING_FIELD, reason(Type.SETTING, emptyMap()))
        assertEquals(Reason.MISSING_FIELD, reason(Type.PING_ACK, mapOf(Field.IP to s("10.0.0.5"))))
        assertEquals(Reason.UNEXPECTED_FIELD, reason(Type.HANDSHAKE, mapOf(Field.REPLY_TO to requestId)))
        assertEquals(Reason.INVALID_VALUE, reason(Type.HANDSHAKE, mapOf(Field.IP to s("10.0.0.256"))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.HANDSHAKE, mapOf(Field.IP to s("evil.example.com"))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.HANDSHAKE, mapOf(Field.PORT to u16(0))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.HANDSHAKE, mapOf(Field.BATTERY to u8(101))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.HANDSHAKE, mapOf(Field.DEVICE_NAME to s("bad\nname"))))
        assertEquals(Reason.MISSING_FIELD, reason(Type.FILE_INCOMING, mapOf(Field.FILE_NAME to s("a.txt"), Field.PORT to u16(8766))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.FILE_INCOMING,
            mapOf(Field.FILE_NAME to s("a.txt"), Field.SIZE to BleControlProtocol.i64(-1), Field.PORT to u16(8766))))
        assertEquals(Reason.INVALID_VALUE, reason(Type.PUSH_TEXT, mapOf(Field.CONTENT to s("not base64!!"))))
    }

    @Test
    fun nonCanonicalTlvRejectedEvenWithValidMac() {
        val payload = byteArrayOf(0x0B, 0, 1, 1, 0x0B, 0, 1, 0) // duplicate ultra_fast
        val signed = java.nio.ByteBuffer.allocate(34 + payload.size).apply {
            put(BleControlProtocol.MAGIC); put(0x02); put(Type.SETTING.code); put(DIRECTION_MAC_TO_ANDROID); put(0)
            putLong(now); put(BleControlProtocol.newMessageId()); putShort(payload.size.toShort()); put(payload)
        }.array()
        val mac = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(auth, "HmacSHA256")); doFinal(signed) }
        assertEquals(Reason.MALFORMED_PAYLOAD, verifyReason(signed + mac, DIRECTION_MAC_TO_ANDROID))
    }

    // ── Android inbound gate: state-changing pushes ──────────────────────────

    @Test
    fun forgedSettingCannotChangeUltraFastButAuthenticatedOneCan() {
        val gate = AndroidBleInbound()
        val forged = signed(Type.SETTING, mapOf(Field.ULTRA_FAST to BleControlProtocol.u8(1))).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(AndroidBleInbound.Result.Rejected(Reason.BAD_MAC), gate.process(forged, root, now, AndroidBleInbound.NOTIFICATION_TYPES))
        assertTrue(gate.process("""{"type":"setting","ultra_fast":true}""".toByteArray(), root, now, AndroidBleInbound.NOTIFICATION_TYPES)
            is AndroidBleInbound.Result.Rejected)
        val otherPairing = BleControlProtocol.authKey(ByteArray(32) { 7 })
        assertEquals(AndroidBleInbound.Result.Rejected(Reason.BAD_MAC),
            gate.process(signed(Type.SETTING, mapOf(Field.ULTRA_FAST to BleControlProtocol.u8(1)), key = otherPairing), root, now, AndroidBleInbound.NOTIFICATION_TYPES))

        val good = signed(Type.SETTING, mapOf(Field.ULTRA_FAST to BleControlProtocol.u8(1)))
        val accepted = gate.process(good, root, now, AndroidBleInbound.NOTIFICATION_TYPES) as AndroidBleInbound.Result.Accepted
        assertEquals(Type.SETTING, accepted.message.type)
        assertEquals(1L, accepted.message.uint(Field.ULTRA_FAST))
        assertEquals("exact replay rejected", AndroidBleInbound.Result.Rejected(Reason.REPLAYED),
            gate.process(good, root, now, AndroidBleInbound.NOTIFICATION_TYPES))
    }

    @Test
    fun forgedFileIncomingCannotStartAReceiver() {
        val gate = AndroidBleInbound()
        val fields = mapOf(Field.FILE_NAME to BleControlProtocol.utf8("invoice.pdf"), Field.SIZE to BleControlProtocol.i64(1234),
            Field.PORT to BleControlProtocol.u16(8766))
        val forged = signed(Type.FILE_INCOMING, fields, key = BleControlProtocol.authKey(ByteArray(32)))
        assertTrue(gate.process(forged, root, now, AndroidBleInbound.NOTIFICATION_TYPES) is AndroidBleInbound.Result.Rejected)
        assertEquals("not paired", AndroidBleInbound.Result.Rejected(Reason.NOT_PAIRED),
            gate.process(signed(Type.FILE_INCOMING, fields), null, now, AndroidBleInbound.NOTIFICATION_TYPES))
        val ok = gate.process(signed(Type.FILE_INCOMING, fields), root, now, AndroidBleInbound.NOTIFICATION_TYPES) as AndroidBleInbound.Result.Accepted
        assertEquals("invoice.pdf", ok.message.string(Field.FILE_NAME))
        assertEquals(1234L, ok.message.uint(Field.SIZE))
    }

    @Test
    fun deviceInfoOnlyAcceptedOnItsOwnPathAndOnlyWhenAuthenticated() {
        val gate = AndroidBleInbound()
        val fields = mapOf(Field.NAME to BleControlProtocol.utf8("Mac"), Field.PORT to BleControlProtocol.u16(8765),
            Field.IP to BleControlProtocol.utf8("192.168.1.10"))
        assertEquals("device_info is not a notification", AndroidBleInbound.Result.Rejected(Reason.UNEXPECTED_TYPE),
            gate.process(signed(Type.DEVICE_INFO, fields), root, now, AndroidBleInbound.NOTIFICATION_TYPES))
        val keyless = BleControlProtocol.encode(Type.DEVICE_INFO, fields, BleControlProtocol.newMessageId(), now, null)
        assertEquals(AndroidBleInbound.Result.Rejected(Reason.BAD_MAC), gate.process(keyless, root, now, AndroidBleInbound.DEVICE_INFO_TYPES))
        assertEquals("pre-pairing display name", "Mac", BleControlProtocol.unverifiedDisplayName(keyless))
        val ok = gate.process(signed(Type.DEVICE_INFO, fields), root, now, AndroidBleInbound.DEVICE_INFO_TYPES) as AndroidBleInbound.Result.Accepted
        assertEquals("192.168.1.10", ok.message.string(Field.IP))
    }

    @Test
    fun androidToMacTypesRejectedOnTheMacToAndroidPath() {
        val gate = AndroidBleInbound()
        assertEquals(AndroidBleInbound.Result.Rejected(Reason.WRONG_DIRECTION),
            gate.process(pingAck, root, now, AndroidBleInbound.NOTIFICATION_TYPES))
    }

    // ── Outbound (WakeupPing) ────────────────────────────────────────────────

    @Test
    fun wakeupPingsBuildValidAuthenticatedEnvelopes() {
        val reply = BleControlProtocol.newMessageId()
        val ack = WakeupPing(localIp = "10.0.0.9", tcpPort = 8766, payloadSize = 0, payloadType = "ping_ack",
            battery = 80, deviceName = "Pixel\u0007 8", replyTo = reply)
        assertEquals(Type.PING_ACK, ack.messageType())
        val env = BleControlProtocol.encode(ack.messageType()!!, ack.toFields(), BleControlProtocol.newMessageId(), now, auth)
        val m = BleControlProtocol.verify(env, auth, DIRECTION_ANDROID_TO_MAC, now)
        assertEquals("10.0.0.9", m.string(Field.IP))
        assertEquals("control characters stripped", "Pixel 8", m.string(Field.DEVICE_NAME))
        assertArrayEquals(reply, m.fields[Field.REPLY_TO])

        for (t in listOf("pairing_ack", "handshake", "tcp_ready", "text", "image", "file", "ip_probe")) {
            assertNotEquals(t, null, WakeupPing(localIp = "", payloadSize = 0, payloadType = t).messageType())
        }
        assertEquals(Type.DIAGNOSTIC, WakeupPing(localIp = "", payloadSize = 0, payloadType = "diagnostic", isDiagnostic = true).messageType())
        assertNull("unknown types are never sent", WakeupPing(localIp = "", payloadSize = 0, payloadType = "pair").messageType())
    }

    @Test
    fun replayCacheBounded() {
        val gate = AndroidBleInbound(TcpReplayCache(capacity = 4, ttlMs = 1000))
        val cache = TcpReplayCache(capacity = 4, ttlMs = 1000)
        repeat(10) { cache.insertIfNew(BleControlProtocol.newMessageId(), now) }
        assertTrue(cache.size <= 4)
        repeat(10) { gate.process(signed(Type.PING, emptyMap()), root, now, AndroidBleInbound.NOTIFICATION_TYPES) }
    }
}
