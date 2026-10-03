package com.bunty.clipsync

import com.bunty.clipsync.OTPNotificationService.OtpPublishResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class OTPNotificationServiceTest {

    private val otp = "847291"
    private val validKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it) }

    private fun publish(hexKey: String?, pairingId: String? = "pairing-1", sourceUid: String? = "uid-1"): Pair<OtpPublishResult, List<Map<String, Any>>> {
        val uploads = mutableListOf<Map<String, Any>>()
        val result = OTPNotificationService.publishEncryptedOTP(
            otpCode    = otp,
            pairingId  = pairingId,
            sourceUid  = sourceUid,
            hexKey     = hexKey,
            deviceId   = "device-1",
            deviceName = "Test Phone"
        ) { uploads += it }
        return result to uploads
    }

    @Test
    fun missingKeyDoesNotUpload() {
        for (key in listOf(null, "")) {
            val (result, uploads) = publish(key)
            assertEquals(OtpPublishResult.ENCRYPTION_UNAVAILABLE, result)
            assertTrue(uploads.isEmpty())
        }
    }

    @Test
    fun encryptionFailureDoesNotUpload() {
        // Non-hex characters, odd length, and an invalid AES key length all make encryption throw.
        for (key in listOf("zz".repeat(32), "abc", "00".repeat(10))) {
            val (result, uploads) = publish(key)
            assertEquals("key $key", OtpPublishResult.ENCRYPTION_UNAVAILABLE, result)
            assertTrue("key $key", uploads.isEmpty())
            assertNull("key $key", OTPNotificationService.encryptOTP(otp, key))
        }
    }

    @Test
    fun unauthenticatedDeviceDoesNotUpload() {
        for (uid in listOf(null, "", "bad/uid")) {
            val (result, uploads) = publish(validKey, sourceUid = uid)
            assertEquals(OtpPublishResult.NOT_AUTHENTICATED, result)
            assertTrue(uploads.isEmpty())
        }
    }

    @Test
    fun uploadCarriesTheAuthenticatedSource() {
        val (_, uploads) = publish(validKey, sourceUid = "uid-1")
        assertEquals("uid-1", uploads.single()["sourceUid"])
    }

    @Test
    fun unpairedDeviceDoesNotUpload() {
        val (result, uploads) = publish(validKey, pairingId = null)
        assertEquals(OtpPublishResult.NOT_PAIRED, result)
        assertTrue(uploads.isEmpty())
    }

    @Test
    fun encryptedOtpIsUploadedAndDecryptsWithSharedKey() {
        val (result, uploads) = publish(validKey)
        assertEquals(OtpPublishResult.SENT, result)
        assertEquals(1, uploads.size)

        val fields = uploads.single()
        assertEquals("OTP_NOTIFICATION", fields["type"])
        assertEquals("pairing-1", fields["pairingId"])

        val encrypted = fields["encryptedOTP"] as String
        val decrypted = AesGcmCipher.decryptToString(java.util.Base64.getDecoder().decode(encrypted), validKey)
        assertEquals(otp, decrypted)
    }

    @Test
    fun plaintextOtpNeverAppearsInUploadedFields() {
        val (_, uploads) = publish(validKey)
        for ((name, value) in uploads.single()) {
            assertFalse("field $name leaks the OTP", value.toString().contains(otp))
        }
    }
}
