package com.bunty.clipsync

import android.content.Context
import android.util.Log

/**
 * Singleton service responsible for forwarding detected OTP codes from the Android device
 * to the paired Mac via the shared Firestore `notifications` collection.
 *
 * The end-to-end forwarding pipeline works as follows:
 *  1. A caller — typically [OTPListeningService] for SMS-sourced OTPs, or
 *     [EmailOTPListenerService] for email-sourced OTPs — invokes [notifyOTPDetected].
 *  2. The raw OTP string is encrypted with AES-256-GCM using the session key established
 *     during the pairing handshake. A fresh 12-byte IV is generated for every message.
 *  3. The encrypted payload, alongside metadata (pairing ID, device ID, device name, and a
 *     server-generated timestamp), is written as a new document to Firestore.
 *  4. The Mac's ClipSync app, which maintains a live snapshot listener on the same collection,
 *     picks up the document within milliseconds, decrypts it with the shared key, and either
 *     copies the OTP to the Mac clipboard or surfaces it in a notification.
 *
 * The encryption scheme intentionally mirrors [FirestoreManager]'s encrypt/decrypt logic so
 * the Mac can use a single decryption path for all payloads received from Firestore.
 */
object OTPNotificationService {

    private const val TAG = "OTPNotificationService"

    /** Outcome of [publishEncryptedOTP]; never carries the OTP itself. */
    internal enum class OtpPublishResult { SENT, NOT_PAIRED, NOT_AUTHENTICATED, ENCRYPTION_UNAVAILABLE }

    /**
     * Encrypts the given [otpCode] and writes it to the Firestore `notifications` collection
     * so the paired Mac can receive it in near-real-time.
     *
     * The document written to Firestore has the following structure:
     * ```json
     * {
     *   "type":             "OTP_NOTIFICATION",
     *   "encryptedOTP":     "<Base64-AES-256-GCM ciphertext with prepended IV>",
     *   "pairingId":        "<current pairing document ID>",
     *   "sourceDeviceId":   "<stable Android device identifier>",
     *   "sourceDeviceName": "<human-readable device name>",
     *   "timestamp":        "<Firestore server timestamp>"
     * }
     * ```
     *
     * Fails closed: if the device is not paired, the key is missing, or encryption fails for
     * any reason, nothing is written. The OTP is never uploaded or logged in plain text.
     *
     * @param context  Application context used to look up pairing and device metadata.
     * @param otpCode  The plain-text OTP string to encrypt and forward (e.g. `"847291"`).
     */
    fun notifyOTPDetected(context: Context, otpCode: String) {
        val appContext = context.applicationContext

        // Local-only mode never talks to the cloud (no upload, no Firebase sign-in); OTPs still
        // reach the Mac over the local route via LocalSyncManager.
        if (DeviceManager.getSyncMode(appContext) != "hybrid") return

        try {
            val result = publishEncryptedOTP(
                otpCode    = otpCode,
                pairingId  = DeviceManager.getPairingId(appContext),
                sourceUid  = CloudAuth.currentUid(appContext),
                hexKey     = DeviceManager.getEncryptionKey(appContext),
                deviceId   = DeviceManager.getDeviceId(appContext),
                deviceName = DeviceManager.getAndroidDeviceName()
            ) { fields ->
                val notificationData = HashMap<String, Any>(fields).apply {
                    put("timestamp", com.google.firebase.firestore.FieldValue.serverTimestamp())
                }
                FirestoreManager.getDb(appContext).collection("notifications")
                    .add(notificationData)
                    .addOnSuccessListener { documentReference ->
                    }
                    .addOnFailureListener { exception ->
                        Log.e(TAG, "Failed to send OTP notification", exception)
                    }
            }

            when (result) {
                OtpPublishResult.SENT -> Unit
                // Without a valid pairing ID the Mac cannot match this document to an active session.
                OtpPublishResult.NOT_PAIRED ->
                    Log.e(TAG, "No pairing ID found - cannot send OTP notification")
                OtpPublishResult.NOT_AUTHENTICATED -> {
                    // Firestore rules require a member identity; sign in for next time.
                    Log.e(TAG, "OTP not sent: not signed in to cloud sync")
                    CloudAuth.withUid(appContext) { }
                }
                OtpPublishResult.ENCRYPTION_UNAVAILABLE -> {
                    Log.e(TAG, "OTP not sent: encryption key unavailable or encryption failed")
                    DeviceManager.notifySecurityError(appContext, "Encryption failed — OTP not sent")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending OTP notification", e)
        }
    }

    /**
     * Encrypts [otpCode] and hands the document fields to [upload] — only on success.
     *
     * Separated from [notifyOTPDetected] so the fail-closed behaviour can be unit tested
     * without Android or Firestore. [upload] is never invoked with, or without, an OTP when
     * encryption is not possible; there is no plaintext fallback.
     */
    internal fun publishEncryptedOTP(
        otpCode:    String,
        pairingId:  String?,
        sourceUid:  String?,
        hexKey:     String?,
        deviceId:   String,
        deviceName: String,
        upload:     (Map<String, Any>) -> Unit
    ): OtpPublishResult {
        if (pairingId == null) return OtpPublishResult.NOT_PAIRED
        if (!CloudPairingAuth.isValidUid(sourceUid)) return OtpPublishResult.NOT_AUTHENTICATED

        // Encrypt the OTP before it leaves the device; the Mac decrypts it with the shared key.
        val encryptedOTP = encryptOTP(otpCode, hexKey) ?: return OtpPublishResult.ENCRYPTION_UNAVAILABLE

        upload(
            mapOf(
                "type"             to "OTP_NOTIFICATION",
                "encryptedOTP"     to encryptedOTP,
                "pairingId"        to pairingId,
                "sourceUid"        to sourceUid!!,
                "sourceDeviceId"   to deviceId,
                "sourceDeviceName" to deviceName
            )
        )
        return OtpPublishResult.SENT
    }

    /**
     * Encrypts [otpCode] with AES-256-GCM via [AesGcmCipher] and returns it Base64-encoded
     * (standard alphabet, no line wrapping — identical to `android.util.Base64.NO_WRAP`).
     *
     * Binary layout before encoding: `[ 12-byte IV ][ ciphertext ][ 16-byte GCM tag ]`, the
     * same format [FirestoreManager] uses, so the Mac decrypts it with its existing path.
     *
     * @return the encoded ciphertext, or `null` if [hexKey] is missing or encryption fails
     *         for any reason (malformed key, wrong key length, provider error). Never returns
     *         the plain-text OTP.
     */
    internal fun encryptOTP(otpCode: String, hexKey: String?): String? {
        if (hexKey.isNullOrEmpty()) return null
        return try {
            java.util.Base64.getEncoder().encodeToString(AesGcmCipher.encrypt(otpCode, hexKey))
        } catch (e: Exception) {
            null
        }
    }
}
