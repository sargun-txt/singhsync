package com.bunty.clipsync

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Firestore pairing membership (v2). Byte-for-byte compatible with CloudPairingAuth.swift
 * and protocol/generate_firestore_pairing_vectors.py.
 *
 * The phone, which learned the Mac's Firebase UID and the pairing key from the QR code,
 * creates `pairings/{pairingId}` as its only member and stores
 *
 *   proof = hex(HMAC-SHA256(HKDF(pairing key, "ClipSync/Firestore/Pairing/v1"),
 *               len16(pairingId) ‖ pairingId ‖ len16(androidUid) ‖ androidUid ‖
 *               len16(macUid) ‖ macUid ‖ len16(nonce) ‖ nonce))
 *
 * The Mac verifies the proof locally before adding its own UID to `members`; Firestore rules
 * only let that named Mac join, once. The pairing key never reaches Firestore.
 *
 * Pure JVM so it is covered by local unit tests.
 */
object CloudPairingAuth {

    const val VERSION = 2L
    const val NONCE_LENGTH = 16
    const val MAX_UID_LENGTH = 128
    private val INFO = "ClipSync/Firestore/Pairing/v1".toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    fun membershipKey(rootKey: ByteArray): ByteArray =
        // An empty HKDF salt is defined as HashLen zero bytes (RFC 5869 §2.2).
        TcpFrameProtocol.hkdfSha256(rootKey, ByteArray(32), INFO, 32)

    fun message(pairingId: String, androidUid: String, macUid: String, nonce: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (part in listOf(pairingId.toByteArray(Charsets.UTF_8), androidUid.toByteArray(Charsets.UTF_8),
                            macUid.toByteArray(Charsets.UTF_8), nonce)) {
            require(part.size <= 0xFFFF) { "field too long" }
            out.write(part.size shr 8)
            out.write(part.size and 0xFF)
            out.write(part)
        }
        return out.toByteArray()
    }

    fun proof(rootKey: ByteArray, pairingId: String, androidUid: String, macUid: String, nonce: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(membershipKey(rootKey), "HmacSHA256")) }
        return mac.doFinal(message(pairingId, androidUid, macUid, nonce)).joinToString("") { "%02x".format(it) }
    }

    fun newNonce(): ByteArray = ByteArray(NONCE_LENGTH).also { random.nextBytes(it) }

    /** Firebase UIDs are short opaque strings; anything else is refused. */
    fun isValidUid(uid: String?): Boolean =
        uid != null && uid.length in 1..MAX_UID_LENGTH && uid.none { it == '/' || it.isWhitespace() || it.isISOControl() }

    /**
     * Fields for a new pending v2 pairing created by the phone (as its only member), or null
     * if either identity is missing/invalid. Device metadata and the server timestamp are
     * added by the caller.
     */
    fun pendingPairingFields(
        pairingId: String,
        androidUid: String?,
        macUid: String?,
        rootKey: ByteArray,
        nonce: ByteArray = newNonce()
    ): Map<String, Any>? {
        if (!isValidUid(androidUid) || !isValidUid(macUid) || androidUid == macUid) return null
        if (nonce.size != NONCE_LENGTH) return null
        return mapOf(
            "pairingId"  to pairingId,
            "version"    to VERSION,
            "members"    to listOf(androidUid!!),
            "androidUid" to androidUid,
            "macUid"     to macUid!!,
            "proof"      to proof(rootKey, pairingId, androidUid, macUid, nonce),
            "proofNonce" to nonce.joinToString("") { "%02x".format(it) },
            "status"     to "pending"
        )
    }

    /**
     * Fields for a cloud clipboard item, or null if the upload must not happen: no
     * authenticated identity, no pairing, or no ciphertext. There is no plaintext path.
     */
    fun clipboardItemFields(uid: String?, pairingId: String?, encryptedContent: String?, deviceId: String): Map<String, Any>? {
        if (!isValidUid(uid) || pairingId.isNullOrEmpty() || encryptedContent.isNullOrEmpty()) return null
        return mapOf(
            "content"        to encryptedContent,
            "pairingId"      to pairingId,
            "sourceDeviceId" to deviceId,
            "sourceUid"      to uid!!,
            "type"           to "text"
        )
    }
}
