package com.bunty.clipsync

import com.bunty.clipsync.TcpTestSupport.hex
import com.bunty.clipsync.TcpTestSupport.hexOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudPairingAuthTest {

    private val v = TcpTestSupport.loadVectors("firestore-pairing-v1-test-vectors.properties")
    private val root = hex(v.getValue("rootKey"))
    private val pid = v.getValue("pairingId")
    private val a = v.getValue("androidUid")
    private val m = v.getValue("macUid")
    private val nonce = hex(v.getValue("nonce"))

    @Test
    fun matchesCrossPlatformFixtures() {
        assertEquals(v["membershipKey"], hexOf(CloudPairingAuth.membershipKey(root)))
        assertEquals(v["message"], hexOf(CloudPairingAuth.message(pid, a, m, nonce)))
        assertEquals(v["proof"], CloudPairingAuth.proof(root, pid, a, m, nonce))
    }

    @Test
    fun membershipKeyIsSeparateFromTransportKeys() {
        val k = CloudPairingAuth.membershipKey(root)
        assertFalse(k.contentEquals(TcpFrameProtocol.authKey(root)))
        assertFalse(k.contentEquals(BleControlProtocol.authKey(root)))
    }

    @Test
    fun proofBindsEveryField() {
        val p = CloudPairingAuth.proof(root, pid, a, m, nonce)
        assertNotEquals(p, CloudPairingAuth.proof(root, "otherPairing", a, m, nonce))
        assertNotEquals(p, CloudPairingAuth.proof(root, pid, "attackerUid", m, nonce))
        assertNotEquals(p, CloudPairingAuth.proof(root, pid, a, "otherMacUid", nonce))
        assertNotEquals(p, CloudPairingAuth.proof(root, pid, a, m, ByteArray(16)))
        assertNotEquals(p, CloudPairingAuth.proof(ByteArray(32), pid, a, m, nonce))
        // Length prefixes prevent boundary-shifting collisions.
        assertNotEquals(CloudPairingAuth.proof(root, "ab", "c", m, nonce), CloudPairingAuth.proof(root, "a", "bc", m, nonce))
    }

    @Test
    fun pendingPairingHasPhoneAsOnlyMemberAndVerifiableProof() {
        val f = CloudPairingAuth.pendingPairingFields(pid, a, m, root, nonce)!!
        assertEquals(listOf(a), f["members"])
        assertEquals(a, f["androidUid"])
        assertEquals(m, f["macUid"])
        assertEquals(pid, f["pairingId"])
        assertEquals(2L, f["version"])
        assertEquals("pending", f["status"])
        assertEquals(v["proof"], f["proof"])
        assertEquals(v["nonce"], f["proofNonce"])
        assertFalse("pairing key never stored", f.values.any { it.toString().contains(hexOf(root)) })
    }

    @Test
    fun pendingPairingRefusedWithoutValidIdentities() {
        assertNull("no phone identity", CloudPairingAuth.pendingPairingFields(pid, null, m, root))
        assertNull("old Mac QR without UID", CloudPairingAuth.pendingPairingFields(pid, a, null, root))
        assertNull(CloudPairingAuth.pendingPairingFields(pid, a, "", root))
        assertNull(CloudPairingAuth.pendingPairingFields(pid, a, a, root))
        assertNull(CloudPairingAuth.pendingPairingFields(pid, a, "x/y", root))
        assertNull(CloudPairingAuth.pendingPairingFields(pid, a, m, root, ByteArray(4)))
        assertTrue(CloudPairingAuth.pendingPairingFields(pid, a, m, root)!!["proofNonce"].toString().length == 32)
    }

    @Test
    fun clipboardUploadRequiresIdentityPairingAndCiphertext() {
        assertNull("no Firebase identity", CloudPairingAuth.clipboardItemFields(null, pid, "CT==", "dev"))
        assertNull("no pairing", CloudPairingAuth.clipboardItemFields(a, null, "CT==", "dev"))
        assertNull("encryption failed", CloudPairingAuth.clipboardItemFields(a, pid, null, "dev"))
        assertNull(CloudPairingAuth.clipboardItemFields(a, pid, "", "dev"))
        val f = CloudPairingAuth.clipboardItemFields(a, pid, "CT==", "dev")!!
        assertEquals(setOf("content", "pairingId", "sourceDeviceId", "sourceUid", "type"), f.keys)
        assertEquals(a, f["sourceUid"])
    }
}
