package com.bunty.clipsync

import org.junit.Assert.*
import org.junit.Test

class FcmTokenPolicyTest {
    private fun binding(region: String = "IN", mode: String = "hybrid", uid: String? = "uid",
                        pairingId: String? = "pair", auth: String? = FcmTokenPolicy.authProject(region),
                        issuer: String? = "clipsyncind", sender: String? = "123456789012",
                        app: String? = "1:123456789012:android:abcdef") =
        FcmTokenPolicy.binding(mode, region, uid, pairingId, auth, issuer, sender, app)

    @Test fun initializedHybridProcessMustCloseBeforeLocalActivity() {
        assertTrue(FcmTokenPolicy.requiresLocalRestart("hybrid", "local", true))
    }
    @Test fun coldLocalAndRegionalChangesDoNotRequireDefaultAppMutation() {
        assertFalse(FcmTokenPolicy.requiresLocalRestart("hybrid", "local", false))
        assertFalse(FcmTokenPolicy.requiresLocalRestart("local", "local", false))
        assertFalse(FcmTokenPolicy.requiresLocalRestart("hybrid", "hybrid", true))
    }
    @Test fun indiaUsesIndiaAuthAndDefaultPush() {
        val b = binding()!!
        assertEquals("clipsyncind", b.authProjectId)
        assertEquals("clipsyncind", b.projectId)
    }
    @Test fun usKeepsUsAuthAndExplicitSharedPushIssuer() {
        val b = binding("US")!!
        assertEquals("clipsync1-c3c3c", b.authProjectId)
        assertEquals("clipsyncind", b.projectId) // Option C: no claim that this is a US-issued token.
    }
    @Test fun wrongIssuerOrRegionalProjectRejected() {
        assertNull(binding("US", auth = "clipsyncind"))
        assertNull(binding(issuer = "clipsync1-c3c3c"))
        assertNull(binding(auth = "unexpected"))
    }
    @Test fun unknownRegionDoesNotFallBack() {
        assertNull(binding("unknown"))
        assertNull(FcmTokenPolicy.authProject(""))
    }
    @Test fun localModeRegistersNothing() { assertNull(binding(mode = "local")) }
    @Test fun unauthenticatedUserRegistersNothing() {
        assertNull(binding(uid = null)); assertNull(binding(uid = ""))
    }
    @Test fun unpairedUserRegistersNothing() { assertNull(binding(pairingId = null)) }
    @Test fun regionChangeInvalidatesPendingRegistration() {
        assertFalse(FcmTokenPolicy.isCurrent(binding()!!, binding("US")))
    }
    @Test fun uidAndPairingChangeInvalidatePendingRegistration() {
        assertFalse(FcmTokenPolicy.isCurrent(binding()!!, binding(uid = "newUid")))
        assertFalse(FcmTokenPolicy.isCurrent(binding()!!, binding(pairingId = "newPair")))
    }
    @Test fun switchingLocalInvalidatesPendingRegistration() {
        assertFalse(FcmTokenPolicy.isCurrent(binding()!!, binding(mode = "local")))
    }
    @Test fun restartWithSameBindingCanRefresh() {
        assertTrue(FcmTokenPolicy.isCurrent(binding()!!, binding()))
    }
    @Test fun metadataDistinguishesIssuerFromRegionalAuth() {
        val fields = FcmTokenPolicy.fields(binding("US")!!, "token")!!
        assertEquals("clipsyncind", fields["projectId"])
        assertEquals("clipsync1-c3c3c", fields["authProjectId"])
        assertEquals("123456789012", fields["senderId"])
        assertEquals("1:123456789012:android:abcdef", fields["applicationId"])
        assertEquals("pair", fields["pairingId"])
    }
    @Test fun senderAppRelationshipCannotDrift() {
        assertNull(binding(sender = "wrong"))
        assertNull(binding(sender = "999", app = "1:123456789012:android:abcdef"))
        assertNull(binding(app = "1:123456789012:ios:abcdef"))
    }
    @Test fun invalidTokensCannotBeStored() {
        assertNull(FcmTokenPolicy.fields(binding()!!, ""))
        assertNull(FcmTokenPolicy.fields(binding()!!, "x".repeat(4097)))
    }
    @Test fun sameProjectGuardStillRejectsUnexplainedMismatch() {
        assertTrue(FcmTokenPolicy.canRegister("clipsyncind", "clipsyncind"))
        assertFalse(FcmTokenPolicy.canRegister("clipsync1-c3c3c", "clipsyncind"))
        assertFalse(FcmTokenPolicy.canRegister(null, null))
    }
}
