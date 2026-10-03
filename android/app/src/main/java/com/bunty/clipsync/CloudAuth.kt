package com.bunty.clipsync

import android.content.Context
import android.util.Log
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.ListenerRegistration
import kotlinx.coroutines.tasks.await

/**
 * The device's Firebase identity for cloud (hybrid) sync.
 *
 * Firestore rules require an authenticated member identity for every protected document, so
 * cloud operations run only after [withUid] / [awaitUid] yields a UID; on failure they are
 * skipped (fail closed). The identity is a persisted anonymous Firebase user on the SAME
 * FirebaseApp that [FirestoreManager.getDb] uses — the US region has its own app, and
 * therefore its own Auth instance.
 */
object CloudAuth {

    private const val TAG = "CloudAuth"

    /** Default India app owns push/Crashlytics; secondary US app retains US Auth/Firestore. */
    @Synchronized
    fun app(context: Context): FirebaseApp {
        check(DeviceManager.getSyncMode(context) == "hybrid") { "Cloud sync disabled" }
        val region = DeviceManager.getTargetRegion(context)
        val expected = FcmTokenPolicy.authProject(region)
            ?: throw IllegalStateException("Unknown Firebase region")
        val defaultApp = FirebaseApp.getApps(context).firstOrNull { it.name == FirebaseApp.DEFAULT_APP_NAME }
            ?: FirebaseApp.initializeApp(context.applicationContext)
            ?: throw IllegalStateException("Default Firebase configuration unavailable")
        check(defaultApp.options.projectId == FcmTokenPolicy.INDIA_PROJECT) { "Default push project mismatch" }
        val selected = if (region == "US") {
            FirebaseApp.getApps(context).firstOrNull { it.name == "ClipSyncUS" }
                ?: run {
                    val options = RegionConfig.getOptionsForRegion(context, RegionConfig.REGION_US)
                        ?: throw IllegalStateException("US Firebase configuration unavailable")
                    FirebaseApp.initializeApp(context.applicationContext, options, "ClipSyncUS")
                        ?: throw IllegalStateException("US Firebase initialization failed")
                }
        } else defaultApp
        check(selected.options.projectId == expected) { "Regional Firebase project mismatch" }
        return selected
    }

    private fun auth(context: Context): FirebaseAuth = FirebaseAuth.getInstance(app(context))

    /** The signed-in UID, or null. Never triggers network activity. */
    fun currentUid(context: Context): String? = try {
        auth(context).currentUser?.uid
    } catch (e: Exception) {
        null
    }

    /** Calls [onReady] with the UID, signing in anonymously first if needed. */
    fun withUid(context: Context, onFailure: (Exception) -> Unit = {}, onReady: (String) -> Unit) {
        if (DeviceManager.getSyncMode(context) != "hybrid") { onFailure(IllegalStateException("Cloud sync disabled")); return }
        val region = DeviceManager.getTargetRegion(context)
        val auth = try { auth(context) } catch (e: Exception) { onFailure(e); return }
        auth.currentUser?.uid?.let { onReady(it); return }
        auth.signInAnonymously()
            .addOnSuccessListener { result ->
                val uid = result.user?.uid
                if (DeviceManager.getSyncMode(context) != "hybrid") return@addOnSuccessListener
                if (DeviceManager.getTargetRegion(context) != region) {
                    onFailure(IllegalStateException("Region changed during sign-in; retry pairing"))
                    return@addOnSuccessListener
                }
                if (uid != null) onReady(uid) else onFailure(IllegalStateException("No Firebase user"))
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Anonymous sign-in failed")
                onFailure(e)
            }
    }

    /** Suspending form of [withUid]; null means "not signed in — do not touch Firestore". */
    suspend fun awaitUid(context: Context): String? {
        if (DeviceManager.getSyncMode(context) != "hybrid") return null
        return try {
            val auth = auth(context)
            val uid = auth.currentUser?.uid ?: auth.signInAnonymously().await().user?.uid
            if (DeviceManager.getSyncMode(context) == "hybrid") uid else null
        } catch (e: Exception) {
            Log.e(TAG, "Anonymous sign-in failed")
            null
        }
    }

    /**
     * A listener registration that is attached only once authentication succeeds, so callers
     * can hold and remove it immediately even though the real listener starts later.
     */
    class DeferredRegistration : ListenerRegistration {
        @Volatile private var inner: ListenerRegistration? = null
        @Volatile private var removed = false

        @Synchronized
        fun attach(registration: ListenerRegistration) {
            if (removed) registration.remove() else inner = registration
        }

        @Synchronized
        override fun remove() {
            removed = true
            inner?.remove()
            inner = null
        }
    }

    const val SIGN_IN_FAILED_MESSAGE = "Couldn't connect to ClipSync cloud sync. Check your connection and try again."
    const val MAC_TOO_OLD_MESSAGE = "Update ClipSync on your Mac, then show a new QR code to pair with cloud sync."
    const val REPAIR_REQUIRED_MESSAGE = "Cloud sync was updated for security. Unpair and pair your devices again."
}
