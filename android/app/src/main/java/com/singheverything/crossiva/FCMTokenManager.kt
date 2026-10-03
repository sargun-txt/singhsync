package com.singheverything.crossiva

import android.content.Context
import android.util.Log
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FieldValue
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await

/** UID-owned registrations in regional Firestore; projectId always identifies the FCM issuer. */
object FCMTokenManager {
    private const val TAG = "FCMTokenManager"
    private val registrationLock = Mutex()
    // Held only while enqueueing writes or changing persisted routing state, never across await.
    internal val stateLock = Any()

    private fun currentBinding(context: Context): FcmTokenPolicy.Binding? {
        if (DeviceManager.getSyncMode(context) != "hybrid") return null
        val pairingId = DeviceManager.getPairingId(context) ?: return null
        val app = CloudAuth.app(context)
        val issuer = FirebaseApp.getInstance().options
        val senderId = issuer.gcmSenderId ?: issuer.applicationId.split(':').getOrNull(1)
        return FcmTokenPolicy.binding("hybrid", DeviceManager.getTargetRegion(context),
            FirebaseAuth.getInstance(app).currentUser?.uid, pairingId,
            app.options.projectId, issuer.projectId, senderId, issuer.applicationId)
    }

    private suspend fun authenticatedBinding(context: Context): FcmTokenPolicy.Binding? {
        if (DeviceManager.getSyncMode(context) != "hybrid" || DeviceManager.getPairingId(context) == null) return null
        val region = DeviceManager.getTargetRegion(context)
        val pairingId = DeviceManager.getPairingId(context)
        val uid = CloudAuth.awaitUid(context) ?: return null
        val current = currentBinding(context) ?: return null
        return current.takeIf { it.region == region && it.pairingId == pairingId && it.uid == uid }
    }

    /** Authentication completes before asking FCM to create/retrieve any token. */
    suspend fun registerFCMToken(context: Context) = registrationLock.withLock {
        try {
            val binding = authenticatedBinding(context) ?: return@withLock
            val token = FirebaseMessaging.getInstance().token.await()
            persist(context, binding, token)
        } catch (e: Exception) {
            Log.e(TAG, "FCM registration failed")
        }
    }

    /** Only used for tokens delivered by the default-app FirebaseMessagingService callback. */
    suspend fun storeFCMToken(context: Context, token: String) = registrationLock.withLock {
        try {
            val binding = authenticatedBinding(context) ?: return@withLock
            persist(context, binding, token)
        } catch (e: Exception) {
            Log.e(TAG, "FCM refresh registration failed")
        }
    }

    private suspend fun persist(context: Context, binding: FcmTokenPolicy.Binding, token: String) {
        if (!FcmTokenPolicy.isCurrent(binding, currentBinding(context))) return
        val fields = FcmTokenPolicy.fields(binding, token) ?: return
        val data = HashMap<String, Any>(fields).apply {
            put("deviceId", DeviceManager.getDeviceId(context))
            put("deviceName", DeviceManager.getAndroidDeviceName())
            put("appVersion", context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown")
            put("lastUpdated", FieldValue.serverTimestamp())
        }
        // Capture this database and identity before suspension. Never write through a mutable region.
        val app = CloudAuth.app(context)
        val reference = FirebaseFirestore.getInstance(app).collection("fcmTokens").document(binding.uid)
        val write = synchronized(stateLock) {
            if (!FcmTokenPolicy.isCurrent(binding, currentBinding(context))) return
            reference.set(data) // Replace stale metadata as well as the token.
        }
        write.await()
        // DeviceManager enqueues deletion in the captured old project before any transition.
        // No client read-back is used: token documents intentionally remain unreadable.

    }

    /** Initiated while still hybrid, before region/mode/pairing state changes. Never signs in. */
    fun deleteStoredRegistration(context: Context) {
        if (DeviceManager.getSyncMode(context) != "hybrid") return
        try {
            val appName = RegionConfig.appName(DeviceManager.getTargetRegion(context))
            val app = FirebaseApp.getApps(context).firstOrNull { it.name == appName } ?: return
            val uid = FirebaseAuth.getInstance(app).currentUser?.uid ?: return
            FirebaseFirestore.getInstance(app).collection("fcmTokens").document(uid).delete()
                .addOnFailureListener { Log.w(TAG, "FCM cleanup deferred to server expiry") }
        } catch (e: Exception) {
            Log.w(TAG, "FCM cleanup unavailable; server expiry will apply")
        }
    }

    suspend fun deleteFCMToken(context: Context) {
        if (DeviceManager.getSyncMode(context) != "hybrid") return
        try {
            val app = CloudAuth.app(context)
            val uid = FirebaseAuth.getInstance(app).currentUser?.uid ?: return
            FirebaseFirestore.getInstance(app).collection("fcmTokens").document(uid).delete().await()
        } catch (e: Exception) {
            Log.w(TAG, "FCM cleanup deferred to server expiry")
        }
    }
}
