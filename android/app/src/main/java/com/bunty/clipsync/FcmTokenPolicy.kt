package com.bunty.clipsync

/** Android uses one default-app FCM issuer, independently of regional Auth/Firestore. */
object FcmTokenPolicy {
    const val INDIA_PROJECT = "clipsyncind"
    const val US_PROJECT = "clipsync1-c3c3c"
    const val ANDROID_PUSH_PROJECT = INDIA_PROJECT

    data class Binding(
        val region: String,
        val uid: String,
        val pairingId: String,
        val authProjectId: String,
        val projectId: String,
        val senderId: String,
        val applicationId: String
    )

    fun requiresLocalRestart(currentMode: String, newMode: String, cloudInitialized: Boolean): Boolean =
        currentMode == "hybrid" && newMode == "local" && cloudInitialized

    fun authProject(region: String): String? = when (region) {
        "IN" -> INDIA_PROJECT
        "US" -> US_PROJECT
        else -> null // Unknown regions never silently select another project.
    }

    /** Retained same-project check; decoupling is permitted only by [binding]. */
    fun canRegister(selectedProject: String?, messagingProject: String?): Boolean =
        !selectedProject.isNullOrBlank() && selectedProject == messagingProject

    fun binding(mode: String, region: String, uid: String?, pairingId: String?,
                authProjectId: String?, messagingProjectId: String?, senderId: String?,
                applicationId: String?): Binding? {
        if (mode != "hybrid" || uid.isNullOrBlank() || pairingId.isNullOrBlank()) return null
        if (authProjectId != authProject(region) || authProjectId == null) return null
        if (messagingProjectId != ANDROID_PUSH_PROJECT || senderId.isNullOrBlank() ||
            !senderId.all { it.isDigit() } || applicationId.isNullOrBlank()) return null
        // Firebase Android app IDs contain the issuing project's numeric sender ID.
        if (!applicationId.startsWith("1:$senderId:android:")) return null
        return Binding(region, uid, pairingId, authProjectId, messagingProjectId, senderId, applicationId)
    }

    fun fields(binding: Binding, token: String): Map<String, String>? {
        if (token.isBlank() || token.length > 4096) return null
        return mapOf("token" to token, "platform" to "android",
            "projectId" to binding.projectId, "authProjectId" to binding.authProjectId,
            "senderId" to binding.senderId, "applicationId" to binding.applicationId,
            "pairingId" to binding.pairingId)
    }

    /** A delayed registration cannot be repurposed for a changed region, pairing or UID. */
    fun isCurrent(original: Binding, current: Binding?): Boolean = original == current
}
