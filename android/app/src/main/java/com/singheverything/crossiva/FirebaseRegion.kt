package com.singheverything.crossiva

/** Region policy contains no Firebase credentials. Unknown regions fail closed. */
object FirebaseRegion {
    fun appName(region: String): String = when (region) {
        "CA" -> "[DEFAULT]"
        "US" -> "CrossivaUS"
        "IN" -> "CrossivaIN"
        else -> error("Unknown Firebase region")
    }
    fun forCountry(country: String): String = when (country.trim().lowercase()) {
        "canada", "ca" -> "CA"
        "india", "in" -> "IN"
        else -> "US"
    }
}
