package com.singheverything.crossiva
import org.junit.Assert.*
import org.junit.Test

class FirebaseRegionTest {
    @Test fun countriesSelectAllThreeRegions() {
        assertEquals("CA", FirebaseRegion.forCountry("Canada"))
        assertEquals("US", FirebaseRegion.forCountry("United States"))
        assertEquals("IN", FirebaseRegion.forCountry("India"))
    }
    @Test fun namedAppsNeverReplaceDefault() {
        assertEquals("[DEFAULT]", FirebaseRegion.appName("CA"))
        assertEquals("CrossivaUS", FirebaseRegion.appName("US"))
        assertEquals("CrossivaIN", FirebaseRegion.appName("IN"))
    }
    @Test(expected = IllegalStateException::class) fun unknownRegionFailsClosed() { FirebaseRegion.appName("unknown") }
}
