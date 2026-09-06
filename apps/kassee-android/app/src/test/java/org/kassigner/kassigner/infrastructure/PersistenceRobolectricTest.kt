package org.kassigner.kassigner.infrastructure

import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherDay
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import org.kassigner.kassigner.domain.weather.WeatherUnlockTarget
import org.kassigner.kassigner.infrastructure.persistence.AppPreferences
import org.kassigner.kassigner.infrastructure.persistence.AppearanceTheme
import org.kassigner.kassigner.infrastructure.persistence.WeatherCoverPreferences
import org.kassigner.kassigner.infrastructure.persistence.WeatherCoverSettings
import org.kassigner.kassigner.infrastructure.persistence.WeatherSnapshotCache
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class PersistenceRobolectricTest {
    private val context get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Before
    fun clear() {
        context.getSharedPreferences("kassigner.preferences.v1", 0).edit().clear().commit()
        context.getSharedPreferences("kassigner.weather.v1", 0).edit().clear().commit()
        context.getSharedPreferences("kassigner.weather.cache.v1", 0).edit().clear().commit()
    }

    @After
    fun cleanup() = clear()

    @Test
    fun appearanceRoundTripsThroughNativeShellPreferences() {
        val preferences = AppPreferences(context)
        preferences.update { it.copy(appearance = AppearanceTheme.LIGHT) }
        assertEquals(AppearanceTheme.LIGHT, AppPreferences(context).snapshot.value.appearance)
    }

    @Test
    fun weatherCoverDefaultsRoundTripAndSanitizeCoordinates() {
        val directDefaults = WeatherCoverSettings()
        assertFalse(directDefaults.enabled)

        val preferences = WeatherCoverPreferences(context)
        assertFalse(preferences.settings.value.enabled)
        preferences.update {
            it.copy(
                enabled = true,
                cityName = "Boston",
                latitude = 42.3601,
                longitude = -71.0589,
                temperatureUnit = TemperatureUnit.CELSIUS,
                unlockTarget = WeatherUnlockTarget.TEMPERATURE,
                unlockTapCount = 5,
            )
        }
        val restored = WeatherCoverPreferences(context).settings.value
        assertTrue(restored.enabled)
        assertEquals("Boston", restored.cityName)
        assertEquals(TemperatureUnit.CELSIUS, restored.temperatureUnit)
        assertEquals(WeatherUnlockTarget.TEMPERATURE, restored.unlockTarget)
        assertEquals(5, restored.unlockTapCount)

        preferences.update { it.copy(latitude = 91.0, longitude = 181.0) }
        assertEquals(40.7128, preferences.settings.value.latitude, 0.0)
        assertEquals(-74.0060, preferences.settings.value.longitude, 0.0)

        preferences.reset()
        assertFalse(preferences.settings.value.enabled)
    }

    @Test
    fun weatherCacheRequiresMatchingLocationUnitAndFinitePayload() {
        val cache = WeatherSnapshotCache(context)
        val settings = WeatherCoverSettings(latitude = 40.7128, longitude = -74.0060)
        val snapshot = weatherSnapshot(latitude = settings.latitude, longitude = settings.longitude)

        cache.save(snapshot)
        assertEquals(snapshot, cache.load(settings))
        assertNull(cache.load(settings.copy(latitude = settings.latitude + 0.01)))
        assertNull(cache.load(settings.copy(longitude = settings.longitude + 0.01)))
        assertNull(cache.load(settings.copy(temperatureUnit = TemperatureUnit.CELSIUS)))

        assertRejects { cache.requireFinite(snapshot.copy(latitude = 91.0)) }
        assertRejects { cache.requireFinite(snapshot.copy(longitude = 181.0)) }
        assertRejects {
            cache.requireFinite(
                snapshot.copy(daily = listOf(WeatherDay("2026-09-01", Double.NaN, 60.0, 0)))
            )
        }
    }

    private fun weatherSnapshot(
        latitude: Double,
        longitude: Double,
    ) = WeatherSnapshot(
        temperature = 72.0,
        apparentTemperature = 73.0,
        weatherCode = 1,
        windSpeed = 5.0,
        daily = listOf(WeatherDay("2026-09-01", 80.0, 60.0, 1)),
        updatedAtEpochSeconds = 1_788_300_000,
        latitude = latitude,
        longitude = longitude,
        temperatureUnit = TemperatureUnit.FAHRENHEIT,
    )

    private fun assertRejects(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        }
        throw AssertionError("Expected IllegalArgumentException")
    }
}
