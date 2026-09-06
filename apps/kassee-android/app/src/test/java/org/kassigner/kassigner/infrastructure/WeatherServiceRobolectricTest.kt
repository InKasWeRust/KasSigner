package org.kassigner.kassigner.infrastructure

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherDay
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import org.kassigner.kassigner.infrastructure.network.WeatherService
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class WeatherServiceRobolectricTest {
    @Test
    fun rejectsInvalidSearchRowsAndNonFiniteForecastData() {
        val service = WeatherService()
        val root = JSONObject().put(
            "results",
            JSONArray()
                .put(city("  Valid  ", "  US  ", 40.0, -75.0).put("admin1", "  Pennsylvania  "))
                .put(JSONObject.NULL)
                .put(city("Bad latitude", "US", 91.0, -75.0))
                .put(city("Bad longitude", "US", 40.0, 181.0))
                .put(city("", "US", 40.0, -75.0))
                .put(city("Missing country", "", 40.0, -75.0))
        )
        val decoded = service.decodeCitySearch(root)
        assertEquals(1, decoded.size)
        assertEquals("Valid", decoded.single().name)
        assertEquals("US", decoded.single().country)
        assertEquals("Pennsylvania", decoded.single().region)

        val valid = weatherSnapshot()
        service.requireFinite(valid)
        assertRejects { service.requireFinite(valid.copy(temperature = Double.NaN)) }
        assertRejects {
            service.requireFinite(
                valid.copy(daily = listOf(WeatherDay("2026-09-01", Double.NaN, 60.0, 0)))
            )
        }
    }

    private fun city(name: String, country: String, latitude: Double, longitude: Double) =
        JSONObject()
            .put("name", name)
            .put("country", country)
            .put("latitude", latitude)
            .put("longitude", longitude)

    private fun weatherSnapshot() = WeatherSnapshot(
        temperature = 72.0,
        apparentTemperature = 73.0,
        weatherCode = 1,
        windSpeed = 5.0,
        daily = listOf(WeatherDay("2026-09-01", 80.0, 60.0, 1)),
        updatedAtEpochSeconds = 1_788_300_000,
        latitude = 40.7128,
        longitude = -74.0060,
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
