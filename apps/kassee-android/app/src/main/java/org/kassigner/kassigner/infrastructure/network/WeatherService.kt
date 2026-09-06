package org.kassigner.kassigner.infrastructure.network

import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherDay
import org.kassigner.kassigner.domain.weather.WeatherLocation
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import org.kassigner.kassigner.infrastructure.persistence.WeatherCoverSettings

class WeatherService {
    suspend fun forecast(settings: WeatherCoverSettings): WeatherSnapshot = withContext(Dispatchers.IO) {
        val unit = settings.temperatureUnit
        val url = "https://api.open-meteo.com/v1/forecast" +
            "?latitude=${settings.latitude}&longitude=${settings.longitude}" +
            "&current=temperature_2m,apparent_temperature,weather_code,wind_speed_10m" +
            "&daily=weather_code,temperature_2m_max,temperature_2m_min" +
            "&temperature_unit=${unit.wireValue}&wind_speed_unit=${if (unit == TemperatureUnit.FAHRENHEIT) "mph" else "kmh"}" +
            "&timezone=auto&forecast_days=6"
        decodeForecast(JSONObject(request(url)), settings)
    }

    suspend fun searchCities(query: String): List<WeatherLocation> = withContext(Dispatchers.IO) {
        val cleaned = query.trim()
        if (cleaned.length < 2) return@withContext emptyList()
        val encoded = URLEncoder.encode(cleaned, StandardCharsets.UTF_8.name())
        val root = JSONObject(request("https://geocoding-api.open-meteo.com/v1/search?name=$encoded&count=12&language=en&format=json"))
        decodeCitySearch(root)
    }

    internal fun decodeCitySearch(root: JSONObject): List<WeatherLocation> {
        val results = root.optJSONArray("results") ?: return emptyList()
        return (0 until results.length()).mapNotNull { index ->
            decodeCitySearchRow(results.optJSONObject(index), index)
        }
    }

    private fun decodeCitySearchRow(item: JSONObject?, index: Int): WeatherLocation? {
        val source = item ?: return null
        val latitude = source.optDouble("latitude", Double.NaN)
        val longitude = source.optDouble("longitude", Double.NaN)
        if (!validLatitude(latitude)) return null
        if (!validLongitude(longitude)) return null
        return buildWeatherLocation(source, index, latitude, longitude)
    }

    private fun validLatitude(value: Double) = value.isFinite() && value in -90.0..90.0

    private fun validLongitude(value: Double) = value.isFinite() && value in -180.0..180.0

    private fun buildWeatherLocation(
        item: JSONObject,
        index: Int,
        latitude: Double,
        longitude: Double,
    ): WeatherLocation? {
        val name = item.optString("name", "").trim()
        if (name.isBlank()) return null
        val country = item.optString("country", "").trim()
        if (country.isBlank()) return null
        return WeatherLocation(
            id = item.optInt("id", index),
            name = name,
            region = item.optString("admin1", "").trim().ifBlank { null },
            country = country,
            latitude = latitude,
            longitude = longitude,
        )
    }

    internal fun decodeForecast(root: JSONObject, settings: WeatherCoverSettings): WeatherSnapshot {
        val current = root.getJSONObject("current")
        val daily = root.getJSONObject("daily")
        val dates = daily.getJSONArray("time")
        val codes = daily.getJSONArray("weather_code")
        val highs = daily.getJSONArray("temperature_2m_max")
        val lows = daily.getJSONArray("temperature_2m_min")
        val count = minOf(dates.length(), codes.length(), highs.length(), lows.length())
        val snapshot = WeatherSnapshot(
            temperature = current.getDouble("temperature_2m"),
            apparentTemperature = current.getDouble("apparent_temperature"),
            weatherCode = current.getInt("weather_code"),
            windSpeed = current.getDouble("wind_speed_10m"),
            daily = List(count) { index -> WeatherDay(dates.getString(index), highs.getDouble(index), lows.getDouble(index), codes.getInt(index)) },
            updatedAtEpochSeconds = System.currentTimeMillis() / 1000,
            latitude = settings.latitude,
            longitude = settings.longitude,
            temperatureUnit = settings.temperatureUnit,
        )
        requireFinite(snapshot)
        return snapshot
    }

    internal fun requireFinite(snapshot: WeatherSnapshot) {
        require(snapshot.temperature.isFinite() && snapshot.apparentTemperature.isFinite())
        require(snapshot.windSpeed.isFinite())
        require(snapshot.daily.all { it.high.isFinite() && it.low.isFinite() })
    }

    private fun request(url: String): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 12_000
        connection.readTimeout = 12_000
        connection.setRequestProperty("Accept", "application/json")
        return try {
            if (connection.responseCode !in 200..299) error("HTTP ${connection.responseCode}")
            val bytes = ByteArray(MAXIMUM_RESPONSE_BYTES + 1)
            val length = connection.inputStream.use { input ->
                var offset = 0
                while (offset < bytes.size) {
                    val read = input.read(bytes, offset, bytes.size - offset)
                    if (read < 0) break
                    offset += read
                }
                offset
            }
            if (length > MAXIMUM_RESPONSE_BYTES) error("Weather response exceeded size limit")
            String(bytes, 0, length, StandardCharsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        const val MAXIMUM_RESPONSE_BYTES = 1_000_000
    }
}
