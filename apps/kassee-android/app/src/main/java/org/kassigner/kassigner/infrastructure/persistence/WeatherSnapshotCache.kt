package org.kassigner.kassigner.infrastructure.persistence

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherDay
import org.kassigner.kassigner.domain.weather.WeatherSnapshot

class WeatherSnapshotCache(context: Context) {
    private val store = context.getSharedPreferences("kassigner.weather.cache.v1", Context.MODE_PRIVATE)

    fun load(settings: WeatherCoverSettings): WeatherSnapshot? = runCatching {
        val raw = store.getString("snapshot", null) ?: return null
        decode(JSONObject(raw)).takeIf { snapshot -> matches(snapshot, settings) }
    }.getOrNull()

    fun save(snapshot: WeatherSnapshot) {
        store.edit().putString("snapshot", encode(snapshot).toString()).apply()
    }

    fun clear() = store.edit().clear().apply()

    private fun matches(snapshot: WeatherSnapshot, settings: WeatherCoverSettings): Boolean =
        kotlin.math.abs(snapshot.latitude - settings.latitude) < 0.000_001 &&
            kotlin.math.abs(snapshot.longitude - settings.longitude) < 0.000_001 &&
            snapshot.temperatureUnit == settings.temperatureUnit

    private fun encode(snapshot: WeatherSnapshot): JSONObject = JSONObject()
        .put("temperature", snapshot.temperature)
        .put("apparent_temperature", snapshot.apparentTemperature)
        .put("weather_code", snapshot.weatherCode)
        .put("wind_speed", snapshot.windSpeed)
        .put("updated_at", snapshot.updatedAtEpochSeconds)
        .put("latitude", snapshot.latitude)
        .put("longitude", snapshot.longitude)
        .put("temperature_unit", snapshot.temperatureUnit.name)
        .put("daily", JSONArray().apply {
            snapshot.daily.forEach { day ->
                put(JSONObject().put("date", day.date).put("high", day.high).put("low", day.low).put("weather_code", day.weatherCode))
            }
        })

    private fun decode(root: JSONObject): WeatherSnapshot {
        val days = root.getJSONArray("daily")
        return WeatherSnapshot(
            temperature = root.getDouble("temperature"),
            apparentTemperature = root.getDouble("apparent_temperature"),
            weatherCode = root.getInt("weather_code"),
            windSpeed = root.getDouble("wind_speed"),
            daily = List(days.length()) { index ->
                val day = days.getJSONObject(index)
                WeatherDay(day.getString("date"), day.getDouble("high"), day.getDouble("low"), day.getInt("weather_code"))
            },
            updatedAtEpochSeconds = root.getLong("updated_at"),
            latitude = root.getDouble("latitude"),
            longitude = root.getDouble("longitude"),
            temperatureUnit = TemperatureUnit.valueOf(root.getString("temperature_unit")),
        ).also(::requireFinite)
    }

    internal fun requireFinite(snapshot: WeatherSnapshot) {
        require(snapshot.temperature.isFinite())
        require(snapshot.apparentTemperature.isFinite())
        require(snapshot.windSpeed.isFinite())
        require(snapshot.latitude.isFinite() && snapshot.latitude in -90.0..90.0)
        require(snapshot.longitude.isFinite() && snapshot.longitude in -180.0..180.0)
        require(snapshot.daily.all { it.high.isFinite() && it.low.isFinite() })
    }
}
