package org.kassigner.kassigner.infrastructure.persistence

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherUnlockPolicy
import org.kassigner.kassigner.domain.weather.WeatherUnlockTarget

data class WeatherCoverSettings(
    val enabled: Boolean = false,
    val cityName: String = "New York",
    val latitude: Double = 40.7128,
    val longitude: Double = -74.0060,
    val temperatureUnit: TemperatureUnit = TemperatureUnit.FAHRENHEIT,
    val unlockTarget: WeatherUnlockTarget = WeatherUnlockTarget.CONDITION_ICON,
    val unlockTapCount: Int = WeatherUnlockPolicy.DEFAULT_TAPS,
)

class WeatherCoverPreferences(context: Context) {
    private val store = context.getSharedPreferences("kassigner.weather.v1", Context.MODE_PRIVATE)
    private val mutableSettings = MutableStateFlow(load())
    val settings: StateFlow<WeatherCoverSettings> = mutableSettings.asStateFlow()

    fun update(transform: (WeatherCoverSettings) -> WeatherCoverSettings) {
        val updated = sanitize(transform(mutableSettings.value))
        mutableSettings.value = updated
        persist(updated)
    }

    fun reset() {
        store.edit().clear().apply()
        mutableSettings.value = WeatherCoverSettings()
    }

    private fun load(): WeatherCoverSettings = sanitize(
        WeatherCoverSettings(
            enabled = store.getBoolean("enabled", false),
            cityName = store.getString("city_name", "New York").orEmpty().ifBlank { "New York" },
            latitude = java.lang.Double.longBitsToDouble(store.getLong("latitude", java.lang.Double.doubleToLongBits(40.7128))),
            longitude = java.lang.Double.longBitsToDouble(store.getLong("longitude", java.lang.Double.doubleToLongBits(-74.0060))),
            temperatureUnit = enumValue(store.getString("temperature_unit", null), TemperatureUnit.FAHRENHEIT),
            unlockTarget = enumValue(store.getString("unlock_target", null), WeatherUnlockTarget.CONDITION_ICON),
            unlockTapCount = store.getInt("unlock_taps", WeatherUnlockPolicy.DEFAULT_TAPS),
        )
    )

    private fun sanitize(value: WeatherCoverSettings): WeatherCoverSettings = value.copy(
        latitude = value.latitude.takeIf { it.isFinite() && it in -90.0..90.0 } ?: 40.7128,
        longitude = value.longitude.takeIf { it.isFinite() && it in -180.0..180.0 } ?: -74.0060,
        unlockTapCount = WeatherUnlockPolicy.normalizeTapCount(value.unlockTapCount),
    )

    private fun persist(value: WeatherCoverSettings) {
        store.edit()
            .putBoolean("enabled", value.enabled)
            .putString("city_name", value.cityName)
            .putLong("latitude", java.lang.Double.doubleToRawLongBits(value.latitude))
            .putLong("longitude", java.lang.Double.doubleToRawLongBits(value.longitude))
            .putString("temperature_unit", value.temperatureUnit.name)
            .putString("unlock_target", value.unlockTarget.name)
            .putInt("unlock_taps", value.unlockTapCount)
            .apply()
    }

    private inline fun <reified T : Enum<T>> enumValue(raw: String?, fallback: T): T =
        enumValues<T>().firstOrNull { it.name == raw } ?: fallback
}
