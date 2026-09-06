package org.kassigner.kassigner.domain.weather

enum class TemperatureUnit(val wireValue: String) {
    FAHRENHEIT("fahrenheit"),
    CELSIUS("celsius"),
}

enum class WeatherUnlockTarget(val title: String) {
    LOCATION("Location"),
    CONDITION_ICON("Condition Icon"),
    TEMPERATURE("Temperature"),
}

data class WeatherDay(
    val date: String,
    val high: Double,
    val low: Double,
    val weatherCode: Int,
)

data class WeatherSnapshot(
    val temperature: Double,
    val apparentTemperature: Double,
    val weatherCode: Int,
    val windSpeed: Double,
    val daily: List<WeatherDay>,
    val updatedAtEpochSeconds: Long,
    val latitude: Double,
    val longitude: Double,
    val temperatureUnit: TemperatureUnit,
)

data class WeatherLocation(
    val id: Int,
    val name: String,
    val region: String?,
    val country: String,
    val latitude: Double,
    val longitude: Double,
) {
    val displayName: String
        get() = listOfNotNull(name, region, country).filter { it.isNotBlank() }.joinToString(", ")
}

object WeatherUnlockPolicy {
    const val DEFAULT_TAPS = 3
    const val MINIMUM_TAPS = 2
    const val MAXIMUM_TAPS = 7

    fun normalizeTapCount(value: Int): Int = value.coerceIn(MINIMUM_TAPS, MAXIMUM_TAPS)

    fun shouldUnlock(
        configuredTarget: WeatherUnlockTarget,
        tappedTarget: WeatherUnlockTarget,
        completedTaps: Int,
        requiredTaps: Int,
    ): Boolean = configuredTarget == tappedTarget && completedTaps == normalizeTapCount(requiredTaps)
}
