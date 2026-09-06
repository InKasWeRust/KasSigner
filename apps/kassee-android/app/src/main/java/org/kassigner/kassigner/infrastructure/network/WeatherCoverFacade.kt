package org.kassigner.kassigner.infrastructure.network

import org.kassigner.kassigner.domain.weather.WeatherLocation
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import org.kassigner.kassigner.infrastructure.persistence.WeatherCoverSettings
import org.kassigner.kassigner.infrastructure.persistence.WeatherSnapshotCache

class WeatherCoverFacade(
    private val service: WeatherService,
    private val cache: WeatherSnapshotCache,
) {
    fun cached(settings: WeatherCoverSettings): WeatherSnapshot? = cache.load(settings)

    suspend fun refresh(settings: WeatherCoverSettings): WeatherSnapshot =
        service.forecast(settings).also(cache::save)

    suspend fun searchCities(query: String): List<WeatherLocation> = service.searchCities(query)

    fun clearCache() = cache.clear()
}
