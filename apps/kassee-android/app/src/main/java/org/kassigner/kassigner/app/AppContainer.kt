package org.kassigner.kassigner.app

import android.content.Context
import org.kassigner.kassigner.infrastructure.network.WeatherCoverFacade
import org.kassigner.kassigner.infrastructure.network.WeatherService
import org.kassigner.kassigner.infrastructure.persistence.AppPreferences
import org.kassigner.kassigner.infrastructure.persistence.WeatherCoverPreferences
import org.kassigner.kassigner.infrastructure.persistence.WeatherSnapshotCache
import org.kassigner.kassigner.infrastructure.security.AppLockService

/** Native services that remain intentionally outside the embedded KasSee wallet surface. */
class AppContainer(context: Context) {
    private val applicationContext = context.applicationContext

    val preferences = AppPreferences(applicationContext)
    val weatherCoverPreferences = WeatherCoverPreferences(applicationContext)
    val weatherCover = WeatherCoverFacade(WeatherService(), WeatherSnapshotCache(applicationContext))
    val appLock = AppLockService(applicationContext)
}
