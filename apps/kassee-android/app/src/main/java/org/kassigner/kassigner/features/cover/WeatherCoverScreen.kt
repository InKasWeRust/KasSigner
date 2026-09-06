package org.kassigner.kassigner.features.cover

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.kassigner.kassigner.app.AppContainer
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import org.kassigner.kassigner.domain.weather.WeatherUnlockPolicy
import org.kassigner.kassigner.domain.weather.WeatherUnlockTarget
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun WeatherCoverScreen(container: AppContainer, activity: FragmentActivity) {
    val settings by container.weatherCoverPreferences.settings.collectAsStateWithLifecycle()
    var snapshot by remember(settings.latitude, settings.longitude, settings.temperatureUnit) {
        mutableStateOf(container.weatherCover.cached(settings))
    }
    var message by remember { mutableStateOf<String?>(null) }
    var refreshing by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    suspend fun refresh() {
        if (refreshing) return
        refreshing = true
        message = null
        runCatching { container.weatherCover.refresh(settings) }
            .onSuccess { snapshot = it }
            .onFailure { message = if (snapshot == null) "Weather is temporarily unavailable." else "Unable to refresh. Showing the last update." }
        refreshing = false
    }

    LaunchedEffect(settings.latitude, settings.longitude, settings.temperatureUnit) { refresh() }
    if (showSettings) {
        WeatherSettingsScreen(container, activity, snapshot, { snapshot = it }, { showSettings = false })
        return
    }

    var tapCount by remember { mutableIntStateOf(0) }
    var tapJob by remember { mutableStateOf<Job?>(null) }
    var unlockBusy by remember { mutableStateOf(false) }
    val recordTap: (WeatherUnlockTarget) -> Unit = { tapped ->
        if (tapped == settings.unlockTarget && !unlockBusy) {
            tapCount += 1
            tapJob?.cancel()
            tapJob = scope.launch {
                delay(500)
                val completed = tapCount
                tapCount = 0
                if (WeatherUnlockPolicy.shouldUnlock(settings.unlockTarget, tapped, completed, settings.unlockTapCount)) {
                    unlockBusy = true
                    container.appLock.unlockFromPrivacyCover(activity)
                    unlockBusy = false
                }
            }
        }
    }
    DisposableEffect(Unit) { onDispose { tapJob?.cancel() } }

    Scaffold(topBar = {
        Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = { showSettings = true }) { Text("Weather Settings") }
        }
    }) { padding ->
        LazyColumn(
            Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            item {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(settings.cityName, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.clickable { recordTap(WeatherUnlockTarget.LOCATION) })
                    Text(LocalDate.now().format(DateTimeFormatter.ofPattern("EEEE, MMMM d")), style = MaterialTheme.typography.bodyMedium)
                }
            }
            item {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(weatherEmoji(snapshot?.weatherCode), fontSize = 80.sp, modifier = Modifier.clickable { recordTap(WeatherUnlockTarget.CONDITION_ICON) })
                    Text(temperature(snapshot?.temperature), fontSize = 64.sp, fontWeight = FontWeight.Light, modifier = Modifier.clickable { recordTap(WeatherUnlockTarget.TEMPERATURE) })
                    Text(weatherCondition(snapshot?.weatherCode), style = MaterialTheme.typography.titleLarge)
                    snapshot?.let {
                        val wind = if (settings.temperatureUnit == TemperatureUnit.FAHRENHEIT) "mph" else "km/h"
                        Text("Feels like ${temperature(it.apparentTemperature)}  •  Wind ${it.windSpeed.toInt()} $wind", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            item { ForecastCard(snapshot) }
            item {
                when {
                    refreshing -> CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                    message != null -> Text(message!!, style = MaterialTheme.typography.bodySmall)
                    snapshot != null -> Text("Updated ${updatedTime(snapshot!!)}", style = MaterialTheme.typography.bodySmall)
                }
            }
            item { TextButton(onClick = { scope.launch { refresh() } }, enabled = !refreshing) { Text("Refresh Weather") } }
            item { Text("Weather data by Open-Meteo", style = MaterialTheme.typography.labelSmall) }
        }
    }
}

@Composable
private fun ForecastCard(snapshot: WeatherSnapshot?) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("6-DAY FORECAST", style = MaterialTheme.typography.labelMedium)
            if (snapshot == null || snapshot.daily.isEmpty()) {
                Text("Forecast unavailable")
                return@Column
            }
            snapshot.daily.forEachIndexed { index, day ->
                if (index > 0) HorizontalDivider()
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(if (index == 0) "Today" else weekday(day.date), Modifier.width(70.dp))
                    Text(weatherEmoji(day.weatherCode), Modifier.weight(1f))
                    Text("${day.low.toInt()}°", Modifier.width(48.dp))
                    Text("${day.high.toInt()}°", Modifier.width(48.dp))
                }
            }
        }
    }
}

private fun temperature(value: Double?): String = value?.let { "${kotlin.math.round(it).toInt()}°" } ?: "--°"
private fun weekday(value: String): String = runCatching { LocalDate.parse(value).format(DateTimeFormatter.ofPattern("EEE")) }.getOrDefault(value)
private fun updatedTime(snapshot: WeatherSnapshot): String = Instant.ofEpochSecond(snapshot.updatedAtEpochSeconds)
    .atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("h:mm a"))
