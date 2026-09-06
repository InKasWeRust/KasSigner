package org.kassigner.kassigner.features.cover

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import org.kassigner.kassigner.app.AppContainer
import org.kassigner.kassigner.domain.weather.TemperatureUnit
import org.kassigner.kassigner.domain.weather.WeatherSnapshot
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun WeatherSettingsScreen(
    container: AppContainer,
    activity: FragmentActivity,
    currentSnapshot: WeatherSnapshot?,
    onSnapshot: (WeatherSnapshot?) -> Unit,
    onClose: () -> Unit,
) {
    val settings by container.weatherCoverPreferences.settings.collectAsStateWithLifecycle()
    var searching by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    if (searching) {
        CitySearchScreen(container.weatherCover, { location ->
            container.weatherCover.clearCache()
            container.weatherCoverPreferences.update { it.copy(cityName = location.name, latitude = location.latitude, longitude = location.longitude) }
            searching = false
            scope.launch {
                runCatching { container.weatherCover.refresh(container.weatherCoverPreferences.settings.value) }
                    .onSuccess(onSnapshot).onFailure { message = "Unable to refresh weather." }
            }
        }, { searching = false })
        return
    }
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Weather Settings", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = onClose) { Text("Done") }
        }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Location", style = MaterialTheme.typography.titleMedium)
                OutlinedButton(onClick = { searching = true }) { Text("City: ${settings.cityName}") }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(settings.temperatureUnit == TemperatureUnit.FAHRENHEIT, { changeUnit(container, TemperatureUnit.FAHRENHEIT, onSnapshot) }, { Text("Fahrenheit") })
                    FilterChip(settings.temperatureUnit == TemperatureUnit.CELSIUS, { changeUnit(container, TemperatureUnit.CELSIUS, onSnapshot) }, { Text("Celsius") })
                }
            }
        }
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    busy = true; message = null
                    runCatching { container.weatherCover.refresh(container.weatherCoverPreferences.settings.value) }
                        .onSuccess(onSnapshot).onFailure { message = "Weather is temporarily unavailable." }
                    busy = false
                }
            },
        ) { Text(if (busy) "Refreshing…" else "Refresh Weather") }
        message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        currentSnapshot?.let { Text("Cached forecast: ${it.daily.size} days", style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.weight(1f))
        TextButton(onClick = { confirmReset = true }) { Text("Reset Weather App", color = MaterialTheme.colorScheme.error) }
    }
    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset weather information?") },
            text = { Text("This clears saved cities and weather data after authentication.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    scope.launch {
                        if (container.appLock.authorizePrivacyCoverChange(activity)) {
                            container.weatherCover.clearCache()
                            container.weatherCoverPreferences.reset()
                            onSnapshot(null)
                            onClose()
                        }
                    }
                }) { Text("Reset Weather App", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } },
        )
    }
}

private fun changeUnit(container: AppContainer, unit: TemperatureUnit, onSnapshot: (WeatherSnapshot?) -> Unit) {
    if (container.weatherCoverPreferences.settings.value.temperatureUnit == unit) return
    container.weatherCover.clearCache()
    container.weatherCoverPreferences.update { it.copy(temperatureUnit = unit) }
    onSnapshot(null)
}
