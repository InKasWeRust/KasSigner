package org.kassigner.kassigner.features.settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import org.kassigner.kassigner.app.AppContainer
import org.kassigner.kassigner.domain.weather.WeatherUnlockPolicy
import org.kassigner.kassigner.domain.weather.WeatherUnlockTarget
import org.kassigner.kassigner.shared.ui.EnumSetting
import org.kassigner.kassigner.shared.ui.SettingsHeader
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun DecoyLaunchSettingsScreen(container: AppContainer, activity: FragmentActivity, onBack: () -> Unit, onHome: (() -> Unit)? = null) {
    val security by container.appLock.state.collectAsStateWithLifecycle()
    val weather by container.weatherCoverPreferences.settings.collectAsStateWithLifecycle()
    var toggle by remember(weather.enabled) { mutableStateOf(weather.enabled) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(security.enabled) {
        if (!security.enabled && weather.enabled) container.weatherCoverPreferences.update { it.copy(enabled = false) }
    }
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        SettingsHeader("Decoy Launch", onBack, onHome)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Weather Cover")
                    Switch(
                        checked = toggle,
                        enabled = security.enabled && !security.authenticating,
                        onCheckedChange = { requested ->
                            toggle = requested
                            scope.launch {
                                if (container.appLock.authorizePrivacyCoverChange(activity)) {
                                    container.appLock.suspendPrivacyCoverForCurrentSession()
                                    container.weatherCoverPreferences.update { it.copy(enabled = requested) }
                                } else toggle = weather.enabled
                            }
                        },
                    )
                }
                Text(
                    if (security.enabled) "When enabled, KasSigner opens to a functional weather screen."
                    else "Turn on App Lock in Security before enabling Weather Cover.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        if (weather.enabled) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Unlock Gesture", style = MaterialTheme.typography.titleMedium)
                    EnumSetting("Tap", weather.unlockTarget, WeatherUnlockTarget.entries) { target ->
                        container.weatherCoverPreferences.update { it.copy(unlockTarget = target) }
                    }
                    Text("Number of taps")
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        (WeatherUnlockPolicy.MINIMUM_TAPS..WeatherUnlockPolicy.MAXIMUM_TAPS).forEach { count ->
                            FilterChip(
                                selected = weather.unlockTapCount == count,
                                onClick = { container.weatherCoverPreferences.update { it.copy(unlockTapCount = count) } },
                                label = { Text(count.toString()) },
                            )
                        }
                    }
                    Text("Tap the selected weather item the chosen number of times, then authenticate to open protected content.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
