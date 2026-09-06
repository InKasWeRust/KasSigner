package org.kassigner.kassigner.features.settings

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import org.kassigner.kassigner.app.AppContainer
import org.kassigner.kassigner.infrastructure.security.LockDelay
import org.kassigner.kassigner.shared.ui.EnumSetting
import org.kassigner.kassigner.shared.ui.SettingsHeader
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun SecuritySettingsScreen(container: AppContainer, activity: FragmentActivity, onBack: () -> Unit, onHome: (() -> Unit)? = null) {
    val security by container.appLock.state.collectAsStateWithLifecycle()
    var showDecoy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    if (showDecoy) {
        DecoyLaunchSettingsScreen(container, activity, { showDecoy = false }, onHome)
        return
    }
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        SettingsHeader("Security", onBack, onHome)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Biometrics", style = MaterialTheme.typography.titleMedium)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("App Lock")
                    Switch(
                        checked = security.enabled,
                        enabled = !security.authenticating,
                        onCheckedChange = { enabled ->
                            scope.launch {
                                val succeeded = if (enabled) container.appLock.enable(activity) else container.appLock.disable(activity)
                                if (succeeded && !enabled) container.weatherCoverPreferences.update { it.copy(enabled = false) }
                            }
                        },
                    )
                }
                if (security.enabled) EnumSetting("Authentication", security.delay, LockDelay.entries, container.appLock::setDelay)
                Text("Use biometrics or your device credential to unlock KasSigner.", style = MaterialTheme.typography.bodySmall)
            }
        }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Privacy", style = MaterialTheme.typography.titleMedium)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Hide app switcher preview")
                    Switch(security.hideSwitcherPreview, container.appLock::setHideSwitcherPreview)
                }
                OutlinedButton(onClick = { showDecoy = true }) { Text("Decoy Launch") }
            }
        }
        security.error?.let {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp)) {
                    Text(it, color = MaterialTheme.colorScheme.error)
                    TextButton(onClick = container.appLock::clearError) { Text("Dismiss") }
                }
            }
        }
    }
}
