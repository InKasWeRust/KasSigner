package org.kassigner.kassigner.features.cover

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.kassigner.kassigner.domain.weather.WeatherLocation
import org.kassigner.kassigner.infrastructure.network.WeatherCoverFacade

@Composable
fun CitySearchScreen(facade: WeatherCoverFacade, onSelect: (WeatherLocation) -> Unit, onClose: () -> Unit) {
    var query by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<WeatherLocation>>(emptyList()) }
    var searching by remember { mutableStateOf(false) }
    LaunchedEffect(query) {
        val cleaned = query.trim()
        if (cleaned.length < 2) {
            results = emptyList()
            searching = false
            return@LaunchedEffect
        }
        searching = true
        delay(350)
        results = runCatching { facade.searchCities(cleaned) }.getOrDefault(emptyList())
        searching = false
    }
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Choose City", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = onClose) { Text("Cancel") }
        }
        OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), label = { Text("City or postal code") }, singleLine = true)
        if (searching) LinearProgressIndicator(Modifier.fillMaxWidth())
        LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(results, key = { it.id }) { location ->
                Card(Modifier.fillMaxWidth().clickable { onSelect(location) }) {
                    Column(Modifier.padding(14.dp)) {
                        Text(location.name, style = MaterialTheme.typography.titleMedium)
                        Text(location.displayName, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
