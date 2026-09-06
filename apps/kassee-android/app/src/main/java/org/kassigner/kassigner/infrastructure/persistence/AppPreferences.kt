package org.kassigner.kassigner.infrastructure.persistence

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class AppearanceTheme { SYSTEM, LIGHT, DARK }

data class PreferenceSnapshot(
    val appearance: AppearanceTheme = AppearanceTheme.DARK,
)

/** Native-shell preferences only. Wallet preferences live in the embedded KasSee application. */
class AppPreferences(context: Context) {
    private val store = context.getSharedPreferences("kassigner.preferences.v1", Context.MODE_PRIVATE)
    private val mutableSnapshot = MutableStateFlow(load())
    val snapshot: StateFlow<PreferenceSnapshot> = mutableSnapshot.asStateFlow()

    fun update(transform: (PreferenceSnapshot) -> PreferenceSnapshot) {
        val updated = transform(mutableSnapshot.value)
        mutableSnapshot.value = updated
        store.edit().putString("appearance", updated.appearance.name).apply()
    }

    private fun load(): PreferenceSnapshot = PreferenceSnapshot(
        appearance = enumValues<AppearanceTheme>()
            .firstOrNull { it.name == store.getString("appearance", null) }
            ?: AppearanceTheme.DARK,
    )
}
