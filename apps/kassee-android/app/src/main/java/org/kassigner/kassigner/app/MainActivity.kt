package org.kassigner.kassigner.app

import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import org.kassigner.kassigner.features.root.KasSeeBootState
import org.kassigner.kassigner.features.root.MobileOverlayScreen

class MainActivity : FragmentActivity() {
    private lateinit var container: AppContainer
    private lateinit var rootView: FrameLayout
    private lateinit var overlayView: ComposeView
    private lateinit var kasSeeHost: KasSeeWebViewHost
    private val bootState = MutableStateFlow<KasSeeBootState>(KasSeeBootState.Loading)
    private val showMobileSettings = MutableStateFlow(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        container = AppContainer(this)
        installViewHierarchy()
        kasSeeHost = KasSeeWebViewHost(
            activity = this,
            rootView = rootView,
            overlayView = overlayView,
            bootState = bootState,
            onOpenMobileSettings = { showMobileSettings.value = true },
        )
        observeNativeOverlays()
        kasSeeHost.install()
    }

    override fun onStart() {
        super.onStart()
        container.appLock.onForeground()
        kasSeeHost.onResume()
    }

    override fun onStop() {
        kasSeeHost.onPause()
        container.appLock.onBackground()
        super.onStop()
    }

    override fun onDestroy() {
        kasSeeHost.destroy()
        overlayView.disposeComposition()
        super.onDestroy()
    }

    private fun installViewHierarchy() {
        rootView = FrameLayout(this).apply { setBackgroundColor(Color.rgb(8, 12, 18)) }
        overlayView = ComposeView(this).apply {
            setBackgroundColor(Color.TRANSPARENT)
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
            setContent {
                val preferences by container.preferences.snapshot.collectAsState()
                val boot by bootState.collectAsState()
                val mobileSettings by showMobileSettings.collectAsState()
                KasSignerTheme(preferences.appearance) {
                    MobileOverlayScreen(
                        container = container,
                        activity = this@MainActivity,
                        bootState = boot,
                        showMobileSettings = mobileSettings,
                        onRetry = { kasSeeHost.install() },
                        onCloseMobileSettings = { showMobileSettings.value = false },
                    )
                }
            }
        }
        rootView.addView(
            overlayView,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT),
        )
        setContentView(rootView)
    }

    private fun observeNativeOverlays() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    combine(
                        container.appLock.state,
                        container.weatherCoverPreferences.settings,
                        bootState,
                        showMobileSettings,
                    ) { security, weather, boot, mobileSettings ->
                        val weatherCover = security.enabled && weather.enabled && !security.privacyCoverSuspendedForSession
                        OverlayVisibility(
                            overlayNeeded = security.locked || weatherCover || mobileSettings || boot != KasSeeBootState.Ready,
                            hideWallet = security.locked || weatherCover || mobileSettings,
                        )
                    }.collect { visibility ->
                        overlayView.visibility = if (visibility.overlayNeeded) View.VISIBLE else View.GONE
                        kasSeeHost.setWalletHidden(visibility.hideWallet)
                        if (visibility.overlayNeeded) overlayView.bringToFront()
                    }
                }
                launch {
                    container.appLock.state.collect { security ->
                        updateRecentsPrivacy(security.enabled && security.hideSwitcherPreview)
                    }
                }
            }
        }
    }

    private fun updateRecentsPrivacy(enabled: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            setRecentsScreenshotEnabled(!enabled)
        } else if (enabled) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private data class OverlayVisibility(val overlayNeeded: Boolean, val hideWallet: Boolean)
}
