package org.kassigner.kassigner.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.webkit.ConsoleMessage
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.ComposeView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewAssetLoader
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.kassigner.kassigner.BuildConfig
import org.kassigner.kassigner.features.root.KasSeeBootState

private const val ASSET_HOST = "appassets.androidplatform.net"
private const val KASSEE_URL = "https://$ASSET_HOST/assets/kassee/index.html"
private const val WEBVIEW_TAG = "KasSignerKasSee"
private const val KASSEE_BOOT_TIMEOUT_MS = 12_000L

internal class KasSeeWebViewHost(
    private val activity: FragmentActivity,
    private val rootView: FrameLayout,
    private val overlayView: ComposeView,
    private val bootState: MutableStateFlow<KasSeeBootState>,
    private val onOpenMobileSettings: () -> Unit,
) {
    private val cameraPermission: ActivityResultLauncher<String>
    private val filePicker: ActivityResultLauncher<Intent>
    private var webView: WebView? = null
    private var pendingCameraRequest: PermissionRequest? = null
    private var pendingFileCallback: ValueCallback<Array<Uri>>? = null
    private var bootTimeout: Job? = null

    init {
        cameraPermission = activity.registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            pendingCameraRequest?.let { request ->
                if (granted) request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE)) else request.deny()
            }
            pendingCameraRequest = null
        }
        filePicker = activity.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            pendingFileCallback?.onReceiveValue(
                WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data),
            )
            pendingFileCallback = null
        }
    }

    fun onResume() {
        webView?.onResume()
    }

    fun onPause() {
        webView?.onPause()
    }

    fun setWalletHidden(hidden: Boolean) {
        webView?.visibility = if (hidden) View.INVISIBLE else View.VISIBLE
    }

    @SuppressLint("SetJavaScriptEnabled")
    fun install() {
        bootTimeout?.cancel()
        bootState.value = KasSeeBootState.Loading
        destroyWebView()
        val loader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(activity))
            .build()
        val target = WebView(activity)
        webView = target
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        target.apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            settings.mediaPlaybackRequiresUserGesture = true
            settings.cacheMode = WebSettings.LOAD_NO_CACHE
            settings.useWideViewPort = true
            settings.loadWithOverviewMode = false
            settings.textZoom = 100
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                settings.isAlgorithmicDarkeningAllowed = false
            }
            setBackgroundColor(Color.WHITE)
            alpha = 1f
            isFocusable = true
            isFocusableInTouchMode = true
            addJavascriptInterface(
                KasSeeMobileBridge(
                    openMobileSettings = { activity.runOnUiThread { onOpenMobileSettings() } },
                    resetWalletSurface = { activity.runOnUiThread { install() } },
                ),
                "KasSignerMobile",
            )
            webViewClient = createWebViewClient(loader)
            webChromeClient = createChromeClient()
        }
        rootView.addView(
            target,
            0,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT),
        )
        overlayView.bringToFront()
        target.loadUrl(KASSEE_URL)
        bootTimeout = activity.lifecycleScope.launch {
            delay(KASSEE_BOOT_TIMEOUT_MS)
            if (webView === target && bootState.value == KasSeeBootState.Loading) {
                failBoot("KasSee did not render within 12 seconds. The bundled UI did not reach a visible committed frame.")
            }
        }
    }

    fun destroy() {
        bootTimeout?.cancel()
        pendingCameraRequest?.deny()
        pendingCameraRequest = null
        pendingFileCallback?.onReceiveValue(null)
        pendingFileCallback = null
        destroyWebView()
    }

    private fun createWebViewClient(loader: WebViewAssetLoader): WebViewClient = object : WebViewClient() {
        private var pageCommitted = false
        private var domReady = false
        private var visualStateRequested = false

        override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? =
            request?.url?.let(loader::shouldInterceptRequest)

        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
            val url = request?.url ?: return true
            if (url.host == ASSET_HOST) return false
            if (url.scheme == "https" || url.scheme == "http") {
                runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, url)) }
            }
            return true
        }

        override fun onPageCommitVisible(view: WebView, url: String) {
            super.onPageCommitVisible(view, url)
            if (webView !== view || Uri.parse(url).host != ASSET_HOST) return
            pageCommitted = true
            maybeFinishBoot(view)
        }

        override fun onPageFinished(view: WebView, url: String) {
            super.onPageFinished(view, url)
            if (webView !== view || Uri.parse(url).host != ASSET_HOST) return
            injectMobileAdaptations(view)
            verifyRendered(view) { ready, detail ->
                if (webView !== view) return@verifyRendered
                if (!ready) {
                    failBoot(detail)
                    return@verifyRendered
                }
                domReady = true
                maybeFinishBoot(view)
            }
        }

        private fun maybeFinishBoot(view: WebView) {
            if (!pageCommitted || !domReady || visualStateRequested || webView !== view) return
            visualStateRequested = true
            view.postVisualStateCallback(1L, object : WebView.VisualStateCallback() {
                override fun onComplete(requestId: Long) {
                    if (webView !== view) return
                    view.alpha = 1f
                    view.visibility = View.VISIBLE
                    view.requestLayout()
                    view.invalidate()
                    bootTimeout?.cancel()
                    bootState.value = KasSeeBootState.Ready
                    Log.i(WEBVIEW_TAG, "KasSee direct WebView committed: ${view.width}x${view.height}")
                }
            })
        }

        override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
            super.onReceivedError(view, request, error)
            if (webView !== view) return
            if (request?.isForMainFrame == true || isCriticalResource(request?.url)) {
                val detail = error?.description?.toString().orEmpty().ifBlank { "unknown WebView load error" }
                failBoot("KasSee could not load ${request?.url?.lastPathSegment ?: "page"}: $detail")
            }
        }

        override fun onReceivedHttpError(
            view: WebView?,
            request: WebResourceRequest?,
            errorResponse: WebResourceResponse?,
        ) {
            super.onReceivedHttpError(view, request, errorResponse)
            if (webView !== view) return
            if (request?.isForMainFrame == true || isCriticalResource(request?.url)) {
                failBoot(
                    "KasSee bundled resource ${request?.url?.lastPathSegment ?: "page"} returned HTTP ${errorResponse?.statusCode ?: 0}.",
                )
            }
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            if (webView === view) {
                webView = null
                failBoot(
                    if (detail.didCrash()) "KasSee's Android WebView renderer crashed."
                    else "KasSee's Android WebView renderer was terminated by the system.",
                )
            }
            rootView.removeView(view)
            view.destroy()
            return true
        }
    }

    private fun createChromeClient(): WebChromeClient = object : WebChromeClient() {
        override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
            Log.d(
                WEBVIEW_TAG,
                "${consoleMessage.messageLevel()}: ${consoleMessage.message()} (${consoleMessage.sourceId()}:${consoleMessage.lineNumber()})",
            )
            return true
        }

        override fun onPermissionRequest(request: PermissionRequest) {
            activity.runOnUiThread {
                val localRequest = request.origin.host == ASSET_HOST
                val videoOnly = request.resources.isNotEmpty() &&
                    request.resources.all { it == PermissionRequest.RESOURCE_VIDEO_CAPTURE }
                if (!localRequest || !videoOnly) {
                    request.deny()
                    return@runOnUiThread
                }
                if (ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    request.grant(arrayOf(PermissionRequest.RESOURCE_VIDEO_CAPTURE))
                } else {
                    pendingCameraRequest?.deny()
                    pendingCameraRequest = request
                    cameraPermission.launch(Manifest.permission.CAMERA)
                }
            }
        }

        override fun onPermissionRequestCanceled(request: PermissionRequest) {
            if (pendingCameraRequest === request) pendingCameraRequest = null
        }

        override fun onShowFileChooser(
            webView: WebView?,
            filePathCallback: ValueCallback<Array<Uri>>,
            fileChooserParams: FileChooserParams,
        ): Boolean {
            pendingFileCallback?.onReceiveValue(null)
            pendingFileCallback = filePathCallback
            return runCatching {
                filePicker.launch(fileChooserParams.createIntent())
                true
            }.getOrElse {
                pendingFileCallback?.onReceiveValue(null)
                pendingFileCallback = null
                false
            }
        }
    }

    private fun failBoot(message: String) {
        bootTimeout?.cancel()
        bootState.value = KasSeeBootState.Failed(message)
        Log.e(WEBVIEW_TAG, message)
    }

    private fun destroyWebView() {
        webView?.let { view ->
            rootView.removeView(view)
            view.removeJavascriptInterface("KasSignerMobile")
            view.stopLoading()
            view.loadUrl("about:blank")
            view.clearHistory()
            view.removeAllViews()
            view.destroy()
        }
        webView = null
    }

    private fun verifyRendered(
        target: WebView,
        attempt: Int = 0,
        done: (Boolean, String) -> Unit,
    ) {
        target.evaluateJavascript(
            """
            (() => {
              if (document.readyState !== 'complete') return 'wait';
              const app = document.getElementById('app');
              const header = document.getElementById('header');
              const active = document.querySelector('.screen.active');
              const status = document.getElementById('kassee-startup-status');
              if (!app || !header || !active || !status) return 'shell';
              const root = getComputedStyle(document.documentElement);
              const body = getComputedStyle(document.body);
              if (root.getPropertyValue('--bg').trim() !== '#080c12' || body.color === 'rgb(0, 0, 0)') return 'css';
              const appRect = app.getBoundingClientRect();
              const headerRect = header.getBoundingClientRect();
              const activeRect = active.getBoundingClientRect();
              if (appRect.width <= 0 || appRect.height <= 0 || headerRect.height <= 0 || activeRect.width <= 0 || activeRect.height <= 0) return 'layout';
              if (getComputedStyle(active).display === 'none' || getComputedStyle(active).visibility === 'hidden') return 'layout';
              if (!['ready', 'warning', 'error'].includes(status.dataset.state || '')) return 'wait';
              return 'ready';
            })()
            """.trimIndent(),
        ) { result ->
            when (result) {
                "\"ready\"" -> done(true, "")
                "\"wait\"" -> if (attempt >= 49) {
                    done(false, "KasSee HTML loaded, but application startup did not finish within 10 seconds.")
                } else {
                    target.postDelayed({ verifyRendered(target, attempt + 1, done) }, 200L)
                }
                "\"shell\"" -> done(false, "KasSee HTML loaded, but its required application shell is incomplete.")
                "\"css\"" -> done(false, "KasSee HTML loaded, but its bundled stylesheet did not apply.")
                "\"layout\"" -> done(false, "KasSee loaded, but its application shell has no visible layout.")
                else -> done(false, "KasSee startup probe returned an unexpected result: $result")
            }
        }
    }

    private fun isCriticalResource(uri: Uri?): Boolean {
        if (uri?.host != ASSET_HOST || !uri.path.orEmpty().startsWith("/assets/kassee/")) return false
        return uri.path.orEmpty().let { it.endsWith(".css") || it.endsWith(".js") || it.endsWith(".wasm") }
    }

    private fun injectMobileAdaptations(target: WebView) {
        target.evaluateJavascript(
            """
            (() => {
              const bridge = {
                openMobileSettings: () => window.KasSignerMobile?.openMobileSettings?.(),
                resetWalletSurface: () => window.KasSignerMobile?.resetWalletSurface?.(),
              };
              import('./js/mobile/native_adaptations.js')
                .then(module => module.installMobileAdaptations(bridge))
                .catch(error => console.error('KasSigner mobile adaptations failed', error));
            })();
            """.trimIndent(),
            null,
        )
    }
}
