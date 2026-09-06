package org.kassigner.kassigner.app

import android.webkit.JavascriptInterface

internal class KasSeeMobileBridge(
    private val openMobileSettings: () -> Unit,
    private val resetWalletSurface: () -> Unit,
) {
    @JavascriptInterface
    fun openMobileSettings() = openMobileSettings.invoke()

    @JavascriptInterface
    fun resetWalletSurface() = resetWalletSurface.invoke()
}
