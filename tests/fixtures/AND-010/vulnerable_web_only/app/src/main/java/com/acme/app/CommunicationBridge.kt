package com.acme.app

import android.webkit.WebView

// Low: universal access is on, but only https pages load, so no file:// page gets the access.
class CommunicationBridge(private val webView: WebView) {
    fun setup() {
        webView.settings.allowUniversalAccessFromFileURLs = true
        webView.loadUrl("https://en.wikipedia.org/api/page")
    }
}
