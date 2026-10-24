package com.acme.app

import android.webkit.WebView

// Medium: the WebView only loads a bundled page and a fixed https page.
class Dashboard(private val webView: WebView) {
    fun show() {
        webView.addJavascriptInterface(Bridge(), "b")
        webView.loadUrl("file:///android_asset/dash.html")
    }

    fun help() {
        webView.loadUrl(HELP_URL)
        webView.loadUrl("about:blank")
    }

    companion object {
        const val HELP_URL = "https://help.example.com/dashboard"
    }
}
