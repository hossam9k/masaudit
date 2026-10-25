package com.example.bank

import android.webkit.JavascriptInterface
import android.webkit.WebView

class SupportBridge {
    @JavascriptInterface
    fun accountId(): String = "demo"
}

class SupportScreen(private val webView: WebView, private val pageUrl: String) {
    fun show() {
        webView.apply {
            settings.javaScriptEnabled = true
            addJavascriptInterface(SupportBridge(), "SupportBridge")
            loadUrl(pageUrl)
        }
    }
}
