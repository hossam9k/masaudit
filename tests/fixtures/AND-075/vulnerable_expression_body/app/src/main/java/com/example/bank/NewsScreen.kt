package com.example.bank

import android.webkit.WebView
import android.webkit.WebViewClient

// An expression body that starts on the next line: `fun ...(...)` then `= false`.
class NewsClient : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, url: String?)
        = false
}

class NewsScreen {
    fun setUp(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        webView.webViewClient = NewsClient()
    }
}
