package com.example.bank

import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient

// JavaScript stays off in this WebView.
class NoScriptScreen {
    fun setUp(webView: WebView) {
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean = false
        }
        webView.loadUrl("https://terms.example.com/")
    }
}
