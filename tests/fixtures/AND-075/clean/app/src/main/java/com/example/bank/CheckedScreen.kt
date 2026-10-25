package com.example.bank

import android.content.Intent
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient

class CheckedScreen {
    private val allowedHosts = setOf("help.example.com")

    fun setUp(webView: WebView) {
        webView.settings.javaScriptEnabled = true
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url
                if (url.scheme == "https" && url.host in allowedHosts) return false
                view.context.startActivity(Intent(Intent.ACTION_VIEW, url))
                return true
            }
        }
        webView.loadUrl("https://help.example.com/")
    }
}
