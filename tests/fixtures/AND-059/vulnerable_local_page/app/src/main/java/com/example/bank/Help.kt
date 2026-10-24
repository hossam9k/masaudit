package com.example.bank

import android.webkit.WebView

// Medium: a file: page runs script with content:// access on.
fun showHelp(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.loadUrl("file:///android_asset/x.html")
}
