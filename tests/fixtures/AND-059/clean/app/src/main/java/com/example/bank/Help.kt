package com.example.bank

fun setup(webView: WebView) {
    webView.settings.apply {
        javaScriptEnabled = true
        allowContentAccess = false
    }
}
