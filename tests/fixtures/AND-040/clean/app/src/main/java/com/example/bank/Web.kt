package com.example.bank

fun configure(webView: WebView) {
    webView.settings.safeBrowsingEnabled = true
    // webView.settings.safeBrowsingEnabled = false
    WebSettingsCompat.setSafeBrowsingEnabled(webView.settings, true)
}
