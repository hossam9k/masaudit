package com.example.bank

fun setup(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.loadUrl("https://help.example-bank.com")
}
