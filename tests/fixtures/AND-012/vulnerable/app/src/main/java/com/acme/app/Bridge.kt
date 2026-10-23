package com.acme.app

fun setup(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.addJavascriptInterface(NarrowBridge(), "AppBridge")
}
