package com.acme.app

fun setup(webView: WebView) {
    // webView.addJavascriptInterface(...) exposed every frame; replaced below
    webView.removeJavascriptInterface("AppBridge")
    WebViewCompat.addWebMessageListener(webView, "AppBridge", setOf("https://app.example.com")) { _, _, _, _, _ -> }
}
