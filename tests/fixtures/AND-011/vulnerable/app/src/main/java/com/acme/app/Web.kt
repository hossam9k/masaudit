package com.acme.app

fun setup(webView: WebView) {
    webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
}
