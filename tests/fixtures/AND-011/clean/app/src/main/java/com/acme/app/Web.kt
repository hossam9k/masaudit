package com.acme.app

fun setup(webView: WebView) {
    // mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW was removed
    webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
}
