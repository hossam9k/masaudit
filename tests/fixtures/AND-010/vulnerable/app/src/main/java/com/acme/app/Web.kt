package com.acme.app

fun setup(webView: WebView) {
    webView.settings.allowFileAccess = true
    webView.settings.allowUniversalAccessFromFileURLs = true
}
