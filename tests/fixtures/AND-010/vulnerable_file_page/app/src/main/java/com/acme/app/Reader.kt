package com.acme.app

import android.webkit.WebView

// High: a file:// page from shared storage gets universal access.
fun openDownloaded(webView: WebView) {
    webView.settings.allowUniversalAccessFromFileURLs = true
    webView.loadUrl("file:///sdcard/x.html")
}
