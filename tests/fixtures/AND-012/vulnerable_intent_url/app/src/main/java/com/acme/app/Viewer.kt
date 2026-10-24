package com.acme.app

import android.app.Activity
import android.webkit.WebView

// High: the bridge sits in a WebView that loads whatever URL the intent carries.
class Viewer : Activity() {
    fun show(webView: WebView) {
        webView.addJavascriptInterface(Bridge(), "b")
        webView.loadUrl(intent.dataString!!)
    }
}
