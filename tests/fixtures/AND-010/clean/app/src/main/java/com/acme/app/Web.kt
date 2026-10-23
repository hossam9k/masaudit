package com.acme.app

fun setup(webView: WebView) {
    webView.settings.apply {
        allowFileAccess = false
        allowContentAccess = false
        // allowFileAccess = true was removed
    }
    Log.d("web", "allowFileAccess = true is unsafe")
    if (webView.settings.allowFileAccess == true) Log.w("web", "check")
}
