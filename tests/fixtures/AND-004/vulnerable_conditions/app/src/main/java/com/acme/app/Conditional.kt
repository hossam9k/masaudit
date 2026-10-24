package com.acme.app

class Conditional(private val prefs: SharedPreferences) : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        if (prefs.getBoolean("ignore_ssl", false)) handler.proceed()
        if (BuildConfig.DEBUG) {
            handler.proceed()
        }
    }
}
