package com.acme.app

class WebClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        Log.w("web", "ssl error")
        handler.proceed()
    }
}
