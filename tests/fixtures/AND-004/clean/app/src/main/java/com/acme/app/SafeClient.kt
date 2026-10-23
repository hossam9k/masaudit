package com.acme.app

class SafeClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        // handler.proceed() would accept any certificate
        handler.cancel()
    }
}

class Flow {
    fun next(chain: Chain) {
        chain.proceed()
    }
}
