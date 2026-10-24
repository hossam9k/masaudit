package com.acme.app

class Validating(private val validator: ChainValidator) : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        if (validator.validate(error.certificate) is TrustedChain) {
            handler.proceed()
        } else {
            handler.cancel()
        }
    }
}
