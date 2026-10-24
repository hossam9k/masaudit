package com.acme.app

class Messaging(private val webView: WebView, private val secret: String) {
    private val allowedDomains = setOf("duckduckgo.com")

    fun register() = webView.addJavascriptInterface(this, "Bridge")

    @JavascriptInterface
    fun process(message: String, secret: String) {
        val host = webView.url?.toUri()?.host
        if (secret != this.secret || host !in allowedDomains) return
    }
}
