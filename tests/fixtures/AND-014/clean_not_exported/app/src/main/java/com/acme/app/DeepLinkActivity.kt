package com.acme.app

class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = sanitizeRecaptchaUrl(intent.getStringExtra("url"))
        webView.loadUrl(url)
    }
}
