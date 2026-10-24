package com.acme.app

class ReCaptchaActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView.loadUrl(intent.getStringExtra("url")!!)
    }
}
