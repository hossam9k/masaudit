package com.acme.app

class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView.loadUrl(intent.getStringExtra("url")!!)
        val target = intent.data?.getQueryParameter("next") ?: return
        webView.loadUrl(target)
    }
}
