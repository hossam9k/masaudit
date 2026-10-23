package com.acme.app

class SafeActivity : Activity() {
    private val allowedHosts = setOf("app.example.com")
    fun isAllowed(uri: Uri) = uri.scheme == "https" && uri.host?.lowercase() in allowedHosts
    fun open() {
        val target = Uri.parse(intent.getStringExtra("url") ?: return)
        if (isAllowed(target)) webView.loadUrl(target.toString())
    }
}
