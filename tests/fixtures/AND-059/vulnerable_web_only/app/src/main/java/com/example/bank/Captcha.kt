package com.example.bank

import android.webkit.WebView

// Low: only an https page loads here, and a web page can't open content:// URLs.
fun showCaptcha(webView: WebView) {
    webView.settings.javaScriptEnabled = true
    webView.loadUrl("https://captcha.example.com")
}
