package com.acme.app

class HelpActivity : Activity() {
    fun open() {
        val title = intent.getStringExtra("title")
        titleView.text = title
        webView.loadUrl("https://app.example.com/help")
        // webView.loadUrl(intent.getStringExtra("url"))
    }
}
