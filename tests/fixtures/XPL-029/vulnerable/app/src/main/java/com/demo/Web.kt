package com.demo
fun show(webView: WebView, balance: String) {
    webView.evaluateJavascript("document.querySelector('#bal').textContent = '" + balance + "'", null)
}
