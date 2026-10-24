package com.demo
val implicit = "https://login.demo.com/authorize?client_id=app&response_type=token&redirect_uri=demo://cb"
val body = mapOf("grant_type" to "password", "username" to user, "password" to pass)
fun login(webView: WebView) = webView.loadUrl("https://login.demo.com/oauth2/authorize?client_id=app")
