package com.example.bank

// A wrapper that declares the method; nothing here adds a bridge to a WebView.
interface BridgeHost {
    fun addJavascriptInterface(bridge: Any, name: String)
}

class LoggingBridgeHost : BridgeHost {
    override fun addJavascriptInterface(bridge: Any, name: String) {
        println("bridge requested: $name")
    }
}
