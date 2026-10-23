package com.acme.app;

class BridgeJava {
    void setup(WebView w) {
        w.addJavascriptInterface(new NarrowBridge(), "AppBridge");
    }
}
