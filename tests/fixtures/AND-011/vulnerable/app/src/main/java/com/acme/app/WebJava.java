package com.acme.app;

class WebJava {
    void setup(WebView w) {
        w.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }
}
