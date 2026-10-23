package com.acme.app;

class WebJava {
    void setup(WebView w) {
        w.getSettings().setAllowFileAccessFromFileURLs(true);
    }
}
