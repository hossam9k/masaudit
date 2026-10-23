package com.acme.app;

class WebJava {
    void setup(WebView w) {
        w.getSettings().setAllowContentAccess(false);
        w.getSettings().setAllowFileAccess(false);
    }
}
