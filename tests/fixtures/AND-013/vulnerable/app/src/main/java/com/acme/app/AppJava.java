package com.acme.app;

class AppJava {
    void init() {
        if (!BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
    }
}
