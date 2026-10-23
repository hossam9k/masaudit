package com.acme.app

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        WebView.setWebContentsDebuggingEnabled(debuggable)
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)
        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        WebView.setWebContentsDebuggingEnabled(false)
        // WebView.setWebContentsDebuggingEnabled(true)
    }
}
