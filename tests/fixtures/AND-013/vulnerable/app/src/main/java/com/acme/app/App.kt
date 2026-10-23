package com.acme.app

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        WebView.setWebContentsDebuggingEnabled(true)
    }

    fun later() {
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        WebView.setWebContentsDebuggingEnabled(true)
    }
}
