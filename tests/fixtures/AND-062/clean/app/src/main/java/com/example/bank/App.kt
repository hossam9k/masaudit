package com.example.bank

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
        if (BuildConfig.DEBUG) enableVmPolicy()
        initStrictMode()
    }

    private fun enableVmPolicy() {
        StrictMode.setVmPolicy(StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build())
    }

    private fun initStrictMode() {
        if (!BuildConfig.DEBUG) return
        StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())
    }
}
