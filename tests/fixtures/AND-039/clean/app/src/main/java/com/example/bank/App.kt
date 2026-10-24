package com.example.bank

import timber.log.Timber

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        } else {
            Timber.plant(ReleaseTree())
        }
        if (BuildConfig.VERBOSE_LOGS) Timber.plant(Timber.DebugTree())
        plantFiltered()
        devTools()
    }

    private fun devTools() {
        if (!BuildConfig.DEBUG) return
        Timber.plant(Timber.DebugTree())
    }

    private fun plantFiltered() = Timber.plant(WarningTree())
    // Timber.plant(Timber.DebugTree())
}

class WarningTree : Timber.DebugTree() {
    override fun isLoggable(tag: String?, priority: Int) = priority >= Log.WARN
}

class ReleaseTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) = Unit
}
