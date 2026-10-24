package com.example.bank

import timber.log.Timber

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Timber.plant(Timber.DebugTree())
        Timber.plant(LineNumberTree())
    }
}

class LineNumberTree : Timber.DebugTree() {
    override fun createStackElementTag(element: StackTraceElement) = "${element.fileName}:${element.lineNumber}"
}
