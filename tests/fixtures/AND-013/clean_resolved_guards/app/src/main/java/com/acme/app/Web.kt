package com.acme.app

class Web(private val context: Context) {
    private val isDebuggable get() = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    fun setup() {
        if (isDebuggable || context.resources.getBoolean(R.bool.is_beta)) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
    }

    fun devOnly() {
        if (!BuildConfig.DEBUG) return
        WebView.setWebContentsDebuggingEnabled(true)
    }
}
