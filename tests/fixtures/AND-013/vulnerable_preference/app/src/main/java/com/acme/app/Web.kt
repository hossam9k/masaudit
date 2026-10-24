package com.acme.app

fun setup(prefs: SharedPreferences) {
    if (prefs.getBoolean("dev", false)) WebView.setWebContentsDebuggingEnabled(true)
}
