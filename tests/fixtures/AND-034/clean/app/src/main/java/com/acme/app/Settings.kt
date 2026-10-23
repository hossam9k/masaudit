package com.acme.app

import android.content.SharedPreferences
import androidx.datastore.preferences.core.stringPreferencesKey

// Storing the refresh_token in plain prefs would be wrong; we don't.
class Settings(private val prefs: SharedPreferences) {
    private val themeKey = stringPreferencesKey("theme")
    private val fcmKey = stringPreferencesKey("fcm_token")

    fun save(theme: String, pushToken: String) {
        prefs.edit().putString("theme", theme).apply()
        prefs.edit().putString("push_token", pushToken).apply()
        prefs.edit().putString("message", "Your token expired").apply()
    }
}
