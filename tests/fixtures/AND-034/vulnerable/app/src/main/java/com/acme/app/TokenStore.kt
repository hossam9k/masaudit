package com.acme.app

import android.content.SharedPreferences
import androidx.datastore.preferences.core.stringPreferencesKey

private const val KEY_REFRESH = "refresh_token"

class TokenStore(private val prefs: SharedPreferences) {
    private val accessKey = stringPreferencesKey("access_token")

    fun save(token: String, refresh: String) {
        prefs.edit().putString("auth_token", token).apply()
        prefs.edit().putString(KEY_REFRESH, refresh).apply()
    }
}
