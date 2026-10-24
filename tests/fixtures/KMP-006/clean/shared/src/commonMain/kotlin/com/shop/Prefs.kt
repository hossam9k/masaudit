package com.shop

import com.russhwolf.settings.Settings
import com.russhwolf.settings.set

class Prefs(private val settings: Settings, private val editor: android.content.SharedPreferences.Editor) {
    fun saveTheme(theme: String) = settings.putString("theme", theme)
    fun savePushToken(t: String) = settings.putString("fcm_token", t)
    fun saveUserId(id: String) { settings["user_id"] = id }
    fun legacy(t: String) = editor.putString("auth_token", t)
    fun state(t: String) { tokenFlow.set(t) }
}
