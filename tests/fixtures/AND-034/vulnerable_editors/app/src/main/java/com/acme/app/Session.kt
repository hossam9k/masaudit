package com.acme.app

fun save(prefs: SharedPreferences, rt: String) {
    prefs.edit { putString("refresh_token", rt) }
}
