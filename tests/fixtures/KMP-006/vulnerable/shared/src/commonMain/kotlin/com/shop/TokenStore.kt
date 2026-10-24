package com.shop

import com.russhwolf.settings.Settings
import com.russhwolf.settings.set

class TokenStore(private val settings: Settings) {
    fun saveAccess(token: String) = settings.putString("access_token", token)
    fun saveRefresh(token: String) {
        settings[KEY_REFRESH] = token
    }
    fun savePassword(pw: String) = settings.set(PASSWORD_KEY, pw)
    fun saveTheme(theme: String) = settings.putString("theme", theme)

    companion object {
        const val KEY_REFRESH = "refresh_token"
        const val PASSWORD_KEY = "pw"
    }
}
