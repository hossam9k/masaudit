package com.shop

import com.russhwolf.settings.SharedPreferencesSettings

fun provideSettings(prefs: android.content.SharedPreferences) = SharedPreferencesSettings(prefs)
