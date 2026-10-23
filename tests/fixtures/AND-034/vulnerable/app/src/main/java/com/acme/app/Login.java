package com.acme.app;

import android.content.SharedPreferences;

class Login {
    private static final String PREF_PASSWORD = "user_pass";

    void remember(SharedPreferences prefs, String password) {
        prefs.edit().putString(PREF_PASSWORD, password).apply();
    }
}
