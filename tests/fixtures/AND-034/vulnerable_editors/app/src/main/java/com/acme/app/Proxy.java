package com.acme.app;

class Proxy {
    void save(SharedPreferences prefs, String password) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("proxy_password", password);
        editor.apply();
    }
}
