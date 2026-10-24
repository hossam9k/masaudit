package com.demo
fun createKey(prefs: SharedPreferences) {
    val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    prefs.edit().putString("db_key", Base64.encodeToString(key.encoded, Base64.NO_WRAP)).apply()
}
