package com.demo
fun createKey() {
    val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    gen.init(KeyGenParameterSpec.Builder("db", KeyProperties.PURPOSE_ENCRYPT).build())
    gen.generateKey()
}
fun wrapped(prefs: SharedPreferences, wrapper: Cipher) {
    val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    prefs.edit().putString("db_key", Base64.encodeToString(wrapper.wrap(key), Base64.NO_WRAP)).apply()
}
