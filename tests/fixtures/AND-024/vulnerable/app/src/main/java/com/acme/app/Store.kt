package com.acme.app

fun aead(context: Context): Aead {
    val manager = AndroidKeysetManager.Builder()
        .withSharedPref(context, "session_keyset", "tink_keysets")
        .withMasterKeyUri("android-keystore://session_master_key")
        .build()
    // TODO: check isUsingKeystore
    return manager.keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
}
