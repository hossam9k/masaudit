package com.acme.app

fun aead(context: Context): Aead {
    val manager = AndroidKeysetManager.Builder()
        .withSharedPref(context, "session_keyset", "tink_keysets")
        .withMasterKeyUri("android-keystore://session_master_key")
        .build()
    if (!manager.isUsingKeystore) SecurityTelemetry.record("tink_keystore_unavailable")
    return manager.keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
}
