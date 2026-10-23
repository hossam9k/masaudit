package com.demo
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
val spec = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_ENCRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
    .build()
