package com.demo
import android.security.keystore.KeyProperties
val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
val spec = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)   // RSA: "ECB" is only a name here
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
    .build()
// KEY_ALGORITHM_AES keys in this app use GCM elsewhere.
