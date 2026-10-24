package com.example.bank

fun spec() = KeyGenParameterSpec.Builder("vault", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setRandomizedEncryptionRequired(false)
    .build()
