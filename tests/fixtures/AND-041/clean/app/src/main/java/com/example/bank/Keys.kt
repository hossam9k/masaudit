package com.example.bank

// .setRandomizedEncryptionRequired(false) would let callers pick the IV
fun spec() = KeyGenParameterSpec.Builder("vault", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setRandomizedEncryptionRequired(true)
    .build()
