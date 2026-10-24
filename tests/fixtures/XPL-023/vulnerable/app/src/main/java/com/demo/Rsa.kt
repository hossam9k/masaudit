package com.demo
val a = Cipher.getInstance("RSA")
val b = Cipher.getInstance("RSA/ECB/PKCS1Padding")
val spec = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_DECRYPT)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1).build()
