package com.demo
val a = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
val sig = KeyGenParameterSpec.Builder("s", KeyProperties.PURPOSE_SIGN)
    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).build()
