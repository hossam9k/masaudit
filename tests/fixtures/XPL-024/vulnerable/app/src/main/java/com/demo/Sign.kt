package com.demo
val s = Signature.getInstance("SHA1withRSA")
val m = Signature.getInstance("MD5withRSA")
val spec = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN)
    .setDigests(KeyProperties.DIGEST_SHA1)
    .build()
