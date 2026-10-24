package com.demo
val s = Signature.getInstance("SHA256withECDSA")
val spec = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build()
val legacyHash = KeyGenParameterSpec.Builder("h", KeyProperties.PURPOSE_ENCRYPT).setDigests(KeyProperties.DIGEST_SHA1).build()
