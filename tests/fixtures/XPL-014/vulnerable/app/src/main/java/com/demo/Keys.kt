package com.demo
const val KEY_BITS = 1024
fun rsa(): KeyPair {
    val gen = KeyPairGenerator.getInstance("RSA")
    gen.initialize(KEY_BITS)
    return gen.generateKeyPair()
}
fun curve() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp160r1")) }
fun keystore() = KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN)
    .setKeySize(1024).setDigests(KeyProperties.DIGEST_SHA256)
    .build().also { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore") }
