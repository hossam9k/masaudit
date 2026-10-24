package com.demo
fun ec(): KeyPair {
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(256)
    return gen.generateKeyPair()
}
fun rsa() = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }
fun aes() = KeyGenParameterSpec.Builder("a", KeyProperties.PURPOSE_ENCRYPT)
    .setKeySize(256).build().also { KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES) }
fun p256() = ECGenParameterSpec("secp256r1")
fun dyn(bits: Int) = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }
