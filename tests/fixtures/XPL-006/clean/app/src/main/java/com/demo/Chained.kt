package com.demo
fun seal(key: SecretKey, random: SecureRandom): ByteArray {
    val iv = ByteArray(16).also { random.nextBytes(it) }
    cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
    return iv + cipher.doFinal(data)
}
