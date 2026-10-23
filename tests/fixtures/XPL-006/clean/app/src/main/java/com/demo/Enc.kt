package com.demo
fun encrypt(plaintext: ByteArray, key: SecretKey): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.iv + cipher.doFinal(plaintext)
}
fun decrypt(stored: ByteArray, key: SecretKey): ByteArray {
    val iv = stored.copyOfRange(0, 12)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    return cipher.doFinal(stored.copyOfRange(12, stored.size))
}
fun legacy(key: SecretKey) {
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    Cipher.getInstance("AES/CBC/PKCS5Padding").init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
    // IvParameterSpec(ByteArray(16)) was the old, broken version
}
