package com.demo
private const val CIPHER_TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" +
    KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7
fun encrypt(key: SecretKey, data: ByteArray): ByteArray =
    Cipher.getInstance(CIPHER_TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }.doFinal(data)
