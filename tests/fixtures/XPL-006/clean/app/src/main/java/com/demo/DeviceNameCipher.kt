package com.demo
object DeviceNameCipher {
    fun encrypt(plaintext: ByteArray, masterSecret: ByteArray): ByteArray {
        val syntheticIv = computeSyntheticIv(masterSecret, plaintext)
        val cipherKey: ByteArray = computeCipherKey(masterSecret, syntheticIv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(cipherKey, "AES"), IvParameterSpec(ByteArray(16)))
        return cipher.doFinal(plaintext)
    }
}
