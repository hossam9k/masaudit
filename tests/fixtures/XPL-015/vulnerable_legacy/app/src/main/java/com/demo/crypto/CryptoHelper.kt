package com.demo.crypto

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object CryptoHelper {
    private enum class Algorithm(
        val factory: String,
        val iterationCount: Int,
        val keyStrength: Int
    ) {
        SHA1("PBKDF2WithHmacSHA1", 1024, 256),
        SHA256("PBKDF2WithHmacSHA256", 600000, 256)
    }

    private fun decrypt(algorithm: Algorithm, password: CharArray, salt: ByteArray): ByteArray {
        val f = SecretKeyFactory.getInstance(algorithm.factory)
        return f.generateSecret(PBEKeySpec(password, salt, algorithm.iterationCount, algorithm.keyStrength)).encoded
    }

    private fun encrypt(algorithm: Algorithm, password: CharArray, salt: ByteArray): ByteArray {
        val f = SecretKeyFactory.getInstance(algorithm.factory)
        return f.generateSecret(PBEKeySpec(password, salt, algorithm.iterationCount, algorithm.keyStrength)).encoded
    }
}
