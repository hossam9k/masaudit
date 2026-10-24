package com.demo.securestorage

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class SecureStorageKeyGenerator {
    fun generateKeyFromPassword(password: String, salt: ByteArray): SecretKeySpec {
        val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val key = f.generateSecret(PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256))
        return SecretKeySpec(key.encoded, "AES")
    }

    companion object {
        private const val ITERATIONS = 100_000
    }
}
